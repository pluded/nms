import logging
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity, nextCmd
)
from pysnmp.smi import rfc1902

logger = logging.getLogger(__name__)

# LLDP Remote Table OIDs
LLDP_REM_TABLE_OID = '1.0.8802.1.1.2.1.4.1'
LLDP_REM_ENTRY_OID = LLDP_REM_TABLE_OID + '.1' # lldpRemEntry

# Column OIDs within lldpRemEntry
OID_LLDP_REM_CHASSIS_ID_SUBTYPE = LLDP_REM_ENTRY_OID + '.4' # lldpRemChassisIdSubtype
OID_LLDP_REM_CHASSIS_ID = LLDP_REM_ENTRY_OID + '.5'       # lldpRemChassisId
OID_LLDP_REM_PORT_ID_SUBTYPE = LLDP_REM_ENTRY_OID + '.6'  # lldpRemPortIdSubtype
OID_LLDP_REM_PORT_ID = LLDP_REM_ENTRY_OID + '.7'          # lldpRemPortId
OID_LLDP_REM_PORT_DESC = LLDP_REM_ENTRY_OID + '.8'        # lldpRemPortDesc
OID_LLDP_REM_SYS_NAME = LLDP_REM_ENTRY_OID + '.9'         # lldpRemSysName
# lldpRemLocalPortNum is part of the index, not a column OID to fetch directly via getCmd in this manner.
# It's the second part of the instance identifier for lldpRemEntry.

def _format_mac_address(octet_string: rfc1902.OctetString) -> str:
    """Formats an OctetString representing a MAC address into AA:BB:CC:DD:EE:FF format."""
    return ':'.join(['%02X' % ord(x) for x in octet_string.asOctets()])

def get_lldp_neighbors(ip_address: str, community_string: str, timeout: int = 2, retries: int = 1) -> list[dict] | None:
    """
    Retrieves LLDP neighbor information from a device using SNMP.

    Args:
        ip_address: The IP address of the target device.
        community_string: The SNMP community string.
        timeout: SNMP request timeout in seconds.
        retries: Number of SNMP request retries.

    Returns:
        A list of dictionaries, where each dictionary represents an LLDP neighbor.
        Returns None if there's a major SNMP error.
        Returns an empty list if no neighbors are found or table is empty.
    """
    logger.debug(f"Attempting LLDP neighbor discovery for {ip_address} with community '{community_string}'")

    snmp_engine = SnmpEngine()
    community_data = CommunityData(community_string)
    transport_target = UdpTransportTarget((ip_address, 161), timeout=timeout, retries=retries)
    context_data = ContextData()

    # OIDs to walk. We are walking columns of the lldpRemTable.
    var_binds_to_walk = [
        ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID_SUBTYPE)),
        ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID)),
        ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID_SUBTYPE)),
        ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID)),
        ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_DESC)),
        ObjectType(ObjectIdentity(OID_LLDP_REM_SYS_NAME)),
    ]

    neighbors = []
    current_row_data = {}
    # The index of lldpRemEntry is (lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex)
    # We need to track changes in these to know when we are on a new row.
    last_row_indices = None

    for error_indication, error_status, error_index, var_bind_table_row in nextCmd(
            snmp_engine, community_data, transport_target, context_data,
            *var_binds_to_walk, lexicographicMode=False): # lexicographicMode=False is important

        if error_indication:
            logger.error(f"SNMP error for {ip_address} during LLDP discovery: {error_indication}")
            return None  # Major SNMP error
        elif error_status:
            logger.error(
                f"SNMP error for {ip_address} at OID {var_bind_table_row[int(error_index) - 1][0] if error_index else '?'}: {error_status.prettyPrint()}"
            )
            break # Stop processing on error for this row or further rows

        # var_bind_table_row contains one varBind for each OID in var_binds_to_walk for the current conceptual "row"
        # All varBinds in var_bind_table_row should belong to the same conceptual neighbor entry.
        # We need to check if the OID prefix indicates we are still in the lldpRemEntry table.
        
        # Check if we are still in the LLDP remote table for all returned OIDs
        # If any OID is outside LLDP_REM_ENTRY_OID, we've walked past the table.
        if not all(str(var_bind[0]).startswith(LLDP_REM_ENTRY_OID) for var_bind in var_bind_table_row):
            logger.debug(f"Finished LLDP table walk for {ip_address} or OID out of scope.")
            break # Exited the lldpRemTable

        # Extract instance identifiers to determine the row (lldpRemLocalPortNum is key)
        # The instance part of the OID for lldpRemEntry is .TimeMark.LocalPortNum.RemIndex
        # Example: OID_LLDP_REM_CHASSIS_ID + .1.56.1 (TimeMark=1, LocalPortNum=56, RemIndex=1)
        # We can get the full instance suffix from any of the varBinds in the row.
        
        try:
            # Assuming all varBinds in this row share the same index part after their base column OID
            # Example: OID_LLDP_REM_CHASSIS_ID is '1.0.8802.1.1.2.1.4.1.1.5'
            # Full OID might be '1.0.8802.1.1.2.1.4.1.1.5.time_mark.local_port_num.rem_index'
            # We need to get the suffix parts: time_mark, local_port_num, rem_index
            
            # Take the first varBind to extract index info
            first_var_bind_oid_str = str(var_bind_table_row[0][0])
            base_column_oid_str = str(var_binds_to_walk[0][0]) # e.g. OID_LLDP_REM_CHASSIS_ID_SUBTYPE
            
            # The instance part starts after the base column OID.
            # This is a bit fragile if base_column_oid_str isn't an exact prefix of first_var_bind_oid_str
            # (e.g. if table is empty, nextCmd might return something way out of scope)
            # The check `startswith(LLDP_REM_ENTRY_OID)` above should guard this.
            
            instance_suffix_str = first_var_bind_oid_str[len(base_column_oid_str):]
            instance_parts = instance_suffix_str.strip('.').split('.')
            
            if len(instance_parts) < 3:
                logger.warning(f"Could not parse instance indices from OID {first_var_bind_oid_str} for {ip_address}")
                continue # Skip this entry

            # lldpRemLocalPortNum is the second part of the index for lldpRemEntry
            local_port_num = int(instance_parts[1]) # Index 1 is lldpRemLocalPortNum
            current_row_indices = tuple(instance_parts) # Use all parts for unique row ID

        except (ValueError, IndexError) as e:
            logger.error(f"Error parsing LLDP indices for {ip_address}: {e}. OID: {first_var_bind_oid_str}", exc_info=True)
            continue # Skip this entry if indices are malformed

        if last_row_indices != current_row_indices:
            if current_row_data: # Save completed previous row
                neighbors.append(current_row_data)
            current_row_data = {'local_port_num': local_port_num, 'protocol': 'LLDP'}
            last_row_indices = current_row_indices

        # Populate current_row_data
        for var_bind in var_bind_table_row:
            oid_str = str(var_bind[0])
            val = var_bind[1]

            if oid_str.startswith(OID_LLDP_REM_CHASSIS_ID_SUBTYPE):
                current_row_data['remote_chassis_id_subtype'] = int(val)
            elif oid_str.startswith(OID_LLDP_REM_CHASSIS_ID):
                subtype = current_row_data.get('remote_chassis_id_subtype')
                if subtype == 4 and isinstance(val, rfc1902.OctetString): # MAC address
                    current_row_data['remote_chassis_id'] = _format_mac_address(val)
                else:
                    current_row_data['remote_chassis_id'] = str(val.prettyPrint())
            elif oid_str.startswith(OID_LLDP_REM_PORT_ID_SUBTYPE):
                current_row_data['remote_port_id_subtype'] = int(val)
            elif oid_str.startswith(OID_LLDP_REM_PORT_ID):
                subtype = current_row_data.get('remote_port_id_subtype')
                if subtype == 3 and isinstance(val, rfc1902.OctetString): # MAC address
                     current_row_data['remote_port_id'] = _format_mac_address(val)
                elif subtype == 7 and isinstance(val, rfc1902.OctetString): # Locally assigned, often a string
                    current_row_data['remote_port_id'] = val.asOctets().decode('utf-8', 'ignore')
                else:
                    current_row_data['remote_port_id'] = str(val.prettyPrint())
            elif oid_str.startswith(OID_LLDP_REM_PORT_DESC):
                current_row_data['remote_port_desc'] = str(val.prettyPrint())
            elif oid_str.startswith(OID_LLDP_REM_SYS_NAME):
                current_row_data['remote_system_name'] = str(val.prettyPrint())
    
    # Add the last processed row if it exists
    if current_row_data and 'remote_chassis_id' in current_row_data : # Ensure some data was collected for the row
        neighbors.append(current_row_data)

    # Clean up subtype fields as they are intermediate
    for neighbor in neighbors:
        neighbor.pop('remote_chassis_id_subtype', None)
        neighbor.pop('remote_port_id_subtype', None)

    logger.info(f"Found {len(neighbors)} LLDP neighbors for {ip_address}.")
    return neighbors


if __name__ == '__main__':
    # Example Usage - Requires a device with LLDP enabled and SNMP agent
    # Ensure logger is configured for direct script execution for testing
    try:
        from nms.utils.logger import setup_logging
        setup_logging(log_level=logging.DEBUG, force_setup=True)
    except ImportError: # Fallback if run completely standalone
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


    # --- LLDP Test ---
    test_target_ip_lldp = "127.0.0.1"  # Replace with your test device's IP for LLDP
    test_target_community_lldp = "public"   # Replace with your community string for LLDP

    logger.info(f"--- Starting direct test for LLDP link_discovery.py on {test_target_ip_lldp} ---")
    
    lldp_info = get_lldp_neighbors(test_target_ip_lldp, test_target_community_lldp)

    if lldp_info is None:
        logger.error(f"LLDP discovery failed for {test_target_ip_lldp}. Check SNMP settings and device logs.")
    elif not lldp_info:
        logger.info(f"No LLDP neighbors found for {test_target_ip_lldp} or LLDP not supported/enabled.")
    else:
        logger.info(f"LLDP Neighbors for {test_target_ip_lldp}:")
        for i, neighbor in enumerate(lldp_info):
            logger.info(f"  Neighbor #{i+1}:")
            logger.info(f"    Local Port Num: {neighbor.get('local_port_num')}")
            logger.info(f"    Remote Chassis ID: {neighbor.get('remote_chassis_id')}")
            logger.info(f"    Remote Port ID: {neighbor.get('remote_port_id')}")
            logger.info(f"    Remote Port Description: {neighbor.get('remote_port_desc')}")
            logger.info(f"    Remote System Name: {neighbor.get('remote_system_name')}")
            logger.info(f"    Protocol: {neighbor.get('protocol')}")

    non_existent_ip_lldp = "192.0.2.254" # TEST-NET-3
    logger.info(f"--- Testing LLDP for non-existent IP {non_existent_ip_lldp} ---")
    lldp_info_timeout = get_lldp_neighbors(non_existent_ip_lldp, test_target_community_lldp, timeout=1, retries=0)
    if lldp_info_timeout is None:
        logger.info(f"LLDP for {non_existent_ip_lldp} correctly returned None (expected timeout/error).")
    else:
        logger.error(f"LLDP for {non_existent_ip_lldp} unexpectedly returned data or empty list: {lldp_info_timeout}")

    logger.info("--- Direct test for LLDP link_discovery.py complete ---")


    # --- CDP Test ---
    test_target_ip_cdp = "127.0.0.1"  # Replace with your Cisco test device's IP for CDP
    test_target_community_cdp = "public"   # Replace with your community string for CDP

    logger.info(f"--- Starting direct test for CDP link_discovery.py on {test_target_ip_cdp} ---")
    cdp_info = get_cdp_neighbors(test_target_ip_cdp, test_target_community_cdp)

    if cdp_info is None:
        logger.error(f"CDP discovery failed for {test_target_ip_cdp}. Check SNMP settings and device logs.")
    elif not cdp_info:
        logger.info(f"No CDP neighbors found for {test_target_ip_cdp} or CDP not supported/enabled.")
    else:
        logger.info(f"CDP Neighbors for {test_target_ip_cdp}:")
        for i, neighbor in enumerate(cdp_info):
            logger.info(f"  Neighbor #{i+1}:")
            logger.info(f"    Local ifIndex: {neighbor.get('local_ifindex')}")
            logger.info(f"    Remote Device ID: {neighbor.get('remote_device_id')}")
            logger.info(f"    Remote IP: {neighbor.get('remote_device_ip')}")
            logger.info(f"    Remote Interface: {neighbor.get('remote_interface')}")
            logger.info(f"    Remote Platform: {neighbor.get('remote_platform')}")
            logger.info(f"    Protocol: {neighbor.get('protocol')}")
    
    non_existent_ip_cdp = "192.0.2.253" # TEST-NET-3 (different from LLDP test)
    logger.info(f"--- Testing CDP for non-existent IP {non_existent_ip_cdp} ---")
    cdp_info_timeout = get_cdp_neighbors(non_existent_ip_cdp, test_target_community_cdp, timeout=1, retries=0)
    if cdp_info_timeout is None:
        logger.info(f"CDP for {non_existent_ip_cdp} correctly returned None (expected timeout/error).")
    else:
        logger.error(f"CDP for {non_existent_ip_cdp} unexpectedly returned data or empty list: {cdp_info_timeout}")

    logger.info("--- Direct test for CDP link_discovery.py complete ---")
