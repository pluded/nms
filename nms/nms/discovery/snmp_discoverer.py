import logging
from pysnmp.hlapi import (
    getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)

logger = logging.getLogger(__name__)

# Standard OIDs
OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0'
OID_SYS_OBJECT_ID = '1.3.6.1.2.1.1.2.0'

# Simple OID prefix to Vendor mapping
OID_VENDOR_MAP = {
    '1.3.6.1.4.1.9.': 'Cisco',        # Cisco
    '1.3.6.1.4.1.2636.': 'Juniper',     # Juniper
    '1.3.6.1.4.1.11.': 'HPE',          # HP Enterprise
    '1.3.6.1.4.1.25506.': 'HPE',       # Aruba (HPE)
    '1.3.6.1.4.1.311.': 'Microsoft',   # Microsoft (Windows SNMP Agent)
    '1.3.6.1.4.1.8072.': 'NetSNMP',    # Net-SNMP (often Linux)
    '1.3.6.1.4.1.2011.': 'Huawei',     # Huawei
    '1.3.6.1.4.1.1991.': 'Dell',       # Dell
    '1.3.6.1.4.1.2272.': 'Dell',       # Dell Force10
    '1.3.6.1.4.1.45.': 'Extreme',      # Extreme Networks
    '1.3.6.1.4.1.1916.': 'Extreme',    # Enterasys (Extreme)
    '1.3.6.1.4.1.674.': 'Dell',        # Dell PowerEdge Servers
    '1.3.6.1.4.1.232.': 'HPE',         # Compaq (HPE)
    # Add more as needed
}

# Regex patterns for sysDescr parsing
# Order matters: more specific patterns should come first.
SYS_DESCR_PATTERNS = [
    {
        'vendor': 'Cisco', # Known vendor for this pattern
        'regex': r"Cisco IOS Software, ([^ ]+) Software \(([^)]+)\), Version ([^,]+),",
        'model_group': 1, # Model can be complex, this is a simplification (e.g. C2960)
        'platform_group': 2, # Often more detailed platform/series (e.g. C2960-LANBASEK9-M)
        'version_group': 3
    },
    {
        'vendor': 'Cisco', # IOS-XE
        'regex': r"Cisco IOS XE Software, Version ([^,]+)",
        'version_group': 1
        # Model might be harder to get reliably from sysDescr for IOS-XE, often in entity MIB
    },
    {
        'vendor': 'Juniper',
        'regex': r"Juniper Networks, Inc. ([^ ]+)(?: ([^ ]+))? internet router, kernel JUNOS ([^ ]+)",
        # Example: "Juniper Networks, Inc. mx240 internet router, kernel JUNOS 19.4R3-S2.3"
        # Example: "Juniper Networks, Inc. ex2200-c-12t-2g ethernet switch, kernel JUNOS 12.3R12.4"
        'model_group': 1, # e.g., mx240, ex2200-c-12t-2g
        'type_group': 2, # e.g., 'ethernet switch' or None
        'version_group': 3
    },
    {
        'vendor': 'HPE', # ArubaOS / older ProCurve
        'regex': r"ArubaOS \(MODEL: ([^)]+)\), Version ([^\s,]+)",
        'model_group': 1,
        'version_group': 2
    },
    {
        'vendor': 'HPE', # ProCurve / Comware-like
        'regex': r"HPE Comware Software, Version ([^,]+), Release ([^\s,]+) \S+ Model is (HP|HPE) ([^\.]+)\.",
        # Example: "HPE Comware Software, Version 7.1.070, Release 3507P01, PEX. Model is HP A5120-24G-PoE+ EI Switch with 2 Slots."
        'version_group': 2, # Release number as version
        'model_group': 4,
    },
    { # General Linux pattern
        'vendor': 'Linux',
        'regex': r"Linux version ([^\s]+) \(([^)]+)\) (?:\[[^\]]+\] )?([^#]+)#",
        'version_group': 1, # Kernel version
        'model_group': None # Model is not typically in Linux sysDescr this way
    },
    { # Fortinet FortiOS
        'vendor': 'Fortinet',
        'regex': r"FortiGate VM64 v([^\s,]+) \(([^)]+)\)", # Example "FortiGate VM64 v6.0.5,build0268,190307 (GA)"
        'version_group': 1,
        'model_group': None # Model is often generic like VM64 or hardware model not in this string
    },
    # Add more patterns here, from specific to more general
]


def discover_snmp(ip_address: str, community_string: str, timeout: int = 1, retries: int = 0) -> dict | None:
    """
    Performs SNMP GET requests to discover basic system information from a device,
    and attempts to parse vendor, model, and software version from the results.

    Args:
        ip_address: The IP address of the target device.
        community_string: The SNMP community string for authentication.
        timeout: SNMP request timeout in seconds.
        retries: Number of SNMP request retries.

    Returns:
        A dictionary containing 'sysDescr' and 'sysObjectID' if successful,
        otherwise None.
    """
    logger.debug(f"Attempting SNMP discovery for {ip_address} with community '{community_string}'")

    snmp_engine = SnmpEngine()
    community_data = CommunityData(community_string)
    transport_target = UdpTransportTarget((ip_address, 161), timeout=timeout, retries=retries)
    context_data = ContextData()

    oids_to_fetch = [
        ObjectType(ObjectIdentity(OID_SYS_DESCR)),
        ObjectType(ObjectIdentity(OID_SYS_OBJECT_ID))
    ]

    iterator = getCmd(
        snmp_engine,
        community_data,
        transport_target,
        context_data,
        *oids_to_fetch
    )

    error_indication, error_status, error_index, var_binds = next(iterator)

    if error_indication:
        logger.error(f"SNMP error for {ip_address}: {error_indication}")
        return None
    elif error_status:
        error_oid_info = var_binds[int(error_index) - 1] if var_binds and 0 < int(error_index) <= len(var_binds) else 'N/A'
        logger.error(
            f"SNMP error for {ip_address}: {error_status.prettyPrint()} at "
            f"{error_index and oids_to_fetch[int(error_index) - 1][0] or '?'}. "
            f"Problematic OID info: {error_oid_info}"
        )
        return None

    results = {}
    if var_binds and len(var_binds) == 2:
        try:
            # var_binds contains ObjectType instances, which are tuples (ObjectIdentity, value)
            raw_sys_descr = None
            raw_sys_object_id = None

            for oid, val in var_binds:
                oid_str = str(oid)
                if oid_str == OID_SYS_DESCR:
                    raw_sys_descr = val
                elif oid_str == OID_SYS_OBJECT_ID:
                    raw_sys_object_id = val
            
            if raw_sys_descr is None or raw_sys_object_id is None:
                logger.error(f"Could not extract one or both standard OIDs for {ip_address}. varBinds: {var_binds}")
                return None

            sys_descr_str = str(raw_sys_descr.prettyPrint())
            sys_object_id_str = str(raw_sys_object_id.prettyPrint())

            parsed_attributes = {
                'sysDescr': sys_descr_str,
                'sysObjectID': sys_object_id_str
            }
            logger.debug(f"Base SNMP data for {ip_address}: sysDescr='{sys_descr_str}', sysObjectID='{sys_object_id_str}'")

            # Attempt to parse vendor, model, version from sysDescr
            import re # Import re here, only needed for this part
            for pattern_info in SYS_DESCR_PATTERNS:
                match = re.search(pattern_info['regex'], sys_descr_str, re.IGNORECASE)
                if match:
                    logger.debug(f"Matched sysDescr pattern for vendor '{pattern_info['vendor']}' on {ip_address}")
                    if not parsed_attributes.get('vendor') and pattern_info.get('vendor'): # Prioritize pattern's vendor
                        parsed_attributes['vendor'] = pattern_info['vendor']
                    
                    if pattern_info.get('model_group') and match.group(pattern_info['model_group']):
                        parsed_attributes['model'] = match.group(pattern_info['model_group']).strip()
                    
                    # Handle platform_group for Cisco, potentially appending to model or as a separate attribute
                    if pattern_info.get('platform_group') and match.group(pattern_info['platform_group']):
                        platform = match.group(pattern_info['platform_group']).strip()
                        if parsed_attributes.get('model') and platform not in parsed_attributes['model']:
                            # Example: model = "C2960", platform = "C2960-LANBASEK9-M" -> model = "C2960 (C2960-LANBASEK9-M)"
                            # Or decide to store platform in 'other_attributes' or a dedicated field if added to Device
                            parsed_attributes['model'] = f"{parsed_attributes.get('model', '')} ({platform})".strip()
                        elif not parsed_attributes.get('model'):
                             parsed_attributes['model'] = platform


                    if pattern_info.get('version_group') and match.group(pattern_info['version_group']):
                        parsed_attributes['software_version'] = match.group(pattern_info['version_group']).strip()
                    
                    # If a specific pattern matched, especially one with a vendor, we can break
                    # or continue if we want to allow multiple patterns to add/override data.
                    # For now, first specific match for vendor/model/version is usually good.
                    if parsed_attributes.get('vendor') and parsed_attributes.get('model') and parsed_attributes.get('software_version'):
                        break 
            
            # If vendor not found via sysDescr regex, try OID lookup
            if not parsed_attributes.get('vendor'):
                for prefix, vendor_name in OID_VENDOR_MAP.items():
                    if sys_object_id_str.startswith(prefix):
                        parsed_attributes['vendor'] = vendor_name
                        logger.debug(f"Found vendor '{vendor_name}' for {ip_address} via sysObjectID prefix '{prefix}'")
                        break
            
            logger.info(f"SNMP discovery successful for {ip_address}, parsed attributes: {parsed_attributes}")
            return parsed_attributes
            
        except Exception as e:
            logger.error(f"Error processing SNMP varBinds for {ip_address}: {e}. varBinds: {var_binds}", exc_info=True)
            return None
    else:
        logger.error(f"SNMP discovery for {ip_address} did not return the expected varBinds. Received: {var_binds}")
        return None

if __name__ == '__main__':
    # Example usage (requires a local SNMP agent or a test device)
    # Ensure logger is configured for direct script execution for testing
    from nms.utils.logger import setup_logging
    setup_logging(log_level=logging.DEBUG, force_setup=True)

    # Replace with a valid IP and community string for your test environment
    test_ip = "127.0.0.1"  # Example: loopback, if you have an agent running
    test_community = "public"    # Example: common default

    logger.info(f"--- Starting direct test for snmp_discoverer.py on {test_ip} ---")
    
    # Test case 1: Device that should respond
    # Assuming snmpd is running on localhost with community "public"
    # e.g. sudo apt install snmpd, then edit /etc/snmp/snmpd.conf:
    # rocommunity public default -V systemonly (or your specific config)
    # and restart the service: sudo systemctl restart snmpd
    discovery_result = discover_snmp(test_ip, test_community)
    if discovery_result:
        logger.info(f"Discovery result for {test_ip}: {discovery_result}")
    else:
        logger.warning(f"Discovery failed for {test_ip}. This is expected if no SNMP agent is configured.")

    # Test case 2: Device that should time out (non-existent or blocks SNMP)
    non_existent_ip = "192.0.2.254" # TEST-NET-3, unlikely to respond
    logger.info(f"--- Testing timeout case for {non_existent_ip} ---")
    discovery_result_timeout = discover_snmp(non_existent_ip, test_community, timeout=1, retries=0)
    if discovery_result_timeout is None:
        logger.info(f"Discovery for {non_existent_ip} correctly returned None (expected timeout or error).")
    else:
        logger.error(f"Discovery for {non_existent_ip} unexpectedly returned: {discovery_result_timeout}")
    
    logger.info("--- Direct test for snmp_discoverer.py complete ---")
