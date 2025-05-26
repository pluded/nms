import logging
from pysnmp.hlapi import (
    getCmd, SnmpEngine, CommunityData, UdpTransportTarget, 
    ContextData, ObjectType, ObjectIdentity
)
from pysnmp.error import PySnmpError # For more specific PySNMP exceptions

logger = logging.getLogger(__name__)

def fetch_snmp_data(ip_address: str, community_string: str, oids: list[str]) -> dict:
    """
    Fetches SNMP data from a device using SNMPv2c.

    Args:
        ip_address: The IP address of the target device.
        community_string: The SNMP community string for v2c.
        oids: A list of OID strings to fetch.

    Returns:
        A dictionary where keys are the OIDs and values are the retrieved SNMP data.
        If an OID cannot be fetched or an error occurs, its value will be None,
        and the error will be logged.
    """
    snmp_data = {oid: None for oid in oids} # Initialize all OIDs with None
    
    if not oids:
        logger.warning(f"No OIDs provided for SNMP fetch from {ip_address}.")
        return snmp_data

    logger.debug(f"Fetching SNMP data for {ip_address}, OIDs: {oids}, Community: {community_string}")

    try:
        snmp_engine = SnmpEngine()
        community_data = CommunityData(community_string, mpModel=1) # mpModel=1 for SNMPv2c
        # Increased timeout to 2s and retries to 3 for potentially slower devices/networks
        transport_target = UdpTransportTarget((ip_address, 161), timeout=2, retries=3) 
        context_data = ContextData()

        object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]

        iterator = getCmd(
            snmp_engine,
            community_data,
            transport_target,
            context_data,
            *object_types,
            lexicographicMode=False # Important for processing varBinds in the order of OIDs requested
        )

        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            # This usually indicates a transport-level error (e.g., host unreachable, timeout)
            logger.error(f"SNMP transport error for {ip_address}: {error_indication}")
            # All OIDs will remain None as initialized
            return snmp_data
        
        elif error_status:
            # This indicates an SNMP-level error (e.g., noSuchName, readOnly)
            # error_status is an object, error_index is 1-based index into var_binds/object_types
            error_oid_str = "N/A"
            if error_index and error_index <= len(object_types):
                error_oid_str = str(object_types[error_index-1][0]) # Get the OID string that caused the error
            
            logger.warning(
                f"SNMP error for {ip_address}: Status='{error_status.prettyPrint()}', "
                f"Index='{error_index}', OID='{error_oid_str}'"
            )
            # Log the error, but still process var_binds as some might be valid if the error
            # is specific to one OID (e.g. noSuchName for one, but others are fine)
            # However, getCmd typically stops at the first error for the whole batch.
            # The values for failed OIDs will remain None.
            # We will iterate through var_binds to populate what we can.
            # If an error like 'noSuchName' occurs for an OID, its value in var_binds might be a special 'NoSuchObject' or 'NoSuchInstance'
            # which pysnmp hlapi might represent as a specific type or None.

            # Process var_binds to populate data, even if there was an error_status.
            # Some OIDs might have been retrieved, or specific error values set.
            for i, var_bind_row in enumerate(var_binds): # var_binds from getCmd is a list of tuples
                oid_requested_str = oids[i] # The OID we asked for at this position
                actual_oid_str = str(var_bind_row[0])
                value = var_bind_row[1]
                
                # Check if the returned OID matches the requested OID at this position
                if oid_requested_str != actual_oid_str and error_status:
                     # This can happen if the error is for this OID, and var_binds might be short
                     # or the agent returns something unexpected.
                     logger.debug(f"OID mismatch or error for {ip_address}: Requested {oid_requested_str}, Got {actual_oid_str}. Error: {error_status.prettyPrint()}")
                     # Value remains None as initialized

                # Check for PySNMP's way of saying "no such instance/object"
                # These are specific classes from pysnmp.smi.rfc1902
                if value.__class__.__name__ in ('NoSuchObject', 'NoSuchInstance', 'EndOfMibView'):
                    logger.debug(f"SNMP 'No Such...' value for {ip_address}, OID {actual_oid_str}: {value.prettyPrint()}")
                    snmp_data[oid_requested_str] = None # Explicitly ensure it's None
                elif value is not None:
                    if hasattr(value, 'prettyPrint'):
                        snmp_data[oid_requested_str] = value.prettyPrint()
                    else:
                        snmp_data[oid_requested_str] = str(value)
                # If value is None, it remains None from initialization

            # If error_status was set, the OID at error_index is the problematic one.
            # Its value should ideally be None or handled by the loop above.
            if error_index and error_index <= len(oids):
                 failed_oid = oids[error_index-1]
                 logger.warning(f"Confirming OID {failed_oid} for host {ip_address} resulted in error: {error_status.prettyPrint()}")
                 snmp_data[failed_oid] = None # Ensure it's None

            return snmp_data
        
        else:
            # Successful retrieval
            logger.debug(f"Successfully retrieved SNMP data for {ip_address}")
            for i, var_bind_row in enumerate(var_binds):
                oid_str = str(var_bind_row[0]) # This should match oids[i] if lexicographicMode=False
                value = var_bind_row[1]
                
                # Ensure we are assigning to the OID string we requested
                requested_oid_str = oids[i]

                if value.__class__.__name__ in ('NoSuchObject', 'NoSuchInstance', 'EndOfMibView'):
                    logger.debug(f"SNMP 'No Such...' value for {ip_address}, OID {oid_str}: {value.prettyPrint()}")
                    snmp_data[requested_oid_str] = None
                elif value is not None:
                    if hasattr(value, 'prettyPrint'):
                        snmp_data[requested_oid_str] = value.prettyPrint()
                    else:
                        snmp_data[requested_oid_str] = str(value)
                else:
                    # Value is None, it's already set to None during init
                    logger.debug(f"SNMP value is None for {ip_address}, OID {oid_str}")
                    snmp_data[requested_oid_str] = None
            
            # Final check: ensure all requested OIDs have an entry (even if None)
            for oid in oids:
                if oid not in snmp_data: # Should not happen with pre-initialization
                    logger.warning(f"OID {oid} was requested but not found in results for {ip_address}. Setting to None.")
                    snmp_data[oid] = None
            return snmp_data

    except PySnmpError as e: # Catch more specific PySNMP errors if any slip through error_indication
        logger.error(f"A PySNMP library error occurred for {ip_address}: {e}", exc_info=True)
        return snmp_data # Returns dict with all values as None
    except Exception as e:
        logger.error(f"An unexpected error occurred during SNMP fetch for {ip_address}: {e}", exc_info=True)
        return snmp_data # Returns dict with all values as None


if __name__ == '__main__':
    # Ensure logger is configured for direct script execution
    from nms.utils.logger import setup_logging # Adjust import if necessary
    setup_logging(log_level=logging.DEBUG, force_setup=True)

    logger.info("--- Starting direct test for snmp_collector.py ---")

    # Test with a public server
    target_ip_public = "test.net-snmp.org"
    community_public = "public"
    oids_valid = [
        "1.3.6.1.2.1.1.1.0",  # System Description
        "1.3.6.1.2.1.1.3.0",  # System Uptime
        "1.3.6.1.2.1.1.5.0",  # System Name
    ]
    oids_mixed = [
        "1.3.6.1.2.1.1.1.0",  # Valid
        "1.3.6.1.2.1.9999.1.0", # Likely invalid (noSuchName)
        "1.3.6.1.2.1.1.5.0"   # Valid
    ]

    logger.info(f"\nTesting with {target_ip_public} and valid OIDs:")
    data_valid = fetch_snmp_data(target_ip_public, community_public, oids_valid)
    for oid, value in data_valid.items():
        logger.info(f"  {oid}: {value}")

    logger.info(f"\nTesting with {target_ip_public} and mixed (valid/invalid) OIDs:")
    data_mixed = fetch_snmp_data(target_ip_public, community_public, oids_mixed)
    for oid, value in data_mixed.items():
        logger.info(f"  {oid}: {value}")

    # Test with a likely non-responsive IP
    target_ip_down = "192.168.254.254" # Choose an IP unlikely to respond
    logger.info(f"\nTesting with likely down host {target_ip_down}:")
    data_down = fetch_snmp_data(target_ip_down, community_public, oids_valid)
    for oid, value in data_down.items():
        logger.info(f"  {oid}: {value}") # Expect all to be None

    # Test with an invalid community string (agent might return auth error or timeout)
    community_invalid = "wrongcommunity"
    logger.info(f"\nTesting with {target_ip_public} and invalid community '{community_invalid}':")
    data_auth_error = fetch_snmp_data(target_ip_public, community_invalid, oids_valid)
    # Behavior for bad community can vary:
    # - Timeout (if agent drops request) -> error_indication
    # - No response (if agent sends auth error but we don't process v1/v2c traps)
    # - Some agents might not respond at all to bad community string.
    for oid, value in data_auth_error.items():
        logger.info(f"  {oid}: {value}") # Expect all to be None due to error_indication

    logger.info("--- Direct test for snmp_collector.py complete ---")
