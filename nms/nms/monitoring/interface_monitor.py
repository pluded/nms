import time
import logging
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, nextCmd, getCmd
)
from pysnmp.smi import exval # To check for noSuchInstance, noSuchObject

logger = logging.getLogger(__name__)

# OID Constants
# ifTable OIDs (1.3.6.1.2.1.2.2.1)
OID_IF_INDEX = '1.3.6.1.2.1.2.2.1.1'
OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
OID_IF_TYPE = '1.3.6.1.2.1.2.2.1.3' # Not explicitly requested to store, but good for context
OID_IF_SPEED = '1.3.6.1.2.1.2.2.1.5'
OID_IF_ADMIN_STATUS = '1.3.6.1.2.1.2.2.1.7'
OID_IF_OPER_STATUS = '1.3.6.1.2.1.2.2.1.8'
OID_IF_IN_OCTETS = '1.3.6.1.2.1.2.2.1.10'       # Counter32
OID_IF_IN_UCAST_PKTS = '1.3.6.1.2.1.2.2.1.11'  # Counter32
OID_IF_IN_DISCARDS = '1.3.6.1.2.1.2.2.1.13'    # Counter32
OID_IF_IN_ERRORS = '1.3.6.1.2.1.2.2.1.14'      # Counter32
OID_IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.16'      # Counter32
OID_IF_OUT_UCAST_PKTS = '1.3.6.1.2.1.2.2.1.17' # Counter32
OID_IF_OUT_DISCARDS = '1.3.6.1.2.1.2.2.1.19'   # Counter32
OID_IF_OUT_ERRORS = '1.3.6.1.2.1.2.2.1.20'     # Counter32

# ifXTable OIDs (1.3.6.1.2.1.31.1.1.1) - for 64-bit counters
OID_IF_HC_IN_OCTETS = '1.3.6.1.2.1.31.1.1.1.6'    # Counter64
OID_IF_HC_IN_UCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.7' # Counter64
OID_IF_HC_OUT_OCTETS = '1.3.6.1.2.1.31.1.1.1.10'   # Counter64
OID_IF_HC_OUT_UCAST_PKTS = '1.3.6.1.2.1.31.1.1.1.11'# Counter64

MAX_COUNTER32 = 0xFFFFFFFF  # 2^32 - 1
MAX_COUNTER64 = 0xFFFFFFFFFFFFFFFF  # 2^64 - 1

def _calculate_rate(current_val: int, prev_val: int, time_delta: float, max_val: int) -> float:
    """
    Calculates the rate of change for a counter, handling wraps.
    Returns rate per second.
    """
    if time_delta <= 0:
        return 0.0
    
    # Ensure values are integers
    current_val = int(current_val)
    prev_val = int(prev_val)

    diff = current_val - prev_val
    if diff < 0:  # Counter wrapped
        diff += max_val + 1
    
    rate = diff / time_delta
    return rate if rate >= 0 else 0.0 # Ensure non-negative rate

def collect_interface_metrics(ip_address: str, community_string: str,
                              existing_device_metrics: dict | None = None,
                              snmp_timeout: int = 1, snmp_retries: int = 0) -> dict | None:
    """
    Collects interface metrics from a device using SNMP.

    Args:
        ip_address: IP address of the target device.
        community_string: SNMP community string.
        existing_device_metrics: Dictionary of previously collected metrics for rate calculation.
                                 Format: { 'ifIndex_str': { metric_dict }, ... }
        snmp_timeout: Timeout for SNMP requests.
        snmp_retries: Number of retries for SNMP requests.

    Returns:
        A dictionary where keys are interface indices (as strings) and values are
        dictionaries of metrics for that interface. Returns None on major SNMP error.
        Returns empty dict if no interfaces are found or all fail.
    """
    if existing_device_metrics is None:
        existing_device_metrics = {}

    current_poll_time = time.time()
    new_interface_metrics_by_ifindex_str = {} # Use string ifIndex as key

    snmp_engine = SnmpEngine()
    auth_data = CommunityData(community_string)
    transport_target = UdpTransportTarget((ip_address, 161), timeout=snmp_timeout, retries=snmp_retries)

    # 1. Discover all interface indexes by walking ifIndex or ifDescr
    # We use ifDescr as it's generally available and gives us the description too.
    discovered_interfaces_info = {} # Key: ifIndex (str), Value: {'ifDescr': 'desc', 'ifIndex': int}
    
    # Walking ifDescr to get ifIndexes and descriptions
    # Using OID_IF_DESCR for discovery, as ifIndex is just the suffix.
    for error_indication, error_status, error_index, var_binds_row in nextCmd(
            snmp_engine, auth_data, transport_target, ContextData(),
            ObjectType(ObjectIdentity(OID_IF_DESCR)), lexicographicMode=False):

        if error_indication:
            logger.error(f"SNMP error during iface discovery (nextCmd) on {ip_address}: {error_indication}")
            return None # Major error, cannot proceed
        if error_status: # SNMP error reported by the agent
            logger.error(f"SNMP error status during iface discovery (nextCmd) on {ip_address}: {error_status.prettyPrint()} at {error_index and var_binds_row[int(error_index)-1][0] or '?'}")
            return None # Major error

        # Each var_binds_row from nextCmd here contains a single varBind for OID_IF_DESCR
        for var_bind in var_binds_row: 
            oid, val = var_bind
            if exval.isNoSuchInstance(val) or exval.isNoSuchObject(val):
                logger.debug(f"NoSuchInstance/Object for {oid} on {ip_address} during iface discovery.")
                continue 
            
            # Check if OID is still part of ifDescr subtree, otherwise we've walked past it
            if not ObjectIdentity(OID_IF_DESCR).isPrefixOf(oid):
                logger.debug(f"OID {oid} out of ifDescr scope, assuming end of interface discovery for {ip_address}.")
                # This is how we break out of the loop for nextCmd when walking a specific table/column
                # Setting error_indication to True will stop the generator.
                # A more robust way might be to check if the returned OID is still part of the table.
                # For now, if it's not ifDescr, we assume we're done with this part.
                # This break is for the inner loop, we need a way to stop nextCmd itself.
                # The nextCmd loop will terminate naturally when it walks past the requested OID subtree.
                # No explicit break needed here for the outer loop if lexicographicMode=False.
                continue

            if_index_str = str(oid[-1]) # Last part of OID is ifIndex
            if if_index_str not in discovered_interfaces_info:
                try:
                    discovered_interfaces_info[if_index_str] = {'ifIndex': int(if_index_str)}
                except ValueError:
                    logger.warning(f"Could not parse ifIndex '{if_index_str}' from OID {oid} on {ip_address}. Skipping.")
                    continue
            discovered_interfaces_info[if_index_str]['ifDescr'] = str(val) # Store description

    if not discovered_interfaces_info:
        logger.warning(f"No interfaces discovered via ifDescr on {ip_address}. This might be an SNMP issue or an empty ifTable.")
        return {} # Return empty if no interfaces

    # 2. For each discovered interface, fetch all detailed metrics using getCmd
    base_oids_str_list = [ # OIDs that don't depend on HC vs non-HC
        OID_IF_TYPE, OID_IF_SPEED, OID_IF_ADMIN_STATUS, OID_IF_OPER_STATUS,
        OID_IF_IN_DISCARDS, OID_IF_IN_ERRORS,
        OID_IF_OUT_DISCARDS, OID_IF_OUT_ERRORS,
    ]
    counter_oids_str_list = [ # Both HC and non-HC counters
        OID_IF_HC_IN_OCTETS, OID_IF_HC_OUT_OCTETS,
        OID_IF_HC_IN_UCAST_PKTS, OID_IF_HC_OUT_UCAST_PKTS,
        OID_IF_IN_OCTETS, OID_IF_OUT_OCTETS,
        OID_IF_IN_UCAST_PKTS, OID_IF_OUT_UCAST_PKTS,
    ]

    for if_index_str, if_info_dict in discovered_interfaces_info.items():
        if_index_int = if_info_dict['ifIndex']
        current_if_metrics = {'ifIndex': if_index_int, 'ifDescr': if_info_dict.get('ifDescr', f'Interface {if_index_str}')}
        
        # Construct ObjectType list for getCmd for this specific interface
        oids_for_this_if_getcmd = [ObjectType(ObjectIdentity(oid, if_index_int)) for oid in base_oids_str_list + counter_oids_str_list]

        iterator = getCmd(snmp_engine, auth_data, transport_target, ContextData(), *oids_for_this_if_getcmd)
        error_indication, error_status, error_index, var_binds_result = next(iterator)

        if error_indication:
            logger.warning(f"SNMP GET error for ifIndex {if_index_str} on {ip_address}: {error_indication}")
            continue # Skip this interface
        if error_status:
            logger.warning(f"SNMP GET error status for ifIndex {if_index_str} on {ip_address}: {error_status.prettyPrint()} at {error_index and var_binds_result[int(error_index)-1][0] or '?'}")
            continue # Skip this interface

        # Process var_binds_result for this interface
        raw_polled_values = {} # Store OID_PREFIX -> value
        for oid_obj, val_obj in var_binds_result:
            oid_prefix = str(oid_obj.getPrefix()) # Get the base OID string (without instance identifier)
            if exval.isNoSuchInstance(val_obj) or exval.isNoSuchObject(val_obj):
                raw_polled_values[oid_prefix] = None # Mark as not found or error
                logger.debug(f"NoSuchInstance/Object for OID prefix {oid_prefix} on ifIndex {if_index_str}, IP {ip_address}")
            else:
                try:
                    # Try to convert to int if possible, else keep as string
                    raw_polled_values[oid_prefix] = int(val_obj)
                except (ValueError, TypeError):
                    raw_polled_values[oid_prefix] = str(val_obj)
        
        # Populate current_if_metrics with values from raw_polled_values
        current_if_metrics['ifType'] = raw_polled_values.get(OID_IF_TYPE)
        current_if_metrics['ifSpeed'] = raw_polled_values.get(OID_IF_SPEED)
        current_if_metrics['ifAdminStatus'] = raw_polled_values.get(OID_IF_ADMIN_STATUS)
        current_if_metrics['ifOperStatus'] = raw_polled_values.get(OID_IF_OPER_STATUS)
        current_if_metrics['last_ifInDiscards'] = raw_polled_values.get(OID_IF_IN_DISCARDS)
        current_if_metrics['last_ifInErrors'] = raw_polled_values.get(OID_IF_IN_ERRORS)
        current_if_metrics['last_ifOutDiscards'] = raw_polled_values.get(OID_IF_OUT_DISCARDS)
        current_if_metrics['last_ifOutErrors'] = raw_polled_values.get(OID_IF_OUT_ERRORS)
        current_if_metrics['last_poll_time'] = current_poll_time

        # Determine octet counter type and values (prefer HC if available)
        hc_in_oct = raw_polled_values.get(OID_IF_HC_IN_OCTETS)
        hc_out_oct = raw_polled_values.get(OID_IF_HC_OUT_OCTETS)
        
        if hc_in_oct is not None and hc_out_oct is not None:
            current_if_metrics['last_ifInOctets'] = hc_in_oct
            current_if_metrics['last_ifOutOctets'] = hc_out_oct
            current_if_metrics['counter_type_octets'] = '64bit'
            max_oct_val = MAX_COUNTER64
        else: # Fallback to 32-bit counters
            current_if_metrics['last_ifInOctets'] = raw_polled_values.get(OID_IF_IN_OCTETS, 0)
            current_if_metrics['last_ifOutOctets'] = raw_polled_values.get(OID_IF_OUT_OCTETS, 0)
            current_if_metrics['counter_type_octets'] = '32bit'
            max_oct_val = MAX_COUNTER32
        
        # Determine packet counter type and values (prefer HC if available)
        hc_in_pkts = raw_polled_values.get(OID_IF_HC_IN_UCAST_PKTS)
        hc_out_pkts = raw_polled_values.get(OID_IF_HC_OUT_UCAST_PKTS)
        if hc_in_pkts is not None and hc_out_pkts is not None:
            current_if_metrics['last_ifInUcastPkts'] = hc_in_pkts
            current_if_metrics['last_ifOutUcastPkts'] = hc_out_pkts
            current_if_metrics['counter_type_packets'] = '64bit'
            max_pkt_val = MAX_COUNTER64
        else: # Fallback to 32-bit counters
            current_if_metrics['last_ifInUcastPkts'] = raw_polled_values.get(OID_IF_IN_UCAST_PKTS, 0)
            current_if_metrics['last_ifOutUcastPkts'] = raw_polled_values.get(OID_IF_OUT_UCAST_PKTS, 0)
            current_if_metrics['counter_type_packets'] = '32bit'
            max_pkt_val = MAX_COUNTER32

        # Calculate rates if previous data exists for this interface
        prev_if_metrics = existing_device_metrics.get(if_index_str)
        rate_keys_to_init = ['calculated_in_bps', 'calculated_out_bps', 'calculated_in_pps', 'calculated_out_pps', 
                             'calculated_in_error_rate', 'calculated_out_error_rate', 
                             'calculated_in_discard_rate', 'calculated_out_discard_rate']
        
        if prev_if_metrics and 'last_poll_time' in prev_if_metrics:
            time_delta = current_poll_time - prev_if_metrics['last_poll_time']
            if time_delta > 0:
                prev_max_oct_val = MAX_COUNTER64 if prev_if_metrics.get('counter_type_octets') == '64bit' else MAX_COUNTER32
                current_if_metrics['calculated_in_bps'] = _calculate_rate(current_if_metrics['last_ifInOctets'], prev_if_metrics.get('last_ifInOctets',0), time_delta, prev_max_oct_val) * 8
                current_if_metrics['calculated_out_bps'] = _calculate_rate(current_if_metrics['last_ifOutOctets'], prev_if_metrics.get('last_ifOutOctets',0), time_delta, prev_max_oct_val) * 8
                
                prev_max_pkt_val = MAX_COUNTER64 if prev_if_metrics.get('counter_type_packets') == '64bit' else MAX_COUNTER32
                current_if_metrics['calculated_in_pps'] = _calculate_rate(current_if_metrics['last_ifInUcastPkts'], prev_if_metrics.get('last_ifInUcastPkts',0), time_delta, prev_max_pkt_val)
                current_if_metrics['calculated_out_pps'] = _calculate_rate(current_if_metrics['last_ifOutUcastPkts'], prev_if_metrics.get('last_ifOutUcastPkts',0), time_delta, prev_max_pkt_val)

                # Error and discard rates typically use 32-bit counters.
                current_if_metrics['calculated_in_error_rate'] = _calculate_rate(current_if_metrics.get('last_ifInErrors', 0) or 0, prev_if_metrics.get('last_ifInErrors',0) or 0, time_delta, MAX_COUNTER32)
                current_if_metrics['calculated_out_error_rate'] = _calculate_rate(current_if_metrics.get('last_ifOutErrors', 0) or 0, prev_if_metrics.get('last_ifOutErrors',0) or 0, time_delta, MAX_COUNTER32)
                current_if_metrics['calculated_in_discard_rate'] = _calculate_rate(current_if_metrics.get('last_ifInDiscards', 0) or 0, prev_if_metrics.get('last_ifInDiscards',0) or 0, time_delta, MAX_COUNTER32)
                current_if_metrics['calculated_out_discard_rate'] = _calculate_rate(current_if_metrics.get('last_ifOutDiscards', 0) or 0, prev_if_metrics.get('last_ifOutDiscards',0) or 0, time_delta, MAX_COUNTER32)
            else: # time_delta is 0 or negative
                for rate_key in rate_keys_to_init: current_if_metrics[rate_key] = 0.0
        else: # No previous data for this interface
            for rate_key in rate_keys_to_init: current_if_metrics[rate_key] = 0.0
            
        new_interface_metrics_by_ifindex_str[if_index_str] = current_if_metrics
    
    logger.info(f"Collected metrics for {len(new_interface_metrics_by_ifindex_str)} interfaces on {ip_address}")
    return new_interface_metrics_by_ifindex_str

```
