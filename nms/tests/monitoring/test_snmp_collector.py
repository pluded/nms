import pytest
from unittest.mock import patch, MagicMock # For mocking getCmd

# Assuming nms is in PYTHONPATH or project root is configured.
# Adjust path if necessary for your test environment.
# from nms.nms.monitoring.snmp_collector import fetch_snmp_data
# For robust testing, similar to test_icmp_sweeper.py:
import sys
import os
# current_dir = os.path.dirname(os.path.abspath(__file__)) # nms/tests/monitoring
# project_root = os.path.abspath(os.path.join(current_dir, '..', '..')) # nms/
# if project_root not in sys.path:
#    sys.path.insert(0, project_root)

from nms.monitoring.snmp_collector import fetch_snmp_data
from pysnmp.hlapi import ObjectType, ObjectIdentity
from pysnmp.smi import rfc1902 # For NoSuchObject, NoSuchInstance

# Mock logger before it's used by the module
# Similar to icmp_sweeper, snmp_collector.py gets its logger via logging.getLogger(__name__)

@pytest.fixture
def mock_hlapi_getcmd():
    """Fixture to mock pysnmp.hlapi.getCmd."""
    with patch('nms.monitoring.snmp_collector.getCmd') as mock_getcmd:
        yield mock_getcmd

# --- Test Cases for fetch_snmp_data ---

def test_fetch_snmp_data_success(mock_hlapi_getcmd):
    """Test successful SNMP data fetching for multiple OIDs."""
    target_ip = "192.168.1.1"
    community = "public"
    oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]

    # Mock the iterator returned by getCmd
    mock_iterator = MagicMock()
    # Configure the mock to return specific values when next() is called on it
    # errorIndication, errorStatus, errorIndex, varBinds
    mock_iterator.__next__.return_value = (
        None,  # errorIndication
        0,     # errorStatus (0 means noError)
        0,     # errorIndex (0 if noError)
        [ # varBinds: list of ObjectType instances
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0"), rfc1902.OctetString("Test System Description")),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0"), rfc1902.OctetString("TestSystemName"))
        ]
    )
    mock_hlapi_getcmd.return_value = mock_iterator

    result = fetch_snmp_data(target_ip, community, oids)

    assert result["1.3.6.1.2.1.1.1.0"] == "Test System Description"
    assert result["1.3.6.1.2.1.1.5.0"] == "TestSystemName"
    assert len(result) == 2
    
    # Check that getCmd was called once
    mock_hlapi_getcmd.assert_called_once()
    args, kwargs = mock_hlapi_getcmd.call_args
    # SnmpEngine, CommunityData, UdpTransportTarget, ContextData, *varBinds (ObjectType)
    # Check some key parameters
    assert kwargs['lexicographicMode'] is False # Important for our logic
    # Verify OIDs passed to ObjectType
    requested_oids_in_call = [str(arg[0]) for arg in args if isinstance(arg, ObjectType)]
    assert "1.3.6.1.2.1.1.1.0" in requested_oids_in_call
    assert "1.3.6.1.2.1.1.5.0" in requested_oids_in_call


def test_fetch_snmp_data_transport_error(mock_hlapi_getcmd, caplog):
    """Test SNMP fetch failure due to transport error (errorIndication)."""
    target_ip = "192.168.1.254" # Non-existent or unreachable
    community = "public"
    oids = ["1.3.6.1.2.1.1.1.0"]
    
    mock_iterator = MagicMock()
    mock_iterator.__next__.return_value = (
        "Timeout: No SNMP response received before timeout", # errorIndication
        0, # errorStatus
        0, # errorIndex
        [] # varBinds (empty as no response)
    )
    mock_hlapi_getcmd.return_value = mock_iterator
    
    import logging
    caplog.set_level(logging.ERROR)

    result = fetch_snmp_data(target_ip, community, oids)

    assert result["1.3.6.1.2.1.1.1.0"] is None
    assert len(result) == 1 # Still returns a dict with requested OIDs as keys

    assert f"SNMP transport error for {target_ip}: Timeout: No SNMP response received before timeout" in caplog.text


def test_fetch_snmp_data_nosuchname_error(mock_hlapi_getcmd, caplog):
    """Test SNMP fetch with a noSuchName error for one OID."""
    target_ip = "192.168.1.1"
    community = "public"
    oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.999.1.0"] # Second OID is likely invalid

    mock_iterator = MagicMock()
    mock_iterator.__next__.return_value = (
        None, # errorIndication
        rfc1902.NoSuchName(), # errorStatus (using a pysnmp error object) / or use integer 2
        2,    # errorIndex (pointing to the second OID)
        [ # varBinds might reflect the error or be partial
            ObjectType(ObjectIdentity(oids[0]), rfc1902.OctetString("ValidDescription")),
            ObjectType(ObjectIdentity(oids[1]), rfc1902.NoSuchObject('')) # PySNMP representation of noSuchName for this OID
        ]
    )
    mock_hlapi_getcmd.return_value = mock_iterator

    import logging
    caplog.set_level(logging.WARNING)

    result = fetch_snmp_data(target_ip, community, oids)

    assert result[oids[0]] == "ValidDescription"
    assert result[oids[1]] is None # OID with noSuchName should be None
    
    # Check for warning log about the error status
    found_log = False
    for record in caplog.records:
        if record.levelname == "WARNING" and f"SNMP error for {target_ip}" in record.message and "noSuchName" in record.message.lower() and oids[1] in record.message:
            found_log = True
            break
    assert found_log, "Expected warning log for noSuchName not found or incorrect."


def test_fetch_snmp_data_empty_oids_list(mock_hlapi_getcmd, caplog):
    """Test fetch_snmp_data with an empty list of OIDs."""
    target_ip = "192.168.1.1"
    community = "public"
    oids = []

    import logging
    caplog.set_level(logging.WARNING)

    result = fetch_snmp_data(target_ip, community, oids)

    assert result == {} # Expect an empty dictionary
    mock_hlapi_getcmd.assert_not_called() # getCmd should not be called if no OIDs
    assert f"No OIDs provided for SNMP fetch from {target_ip}" in caplog.text


def test_fetch_snmp_data_general_pysnmp_error(mock_hlapi_getcmd, caplog):
    """Test handling of a generic PySnmpError during getCmd call."""
    target_ip = "192.168.1.1"
    community = "public"
    oids = ["1.3.6.1.2.1.1.1.0"]

    # Make getCmd itself raise an exception
    from pysnmp.error import PySnmpError
    mock_hlapi_getcmd.side_effect = PySnmpError("A generic PySNMP library error")

    import logging
    caplog.set_level(logging.ERROR)
    
    result = fetch_snmp_data(target_ip, community, oids)

    assert result[oids[0]] is None
    assert len(result) == 1
    assert f"A PySNMP library error occurred for {target_ip}: A generic PySNMP library error" in caplog.text


def test_fetch_snmp_data_unexpected_exception(mock_hlapi_getcmd, caplog):
    """Test handling of an unexpected non-PySnmpError during getCmd."""
    target_ip = "192.168.1.1"
    community = "public"
    oids = ["1.3.6.1.2.1.1.1.0"]

    mock_hlapi_getcmd.side_effect = Exception("Something totally unexpected")

    import logging
    caplog.set_level(logging.ERROR)

    result = fetch_snmp_data(target_ip, community, oids)

    assert result[oids[0]] is None
    assert len(result) == 1
    assert f"An unexpected error occurred during SNMP fetch for {target_ip}: Something totally unexpected" in caplog.text


def test_fetch_snmp_data_oid_not_found_in_response_but_no_error_status(mock_hlapi_getcmd, caplog):
    """
    Test case where getCmd succeeds (no errorStatus) but a requested OID is somehow
    not in varBinds. This is unusual for getCmd but tests robustness.
    The current implementation initializes all OIDs to None, so this should be handled.
    """
    target_ip = "192.168.1.1"
    community = "public"
    # Request two OIDs
    oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"] 

    mock_iterator = MagicMock()
    mock_iterator.__next__.return_value = (
        None, 0, 0,
        [ # varBinds only contains the first OID
            ObjectType(ObjectIdentity(oids[0]), rfc1902.OctetString("SystemDescriptionOnly"))
        ]
    )
    mock_hlapi_getcmd.return_value = mock_iterator
    
    import logging
    caplog.set_level(logging.DEBUG) # Check debug logs for details

    result = fetch_snmp_data(target_ip, community, oids)

    assert result[oids[0]] == "SystemDescriptionOnly"
    # The second OID was requested but not in varBinds.
    # The current implementation should have it as None (due to pre-initialization).
    assert result[oids[1]] is None 
    assert len(result) == 2
    
    # Check if a log message indicates that an OID was missing from results
    # (The current code might not explicitly log this specific scenario if no error reported by PySNMP,
    #  it relies on the pre-initialization to None. If specific logging is added for this, test it.)
    # logger.warning(f"OID {oid} was requested but not found in results for {ip_address}. Setting to None.")
    # This log is not present in the current code, so we don't assert for it.


def test_fetch_snmp_data_value_is_nosuchinstance(mock_hlapi_getcmd):
    """Test when an OID returns a NoSuchInstance value in varBinds."""
    target_ip = "192.168.1.1"
    community = "public"
    oid_valid = "1.3.6.1.2.1.1.1.0"
    oid_nosuchinstance = "1.3.6.1.2.1.2.2.1.2.999" # e.g. ifDescr for a non-existent interface

    oids = [oid_valid, oid_nosuchinstance]

    mock_iterator = MagicMock()
    mock_iterator.__next__.return_value = (
        None, 0, 0, # No SNMP level error for the request itself
        [
            ObjectType(ObjectIdentity(oid_valid), rfc1902.OctetString("ValidData")),
            ObjectType(ObjectIdentity(oid_nosuchinstance), rfc1902.NoSuchInstance('')) # Value is NoSuchInstance
        ]
    )
    mock_hlapi_getcmd.return_value = mock_iterator

    result = fetch_snmp_data(target_ip, community, oids)

    assert result[oid_valid] == "ValidData"
    assert result[oid_nosuchinstance] is None # Should be None as per implementation
    assert len(result) == 2

# Pytest will automatically discover and run these tests.
# Ensure pytest, pytest-mock are installed, and nms package is in PYTHONPATH.
# Run from the project root:
# pytest nms/tests/monitoring/test_snmp_collector.py
import logging # Make sure logging is imported for caplog tests
# (already imported by pytest if using caplog, but good for clarity)
