import pytest
import subprocess
import platform
from unittest.mock import MagicMock, patch, call # patch is used as a decorator or context manager

# Assuming nms is in PYTHONPATH or project root is configured.
# Adjust path if necessary for your test environment.
# from nms.nms.discovery.icmp_sweeper import sweep_network, PingCommandNotFound
# For robust testing, especially if nms/ is not directly in PYTHONPATH:
import sys
import os
# Add the project root (nms/) to sys.path to allow imports like from nms.discovery...
# This assumes tests are run from the project root or a similar context where nms/ is accessible.
# If your test runner (like pytest) is invoked from the project root (where nms/ folder resides),
# it often handles this. But explicit path manipulation can make tests more robust.
# current_dir = os.path.dirname(os.path.abspath(__file__)) # nms/tests/discovery
# nms_package_dir = os.path.abspath(os.path.join(current_dir, '..', '..', 'nms')) # nms/nms
# project_root = os.path.abspath(os.path.join(current_dir, '..', '..')) # nms/
# if project_root not in sys.path:
#    sys.path.insert(0, project_root)

from nms.discovery.icmp_sweeper import sweep_network, PingCommandNotFound

# Mock logger before it's used by the module
# This is important if the module uses logging at the global level or upon import.
# However, icmp_sweeper.py gets its logger via logging.getLogger(__name__)
# so simply importing it doesn't trigger logging immediately. We can mock it if needed.
# For now, we'll rely on the logger being configured by the application's entry point
# or by a test-specific logging setup if we want to assert log messages.

@pytest.fixture
def mock_subprocess_popen():
    """Fixture to mock subprocess.Popen."""
    with patch('subprocess.Popen') as mock_popen:
        yield mock_popen

@pytest.fixture
def mock_platform_system():
    """Fixture to mock platform.system()."""
    with patch('platform.system') as mock_system:
        yield mock_system

# --- Test Cases for sweep_network ---

def test_sweep_network_success_linux(mock_subprocess_popen, mock_platform_system):
    """Test successful network sweep on a Linux-like system."""
    mock_platform_system.return_value = "Linux"
    
    # Define IPs for the test network "192.168.1.0/30"
    # Network: 192.168.1.0, HostMin: 192.168.1.1, HostMax: 192.168.1.2, Broadcast: 192.168.1.3
    # We expect .1 and .2 to be pinged.
    
    # Mock Popen instances and their communicate method
    mock_proc_host1 = MagicMock()
    mock_proc_host1.communicate.return_value = (b"some output", b"") # stdout, stderr
    mock_proc_host1.returncode = 0 # Success for 192.168.1.1
    
    mock_proc_host2 = MagicMock()
    mock_proc_host2.communicate.return_value = (b"", b"Request timed out.")
    mock_proc_host2.returncode = 1 # Failure for 192.168.1.2

    # Configure mock_subprocess_popen to return different mocks for different calls
    mock_subprocess_popen.side_effect = [mock_proc_host1, mock_proc_host2]

    result = sweep_network("192.168.1.0/30")
    
    assert "192.168.1.1" in result
    assert "192.168.1.2" not in result
    assert len(result) == 1

    expected_calls = [
        call(['ping', '-c', '1', '-W', '1', '192.168.1.1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE),
        call(['ping', '-c', '1', '-W', '1', '192.168.1.2'], stdout=subprocess.PIPE, stderr=subprocess.PIPE),
    ]
    mock_subprocess_popen.assert_has_calls(expected_calls, any_order=False)


def test_sweep_network_success_windows(mock_subprocess_popen, mock_platform_system):
    """Test successful network sweep on Windows."""
    mock_platform_system.return_value = "Windows"
    
    mock_proc_host1 = MagicMock()
    mock_proc_host1.communicate.return_value = (b"Reply from 192.168.1.1...", b"")
    mock_proc_host1.returncode = 0 
    
    mock_proc_host2 = MagicMock()
    mock_proc_host2.communicate.return_value = (b"", b"Request timed out.")
    mock_proc_host2.returncode = 1

    mock_subprocess_popen.side_effect = [mock_proc_host1, mock_proc_host2]

    result = sweep_network("192.168.1.0/30") # .1 and .2
    
    assert "192.168.1.1" in result
    assert "192.168.1.2" not in result
    assert len(result) == 1

    expected_calls = [
        call(['ping', '-n', '1', '-w', '1000', '192.168.1.1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE),
        call(['ping', '-n', '1', '-w', '1000', '192.168.1.2'], stdout=subprocess.PIPE, stderr=subprocess.PIPE),
    ]
    mock_subprocess_popen.assert_has_calls(expected_calls, any_order=False)


def test_sweep_network_all_hosts_up(mock_subprocess_popen, mock_platform_system):
    """Test when all hosts in a small network respond."""
    mock_platform_system.return_value = "Linux"
    
    mock_proc_host1 = MagicMock()
    mock_proc_host1.communicate.return_value = (b"some output", b"")
    mock_proc_host1.returncode = 0 
    
    mock_proc_host2 = MagicMock()
    mock_proc_host2.communicate.return_value = (b"some output", b"")
    mock_proc_host2.returncode = 0 

    mock_subprocess_popen.side_effect = [mock_proc_host1, mock_proc_host2]

    result = sweep_network("10.0.0.0/30") # Scans 10.0.0.1 and 10.0.0.2
    
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result
    assert len(result) == 2


def test_sweep_network_no_hosts_up(mock_subprocess_popen, mock_platform_system):
    """Test when no hosts in the network respond."""
    mock_platform_system.return_value = "Linux"
    
    mock_proc_host1 = MagicMock()
    mock_proc_host1.communicate.return_value = (b"", b"Request timed out.")
    mock_proc_host1.returncode = 1
    
    mock_proc_host2 = MagicMock()
    mock_proc_host2.communicate.return_value = (b"", b"Request timed out.")
    mock_proc_host2.returncode = 1

    mock_subprocess_popen.side_effect = [mock_proc_host1, mock_proc_host2]

    result = sweep_network("172.16.0.0/30") # Scans .1 and .2
    
    assert len(result) == 0


def test_sweep_network_invalid_network_string(mock_subprocess_popen):
    """Test sweep_network with an invalid network address string."""
    # No need to mock platform.system as ipaddress.ip_network should fail first.
    # We also expect no calls to subprocess.Popen.
    
    # The function currently logs an error and returns an empty list.
    # If it were to raise a custom exception, we'd test for that.
    result = sweep_network("this-is-not-a-network/24")
    
    assert result == []
    mock_subprocess_popen.assert_not_called()
    # To assert logs, you would use caplog fixture from pytest.
    # e.g., assert "Invalid network address" in caplog.text


def test_sweep_network_ping_command_not_found(mock_subprocess_popen, mock_platform_system):
    """Test that PingCommandNotFound is raised if ping executable is missing."""
    mock_platform_system.return_value = "Linux"
    mock_subprocess_popen.side_effect = FileNotFoundError("ping command not found")

    with pytest.raises(PingCommandNotFound):
        sweep_network("192.168.1.0/30")
    
    # Assert that Popen was attempted at least once for the first IP.
    mock_subprocess_popen.assert_called_once_with(
        ['ping', '-c', '1', '-W', '1', '192.168.1.1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def test_sweep_network_subprocess_timeout_expired(mock_subprocess_popen, mock_platform_system, caplog):
    """Test subprocess.TimeoutExpired during ping command."""
    mock_platform_system.return_value = "Linux"
    
    # Simulate TimeoutExpired for the first IP, and success for the second
    mock_proc_host2_success = MagicMock()
    mock_proc_host2_success.communicate.return_value = (b"output", b"")
    mock_proc_host2_success.returncode = 0

    # Configure Popen: first call's communicate raises TimeoutExpired, second is normal
    mock_popen_instance_timeout = MagicMock()
    mock_popen_instance_timeout.communicate.side_effect = subprocess.TimeoutExpired(cmd="ping ...", timeout=2)
    
    mock_subprocess_popen.side_effect = [mock_popen_instance_timeout, mock_proc_host2_success]

    caplog.set_level(logging.WARNING) # Ensure warning logs are captured

    result = sweep_network("192.168.1.0/30") # .1 and .2

    assert "192.168.1.1" not in result # First IP timed out
    assert "192.168.1.2" in result    # Second IP was successful
    assert len(result) == 1
    
    assert "Timeout expired while pinging 192.168.1.1" in caplog.text


def test_sweep_network_generic_exception_during_ping(mock_subprocess_popen, mock_platform_system, caplog):
    """Test a generic Exception during a ping operation for one host."""
    mock_platform_system.return_value = "Linux"

    mock_popen_instance_generic_error = MagicMock()
    mock_popen_instance_generic_error.communicate.side_effect = Exception("Some generic error")

    mock_proc_host2_success = MagicMock()
    mock_proc_host2_success.communicate.return_value = (b"output", b"")
    mock_proc_host2_success.returncode = 0

    mock_subprocess_popen.side_effect = [mock_popen_instance_generic_error, mock_proc_host2_success]
    
    caplog.set_level(logging.ERROR)

    result = sweep_network("192.168.1.0/30") # .1 and .2

    assert "192.168.1.1" not in result # Failed due to generic error
    assert "192.168.1.2" in result    # Second IP was successful
    assert len(result) == 1
    
    assert "An error occurred while pinging 192.168.1.1: Some generic error" in caplog.text

# Example of how you might use caplog to check specific log messages
def test_sweep_network_invalid_network_logging(caplog):
    """Test logging for an invalid network string."""
    import logging # Ensure logging is imported if not already
    caplog.set_level(logging.ERROR) # Set level for caplog fixture
    
    result = sweep_network("invalid/24")
    assert result == []
    
    # Check if the expected error message is in the logs
    found_log = False
    for record in caplog.records:
        if record.levelname == "ERROR" and "Invalid network address 'invalid/24'" in record.message:
            found_log = True
            break
    assert found_log, "Expected error log for invalid network address not found."

# To run these tests, you would typically use `pytest` in your terminal
# from the root directory of the project (where nms/ folder is).
# Ensure pytest and pytest-mock are installed (e.g., from requirements-dev.txt).
# Example:
# pip install -r nms/requirements-dev.txt
# pytest nms/tests/discovery/test_icmp_sweeper.py
import logging # Make sure logging is imported for caplog tests
# (already imported by pytest if using caplog, but good for clarity)
