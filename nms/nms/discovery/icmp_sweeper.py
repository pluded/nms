import ipaddress
import subprocess
import platform
import logging

logger = logging.getLogger(__name__)

class PingCommandNotFound(Exception):
    """Custom exception for when the ping command is not found."""
    pass

def sweep_network(network_address: str) -> list[str]:
    """
    Performs an ICMP ping sweep of the given network.

    Args:
        network_address: The network address in CIDR notation (e.g., "192.168.1.0/24").

    Returns:
        A list of IP addresses that responded to the ping.
    
    Raises:
        PingCommandNotFound: If the ping command is not found on the system.
    """
    active_hosts = []
    logger.info(f"Starting ICMP sweep for network: {network_address}")
    try:
        network = ipaddress.ip_network(network_address, strict=False)
    except ValueError as e:
        logger.error(f"Invalid network address '{network_address}': {e}")
        return active_hosts # Return empty list for invalid network

    for ip_obj in network.hosts():
        ip_str = str(ip_obj)
        try:
            # Determine the ping command based on the operating system
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            
            if platform.system().lower() == 'windows':
                command = ['ping', param, '1', timeout_param, '1000', ip_str] # 1000ms timeout
            else:
                command = ['ping', param, '1', timeout_param, '1', ip_str] # 1s timeout

            logger.debug(f"Pinging {ip_str} with command: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=2) # Add a process timeout

            if process.returncode == 0:
                logger.debug(f"Host {ip_str} is active.")
                active_hosts.append(ip_str)
            else:
                logger.debug(f"Host {ip_str} is not responsive. Return code: {process.returncode}, stderr: {stderr.decode('utf-8', errors='ignore').strip()}")

        except FileNotFoundError:
            logger.critical("Ping command not found. Please ensure it's installed and in your system's PATH.")
            raise PingCommandNotFound("Ping command not found. Cannot perform network sweep.")
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout expired while pinging {ip_str}. Assuming host is down or unreachable with current timeout.")
        except Exception as e:
            logger.error(f"An error occurred while pinging {ip_str}: {e}", exc_info=True)
            # Continue to the next IP address

    logger.info(f"ICMP sweep for {network_address} complete. Found {len(active_hosts)} active host(s).")
    return active_hosts

if __name__ == '__main__':
    # Ensure logger is configured for direct script execution
    from nms.utils.logger import setup_logging # Adjust import if necessary
    setup_logging(log_level=logging.DEBUG, force_setup=True)

    test_network_valid = "192.168.1.0/29" # A small range for testing
    test_network_invalid = "192.168.1.0/33"

    logger.info(f"--- Starting direct test for icmp_sweeper.py ---")
    
    logger.info(f"Testing with valid network: {test_network_valid}")
    try:
        responsive_hosts_valid = sweep_network(test_network_valid)
        if responsive_hosts_valid:
            logger.info(f"Responsive hosts in {test_network_valid}:")
            for host in responsive_hosts_valid:
                logger.info(host)
        else:
            logger.info(f"No responsive hosts found in {test_network_valid} or error in sweep.")
    except PingCommandNotFound as e:
        logger.critical(f"Test failed: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during valid network test: {e}", exc_info=True)

    logger.info(f"\nTesting with invalid network: {test_network_invalid}")
    try:
        responsive_hosts_invalid = sweep_network(test_network_invalid)
        if not responsive_hosts_invalid: # Expect empty list
            logger.info(f"Correctly handled invalid network {test_network_invalid}, no hosts returned.")
        else:
            logger.error(f"Invalid network test failed. Hosts returned: {responsive_hosts_invalid}")
    except PingCommandNotFound as e:
        logger.critical(f"Test failed for invalid network due to missing ping: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during invalid network test: {e}", exc_info=True)
    
    logger.info(f"--- Direct test for icmp_sweeper.py complete ---")
