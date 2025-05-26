import argparse
import os
import logging # Import logging
import sys

# Adjust import paths to be robust for different execution contexts
try:
    from nms.discovery.icmp_sweeper import sweep_network, PingCommandNotFound
    from nms.monitoring.snmp_collector import fetch_snmp_data
    from nms.inventory.device import Inventory # Device class is used implicitly by Inventory
except ModuleNotFoundError:
    # This block allows running cli.py directly from nms/nms for testing,
    # assuming nms/ (project root) is in PYTHONPATH.
    # For normal package usage, the top-level nms/ should be in PYTHONPATH.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from discovery.icmp_sweeper import sweep_network, PingCommandNotFound
    from monitoring.snmp_collector import fetch_snmp_data
    from inventory.device import Inventory

# Get a logger for the CLI module
logger = logging.getLogger(__name__)

# Default values
DEFAULT_COMMUNITY_STRING = "public"
DEFAULT_INVENTORY_FILE = "inventory.json"
# OIDs for basic device information
DEFAULT_SNMP_OIDS = [
    "1.3.6.1.2.1.1.1.0",  # System Description (sysDescr.0)
    "1.3.6.1.2.1.1.3.0",  # System Uptime (sysUpTimeInstance)
    "1.3.6.1.2.1.1.5.0",  # System Name (sysName.0)
    "1.3.6.1.2.1.1.6.0",  # System Location (sysLocation.0) - often not set but good to have
]
# Mapping OIDs to Device attribute names for clarity
OID_TO_ATTRIBUTE_MAP = {
    "1.3.6.1.2.1.1.1.0": "system_description",
    "1.3.6.1.2.1.1.3.0": "uptime",
    "1.3.6.1.2.1.1.5.0": "system_name",
    "1.3.6.1.2.1.1.6.0": "location",
}


def handle_discover(args):
    """
    Handles the 'discover' subcommand.
    Sweeps the network, adds devices to inventory, and fetches SNMP data.
    """
    logger.info(f"Starting discovery: network='{args.network}', community='{args.community}', inventory='{args.inventory_file}'")
    
    inventory = Inventory()
    if os.path.exists(args.inventory_file):
        logger.info(f"Loading existing inventory from {args.inventory_file}")
        inventory.load_from_json(args.inventory_file) # Errors logged by Inventory class
    else:
        logger.info(f"No existing inventory file found at {args.inventory_file}. A new one will be created if devices are found.")

    try:
        active_ips = sweep_network(args.network)
    except PingCommandNotFound:
        logger.critical("Ping command not found on this system. Discovery aborted.")
        print("CRITICAL: Ping command not found. Please ensure 'ping' is installed and in your system's PATH to use the discovery feature.")
        return
    except Exception as e: # Catch any other unexpected errors from sweep_network
        logger.error(f"An unexpected error occurred during network sweep: {e}", exc_info=True)
        print(f"ERROR: An unexpected error occurred during network sweep. Check logs for details. Discovery aborted.")
        return

    logger.info(f"ICMP sweep found {len(active_ips)} active host(s).")
    if not active_ips:
        print("No active hosts found on the network. Nothing to process further.")
        # Still save inventory in case it was loaded and needs to be written back (e.g. if it was corrupted and fixed on load)
        inventory.save_to_json(args.inventory_file)
        return

    print(f"Found {len(active_ips)} active host(s). Attempting to fetch SNMP data...")
    
    processed_count = 0
    for ip in active_ips:
        logger.info(f"Processing device: {ip}")
        print(f"\nProcessing device: {ip}...")
        try:
            device = inventory.add_device(ip) # Add or get existing device
            if not device: # Should not happen if IP is valid string, but as a safeguard
                logger.error(f"Failed to add/get device for IP {ip} in inventory. Skipping.")
                print(f"  Error: Could not process device {ip} in inventory. Skipping.")
                continue
        except ValueError as e: # From inventory.add_device if IP is invalid (already checked by sweeper but good practice)
            logger.error(f"Invalid IP address '{ip}' encountered: {e}. Skipping.")
            print(f"  Error: Invalid IP address '{ip}'. Skipping.")
            continue

        snmp_data = fetch_snmp_data(ip, args.community, DEFAULT_SNMP_OIDS)
        
        attributes_to_update = {}
        logger.debug(f"SNMP data received for {ip}: {snmp_data}")
        print(f"  SNMP data for {ip}:")
        if not snmp_data or all(value is None for value in snmp_data.values()):
            logger.warning(f"No valid SNMP data received for {ip} with community '{args.community}'.")
            print(f"    No SNMP data received or all OIDs failed (check logs for details for {ip}).")
        else:
            for oid, value in snmp_data.items():
                attribute_name = OID_TO_ATTRIBUTE_MAP.get(oid, oid) # Default to OID if no friendly name
                print(f"    {attribute_name}: {value if value is not None else 'Not found/Error'}")
                if value is not None and OID_TO_ATTRIBUTE_MAP.get(oid): # Only update known attributes with valid data
                    attributes_to_update[OID_TO_ATTRIBUTE_MAP.get(oid)] = value
            
            if attributes_to_update:
                inventory.update_device_attributes(ip, attributes_to_update)
                logger.info(f"Updated inventory for {ip} with attributes: {attributes_to_update}")
                print(f"  Updated inventory for {ip} with new SNMP data.")
            else:
                logger.info(f"No new, mappable attributes to update for {ip} from SNMP data (possibly all OIDs failed or returned no data).")
                print(f"  No new attributes to update in inventory for {ip} from SNMP data.")
        processed_count +=1

    if processed_count > 0 :
        logger.info(f"Saving updated inventory to {args.inventory_file}...")
        inventory.save_to_json(args.inventory_file) # Errors logged by Inventory class
        print(f"\nDiscovery complete. Processed {processed_count} device(s). Inventory saved to {args.inventory_file}.")
    elif active_ips: # Active IPs found, but none could be processed (e.g. inventory errors)
        logger.warning("Active IPs were found, but no devices were successfully processed into the inventory.")
        print("\nDiscovery attempted, but no devices were successfully added or updated in the inventory.")
    else: # No active_ips initially
        logger.info("Discovery complete. No active devices found to process.")
        print("\nDiscovery complete. No active devices found.")


def handle_show(args):
    """
    Handles the 'show' subcommand.
    Loads and displays the device inventory.
    """
    logger.info(f"Handling 'show' command for inventory file: {args.inventory_file}")
    
    if not os.path.exists(args.inventory_file):
        logger.error(f"Inventory file '{args.inventory_file}' not found for 'show' command.")
        print(f"Error: Inventory file '{args.inventory_file}' not found.")
        print("Please run 'discover' first to create an inventory, or check the file path.")
        return

    inventory = Inventory()
    inventory.load_from_json(args.inventory_file) # Errors logged by Inventory class

    devices = inventory.list_all_devices()
    if not devices:
        logger.info("Inventory loaded but is empty.")
        print("Inventory is empty.")
        return

    print("\n--- Device Inventory ---")
    for i, device in enumerate(devices):
        print(f"\nDevice #{i+1}:")
        # Using device.__str__() implicitly by printing the object
        print(device) 
        print("--------------------")
    logger.info(f"Displayed {len(devices)} device(s) from inventory.")


def main():
    """
    Main function to parse arguments and dispatch commands.
    Logging is configured globally when nms package is imported (nms/nms/__init__.py).
    """
    # If logging hasn't been configured by __init__.py (e.g. running cli.py directly for dev)
    # provide a basic configuration.
    if not logging.getLogger().hasHandlers(): # Check if root logger has handlers
        from nms.utils.logger import setup_logging # Assuming utils is in the same nms.nms level
        print("CLI Main: Basic logging not yet configured, setting up for CLI direct run.")
        setup_logging(log_level=logging.INFO, force_setup=True)


    parser = argparse.ArgumentParser(description="NMS CLI - Network Management System Tool")
    parser.add_argument(
        '--inventory-file', 
        default=DEFAULT_INVENTORY_FILE,
        help=f"Path to the inventory JSON file (default: {DEFAULT_INVENTORY_FILE})"
    )
    parser.add_argument(
        '--log-level',
        default=os.environ.get('NMS_LOG_LEVEL', 'INFO').upper(),
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Set the logging level (default: INFO, or NMS_LOG_LEVEL env var)"
    )
    
    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    # --- Discover Subcommand ---
    discover_parser = subparsers.add_parser("discover", help="Discover devices on a network and update inventory")
    discover_parser.add_argument(
        "network", 
        help="Network address to scan (e.g., '192.168.1.0/24')"
    )
    discover_parser.add_argument(
        "--community", 
        default=DEFAULT_COMMUNITY_STRING, 
        help=f"SNMP community string (default: {DEFAULT_COMMUNITY_STRING})"
    )
    discover_parser.set_defaults(func=handle_discover)

    # --- Show Subcommand ---
    show_parser = subparsers.add_parser("show", help="Show devices in the inventory")
    show_parser.set_defaults(func=handle_show)

    args = parser.parse_args()

    # Update log level from command line argument if nms.utils.logger.setup_logging was called
    # This reconfigures with the new level.
    # This assumes setup_logging in __init__ or above has already run.
    # If we always want CLI --log-level to override, we might need to call setup_logging here.
    # For simplicity, we assume it's okay to re-initialize or that logger is already set.
    # A more robust way would be to get the root logger and set its level.
    
    # Get the root logger and set its level based on args.log_level
    # This will affect all handlers unless they have a more restrictive level set.
    try:
        # This is a more direct way to change the level if logging is already configured.
        logging.getLogger().setLevel(args.log_level.upper())
        for handler in logging.getLogger().handlers:
            handler.setLevel(args.log_level.upper()) # Also update handler levels
        logger.info(f"Logging level set to {args.log_level.upper()} from CLI argument.")
    except Exception as e: # pylint: disable=broad-except
        logger.error(f"Failed to set log level from CLI: {e}")


    logger.info(f"CLI command '{args.command}' initiated with arguments: {vars(args)}")
    try:
        args.func(args)
    except Exception as e:
        logger.critical(f"An unhandled exception occurred in command '{args.command}': {e}", exc_info=True)
        print(f"CRITICAL ERROR: An unexpected error occurred. Please check the logs (e.g., nms.log) for details. Error: {e}")
        sys.exit(1) # Exit with error code

if __name__ == "__main__":
    # This ensures that if cli.py is run directly, the nms/ (project root)
    # is added to sys.path to allow finding the nms package.
    # This is important for development and direct testing of cli.py.
    if __package__ is None or __package__ == '': # Check if run as a script
        # If run as a script, __file__ is nms/nms/cli.py
        # We want to add nms/ (project root) to the path.
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
            print(f"Added {project_root} to sys.path for direct script execution.")
    
    # Now that sys.path is potentially adjusted, we can try importing from nms.utils.logger
    # This needs to be here because `main()` might be called after this block in some scenarios,
    # or this script might be imported.
    # The `main()` function itself also has a fallback for logging setup.
    try:
        from nms.utils.logger import setup_logging
        # Ensure logging is set up if not already done by package import.
        # This is a fallback for direct script execution.
        if not logging.getLogger().hasHandlers():
            print("Setting up logging from __main__ block for direct script run.")
            setup_logging(log_level=logging.INFO, force_setup=True) # Use INFO for CLI default, main() will adjust
    except ImportError:
        print("Error: Could not import setup_logging. Ensure PYTHONPATH is set correctly or run as part of the nms package.")
        # Fallback to basic print if logger setup fails catastrophically for direct run
        logger.addHandler(logging.StreamHandler(sys.stdout)) 
        logger.setLevel(logging.INFO)
        logger.error("Fallback: Logging setup via nms.utils.logger failed.")


    main()
