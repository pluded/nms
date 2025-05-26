import argparse
import os
import logging # Import logging
import sys

# Adjust import paths to be robust for different execution contexts
try:
    from nms.discovery.icmp_sweeper import sweep_network, PingCommandNotFound
    from nms.discovery.snmp_discoverer import discover_snmp 
    from nms.discovery.link_discovery import get_lldp_neighbors, get_cdp_neighbors, get_ip_routing_table 
    from nms.monitoring.interface_monitor import collect_interface_metrics # For poll-metrics
    from nms.inventory.device import Inventory 
except ModuleNotFoundError:
    # This block allows running cli.py directly from nms/nms for testing,
    # assuming nms/ (project root) is in PYTHONPATH.
    # For normal package usage, the top-level nms/ should be in PYTHONPATH.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from discovery.icmp_sweeper import sweep_network, PingCommandNotFound
    from discovery.snmp_discoverer import discover_snmp 
    from discovery.link_discovery import get_lldp_neighbors, get_cdp_neighbors, get_ip_routing_table
    from monitoring.interface_monitor import collect_interface_metrics # For poll-metrics
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
        device = inventory.get_device(ip)
        if not device:
            try:
                device = inventory.add_device(ip_address=ip)
                if not device: # Should not happen if IP is valid string
                    logger.error(f"Failed to add device for IP {ip} in inventory. Skipping.")
                    print(f"  Error: Could not add device {ip} to inventory. Skipping.")
                    continue
            except ValueError as e:
                logger.error(f"Invalid IP address '{ip}' encountered on add: {e}. Skipping.")
                print(f"  Error: Invalid IP address '{ip}'. Skipping.")
                continue
        
        # Initialize or get current discovered_protocols
        current_protocols = getattr(device, 'discovered_protocols', [])
        if not isinstance(current_protocols, list): # Ensure it's a list
            current_protocols = []
        
        if "ICMP" not in current_protocols:
            current_protocols.append("ICMP")
        
        # Attempt SNMP discovery using the new discover_snmp function
        logger.info(f"Attempting SNMP discovery for {ip} using new discoverer...")
        snmp_basic_data = discover_snmp(ip, args.community) # Using new function

        attributes_to_update_for_device = {}

        if snmp_basic_data:
            logger.info(f"SNMP basic discovery successful for {ip}: {snmp_basic_data}")
            print(f"  SNMP Basic Info: sysDescr='{snmp_basic_data.get('sysDescr', 'N/A')}', sysObjectID='{snmp_basic_data.get('sysObjectID', 'N/A')}'")
            # Map sysDescr to system_description if that's the target attribute in Device class
            # The Device.update_attributes will handle this if keys match.
            # If 'sysDescr' is a key in snmp_basic_data, and Device has 'sysDescr' attribute, it's updated.
            # If Device has 'system_description' and we want sysDescr to fill it, a manual mapping is needed here
            # For now, let's pass it as is. If 'sysDescr' isn't a direct attribute, it goes to other_attributes.
            attributes_to_update_for_device.update(snmp_basic_data)

            if "SNMP" not in current_protocols:
                current_protocols.append("SNMP")
        else:
            logger.warning(f"New SNMP discovery failed or returned no data for {ip}.")
            print(f"  SNMP discovery (new method) failed or returned no data for {ip}.")

        # Update discovered_protocols
        attributes_to_update_for_device['discovered_protocols'] = sorted(list(set(current_protocols))) # Ensure uniqueness and sort

        # L2 Link Discovery
        discovered_links = []
        # LLDP
        logger.info(f"Attempting LLDP discovery for {ip}...")
        lldp_links = get_lldp_neighbors(ip, args.community)
        if lldp_links is not None:
            if lldp_links: # If list is not empty
                logger.info(f"Found {len(lldp_links)} LLDP links for {ip}.")
                print(f"  Found {len(lldp_links)} LLDP links.")
                if "LLDP" not in attributes_to_update_for_device['discovered_protocols']:
                    attributes_to_update_for_device['discovered_protocols'].append("LLDP")
                    attributes_to_update_for_device['discovered_protocols'].sort()
                for link in lldp_links:
                    standardized_link = {
                        'local_port_identifier': str(link.pop('local_port_num', 'N/A')),
                        'remote_device_id': link.get('remote_system_name') or link.get('remote_chassis_id', 'N/A'),
                        'remote_port_id': link.get('remote_port_id', 'N/A'),
                        'remote_port_desc': link.get('remote_port_desc', 'N/A'), # Keep if available
                        'protocol': link.get('protocol', 'LLDP')
                    }
                    discovered_links.append(standardized_link)
            else:
                logger.info(f"No LLDP links found for {ip}.")
                print(f"  No LLDP links found for {ip}.")
        else:
            logger.warning(f"LLDP discovery failed for {ip} (returned None).")
            print(f"  LLDP discovery failed for {ip} (check logs).")

        # CDP
        logger.info(f"Attempting CDP discovery for {ip}...")
        cdp_links = get_cdp_neighbors(ip, args.community)
        if cdp_links is not None:
            if cdp_links: # If list is not empty
                logger.info(f"Found {len(cdp_links)} CDP links for {ip}.")
                print(f"  Found {len(cdp_links)} CDP links.")
                if "CDP" not in attributes_to_update_for_device['discovered_protocols']:
                    attributes_to_update_for_device['discovered_protocols'].append("CDP")
                    attributes_to_update_for_device['discovered_protocols'].sort()
                for link in cdp_links:
                    standardized_link = {
                        'local_port_identifier': str(link.pop('local_ifindex', 'N/A')),
                        'remote_device_id': link.get('remote_device_id', 'N/A'),
                        'remote_port_id': link.get('remote_interface', 'N/A'),
                        'remote_platform': link.get('remote_platform', 'N/A'), # Keep if available
                        'remote_device_ip': link.get('remote_device_ip', 'N/A'), # Keep if available
                        'protocol': link.get('protocol', 'CDP')
                    }
                    discovered_links.append(standardized_link)
            else:
                logger.info(f"No CDP links found for {ip}.")
                print(f"  No CDP links found for {ip}.")
        else:
            logger.warning(f"CDP discovery failed for {ip} (returned None).")
            print(f"  CDP discovery failed for {ip} (check logs).")
        
        if discovered_links:
            attributes_to_update_for_device['links'] = discovered_links
            logger.info(f"Adding {len(discovered_links)} L2 links to device {ip}.")
            print(f"  Adding {len(discovered_links)} L2 links to inventory.")
        
        # L3 Routing Table Discovery
        logger.info(f"Attempting L3 routing table discovery for {ip}...")
        routing_table_data = get_ip_routing_table(ip, args.community)
        if routing_table_data is not None: # Will be a list (possibly empty) on success, None on error
            if routing_table_data: # If list is not empty
                attributes_to_update_for_device['routing_table'] = routing_table_data
                logger.info(f"Found {len(routing_table_data)} L3 routes for {ip}.")
                print(f"  Found {len(routing_table_data)} L3 routes.")
                if "Routing" not in attributes_to_update_for_device['discovered_protocols']: # Generic protocol name for now
                    attributes_to_update_for_device['discovered_protocols'].append("Routing")
                    attributes_to_update_for_device['discovered_protocols'].sort()
            else: # Empty list, means table is empty or no routes found
                attributes_to_update_for_device['routing_table'] = [] # Ensure it's set to empty if not already
                logger.info(f"No L3 routes found in table for {ip}.")
                print(f"  No L3 routes found for {ip}.")
        else: # None means SNMP error during fetch
            logger.warning(f"L3 routing table discovery failed for {ip} (returned None).")
            print(f"  L3 routing table discovery failed for {ip} (check logs).")
            # Do not update 'routing_table' if it was None, retain existing or default empty.

        # Update device with all collected attributes (SNMP data, protocols, links, routes)
        if attributes_to_update_for_device: # Check if there's anything to update
            device.update_attributes(attributes_to_update_for_device)
            logger.info(f"Updated inventory for {ip} with attributes: {attributes_to_update_for_device}")
            print(f"  Updated inventory for {ip}.")
        else:
            logger.info(f"No new attributes, links, or routes to update for {ip}.")
            print(f"  No new attributes, links, or routes to update for {ip}.")

        processed_count += 1

    # Save inventory after processing all active IPs
    if processed_count > 0 or os.path.exists(args.inventory_file): # Save if we processed, or if file existed (to persist potential load fixes)
        logger.info(f"Saving updated inventory to {args.inventory_file}...")
        inventory.save_to_json(args.inventory_file) 
        print(f"\nDiscovery complete. Processed {processed_count} device(s). Inventory saved to {args.inventory_file}.")
    elif active_ips: # Active IPs found, but none could be processed (e.g. inventory errors)
        logger.warning("Active IPs were found, but no devices were successfully processed into the inventory.")
        # Still save if inventory file existed initially, might have been cleared/fixed on load
        if os.path.exists(args.inventory_file): inventory.save_to_json(args.inventory_file)
        print("\nDiscovery attempted, but no devices were successfully added or updated in the inventory.")
    else: # No active_ips initially
        logger.info("Discovery complete. No active devices found to process.")
        # Still save if inventory file existed initially, might have been cleared/fixed on load
        if os.path.exists(args.inventory_file): inventory.save_to_json(args.inventory_file)
        print("\nDiscovery complete. No active devices found.")


def handle_poll_metrics(args):
    """
    Handles the 'poll-metrics' subcommand.
    Polls interface metrics for specified device(s) and updates the inventory.
    """
    logger.info(f"Starting 'poll-metrics' for target '{args.target}' with community '{args.community}' on inventory '{args.inventory_file}'")
    
    inventory = Inventory()
    if not os.path.exists(args.inventory_file):
        logger.error(f"Inventory file '{args.inventory_file}' not found. Cannot poll metrics.")
        print(f"Error: Inventory file '{args.inventory_file}' not found. Please run discovery or check the file path.")
        return
    
    try:
        inventory.load_from_json(args.inventory_file)
        logger.info(f"Successfully loaded inventory from {args.inventory_file}")
    except Exception as e: # Catch broad exceptions from load_from_json if it raises them
        logger.error(f"Failed to load inventory from {args.inventory_file}: {e}", exc_info=True)
        print(f"Error: Could not load inventory from {args.inventory_file}. Aborting. Check logs for details.")
        return

    devices_to_poll = []
    if args.target.lower() == 'all':
        devices_to_poll = inventory.list_all_devices()
        if not devices_to_poll:
            logger.info("No devices found in inventory to poll.")
            print("Inventory is empty. Nothing to poll.")
            return
        logger.info(f"Polling metrics for all {len(devices_to_poll)} devices in inventory.")
        print(f"Polling metrics for all {len(devices_to_poll)} devices...")
    else:
        device = inventory.get_device(args.target)
        if device:
            devices_to_poll.append(device)
            logger.info(f"Target device {args.target} found in inventory. Preparing to poll.")
            print(f"Found device {args.target}. Polling metrics...")
        else:
            logger.error(f"Device IP '{args.target}' not found in inventory '{args.inventory_file}'.")
            print(f"Error: Device with IP '{args.target}' not found in the inventory.")
            return

    polled_device_count = 0
    for dev in devices_to_poll:
        logger.info(f"Polling interface metrics for {dev.ip_address}...")
        print(f"\nPolling metrics for {dev.ip_address} ({dev.system_name or 'N/A'})...")
        
        existing_metrics = dev.interface_metrics # This is a dict, possibly empty
        
        new_metrics = collect_interface_metrics(
            dev.ip_address, 
            args.community, 
            existing_device_metrics=existing_metrics
        )
        
        if new_metrics is not None: # collect_interface_metrics returns dict (even empty) on success, None on major SNMP error
            dev.update_attributes({'interface_metrics': new_metrics})
            # Also update discovered_protocols if 'InterfaceMonitoring' is not there
            current_protocols = getattr(dev, 'discovered_protocols', [])
            if "InterfaceMonitoring" not in current_protocols:
                current_protocols.append("InterfaceMonitoring")
                dev.update_attributes({'discovered_protocols': sorted(list(set(current_protocols)))})

            logger.info(f"Successfully collected and updated metrics for {dev.ip_address}.")
            print(f"  Successfully updated metrics for {dev.ip_address}.")
            polled_device_count +=1
        else:
            logger.warning(f"Failed to collect metrics for {dev.ip_address} (SNMP error or device unreachable).")
            print(f"  Warning: Failed to collect metrics for {dev.ip_address}. Check logs.")

    if polled_device_count > 0 or args.target.lower() != 'all': # Save if any attempt was made for specific IP or if 'all' and devices polled
        try:
            inventory.save_to_json(args.inventory_file)
            logger.info(f"Finished polling metrics for {polled_device_count} device(s). Inventory saved to {args.inventory_file}.")
            print(f"\nFinished polling metrics. {polled_device_count} device(s) processed. Inventory saved.")
        except Exception as e:
            logger.critical(f"Failed to save inventory after polling metrics: {e}", exc_info=True)
            print(f"CRITICAL ERROR: Failed to save inventory to {args.inventory_file}. Check logs for details.")
    elif args.target.lower() == 'all' and not devices_to_poll: # 'all' was specified but inventory was empty
        pass # Message already printed
    else: # 'all' specified, devices existed, but none were successfully polled (all had SNMP errors)
        logger.info("Polling complete, but no devices had metrics successfully collected. Inventory not re-saved unless it was modified by loading.")
        print("\nPolling complete. No new metrics were successfully collected.")


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

    # --- Poll Metrics Subcommand ---
    poll_metrics_parser = subparsers.add_parser("poll-metrics", help="Poll interface metrics for a device or all devices")
    poll_metrics_parser.add_argument(
        "target", 
        help="IP address of the device to poll, or 'all' for all devices in inventory."
    )
    poll_metrics_parser.add_argument(
        "--community", 
        default=DEFAULT_COMMUNITY_STRING, 
        help=f"SNMP community string (default: {DEFAULT_COMMUNITY_STRING})"
    )
    poll_metrics_parser.set_defaults(func=handle_poll_metrics)


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
