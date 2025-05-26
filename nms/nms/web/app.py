from flask import Flask, render_template
import os

# Determine the correct template folder path relative to this file
# __file__ is nms/nms/web/app.py
# template_dir should be nms/nms/web/templates
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

import logging
from flask import request, redirect, url_for, flash
# Ensure nms.inventory.device and other modules can be imported.
try:
    from nms.inventory.device import Inventory
    from nms.discovery.icmp_sweeper import sweep_network, PingCommandNotFound
    from nms.monitoring.snmp_collector import fetch_snmp_data
except ModuleNotFoundError:
    import sys
    # Add parent of nms.web (which is nms.nms) to path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from inventory.device import Inventory
    from discovery.icmp_sweeper import sweep_network, PingCommandNotFound
    from monitoring.snmp_collector import fetch_snmp_data

# OIDs for basic device information (consistent with CLI)
DEFAULT_SNMP_OIDS = [
    "1.3.6.1.2.1.1.1.0",  # System Description
    "1.3.6.1.2.1.1.3.0",  # System Uptime
    "1.3.6.1.2.1.1.5.0",  # System Name
    "1.3.6.1.2.1.1.6.0",  # System Location
]
OID_TO_ATTRIBUTE_MAP = {
    "1.3.6.1.2.1.1.1.0": "system_description",
    "1.3.6.1.2.1.1.3.0": "uptime",
    "1.3.6.1.2.1.1.5.0": "system_name",
    "1.3.6.1.2.1.1.6.0": "location",
}


# Configure logging for the web app
# This will use the logging setup from nms.utils.logger if the nms package is properly initialized.
# If running app.py directly, ensure nms.utils.logger.setup_logging() has been called
# or add a basic configuration here.
logger = logging.getLogger(__name__)

# Define the path to inventory.json relative to the project root (nms/)
# app.root_path is nms/nms/web
PROJECT_ROOT = os.path.abspath(os.path.join(app.root_path, '..', '..')) 
DEFAULT_INVENTORY_FILE = os.path.join(PROJECT_ROOT, "inventory.json")


@app.route('/')
def index():
    """
    Serves the main index page.
    """
    return render_template('index.html', message="Welcome to the NMS Web Interface!")


@app.route('/inventory')
def show_inventory():
    """
    Loads device data from the inventory file and displays it.
    """
    inventory_file_path = DEFAULT_INVENTORY_FILE
    logger.info(f"Attempting to load inventory from: {inventory_file_path}")

    inventory = Inventory()
    devices = []
    error_message = None

    if os.path.exists(inventory_file_path):
        try:
            inventory.load_from_json(inventory_file_path) # load_from_json logs its own errors
            devices = inventory.list_all_devices()
            logger.info(f"Successfully loaded {len(devices)} device(s) from {inventory_file_path}")
        except Exception as e: # Catch any unexpected error during load/list
            logger.error(f"Unexpected error loading or listing devices from {inventory_file_path}: {e}", exc_info=True)
            error_message = f"An unexpected error occurred while loading the inventory: {e}"
            devices = [] # Ensure devices is empty on error
    else:
        logger.warning(f"Inventory file not found: {inventory_file_path}")
        error_message = "Inventory file (inventory.json) not found. Please run discovery first."
        # devices remains an empty list

    return render_template('inventory.html', devices=devices, error_message=error_message)


@app.route('/discover', methods=['GET', 'POST'])
def discover_devices():
    """
    Handles device discovery.
    GET: Displays the discovery form.
    POST: Processes the discovery request.
    """
    if request.method == 'POST':
        network_address = request.form.get('network_address')
        community_string = request.form.get('community_string', 'public') # Default to 'public'
        
        discovery_log = [] # To store messages about the process
        error_message = None

        # Basic Input Validation
        if not network_address:
            error_message = "Network address is required."
            flash(error_message, "error")
            return render_template('discover.html', results=discovery_log, error_message=error_message)
        # A more robust validation for CIDR would be good here (e.g. using ipaddress module)
        try:
            import ipaddress
            ipaddress.ip_network(network_address, strict=False)
        except ValueError:
            error_message = f"Invalid network address format: {network_address}. Please use CIDR (e.g., 192.168.1.0/24)."
            flash(error_message, "error")
            return render_template('discover.html', results=discovery_log, error_message=error_message)

        if not community_string: # Should not happen if default is set, but good practice
            community_string = "public"
            flash("Community string was empty, defaulted to 'public'.", "warning")

        discovery_log.append(f"Starting discovery on network: {network_address} with community: '{community_string}'")
        logger.info(f"Web discovery initiated for network: {network_address}, community: {community_string}")

        inventory = Inventory()
        inventory_file_path = DEFAULT_INVENTORY_FILE
        if os.path.exists(inventory_file_path):
            logger.info(f"Loading existing inventory from {inventory_file_path} for web discovery.")
            inventory.load_from_json(inventory_file_path)
        
        active_ips = []
        try:
            active_ips = sweep_network(network_address)
            discovery_log.append(f"ICMP sweep found {len(active_ips)} active host(s): {', '.join(active_ips) if active_ips else 'None'}")
            logger.info(f"Web ICMP sweep found {len(active_ips)} hosts: {active_ips}")
        except PingCommandNotFound:
            error_message = "Ping command not found on the server. Cannot perform discovery."
            logger.critical("Ping command not found during web discovery.")
            flash(error_message, "error")
            return render_template('discover.html', results=discovery_log, error_message=error_message)
        except Exception as e:
            error_message = f"An error occurred during ICMP sweep: {e}"
            logger.error(f"Web ICMP sweep error: {e}", exc_info=True)
            flash(error_message, "error")
            return render_template('discover.html', results=discovery_log, error_message=error_message)

        if not active_ips:
            discovery_log.append("No active devices found to process further.")
        else:
            processed_count = 0
            for ip in active_ips:
                discovery_log.append(f"Processing device: {ip}...")
                try:
                    device = inventory.add_device(ip)
                    if not device:
                        discovery_log.append(f"  Error: Could not add/get device {ip} in inventory. Skipping.")
                        logger.warning(f"Failed to add/get device {ip} in web discovery.")
                        continue
                except ValueError as e:
                     discovery_log.append(f"  Error: Invalid IP address '{ip}': {e}. Skipping.")
                     logger.warning(f"Invalid IP {ip} encountered in web discovery: {e}")
                     continue

                snmp_raw_data = fetch_snmp_data(ip, community_string, DEFAULT_SNMP_OIDS)
                attributes_to_update = {}
                snmp_summary = []
                if not snmp_raw_data or all(value is None for value in snmp_raw_data.values()):
                    discovery_log.append(f"  No valid SNMP data received for {ip}.")
                    logger.warning(f"No SNMP data for {ip} in web discovery.")
                else:
                    for oid, value in snmp_raw_data.items():
                        attr_name = OID_TO_ATTRIBUTE_MAP.get(oid, oid)
                        snmp_summary.append(f"{attr_name}: {value if value is not None else 'N/A'}")
                        if value is not None and OID_TO_ATTRIBUTE_MAP.get(oid):
                            attributes_to_update[OID_TO_ATTRIBUTE_MAP.get(oid)] = value
                    discovery_log.append(f"  SNMP data for {ip}: {'; '.join(snmp_summary)}")
                
                if attributes_to_update:
                    inventory.update_device_attributes(ip, attributes_to_update)
                    discovery_log.append(f"  Updated inventory for {ip} with SNMP data.")
                    logger.info(f"Web discovery updated {ip} with {attributes_to_update}")
                else:
                    discovery_log.append(f"  No new attributes to update in inventory for {ip} from SNMP data.")
                processed_count +=1
            discovery_log.append(f"Processed {processed_count} active host(s) for SNMP data.")

        try:
            inventory.save_to_json(inventory_file_path)
            discovery_log.append(f"Inventory saved to {os.path.basename(inventory_file_path)}.")
            logger.info(f"Web discovery saved inventory to {inventory_file_path}")
            flash("Discovery process completed successfully!", "success")
        except Exception as e:
            error_message = f"Error saving inventory: {e}"
            logger.error(f"Web discovery inventory save error: {e}", exc_info=True)
            flash(error_message, "error")
            discovery_log.append(f"  CRITICAL: Failed to save inventory: {e}")

        return render_template('discover.html', results=discovery_log, error_message=error_message,
                               network_address=network_address, community_string=community_string)

    # For GET request
    return render_template('discover.html', results=None, network_address="192.168.1.0/24", community_string="public")


if __name__ == '__main__':
    # Ensure logging is configured if running app.py directly,
    # especially if the main nms package __init__ hasn't run.
    if not logging.getLogger('nms').hasHandlers() and not logging.getLogger().hasHandlers():
        try:
            # Attempt to use the project's logger setup
            from nms.utils.logger import setup_logging
            setup_logging(log_level=logging.DEBUG, force_setup=True) # Use DEBUG for web dev
            logger.info("NMS logging configured for direct app.py execution.")
        except ImportError:
            # Basic fallback logging if nms.utils.logger is not found
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            logger.warning("Fallback basic logging configured. NMS project logger not found.")

    # Flask secret key is needed for flashing messages
    app.secret_key = os.urandom(24) 
    
    logger.info(f"Flask app starting with template folder: {app.template_folder}")
    logger.info(f"Project root determined as: {PROJECT_ROOT}")
    logger.info(f"Default inventory file path: {DEFAULT_INVENTORY_FILE}")
    app.run(debug=True, host='0.0.0.0', port=5000)
