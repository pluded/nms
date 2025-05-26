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
    from nms.discovery.snmp_discoverer import discover_snmp 
    from nms.discovery.link_discovery import get_lldp_neighbors, get_cdp_neighbors, get_ip_routing_table # L2/L3 Discovery
except ModuleNotFoundError:
    import sys
    # Add parent of nms.web (which is nms.nms) to path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from inventory.device import Inventory
    from discovery.icmp_sweeper import sweep_network, PingCommandNotFound
    from discovery.snmp_discoverer import discover_snmp
    from discovery.link_discovery import get_lldp_neighbors, get_cdp_neighbors, get_ip_routing_table # L2/L3 Discovery

# OIDs for basic device information (consistent with CLI) - Kept if other parts use it, but discover_snmp has its own.
# DEFAULT_SNMP_OIDS = [
#     "1.3.6.1.2.1.1.1.0",  # System Description
#     "1.3.6.1.2.1.1.3.0",  # System Uptime
#     "1.3.6.1.2.1.1.5.0",  # System Name
#     "1.3.6.1.2.1.1.6.0",  # System Location
# ]
# OID_TO_ATTRIBUTE_MAP = {
#     "1.3.6.1.2.1.1.1.0": "system_description",
#     "1.3.6.1.2.1.1.3.0": "uptime",
#     "1.3.6.1.2.1.1.5.0": "system_name",
#     "1.3.6.1.2.1.1.6.0": "location",
# }


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
        community_string = request.form.get('community_string', 'public') 
        
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
                device = inventory.get_device(ip)
                if not device:
                    try:
                        device = inventory.add_device(ip_address=ip)
                        if not device:
                            discovery_log.append(f"  Error: Could not add device {ip} to inventory. Skipping.")
                            logger.warning(f"Failed to add device {ip} in web discovery.")
                            continue
                    except ValueError as e:
                        discovery_log.append(f"  Error: Invalid IP address '{ip}': {e}. Skipping.")
                        logger.warning(f"Invalid IP {ip} encountered in web discovery: {e}")
                        continue
                
                current_protocols = getattr(device, 'discovered_protocols', [])
                if not isinstance(current_protocols, list): # Ensure it's a list
                    current_protocols = []

                if "ICMP" not in current_protocols:
                    current_protocols.append("ICMP")

                attributes_to_update_for_device = {}
                
                # SNMP discovery using new discover_snmp function
                logger.info(f"Web: Attempting SNMP discovery for {ip} with community '{community_string}'")
                snmp_data = discover_snmp(ip, community_string)

                if snmp_data:
                    discovery_log.append(f"  SNMP basic info for {ip}: sysDescr='{snmp_data.get('sysDescr', 'N/A')}', sysObjectID='{snmp_data.get('sysObjectID', 'N/A')}'")
                    logger.info(f"Web SNMP discovery for {ip} successful: {snmp_data}")
                    attributes_to_update_for_device.update(snmp_data)
                    if "SNMP" not in current_protocols:
                        current_protocols.append("SNMP")
                else:
                    discovery_log.append(f"  SNMP discovery failed or returned no data for {ip}.")
                    logger.warning(f"Web SNMP discovery failed for {ip}.")

                attributes_to_update_for_device['discovered_protocols'] = sorted(list(set(current_protocols)))
                
                # L2 Link Discovery
                discovered_links = []
                # LLDP
                logger.info(f"Web: Attempting LLDP discovery for {ip}...")
                lldp_links = get_lldp_neighbors(ip, community_string)
                if lldp_links is not None:
                    if lldp_links:
                        discovery_log.append(f"  Found {len(lldp_links)} LLDP links for {ip}.")
                        if "LLDP" not in attributes_to_update_for_device['discovered_protocols']:
                            attributes_to_update_for_device['discovered_protocols'].append("LLDP")
                            attributes_to_update_for_device['discovered_protocols'].sort()
                        for link in lldp_links:
                            standardized_link = {
                                'local_port_identifier': str(link.pop('local_port_num', 'N/A')),
                                'remote_device_id': link.get('remote_system_name') or link.get('remote_chassis_id', 'N/A'),
                                'remote_port_id': link.get('remote_port_id', 'N/A'),
                                'remote_port_desc': link.get('remote_port_desc', 'N/A'),
                                'protocol': link.get('protocol', 'LLDP')
                            }
                            discovered_links.append(standardized_link)
                    else:
                        discovery_log.append(f"  No LLDP links found for {ip}.")
                else:
                    discovery_log.append(f"  LLDP discovery failed for {ip} (returned None - check logs).")
                    logger.warning(f"Web LLDP discovery for {ip} returned None.")

                # CDP
                logger.info(f"Web: Attempting CDP discovery for {ip}...")
                cdp_links = get_cdp_neighbors(ip, community_string)
                if cdp_links is not None:
                    if cdp_links:
                        discovery_log.append(f"  Found {len(cdp_links)} CDP links for {ip}.")
                        if "CDP" not in attributes_to_update_for_device['discovered_protocols']:
                            attributes_to_update_for_device['discovered_protocols'].append("CDP")
                            attributes_to_update_for_device['discovered_protocols'].sort()
                        for link in cdp_links:
                            standardized_link = {
                                'local_port_identifier': str(link.pop('local_ifindex', 'N/A')),
                                'remote_device_id': link.get('remote_device_id', 'N/A'),
                                'remote_port_id': link.get('remote_interface', 'N/A'),
                                'remote_platform': link.get('remote_platform', 'N/A'),
                                'remote_device_ip': link.get('remote_device_ip', 'N/A'),
                                'protocol': link.get('protocol', 'CDP')
                            }
                            discovered_links.append(standardized_link)
                    else:
                        discovery_log.append(f"  No CDP links found for {ip}.")
                else:
                    discovery_log.append(f"  CDP discovery failed for {ip} (returned None - check logs).")
                    logger.warning(f"Web CDP discovery for {ip} returned None.")
                
                if discovered_links:
                    attributes_to_update_for_device['links'] = discovered_links
                    discovery_log.append(f"  Adding {len(discovered_links)} L2 links to device {ip}.")
                
                # L3 Routing Table Discovery
                logger.info(f"Web: Attempting L3 routing table discovery for {ip}...")
                routing_table_data = get_ip_routing_table(ip, community_string)
                if routing_table_data is not None: # Success (list, possibly empty) or error (None)
                    if routing_table_data:
                        attributes_to_update_for_device['routing_table'] = routing_table_data
                        discovery_log.append(f"  Found {len(routing_table_data)} L3 routes for {ip}.")
                        if "Routing" not in attributes_to_update_for_device['discovered_protocols']:
                             attributes_to_update_for_device['discovered_protocols'].append("Routing")
                             attributes_to_update_for_device['discovered_protocols'].sort()
                    else: # Empty list from successful fetch
                        attributes_to_update_for_device['routing_table'] = []
                        discovery_log.append(f"  No L3 routes found for {ip}.")
                else: # SNMP error
                    discovery_log.append(f"  L3 routing table discovery failed for {ip} (check logs).")
                    logger.warning(f"Web L3 routing table discovery for {ip} returned None.")
                    # Do not update 'routing_table' if it was None, retain existing or default empty.


                if attributes_to_update_for_device: # Check if there's anything to update (SNMP data, protocols, links, routes)
                    device.update_attributes(attributes_to_update_for_device)
                    discovery_log.append(f"  Updated inventory for {ip}.")
                    logger.info(f"Web discovery updated {ip} with attributes: {attributes_to_update_for_device}")
                
                processed_count += 1
            discovery_log.append(f"Completed processing for {processed_count} active host(s).")

        # Save inventory after processing all active IPs
        try:
            inventory.save_to_json(inventory_file_path)
            discovery_log.append(f"Inventory saved to {os.path.basename(inventory_file_path)}.")
            logger.info(f"Web discovery saved inventory to {inventory_file_path}")
            flash("Discovery process completed!", "success")
        except Exception as e:
            error_message = f"Error saving inventory: {e}"
            logger.error(f"Web discovery inventory save error: {e}", exc_info=True)
            flash(error_message, "error")
            discovery_log.append(f"  CRITICAL: Failed to save inventory: {e}")

        return render_template('discover.html', results=discovery_log, error_message=error_message,
                               network_address=network_address, community_string=community_string)

    # For GET request
    return render_template('discover.html', results=None, network_address="192.168.1.0/24", community_string=community_string)


@app.route('/api/topology_data')
def api_topology_data():
    """
    Serves L2 topology data (nodes and edges) for visualization.
    """
    inventory_file_path = DEFAULT_INVENTORY_FILE
    app_inventory = Inventory() # Renamed to avoid conflict if inventory was a global
    nodes = []
    edges = []
    
    if os.path.exists(inventory_file_path):
        try:
            app_inventory.load_from_json(inventory_file_path)
        except Exception as e:
            logger.error(f"API: Error loading inventory for topology: {e}", exc_info=True)
            # Consider returning a 500 error or an error structure
            from flask import jsonify # Import jsonify here
            return jsonify({"error": "Failed to load inventory data", "nodes": [], "edges": []}), 500
    else:
        logger.warning("API: Inventory file not found for topology data.")
        from flask import jsonify # Import jsonify here
        return jsonify({"error": "Inventory file not found", "nodes": [], "edges": []}), 404

    all_devices = app_inventory.list_all_devices()
    managed_device_ips = {dev.ip_address for dev in all_devices}

    # 1. Add all managed devices to the 'nodes' list
    for device in all_devices:
        nodes.append({
            'id': device.ip_address,
            'label': device.system_name or device.ip_address,
            'title': (
                f"IP: {device.ip_address}\n"
                f"Name: {device.system_name or 'N/A'}\n"
                f"Vendor: {device.vendor or 'N/A'}\n"
                f"Model: {device.model or 'N/A'}\n"
                f"SW Version: {device.software_version or 'N/A'}"
            ),
            'group': device.vendor or 'Managed Device' # Group by vendor, or a generic group
        })

    # 2. Iterate through devices to build edges and add unmanaged neighbor nodes
    processed_edges = set()  # To store tuples like tuple(sorted((source_id, target_id)))

    for device in all_devices:
        source_ip = device.ip_address
        if not getattr(device, 'links', None): # Check if device has links attribute and it's not None
            continue

        for link in device.links:
            target_id_from_link = link.get('remote_device_id')
            if not target_id_from_link: # Skip if no remote device identifier
                continue

            resolved_target_ip = None
            # Attempt to resolve target_id_from_link to an IP of a known managed device
            for managed_dev in all_devices:
                if target_id_from_link == managed_dev.ip_address:
                    resolved_target_ip = managed_dev.ip_address
                    break
                if managed_dev.system_name and target_id_from_link == managed_dev.system_name:
                    resolved_target_ip = managed_dev.ip_address
                    break
                if hasattr(managed_dev, 'mac_address') and managed_dev.mac_address and \
                   target_id_from_link == managed_dev.mac_address: # Check if mac_address exists and is not None
                    resolved_target_ip = managed_dev.ip_address
                    break
            
            actual_target_node_id = resolved_target_ip if resolved_target_ip else target_id_from_link

            # If target_id_from_link was not an IP of a managed device AND it's not already in nodes, add it as an unmanaged node
            if not resolved_target_ip and not any(n['id'] == target_id_from_link for n in nodes):
                nodes.append({
                    'id': target_id_from_link,
                    'label': target_id_from_link, # Use the identifier as label
                    'title': f"Unmanaged Neighbor: {target_id_from_link}",
                    'group': 'Unmanaged'
                })
            
            # Add edge, ensuring no duplicates (A-B is same as B-A for this deduplication)
            edge_tuple = tuple(sorted((source_ip, actual_target_node_id)))
            if edge_tuple in processed_edges:
                logger.debug(f"Skipping duplicate edge: {edge_tuple}")
                continue 
            processed_edges.add(edge_tuple)

            edge_title = (
                f"Protocol: {link.get('protocol', 'N/A')}\n"
                f"Local: {device.system_name or source_ip} ({link.get('local_port_identifier', 'N/A')})\n"
                f"Remote: {target_id_from_link} ({link.get('remote_port_id', 'N/A')})"
            )
            if link.get('remote_platform'):
                edge_title += f"\nRemote Platform: {link.get('remote_platform')}"
            if resolved_target_ip and link.get('remote_device_ip') and resolved_target_ip != link.get('remote_device_ip'):
                 # This case might occur if remote_device_id was a hostname, but CDP also gave an IP
                 edge_title += f"\nRemote Reported IP: {link.get('remote_device_ip')}"


            edges.append({
                'from': source_ip,
                'to': actual_target_node_id,
                'title': edge_title,
                'arrows': 'to', # Vis.js can use this for directed rendering if desired
                'dashes': not bool(resolved_target_ip) # Dashed if link to unmanaged/unresolved device
            })

    from flask import jsonify # Import jsonify here
    return jsonify({'nodes': nodes, 'edges': edges})

@app.route('/topology')
def topology_page():
    """
    Serves the page that will display the L2 network topology.
    """
    return render_template('topology.html', title='Network Topology')


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
