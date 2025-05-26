import json
import logging

logger = logging.getLogger(__name__)

class Device:
    """
    Represents a network device.
    """
    def __init__(self, ip_address: str, **kwargs):
        """
        Initializes a new Device.

        Args:
            ip_address: The IP address of the device.
            **kwargs: Arbitrary keyword arguments for other device attributes
                      (e.g., system_description, uptime, system_name).
        """
        if not isinstance(ip_address, str) or not ip_address:
            logger.error(f"Attempted to create Device with invalid IP: {ip_address}")
            raise ValueError("IP address must be a non-empty string.")
        
        self.ip_address: str = ip_address
        self.system_description: str | None = kwargs.get("system_description")
        self.uptime: str | None = kwargs.get("uptime")
        self.system_name: str | None = kwargs.get("system_name")
        self.location: str | None = kwargs.get("location")
        self.contact: str | None = kwargs.get("contact")
        self.if_number: int | None = kwargs.get("if_number")
        # New attributes
        self.vendor: str | None = kwargs.get("vendor")
        self.model: str | None = kwargs.get("model")
        self.serial_number: str | None = kwargs.get("serial_number")
        self.software_version: str | None = kwargs.get("software_version")
        self.mac_address: str | None = kwargs.get("mac_address")
        # Initialize discovered_protocols, ensuring it's a list if provided or an empty list
        self.discovered_protocols: list[str] = kwargs.get("discovered_protocols", []) or []


        self.other_attributes: dict = {
            k: v for k, v in kwargs.items() 
            if k not in [
                "system_description", "uptime", "system_name", "location", 
                "contact", "if_number", "vendor", "model", "serial_number", 
                "software_version", "mac_address", "discovered_protocols"
            ]
        }
        logger.debug(f"Device created: {self.ip_address}")

    def update_attributes(self, new_attributes_dict: dict):
        """
        Updates the device's attributes.

        Args:
            new_attributes_dict: A dictionary containing attributes to update.
        """
        if not isinstance(new_attributes_dict, dict):
            logger.error(f"update_attributes called with non-dict type for {self.ip_address}: {type(new_attributes_dict)}")
            return

        logger.debug(f"Updating attributes for {self.ip_address} with: {new_attributes_dict}")
        for key, value in new_attributes_dict.items():
            if hasattr(self, key):
                old_value = getattr(self, key)
                setattr(self, key, value)
                logger.debug(f"Updated attribute {key} for {self.ip_address} from '{old_value}' to '{value}'")
            else:
                self.other_attributes[key] = value
                logger.debug(f"Added new other_attribute {key}='{value}' for {self.ip_address}")


    def __str__(self) -> str:
        attrs = [f"IP Address: {self.ip_address}"]
        if self.system_name: attrs.append(f"System Name: {self.system_name}")
        if self.system_description: attrs.append(f"Description: {self.system_description}")
        if self.uptime: attrs.append(f"Uptime: {self.uptime}")
        if self.location: attrs.append(f"Location: {self.location}")
        if self.contact: attrs.append(f"Contact: {self.contact}")
        if self.if_number is not None: attrs.append(f"Number of Interfaces: {self.if_number}")
        
        # Existing attributes (like system_description) are already handled if populated
        # It's assumed sysDescr from SNMP discovery updates self.system_description
        # via Device.update_attributes if the key 'system_description' or 'sysDescr' is used in the update dict.
        # For now, let's ensure system_description (potentially from SNMP's sysDescr) is shown if populated.
        # The original __str__ already includes system_description if it's set.

        if self.vendor: attrs.append(f"Vendor: {self.vendor}")
        if self.model: attrs.append(f"Model: {self.model}")
        if self.serial_number: attrs.append(f"Serial Number: {self.serial_number}")
        if self.software_version: attrs.append(f"Software Version: {self.software_version}")
        if self.mac_address: attrs.append(f"MAC Address: {self.mac_address}")
        
        # Display discovered_protocols
        if self.discovered_protocols: 
            attrs.append(f"Discovered Protocols: {', '.join(sorted(list(set(self.discovered_protocols))))}")

        # Display sysObjectID from other_attributes, as it's not a direct attribute
        sys_object_id = self.other_attributes.get('sysObjectID')
        if sys_object_id: 
            attrs.append(f"System Object ID: {sys_object_id}")
        
        # Display any remaining other_attributes that aren't sysObjectID
        # Filter out sysObjectID if it was already displayed
        other_attrs_to_display = {
            k: v for k, v in self.other_attributes.items() if k != 'sysObjectID'
        }
        if other_attrs_to_display:
            attrs.append("Other Attributes:")
            for key, value in sorted(other_attrs_to_display.items()): 
                attrs.append(f"  {key}: {value}")
        return "\n".join(attrs)

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "system_description": self.system_description,
            "uptime": self.uptime,
            "system_name": self.system_name,
            "location": self.location,
            "contact": self.contact,
            "if_number": self.if_number,
            # New attributes
            "vendor": self.vendor,
            "model": self.model,
            "serial_number": self.serial_number,
            "software_version": self.software_version,
            "mac_address": self.mac_address,
            "discovered_protocols": self.discovered_protocols,
            "other_attributes": self.other_attributes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Device | None':
        ip = data.get("ip_address")
        if not ip:
            logger.error("Cannot create Device from dict: 'ip_address' is missing or empty.")
            return None
        
        # Remove ip_address from data to pass the rest as kwargs
        actual_data_for_kwargs = {k:v for k,v in data.items() if k != "ip_address"}
        try:
            return cls(ip, **actual_data_for_kwargs)
        except ValueError as e: # Catch potential ValueError from __init__ if ip is invalid after all
            logger.error(f"Error creating Device from dict for IP {ip}: {e}")
            return None


class Inventory:
    """
    Manages a collection of Device objects.
    """
    def __init__(self):
        self._devices: dict[str, Device] = {}
        logger.info("Inventory initialized.")

    def add_device(self, ip_address: str, **kwargs) -> Device | None:
        if not isinstance(ip_address, str) or not ip_address:
            logger.error(f"Attempted to add device with invalid IP: {ip_address}")
            # Consider raising ValueError here as well, or return None and let caller handle
            raise ValueError("IP address must be a non-empty string for adding to inventory.")

        if ip_address not in self._devices:
            logger.info(f"Adding new device {ip_address} to inventory.")
            try:
                self._devices[ip_address] = Device(ip_address, **kwargs)
            except ValueError as e: # Should be caught by initial check, but good for safety
                logger.error(f"Failed to create device for {ip_address} during add_device: {e}")
                return None
        else:
            logger.debug(f"Device {ip_address} already in inventory. Returning existing instance.")
        return self._devices[ip_address]

    def get_device(self, ip_address: str) -> Device | None:
        device = self._devices.get(ip_address)
        if device:
            logger.debug(f"Retrieved device {ip_address} from inventory.")
        else:
            logger.debug(f"Device {ip_address} not found in inventory.")
        return device

    def update_device_attributes(self, ip_address: str, attributes_dict: dict) -> bool:
        device = self.get_device(ip_address)
        if device:
            logger.info(f"Updating attributes for device {ip_address}.")
            device.update_attributes(attributes_dict)
            return True
        logger.warning(f"Attempted to update non-existent device: {ip_address}")
        return False

    def list_all_devices(self) -> list[Device]:
        logger.debug(f"Listing all {len(self._devices)} devices in inventory.")
        return list(self._devices.values())

    def __str__(self) -> str:
        return f"Inventory contains {len(self._devices)} device(s)."

    def save_to_json(self, filename: str):
        logger.info(f"Attempting to save inventory to {filename}...")
        inventory_data = {ip: device.to_dict() for ip, device in self._devices.items()}
        try:
            with open(filename, 'w') as f:
                json.dump(inventory_data, f, indent=4)
            logger.info(f"Inventory successfully saved to {filename} with {len(self._devices)} devices.")
        except IOError as e:
            logger.error(f"IOError saving inventory to {filename}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error saving inventory to {filename}: {e}", exc_info=True)


    def load_from_json(self, filename: str):
        logger.info(f"Attempting to load inventory from {filename}...")
        try:
            with open(filename, 'r') as f:
                inventory_data = json.load(f)
            
            self._devices.clear() # Clear current inventory
            loaded_count = 0
            for ip_address, device_data in inventory_data.items():
                # Ensure ip_address from key matches data, or prefer key from dict structure
                if 'ip_address' in device_data and device_data['ip_address'] != ip_address:
                    logger.warning(f"Mismatch in IP address for device in {filename}. Key '{ip_address}' vs data '{device_data['ip_address']}'. Using key.")
                
                # Make sure ip_address is part of device_data for from_dict
                device_data_for_creation = device_data.copy()
                device_data_for_creation['ip_address'] = ip_address # Ensure the key IP is used

                device = Device.from_dict(device_data_for_creation)
                if device:
                    self._devices[ip_address] = device
                    loaded_count += 1
                else:
                    logger.warning(f"Skipping device with IP {ip_address} from {filename} due to creation error (check previous logs).")

            logger.info(f"Inventory successfully loaded from {filename}. Added {loaded_count} devices out of {len(inventory_data)} entries.")
        except FileNotFoundError:
            logger.warning(f"Inventory file {filename} not found. Starting with an empty inventory.")
            self._devices.clear()
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from {filename}: {e}. Inventory remains unchanged or empty.", exc_info=True)
            self._devices.clear() # Ensure inventory is clean after bad load
        except Exception as e:
            logger.error(f"An unexpected error occurred loading inventory from {filename}: {e}. Inventory may be inconsistent.", exc_info=True)
            self._devices.clear()


if __name__ == '__main__':
    # Ensure logger is configured for direct script execution
    from nms.utils.logger import setup_logging # Adjust import if necessary
    # It's important to use force_setup=True if other modules also call setup_logging
    # and you want this specific configuration to take precedence for this test run.
    setup_logging(log_level=logging.DEBUG, force_setup=True)

    logger.info("--- Starting direct test for device.py ---")

    # Device Class Demonstration
    logger.info("--- Device Class Demo ---")
    try:
        device1 = Device("192.168.1.1", system_name="Router1", system_description="Main Office Router")
        logger.info(f"Device1 created:\n{device1}")
    except ValueError as e:
        logger.error(f"Error creating device: {e}")

    logger.info("Updating attributes for device1...")
    device1_updates = {
        "uptime": "365 days, 4 hours", "location": "Server Room A",
        "contact": "network-admin@example.com", "serial_number": "ABC123XYZ"
    }
    if 'device1' in locals(): device1.update_attributes(device1_updates)
    logger.info(f"Device1 updated:\n{device1}")

    # Inventory Class Demonstration
    logger.info("--- Inventory Class Demo ---")
    inventory = Inventory()
    logger.info(f"Initial inventory: {inventory}")

    try:
        inv_device1 = inventory.add_device("192.168.1.1", system_name="Router1", system_description="Main Office Router")
        inv_device2 = inventory.add_device("10.0.0.5", system_name="SwitchA", if_number=24)
        if inv_device1: logger.info(f"Added to inventory: {inv_device1.ip_address}")
        if inv_device2: logger.info(f"Added to inventory: {inv_device2.ip_address}")
    except ValueError as e:
        logger.error(f"Error adding device to inventory: {e}")
    logger.info(f"Inventory after additions: {inventory}")

    inventory.update_device_attributes("192.168.1.1", {"location": "Data Center West", "firmware_version": "v1.2.3"})
    
    # JSON Persistence
    inventory_file = "test_device_inventory.json"
    logger.info("--- JSON Persistence Demo ---")
    inventory.save_to_json(inventory_file)

    inventory2 = Inventory()
    inventory2.load_from_json(inventory_file)
    logger.info(f"Inventory2 (loaded from {inventory_file}): {inventory2}")
    for dev in inventory2.list_all_devices():
        logger.debug(f"Device in inv2: {dev.ip_address}")

    logger.info("Attempting to load a non-existent inventory file:")
    inventory3 = Inventory()
    inventory3.load_from_json("non_existent_inventory.json")
    logger.info(f"Inventory3 state: {inventory3}")

    logger.info("--- Direct test for device.py complete ---")
