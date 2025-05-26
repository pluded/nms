import unittest
import json
import os
from nms.inventory.device import Device, Inventory # Assumes /app/nms is in PYTHONPATH, nms is /app/nms/nms
from utils.logger import setup_logging # Assumes /app/nms is in PYTHONPATH, utils is /app/nms/utils
import logging

# It's good practice to set up logging for tests if the tested module uses logging.
# This helps in debugging test failures.
setup_logging(log_level=logging.DEBUG)

class TestDevice(unittest.TestCase):
    def test_device_initialization_basic(self):
        device = Device("192.168.1.1")
        self.assertEqual(device.ip_address, "192.168.1.1")
        self.assertIsNone(device.vendor)
        self.assertIsNone(device.model)
        self.assertIsNone(device.serial_number)
        self.assertIsNone(device.software_version)
        self.assertIsNone(device.mac_address)
        self.assertEqual(device.discovered_protocols, []) # Should default to empty list

    def test_device_initialization_with_new_attributes(self):
        attrs = {
            "vendor": "Cisco",
            "model": "Catalyst 9300",
            "serial_number": "SN12345",
            "software_version": "17.3.1",
            "mac_address": "00:11:22:33:44:55",
            "discovered_protocols": ["snmp", "ssh"],
            "system_name": "CoreSwitch"
        }
        device = Device("10.0.0.1", **attrs)
        self.assertEqual(device.ip_address, "10.0.0.1")
        self.assertEqual(device.vendor, "Cisco")
        self.assertEqual(device.model, "Catalyst 9300")
        self.assertEqual(device.serial_number, "SN12345")
        self.assertEqual(device.software_version, "17.3.1")
        self.assertEqual(device.mac_address, "00:11:22:33:44:55")
        self.assertEqual(device.discovered_protocols, ["snmp", "ssh"])
        self.assertEqual(device.system_name, "CoreSwitch")

    def test_device_initialization_discovered_protocols_none(self):
        # Test that if discovered_protocols is explicitly None, it becomes []
        device = Device("192.168.1.2", discovered_protocols=None)
        self.assertEqual(device.discovered_protocols, [])

    def test_to_dict_serialization(self):
        attrs = {
            "vendor": "Juniper",
            "model": "MX204",
            "serial_number": "JN67890",
            "software_version": "20.4R1",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "discovered_protocols": ["netconf"],
            "location": "DC1",
            "other_custom_field": "custom_value"
        }
        device = Device("10.1.1.1", **attrs)
        device_dict = device.to_dict()

        expected_dict = {
            "ip_address": "10.1.1.1",
            "system_description": None,
            "uptime": None,
            "system_name": None,
            "location": "DC1",
            "contact": None,
            "if_number": None,
            "vendor": "Juniper",
            "model": "MX204",
            "serial_number": "JN67890",
            "software_version": "20.4R1",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "discovered_protocols": ["netconf"],
            "other_attributes": {"other_custom_field": "custom_value"},
        }
        self.assertEqual(device_dict, expected_dict)

    def test_from_dict_deserialization(self):
        data = {
            "ip_address": "172.16.0.1",
            "vendor": "Arista",
            "model": "7050SX3",
            "serial_number": "AR112233",
            "software_version": "EOS-4.25.3M",
            "mac_address": "11:22:33:44:55:66",
            "discovered_protocols": ["lldp", "bgp"],
            "system_name": "Leaf1",
            "other_attributes": {"custom_info": "important"},
        }
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(device.ip_address, "172.16.0.1")
        self.assertEqual(device.vendor, "Arista")
        self.assertEqual(device.model, "7050SX3")
        self.assertEqual(device.serial_number, "AR112233")
        self.assertEqual(device.software_version, "EOS-4.25.3M")
        self.assertEqual(device.mac_address, "11:22:33:44:55:66")
        self.assertEqual(device.discovered_protocols, ["lldp", "bgp"])
        self.assertEqual(device.system_name, "Leaf1")
        self.assertEqual(device.other_attributes, {"custom_info": "important"})

    def test_from_dict_minimal(self):
        data = {"ip_address": "192.168.5.5"}
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(device.ip_address, "192.168.5.5")
        self.assertIsNone(device.vendor) # Ensure defaults
        self.assertEqual(device.discovered_protocols, [])

    def test_update_attributes(self):
        device = Device("10.2.2.2")
        updates = {
            "vendor": "Nokia",
            "model": "7750 SR",
            "serial_number": "NK445566",
            "software_version": "TiMOS 21.10.R1",
            "mac_address": "22:33:44:55:66:77",
            "discovered_protocols": ["ospf"],
            "location": "EdgeSite",
            "non_standard_attr": "test_value"
        }
        device.update_attributes(updates)
        self.assertEqual(device.vendor, "Nokia")
        self.assertEqual(device.model, "7750 SR")
        self.assertEqual(device.serial_number, "NK445566")
        self.assertEqual(device.software_version, "TiMOS 21.10.R1")
        self.assertEqual(device.mac_address, "22:33:44:55:66:77")
        self.assertEqual(device.discovered_protocols, ["ospf"])
        self.assertEqual(device.location, "EdgeSite")
        self.assertEqual(device.other_attributes["non_standard_attr"], "test_value")

    def test_str_representation(self):
        device = Device("10.3.3.3",
                        vendor="Cisco",
                        model="ASR1001-X",
                        serial_number="CSCO123",
                        software_version="XE 16.9.5",
                        mac_address="33:44:55:66:77:88",
                        discovered_protocols=["bgp", "mpls"],
                        system_name="BorderRouter")
        
        device_str = str(device)
        self.assertIn("IP Address: 10.3.3.3", device_str)
        self.assertIn("System Name: BorderRouter", device_str)
        self.assertIn("Vendor: Cisco", device_str)
        self.assertIn("Model: ASR1001-X", device_str)
        self.assertIn("Serial Number: CSCO123", device_str)
        self.assertIn("Software Version: XE 16.9.5", device_str)
        self.assertIn("MAC Address: 33:44:55:66:77:88", device_str)
        self.assertIn("Discovered Protocols: bgp, mpls", device_str)

    def test_str_representation_minimal(self):
        device = Device("10.4.4.4")
        device_str = str(device)
        self.assertIn("IP Address: 10.4.4.4", device_str)
        self.assertNotIn("Vendor:", device_str)
        self.assertNotIn("Discovered Protocols:", device_str)

class TestInventory(unittest.TestCase):
    def setUp(self):
        self.inventory = Inventory()
        self.test_json_file = "test_inventory_data.json"

    def tearDown(self):
        if os.path.exists(self.test_json_file):
            os.remove(self.test_json_file)

    def test_add_device_with_new_attributes(self):
        attrs = {
            "vendor": "Dell",
            "model": "PowerSwitch S5248F-ON",
            "serial_number": "DELL789",
            "software_version": "OS10",
            "mac_address": "44:55:66:77:88:99",
            "discovered_protocols": ["vltp", "lacp"],
            "system_name": "ToRSwitch1"
        }
        device = self.inventory.add_device("192.168.10.1", **attrs)
        self.assertIsNotNone(device)
        retrieved_device = self.inventory.get_device("192.168.10.1")
        self.assertIsNotNone(retrieved_device)
        self.assertEqual(retrieved_device.vendor, "Dell")
        self.assertEqual(retrieved_device.model, "PowerSwitch S5248F-ON")
        self.assertEqual(retrieved_device.serial_number, "DELL789")
        self.assertEqual(retrieved_device.software_version, "OS10")
        self.assertEqual(retrieved_device.mac_address, "44:55:66:77:88:99")
        self.assertEqual(retrieved_device.discovered_protocols, ["vltp", "lacp"])
        self.assertEqual(retrieved_device.system_name, "ToRSwitch1")

    def test_update_device_in_inventory_with_new_attributes(self):
        self.inventory.add_device("192.168.20.1", system_name="AccessPoint1")
        updates = {
            "vendor": "Ubiquiti",
            "model": "UniFi AP AC Pro",
            "serial_number": "UBI001",
            "software_version": "5.60.23",
            "mac_address": "55:66:77:88:99:AA",
            "discovered_protocols": ["wpa2", "snmp"],
            "location": "Office Wing A"
        }
        success = self.inventory.update_device_attributes("192.168.20.1", updates)
        self.assertTrue(success)
        updated_device = self.inventory.get_device("192.168.20.1")
        self.assertIsNotNone(updated_device)
        self.assertEqual(updated_device.vendor, "Ubiquiti")
        self.assertEqual(updated_device.model, "UniFi AP AC Pro")
        self.assertEqual(updated_device.serial_number, "UBI001")
        self.assertEqual(updated_device.software_version, "5.60.23")
        self.assertEqual(updated_device.mac_address, "55:66:77:88:99:AA")
        self.assertEqual(updated_device.discovered_protocols, ["wpa2", "snmp"])
        self.assertEqual(updated_device.location, "Office Wing A")
        self.assertEqual(updated_device.system_name, "AccessPoint1") # Ensure old attrs persist

    def test_save_and_load_json_with_new_attributes(self):
        dev1_attrs = {
            "vendor": "Cisco", "model": "ISR 4331", "serial_number": "CISCO001",
            "software_version": "16.6.4", "mac_address": "AA:AA:AA:AA:AA:AA",
            "discovered_protocols": ["eigrp", "hsrp"], "system_name": "BranchRouter1"
        }
        dev2_attrs = {
            "vendor": "Juniper", "model": "EX4300", "serial_number": "JUNIPER002",
            "software_version": "19.4R2", "mac_address": "BB:BB:BB:BB:BB:BB",
            "discovered_protocols": ["vstp", "lldp-med"], "system_name": "AccessSwitch2",
            "location": "Floor 2"
        }
        self.inventory.add_device("10.100.1.1", **dev1_attrs)
        self.inventory.add_device("10.100.2.1", **dev2_attrs)
        
        self.inventory.save_to_json(self.test_json_file)
        
        new_inventory = Inventory()
        new_inventory.load_from_json(self.test_json_file)
        
        self.assertEqual(len(new_inventory.list_all_devices()), 2)
        
        loaded_dev1 = new_inventory.get_device("10.100.1.1")
        self.assertIsNotNone(loaded_dev1)
        self.assertEqual(loaded_dev1.vendor, "Cisco")
        self.assertEqual(loaded_dev1.model, "ISR 4331")
        self.assertEqual(loaded_dev1.serial_number, "CISCO001")
        self.assertEqual(loaded_dev1.software_version, "16.6.4")
        self.assertEqual(loaded_dev1.mac_address, "AA:AA:AA:AA:AA:AA")
        self.assertEqual(loaded_dev1.discovered_protocols, ["eigrp", "hsrp"])
        self.assertEqual(loaded_dev1.system_name, "BranchRouter1")

        loaded_dev2 = new_inventory.get_device("10.100.2.1")
        self.assertIsNotNone(loaded_dev2)
        self.assertEqual(loaded_dev2.vendor, "Juniper")
        self.assertEqual(loaded_dev2.model, "EX4300")
        self.assertEqual(loaded_dev2.serial_number, "JUNIPER002")
        self.assertEqual(loaded_dev2.software_version, "19.4R2")
        self.assertEqual(loaded_dev2.mac_address, "BB:BB:BB:BB:BB:BB")
        self.assertEqual(loaded_dev2.discovered_protocols, ["vstp", "lldp-med"])
        self.assertEqual(loaded_dev2.system_name, "AccessSwitch2")
        self.assertEqual(loaded_dev2.location, "Floor 2")

    def test_load_json_device_with_missing_new_attributes(self):
        # Simulate loading a device entry that was saved before new attributes were added
        old_format_data = {
            "192.168.77.1": {
                "ip_address": "192.168.77.1",
                "system_name": "OldDevice",
                "location": "Archive"
                # New attributes like vendor, model, etc., are missing
            }
        }
        with open(self.test_json_file, 'w') as f:
            json.dump(old_format_data, f, indent=4)
        
        self.inventory.load_from_json(self.test_json_file)
        loaded_device = self.inventory.get_device("192.168.77.1")
        self.assertIsNotNone(loaded_device)
        self.assertEqual(loaded_device.system_name, "OldDevice")
        self.assertEqual(loaded_device.location, "Archive")
        # Check that new attributes have their default values
        self.assertIsNone(loaded_device.vendor)
        self.assertIsNone(loaded_device.model)
        self.assertIsNone(loaded_device.serial_number)
        self.assertIsNone(loaded_device.software_version)
        self.assertIsNone(loaded_device.mac_address)
        self.assertEqual(loaded_device.discovered_protocols, []) # Default empty list
        self.assertEqual(loaded_device.links, []) # Default empty list for links

    # --- Tests for Device 'links' attribute ---
    def test_device_initialization_with_links(self):
        link1 = {'local_port_identifier': 'Gig0/1', 'remote_device_id': 'SwitchA', 'remote_port_id': 'Eth0/5', 'protocol': 'CDP'}
        link2 = {'local_port_identifier': 'Gig0/2', 'remote_device_id': 'SwitchB', 'remote_port_id': 'Fa0/10', 'protocol': 'LLDP'}
        device = Device("192.168.1.1", links=[link1, link2])
        self.assertEqual(len(device.links), 2)
        self.assertIn(link1, device.links)
        self.assertIn(link2, device.links)

    def test_device_to_dict_with_links(self):
        link1 = {'local_port_identifier': 'Gig0/1', 'remote_device_id': 'SwitchA', 'protocol': 'CDP'}
        device = Device("192.168.1.1", links=[link1])
        device_dict = device.to_dict()
        self.assertIn('links', device_dict)
        self.assertEqual(len(device_dict['links']), 1)
        self.assertEqual(device_dict['links'][0], link1)

    def test_device_from_dict_with_links(self):
        link1 = {'local_port_identifier': 'Eth1', 'remote_device_id': 'RouterX', 'protocol': 'LLDP'}
        data = {"ip_address": "192.168.1.2", "links": [link1]}
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(len(device.links), 1)
        self.assertEqual(device.links[0], link1)

    def test_device_from_dict_links_is_none(self):
        data = {"ip_address": "192.168.1.3", "links": None} # Explicitly None
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(device.links, []) # Should default to empty list

    def test_device_from_dict_links_missing(self):
        data = {"ip_address": "192.168.1.4"} # links key missing
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(device.links, []) # Should default to empty list

    def test_device_update_attributes_links(self):
        device = Device("192.168.1.1")
        self.assertEqual(device.links, []) # Initial state
        
        link1 = {'local_port_identifier': 'Gig0/1', 'remote_device_id': 'SwitchA'}
        device.update_attributes({'links': [link1]})
        self.assertEqual(len(device.links), 1)
        self.assertEqual(device.links[0], link1)

        link2 = {'local_port_identifier': 'Gig0/2', 'remote_device_id': 'SwitchB'}
        # Test replacing links
        device.update_attributes({'links': [link2, link1]})
        self.assertEqual(len(device.links), 2)
        self.assertIn(link1, device.links)
        self.assertIn(link2, device.links)
        
        # Test setting links to empty list
        device.update_attributes({'links': []})
        self.assertEqual(device.links, [])

    def test_device_str_with_links(self):
        link1 = {'local_port_identifier': 'Gig0/1', 'remote_device_id': 'SwitchA', 'remote_port_id': 'Eth0/5', 'protocol': 'CDP'}
        link2 = {'local_port_identifier': 'Gig0/2', 'remote_device_id': 'SwitchB', 'remote_port_id': 'Fa0/10', 'protocol': 'LLDP'}
        device = Device("192.168.1.1", links=[link1, link2])
        device_str = str(device)
        self.assertIn("Links:", device_str)
        self.assertIn("Local: Gig0/1, Remote Dev: SwitchA, Remote Port: Eth0/5, Proto: CDP", device_str)
        self.assertIn("Local: Gig0/2, Remote Dev: SwitchB, Remote Port: Fa0/10, Proto: LLDP", device_str)

    def test_device_str_without_links(self):
        device = Device("192.168.1.1")
        device_str = str(device)
        self.assertNotIn("Links:", device_str)

    # --- Tests for Inventory with 'links' attribute ---
    def test_inventory_save_load_with_links(self):
        link_data = {'local_port_identifier': 'Eth0/0', 'remote_device_id': 'Neighbor1', 'protocol': 'CDP'}
        self.inventory.add_device("10.0.0.10", links=[link_data])
        self.inventory.add_device("10.0.0.11") # Device without links

        self.inventory.save_to_json(self.test_json_file)
        
        new_inventory = Inventory()
        new_inventory.load_from_json(self.test_json_file)

        dev1 = new_inventory.get_device("10.0.0.10")
        self.assertIsNotNone(dev1)
        self.assertEqual(len(dev1.links), 1)
        self.assertEqual(dev1.links[0], link_data)

        dev2 = new_inventory.get_device("10.0.0.11")
        self.assertIsNotNone(dev2)
        self.assertEqual(dev2.links, []) # Should be empty list by default
        self.assertEqual(dev2.routing_table, []) # Should be empty list by default for routing_table

    # --- Tests for Device 'routing_table' attribute ---
    def test_device_initialization_with_routing_table(self):
        route1 = {'destination': '0.0.0.0', 'mask': '0.0.0.0', 'next_hop': '192.168.1.1', 'protocol': 'local'}
        route2 = {'destination': '10.0.0.0', 'mask': '255.0.0.0', 'next_hop': '10.1.1.1', 'protocol': 'ospf'}
        device = Device("172.16.0.1", routing_table=[route1, route2])
        self.assertEqual(len(device.routing_table), 2)
        self.assertIn(route1, device.routing_table)
        self.assertIn(route2, device.routing_table)

    def test_device_to_dict_with_routing_table(self):
        route1 = {'destination': '192.168.2.0', 'mask': '255.255.255.0', 'next_hop': '10.0.0.1'}
        device = Device("172.16.0.2", routing_table=[route1])
        device_dict = device.to_dict()
        self.assertIn('routing_table', device_dict)
        self.assertEqual(len(device_dict['routing_table']), 1)
        self.assertEqual(device_dict['routing_table'][0], route1)

    def test_device_from_dict_with_routing_table(self):
        route1 = {'destination': '172.17.0.0', 'mask': '255.255.0.0', 'if_index': 3}
        data = {"ip_address": "172.16.0.3", "routing_table": [route1]}
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(len(device.routing_table), 1)
        self.assertEqual(device.routing_table[0], route1)

    def test_device_from_dict_routing_table_is_none(self):
        data = {"ip_address": "172.16.0.4", "routing_table": None}
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(device.routing_table, [])

    def test_device_from_dict_routing_table_missing(self):
        data = {"ip_address": "172.16.0.5"}
        device = Device.from_dict(data)
        self.assertIsNotNone(device)
        self.assertEqual(device.routing_table, [])

    def test_device_update_attributes_routing_table(self):
        device = Device("172.16.0.1")
        self.assertEqual(device.routing_table, [])
        
        route1 = {'destination': '0.0.0.0', 'mask': '0.0.0.0'}
        device.update_attributes({'routing_table': [route1]})
        self.assertEqual(len(device.routing_table), 1)
        self.assertEqual(device.routing_table[0], route1)

        route2 = {'destination': '10.0.0.0', 'mask': '255.0.0.0'}
        device.update_attributes({'routing_table': [route2, route1]})
        self.assertEqual(len(device.routing_table), 2)
        self.assertIn(route1, device.routing_table)
        self.assertIn(route2, device.routing_table)
        
        device.update_attributes({'routing_table': []}) # Clear routing table
        self.assertEqual(device.routing_table, [])

    def test_device_str_with_routing_table(self):
        route1 = {'destination': '0.0.0.0', 'mask': '0.0.0.0', 'next_hop': '192.168.1.1', 'protocol': 'local'}
        route2 = {'destination': '10.0.0.0', 'mask': '255.0.0.0', 'next_hop': '10.1.1.1', 'protocol': 'ospf'}
        route3 = {'destination': '172.16.0.0', 'mask': '255.240.0.0', 'next_hop': '172.16.0.254', 'protocol': 'bgp'}
        device = Device("172.16.0.1", routing_table=[route1, route2, route3])
        device_str = str(device)
        self.assertIn("Routing Table Entries: 3", device_str)
        self.assertIn("Dest: 0.0.0.0/0.0.0.0, NextHop: 192.168.1.1, Proto: local", device_str)
        self.assertIn("Dest: 10.0.0.0/255.0.0.0, NextHop: 10.1.1.1, Proto: ospf", device_str)
        self.assertIn("... and more.", device_str) # Since we display first 2 and there are 3

    def test_device_str_with_one_route_in_routing_table(self):
        route1 = {'destination': '0.0.0.0', 'mask': '0.0.0.0', 'next_hop': '192.168.1.1', 'protocol': 'local'}
        device = Device("172.16.0.1", routing_table=[route1])
        device_str = str(device)
        self.assertIn("Routing Table Entries: 1", device_str)
        self.assertIn("Dest: 0.0.0.0/0.0.0.0, NextHop: 192.168.1.1, Proto: local", device_str)
        self.assertNotIn("... and more.", device_str)

    def test_device_str_without_routing_table(self):
        device = Device("172.16.0.1")
        device_str = str(device)
        self.assertNotIn("Routing Table Entries:", device_str)

    # --- Tests for Inventory with 'routing_table' attribute ---
    def test_inventory_save_load_with_routing_table(self):
        route_data = {'destination': '192.168.5.0', 'mask': '255.255.255.0', 'protocol': 'static'}
        self.inventory.add_device("10.0.1.10", routing_table=[route_data])
        self.inventory.add_device("10.0.1.11") # Device without routing table

        self.inventory.save_to_json(self.test_json_file)
        
        new_inventory = Inventory()
        new_inventory.load_from_json(self.test_json_file)

        dev1 = new_inventory.get_device("10.0.1.10")
        self.assertIsNotNone(dev1)
        self.assertEqual(len(dev1.routing_table), 1)
        self.assertEqual(dev1.routing_table[0], route_data)

        dev2 = new_inventory.get_device("10.0.1.11")
        self.assertIsNotNone(dev2)
        self.assertEqual(dev2.routing_table, [])


if __name__ == '__main__':
    unittest.main()
