import unittest
from unittest.mock import patch, MagicMock, call
from pysnmp.hlapi import ObjectType, ObjectIdentity
from pysnmp.smi.rfc1902 import OctetString, Integer32, ObjectIdentifier
from nms.nms.discovery.link_discovery import get_lldp_neighbors, OID_LLDP_REM_CHASSIS_ID_SUBTYPE, OID_LLDP_REM_CHASSIS_ID, \
                                         OID_LLDP_REM_PORT_ID_SUBTYPE, OID_LLDP_REM_PORT_ID, OID_LLDP_REM_PORT_DESC, \
                                         OID_LLDP_REM_SYS_NAME, LLDP_REM_ENTRY_OID
import logging

# Basic logging setup for tests if needed
# from nms.utils.logger import setup_logging
# setup_logging(log_level=logging.DEBUG)

class TestLinkDiscovery(unittest.TestCase):

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_lldp_neighbors_success_multiple_neighbors(self, mock_next_cmd):
        # Simulate two neighbors on different local ports
        # Neighbor 1: LocalPort 1, RemIndex 1
        # Neighbor 2: LocalPort 2, RemIndex 1
        mock_response_neighbor1 = [
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID_SUBTYPE + ".1.1.1"), Integer32(4))), # MAC
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID + ".1.1.1"), OctetString(b'\x11\x22\x33\x44\x55\x66'))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID_SUBTYPE + ".1.1.1"), Integer32(3))),    # MAC
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID + ".1.1.1"), OctetString(b'\xAA\xBB\xCC\xDD\xEE\xFF'))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_DESC + ".1.1.1"), OctetString("Port Eth0/1"))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_SYS_NAME + ".1.1.1"), OctetString("switch1.example.com"))),
        ]
        mock_response_neighbor2 = [
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID_SUBTYPE + ".1.2.1"), Integer32(4))), # MAC
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID + ".1.2.1"), OctetString(b'\x77\x88\x99\xAA\xBB\xCC'))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID_SUBTYPE + ".1.2.1"), Integer32(7))),    # Locally assigned
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID + ".1.2.1"), OctetString("GigabitEthernet0/0/1"))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_DESC + ".1.2.1"), OctetString("Uplink to Core"))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_SYS_NAME + ".1.2.1"), OctetString("core-router.example.com"))),
        ]
        # Simulate end of MIB or table
        mock_end_of_table_response = [
             # OIDs that are outside the LLDP_REM_ENTRY_OID range
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.1.0'), OctetString("Some other MIB data"))),
        ] * 6 # Must match length of var_binds_to_walk

        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_response_neighbor1),
            (None, 0, 0, mock_response_neighbor2),
            (None, 0, 0, mock_end_of_table_response), # To terminate the loop
        ])

        result = get_lldp_neighbors('192.0.2.1', 'public')
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)

        # Neighbor 1 checks
        neighbor1 = result[0]
        self.assertEqual(neighbor1['local_port_num'], 1) # from index .1.1.1 -> lldpRemLocalPortNum = 1
        self.assertEqual(neighbor1['remote_chassis_id'], '11:22:33:44:55:66')
        self.assertEqual(neighbor1['remote_port_id'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(neighbor1['remote_port_desc'], 'Port Eth0/1')
        self.assertEqual(neighbor1['remote_system_name'], 'switch1.example.com')
        self.assertEqual(neighbor1['protocol'], 'LLDP')

        # Neighbor 2 checks
        neighbor2 = result[1]
        self.assertEqual(neighbor2['local_port_num'], 2) # from index .1.2.1 -> lldpRemLocalPortNum = 2
        self.assertEqual(neighbor2['remote_chassis_id'], '77:88:99:AA:BB:CC')
        self.assertEqual(neighbor2['remote_port_id'], 'GigabitEthernet0/0/1') # Locally assigned, decoded
        self.assertEqual(neighbor2['remote_port_desc'], 'Uplink to Core')
        self.assertEqual(neighbor2['remote_system_name'], 'core-router.example.com')
        self.assertEqual(neighbor2['protocol'], 'LLDP')

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_lldp_neighbors_snmp_error_indication(self, mock_next_cmd):
        mock_error_indication = MagicMock()
        mock_error_indication.prettyPrint.return_value = "SNMP request timed out"
        mock_next_cmd.return_value = iter([
            (mock_error_indication, 0, 0, []) 
        ])
        result = get_lldp_neighbors('192.0.2.2', 'public')
        self.assertIsNone(result)

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_lldp_neighbors_snmp_error_status(self, mock_next_cmd):
        mock_error_status = MagicMock()
        mock_error_status.prettyPrint.return_value = "noSuchName"
        # Simulate error status on the first OID request in a row
        mock_response_with_error_status = [
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID_SUBTYPE + ".1.1.1"), Integer32(4))),
        ] * 6 # Full row of varbinds
        mock_next_cmd.return_value = iter([
            (None, mock_error_status, 1, mock_response_with_error_status) 
        ])
        result = get_lldp_neighbors('192.0.2.3', 'public')
        # Current implementation returns an empty list because it breaks from loop, then processes `neighbors` list
        self.assertEqual(result, []) # Or None, depending on how strictly we want to treat this

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_lldp_neighbors_no_neighbors(self, mock_next_cmd):
        # Simulate SNMP returning OIDs outside the LLDP table immediately, indicating an empty table or end of MIB
        mock_end_of_table_response = [
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.1.0'), OctetString("Some other MIB data"))),
        ] * 6
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_end_of_table_response)
        ])
        result = get_lldp_neighbors('192.0.2.4', 'public')
        self.assertEqual(result, [])

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_lldp_neighbors_malformed_index(self, mock_next_cmd):
        # Simulate a response where the OID index is not as expected (e.g., too few parts)
        mock_response_malformed_index = [
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID_SUBTYPE + ".1"), Integer32(4))), # Index ".1" is too short
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID + ".1"), OctetString(b'\x11\x22\x33\x44\x55\x66'))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID_SUBTYPE + ".1"), Integer32(3))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID + ".1"), OctetString(b'\xAA\xBB\xCC\xDD\xEE\xFF'))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_DESC + ".1"), OctetString("Port Eth0/1"))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_SYS_NAME + ".1"), OctetString("switch1.example.com"))),
        ]
        mock_end_of_table_response = [
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.1.0'), OctetString("Some other MIB data"))),
        ] * 6
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_response_malformed_index),
            (None, 0, 0, mock_end_of_table_response)
        ])
        result = get_lldp_neighbors('192.0.2.5', 'public')
        self.assertEqual(result, []) # Malformed entry should be skipped

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_lldp_rem_port_id_subtype_interface_name(self, mock_next_cmd):
        # Test lldpRemPortIdSubtype == 5 (interfaceName)
        mock_response = [
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID_SUBTYPE + ".1.3.1"), Integer32(4))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_CHASSIS_ID + ".1.3.1"), OctetString(b'\xDE\xAD\xBE\xEF\x00\x01'))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID_SUBTYPE + ".1.3.1"), Integer32(5))), # interfaceName
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID + ".1.3.1"), OctetString("GigabitEthernet1/0/1"))), # This is a DisplayString
            (ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_DESC + ".1.3.1"), OctetString("Desc for IntfName"))),
            (ObjectType(ObjectIdentity(OID_LLDP_REM_SYS_NAME + ".1.3.1"), OctetString("RemoteSysName"))),
        ]
        mock_end_of_table_response = [(ObjectType(ObjectIdentity('1.9.9.9'), OctetString("")))] * 6
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_response),
            (None, 0, 0, mock_end_of_table_response)
        ])
        result = get_lldp_neighbors('192.0.2.6', 'public')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['remote_port_id'], 'GigabitEthernet1/0/1') # Should be plain string

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_empty_table_graceful_exit(self, mock_next_cmd):
        # This test ensures that if the first call to nextCmd already returns OIDs outside the table,
        # the function exits gracefully with an empty list.
        # This happens when the table is empty on the device.
        mock_out_of_scope_response = [
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.0'), Integer32(1))), # Example OID after LLDP Rem Table
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.1'), OctetString(b'out of scope'))),
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.2'), Integer32(1))),
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.3'), OctetString(b'out of scope'))),
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.4'), OctetString("out of scope"))),
            (ObjectType(ObjectIdentity('1.0.8802.1.1.2.1.5.5'), OctetString("out of scope"))),
        ]
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_out_of_scope_response)
        ])
        result = get_lldp_neighbors('192.0.2.7', 'public')
        self.assertEqual(result, [])

# --- Tests for CDP ---

class TestCdpLinkDiscovery(unittest.TestCase):
    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_cdp_neighbors_success(self, mock_next_cmd):
        # Simulate one CDP neighbor
        # Index: local_ifindex=1, cdp_device_index=1 (arbitrary for test)
        mock_response_neighbor1 = [
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS_TYPE + ".1.1"), Integer32(1))), # IPv4
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS + ".1.1"), OctetString(b'\xC0\xA8\x01\x02'))), # 192.168.1.2
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_ID + ".1.1"), OctetString("neighbor_switch.example.com"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_PORT + ".1.1"), OctetString("GigabitEthernet0/1"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_PLATFORM + ".1.1"), OctetString("cisco WS-C2960-24TT-L"))),
        ]
         # Simulate end of MIB or table
        mock_end_of_table_response = [
            (ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.23.1.3.0'), OctetString("Some other MIB data"))), # OID outside cdpCacheEntry
        ] * 5 # Must match length of var_binds_to_walk in get_cdp_neighbors

        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_response_neighbor1),
            (None, 0, 0, mock_end_of_table_response),
        ])

        result = get_cdp_neighbors('192.0.2.100', 'cisco_comm')
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

        neighbor1 = result[0]
        self.assertEqual(neighbor1['local_ifindex'], 1)
        self.assertEqual(neighbor1['remote_device_ip'], '192.168.1.2')
        self.assertEqual(neighbor1['remote_device_id'], 'neighbor_switch.example.com')
        self.assertEqual(neighbor1['remote_interface'], 'GigabitEthernet0/1')
        self.assertEqual(neighbor1['remote_platform'], 'cisco WS-C2960-24TT-L')
        self.assertEqual(neighbor1['protocol'], 'CDP')

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_cdp_neighbors_snmp_error(self, mock_next_cmd):
        mock_error_indication = MagicMock()
        mock_error_indication.prettyPrint.return_value = "SNMP request timed out (CDP)"
        mock_next_cmd.return_value = iter([
            (mock_error_indication, 0, 0, [])
        ])
        result = get_cdp_neighbors('192.0.2.101', 'cisco_comm')
        self.assertIsNone(result)

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_cdp_neighbors_no_neighbors(self, mock_next_cmd):
        mock_end_of_table_response = [
            (ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.23.1.3.0'), OctetString("Some other MIB data"))),
        ] * 5
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_end_of_table_response)
        ])
        result = get_cdp_neighbors('192.0.2.102', 'cisco_comm')
        self.assertEqual(result, [])

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_cdp_neighbors_address_type_not_ipv4(self, mock_next_cmd):
        # Simulate a neighbor with a non-IPv4 address type (e.g., 2 for IPv6, or other)
        mock_response = [
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS_TYPE + ".2.1"), Integer32(20))), # type 20 (ipv6)
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS + ".2.1"), OctetString(b'\x20\x01\x0D\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'))), # IPv6 Address
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_ID + ".2.1"), OctetString("ipv6_neighbor"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_PORT + ".2.1"), OctetString("Eth0/0"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_PLATFORM + ".2.1"), OctetString("Cisco CSR1000V"))),
        ]
        mock_end_of_table_response = [(ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.23.1.3.0')))] * 5
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_response),
            (None, 0, 0, mock_end_of_table_response)
        ])
        result = get_cdp_neighbors('192.0.2.103', 'cisco_comm')
        self.assertEqual(len(result), 1)
        # Current _octet_string_to_ip only handles IPv4 explicitly or falls back to prettyPrint.
        self.assertEqual(result[0]['remote_device_ip'], '20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:01') # Default prettyPrint of OctetString for IPv6
    
    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_get_cdp_malformed_index(self, mock_next_cmd):
        # Simulate response with OID index not having enough parts
        mock_response_malformed = [
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS_TYPE + ".1"), Integer32(1))), # Index ".1" is too short
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS + ".1"), OctetString(b'\xC0\xA8\x01\x03'))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_ID + ".1"), OctetString("malformed_idx_neighbor"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_PORT + ".1"), OctetString("Eth0/2"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_PLATFORM + ".1"), OctetString("Cisco 2901"))),
        ]
        mock_end_of_table_response = [(ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.23.1.3.0')))] * 5
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_response_malformed),
            (None, 0, 0, mock_end_of_table_response)
        ])
        result = get_cdp_neighbors('192.0.2.104', 'cisco_comm')
        self.assertEqual(result, []) # Malformed entry should be skipped

    @patch('nms.nms.discovery.link_discovery.nextCmd')
    def test_cdp_ip_address_already_ipaddress_type(self, mock_next_cmd):
        # Test if cdpCacheAddress is returned as pysnmp.proto.rfc1902.IpAddress
        mock_response = [
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS_TYPE + ".3.1"), Integer32(1))), # IPv4
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_ADDRESS + ".3.1"), rfc1902.IpAddress('192.168.10.20'))), # Already IpAddress type
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_ID + ".3.1"), OctetString("typed_ip_neighbor"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_DEVICE_PORT + ".3.1"), OctetString("Fa0/1"))),
            (ObjectType(ObjectIdentity(OID_CDP_CACHE_PLATFORM + ".3.1"), OctetString("Cisco 881"))),
        ]
        mock_end_of_table_response = [(ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.23.1.3.0')))] * 5
        mock_next_cmd.return_value = iter([
            (None, 0, 0, mock_response),
            (None, 0, 0, mock_end_of_table_response)
        ])
        result = get_cdp_neighbors('192.0.2.105', 'cisco_comm')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['remote_device_ip'], '192.168.10.20')


if __name__ == '__main__':
    unittest.main()
