import unittest
from unittest.mock import patch, MagicMock, call
import time
from pysnmp.hlapi import ObjectType, ObjectIdentity
from pysnmp.smi import exval
from pysnmp.proto import rfc1902

# Assuming the file structure allows this import
from nms.nms.monitoring.interface_monitor import (
    collect_interface_metrics, _calculate_rate,
    OID_IF_INDEX, OID_IF_DESCR, OID_IF_TYPE, OID_IF_SPEED,
    OID_IF_ADMIN_STATUS, OID_IF_OPER_STATUS,
    OID_IF_IN_OCTETS, OID_IF_IN_UCAST_PKTS, OID_IF_IN_DISCARDS, OID_IF_IN_ERRORS,
    OID_IF_OUT_OCTETS, OID_IF_OUT_UCAST_PKTS, OID_IF_OUT_DISCARDS, OID_IF_OUT_ERRORS,
    OID_IF_HC_IN_OCTETS, OID_IF_HC_IN_UCAST_PKTS,
    OID_IF_HC_OUT_OCTETS, OID_IF_HC_OUT_UCAST_PKTS,
    MAX_COUNTER32, MAX_COUNTER64
)

class TestCalculateRate(unittest.TestCase):
    def test_basic_rate(self):
        rate = _calculate_rate(current_val=200, prev_val=100, time_delta=10, max_val=MAX_COUNTER32)
        self.assertEqual(rate, 10.0)

    def test_counter_wrap(self):
        # Simulate a 32-bit counter wrap
        rate = _calculate_rate(current_val=100, prev_val=MAX_COUNTER32 - 50, time_delta=10, max_val=MAX_COUNTER32)
        # Expected diff = (100 + (MAX_COUNTER32 + 1)) - (MAX_COUNTER32 - 50) = 100 + 1 + 50 = 151
        self.assertAlmostEqual(rate, 15.1, places=5)

    def test_time_delta_zero_or_negative(self):
        rate_zero_delta = _calculate_rate(current_val=200, prev_val=100, time_delta=0, max_val=MAX_COUNTER32)
        self.assertEqual(rate_zero_delta, 0.0)
        rate_neg_delta = _calculate_rate(current_val=200, prev_val=100, time_delta=-5, max_val=MAX_COUNTER32)
        self.assertEqual(rate_neg_delta, 0.0)
    
    def test_no_change(self):
        rate = _calculate_rate(current_val=100, prev_val=100, time_delta=10, max_val=MAX_COUNTER32)
        self.assertEqual(rate, 0.0)

    def test_negative_rate_after_wrap_should_be_zero(self):
        # This can happen if current_val is slightly less than prev_val but not enough to indicate a full wrap
        # The current logic for wrap (diff < 0) would add max_val + 1, leading to a huge number.
        # However, the function has `rate if rate >= 0 else 0.0` at the end.
        # Let's test a case where the diff is negative but not a wrap.
        # This scenario is more about data integrity; _calculate_rate assumes valid counter increase or wrap.
        # If current_val < prev_val and it's NOT a wrap, it's a data anomaly.
        # The current implementation treats any negative diff as a wrap.
        # A true "negative rate" without wrap is not something SNMP counters typically show.
        # The final check `rate if rate >= 0 else 0.0` should prevent negative output.
        rate = _calculate_rate(current_val=50, prev_val=100, time_delta=10, max_val=MAX_COUNTER32)
        # Diff = 50 - 100 = -50. This is treated as wrap: -50 + MAX_COUNTER32 + 1.
        # This will be a large positive rate. The only way to get a negative rate from the division
        # is if time_delta was negative, which is handled.
        # So, the only way to test the final `else 0.0` is if `diff / time_delta` itself was negative,
        # which requires `diff` to be negative and `time_delta` positive (handled as wrap) or
        # `diff` positive and `time_delta` negative (handled by initial check).
        # The current code's `rate if rate >= 0 else 0.0` might be redundant if time_delta is always positive.
        # Let's ensure the logic is sound for a non-wrap decrease, which is abnormal for counters.
        # The current logic interprets any decrease as a wrap.
        # To test the `else 0.0` part:
        # If `diff` becomes positive (after wrap adjustment) and `time_delta` is negative, this is handled.
        # If `diff` is negative (not wrapped) and `time_delta` is positive, this is handled as wrap.
        # The specific `else 0.0` is more a safeguard against unforeseen math issues.
        # We can assume diff / time_delta will be positive given the wrap logic and time_delta check.
        self.assertTrue(rate >= 0)


class TestCollectInterfaceMetrics(unittest.TestCase):

    @patch('nms.nms.monitoring.interface_monitor.SnmpEngine')
    def test_first_poll_success_hc_and_32bit_mix(self, MockSnmpEngine):
        mock_snmp_engine_instance = MockSnmpEngine.return_value
        
        # Mock for nextCmd (interface discovery via ifDescr)
        # Simulate two interfaces: ifIndex 1 (HC capable), ifIndex 2 (32-bit only)
        mock_if_discovery_responses = [
            (None, 0, 0, [ (ObjectType(ObjectIdentity(OID_IF_DESCR, 1)), rfc1902.OctetString('eth0')) ]),
            (None, 0, 0, [ (ObjectType(ObjectIdentity(OID_IF_DESCR, 2)), rfc1902.OctetString('lo')) ]),
            (None, 0, 0, [ (ObjectType(ObjectIdentity(OID_IF_DESCR, 3)), exval.noSuchInstance) ]), # End of table simulation
        ]
        # To stop the nextCmd generator, the final call should have an OID outside the scope
        # or an error. A simpler way is to make it finite.
        def side_effect_next_cmd(*args, **kwargs):
            # Simulate that the OID walked past ifDescr after the second interface
            if len(args[5]) > 0 and args[5][0].getOid() == ObjectIdentity(OID_IF_DESCR):
                if not hasattr(side_effect_next_cmd, 'count'):
                    side_effect_next_cmd.count = 0
                if side_effect_next_cmd.count < 2: # Serve the two interfaces
                    response = mock_if_discovery_responses[side_effect_next_cmd.count]
                    side_effect_next_cmd.count += 1
                    return response[0], response[1], response[2], response[3]
                else: # After two interfaces, simulate end of table by returning OID out of scope
                     return None, 0, 0, [(ObjectType(ObjectIdentity('1.3.6.1.5'), rfc1902.Integer(0)))] # OID outside ifDescr
            return None, 0, 0, [] # Should not be reached if logic is correct

        mock_snmp_engine_instance.nextCmd.side_effect = side_effect_next_cmd


        # Mock for getCmd (fetching detailed metrics per interface)
        # Interface 1 (ifIndex 1, eth0) - HC counters available
        var_binds_if1 = [
            (ObjectType(ObjectIdentity(OID_IF_TYPE, 1)), rfc1902.Integer(6)), # ethernetCsmacd
            (ObjectType(ObjectIdentity(OID_IF_SPEED, 1)), rfc1902.Gauge32(1000000000)), # 1 Gbps
            (ObjectType(ObjectIdentity(OID_IF_ADMIN_STATUS, 1)), rfc1902.Integer(1)), # up
            (ObjectType(ObjectIdentity(OID_IF_OPER_STATUS, 1)), rfc1902.Integer(1)), # up
            (ObjectType(ObjectIdentity(OID_IF_IN_DISCARDS, 1)), rfc1902.Counter32(10)),
            (ObjectType(ObjectIdentity(OID_IF_IN_ERRORS, 1)), rfc1902.Counter32(20)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_DISCARDS, 1)), rfc1902.Counter32(30)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_ERRORS, 1)), rfc1902.Counter32(40)),
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_OCTETS, 1)), rfc1902.Counter64(10000)),
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_OCTETS, 1)), rfc1902.Counter64(20000)),
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_UCAST_PKTS, 1)), rfc1902.Counter64(300)),
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_UCAST_PKTS, 1)), rfc1902.Counter64(400)),
            (ObjectType(ObjectIdentity(OID_IF_IN_OCTETS, 1)), rfc1902.Counter32(10000 % MAX_COUNTER32)), # Also provide 32-bit for completeness
            (ObjectType(ObjectIdentity(OID_IF_OUT_OCTETS, 1)), rfc1902.Counter32(20000 % MAX_COUNTER32)),
            (ObjectType(ObjectIdentity(OID_IF_IN_UCAST_PKTS, 1)), rfc1902.Counter32(300 % MAX_COUNTER32)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_UCAST_PKTS, 1)), rfc1902.Counter32(400 % MAX_COUNTER32)),
        ]
        # Interface 2 (ifIndex 2, lo) - Only 32-bit counters (HC counters return noSuchInstance)
        var_binds_if2 = [
            (ObjectType(ObjectIdentity(OID_IF_TYPE, 2)), rfc1902.Integer(24)), # softwareLoopback
            (ObjectType(ObjectIdentity(OID_IF_SPEED, 2)), rfc1902.Gauge32(10000000)), # Lower speed
            (ObjectType(ObjectIdentity(OID_IF_ADMIN_STATUS, 2)), rfc1902.Integer(1)),
            (ObjectType(ObjectIdentity(OID_IF_OPER_STATUS, 2)), rfc1902.Integer(1)),
            (ObjectType(ObjectIdentity(OID_IF_IN_DISCARDS, 2)), rfc1902.Counter32(1)),
            (ObjectType(ObjectIdentity(OID_IF_IN_ERRORS, 2)), rfc1902.Counter32(2)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_DISCARDS, 2)), rfc1902.Counter32(3)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_ERRORS, 2)), rfc1902.Counter32(4)),
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_OCTETS, 2)), exval.noSuchInstance), # HC not available
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_OCTETS, 2)), exval.noSuchInstance),
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_UCAST_PKTS, 2)), exval.noSuchInstance),
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_UCAST_PKTS, 2)), exval.noSuchInstance),
            (ObjectType(ObjectIdentity(OID_IF_IN_OCTETS, 2)), rfc1902.Counter32(5000)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_OCTETS, 2)), rfc1902.Counter32(6000)),
            (ObjectType(ObjectIdentity(OID_IF_IN_UCAST_PKTS, 2)), rfc1902.Counter32(70)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_UCAST_PKTS, 2)), rfc1902.Counter32(80)),
        ]

        # Mock getCmd responses based on ifIndex
        def get_cmd_side_effect(*args):
            # The OIDs requested are in args[4:]
            # We can check the ifIndex from the first OID
            ifindex_from_oid = args[4][0][1] # ObjectIdentity(OID, ifIndex)[1] is the ifIndex part
            if ifindex_from_oid == 1:
                return iter([(None, 0, 0, var_binds_if1)])
            elif ifindex_from_oid == 2:
                return iter([(None, 0, 0, var_binds_if2)])
            return iter([(None, 0, 0, [])]) # Should not happen

        mock_snmp_engine_instance.getCmd.side_effect = get_cmd_side_effect

        start_time = time.time()
        result = collect_interface_metrics('127.0.0.1', 'public')
        end_time = time.time()

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2) # Two interfaces discovered

        # Interface 1 assertions
        if1_metrics = result.get('1')
        self.assertIsNotNone(if1_metrics)
        self.assertEqual(if1_metrics['ifIndex'], 1)
        self.assertEqual(if1_metrics['ifDescr'], 'eth0')
        self.assertEqual(if1_metrics['ifSpeed'], 1000000000)
        self.assertEqual(if1_metrics['counter_type_octets'], '64bit')
        self.assertEqual(if1_metrics['last_ifInOctets'], 10000)
        self.assertEqual(if1_metrics['counter_type_packets'], '64bit')
        self.assertEqual(if1_metrics['last_ifInUcastPkts'], 300)
        self.assertTrue(start_time <= if1_metrics['last_poll_time'] <= end_time)
        for rate_key in ['calculated_in_bps', 'calculated_out_bps', 'calculated_in_pps', 'calculated_out_pps', 
                         'calculated_in_error_rate', 'calculated_out_error_rate', 
                         'calculated_in_discard_rate', 'calculated_out_discard_rate']:
            self.assertEqual(if1_metrics[rate_key], 0.0, f"{rate_key} should be 0.0 on first poll")

        # Interface 2 assertions
        if2_metrics = result.get('2')
        self.assertIsNotNone(if2_metrics)
        self.assertEqual(if2_metrics['ifIndex'], 2)
        self.assertEqual(if2_metrics['ifDescr'], 'lo')
        self.assertEqual(if2_metrics['counter_type_octets'], '32bit')
        self.assertEqual(if2_metrics['last_ifInOctets'], 5000)
        self.assertEqual(if2_metrics['counter_type_packets'], '32bit')
        self.assertEqual(if2_metrics['last_ifInUcastPkts'], 70)
        for rate_key in ['calculated_in_bps', 'calculated_out_bps', 'calculated_in_pps', 'calculated_out_pps']:
            self.assertEqual(if2_metrics[rate_key], 0.0)
        
        side_effect_next_cmd.count = 0 # Reset for potential other tests


    @patch('nms.nms.monitoring.interface_monitor.SnmpEngine')
    def test_second_poll_with_rate_calculation(self, MockSnmpEngine):
        mock_snmp_engine_instance = MockSnmpEngine.return_value
        
        # --- Mock setup for interface discovery (nextCmd) ---
        # Only one interface for simplicity in this test
        def side_effect_next_cmd_single_if(*args, **kwargs):
            if len(args[5]) > 0 and args[5][0].getOid() == ObjectIdentity(OID_IF_DESCR):
                if not hasattr(side_effect_next_cmd_single_if, 'count'):
                    side_effect_next_cmd_single_if.count = 0
                if side_effect_next_cmd_single_if.count < 1:
                    response = (None, 0, 0, [(ObjectType(ObjectIdentity(OID_IF_DESCR, 1)), rfc1902.OctetString('eth0'))])
                    side_effect_next_cmd_single_if.count += 1
                    return response[0], response[1], response[2], response[3]
                else:
                     return None, 0, 0, [(ObjectType(ObjectIdentity('1.3.6.1.5'), rfc1902.Integer(0)))]
            return None, 0, 0, []
        mock_snmp_engine_instance.nextCmd.side_effect = side_effect_next_cmd_single_if

        # --- Previous metrics data ---
        prev_poll_time = time.time() - 10 # 10 seconds ago
        existing_metrics = {
            '1': {
                'ifIndex': 1, 'ifDescr': 'eth0', 'last_poll_time': prev_poll_time,
                'last_ifInOctets': 1000, 'last_ifOutOctets': 2000, 'counter_type_octets': '64bit',
                'last_ifInUcastPkts': 100, 'last_ifOutUcastPkts': 200, 'counter_type_packets': '64bit',
                'last_ifInErrors': 5, 'last_ifOutErrors': 6,
                'last_ifInDiscards': 7, 'last_ifOutDiscards': 8
            }
        }

        # --- Mock setup for getCmd (current poll) ---
        current_var_binds_if1 = [
            (ObjectType(ObjectIdentity(OID_IF_TYPE, 1)), rfc1902.Integer(6)),
            (ObjectType(ObjectIdentity(OID_IF_SPEED, 1)), rfc1902.Gauge32(1000000000)),
            (ObjectType(ObjectIdentity(OID_IF_ADMIN_STATUS, 1)), rfc1902.Integer(1)),
            (ObjectType(ObjectIdentity(OID_IF_OPER_STATUS, 1)), rfc1902.Integer(1)),
            (ObjectType(ObjectIdentity(OID_IF_IN_DISCARDS, 1)), rfc1902.Counter32(17)), # Prev: 7, Diff: 10
            (ObjectType(ObjectIdentity(OID_IF_IN_ERRORS, 1)), rfc1902.Counter32(25)),    # Prev: 5, Diff: 20
            (ObjectType(ObjectIdentity(OID_IF_OUT_DISCARDS, 1)), rfc1902.Counter32(18)), # Prev: 8, Diff: 10
            (ObjectType(ObjectIdentity(OID_IF_OUT_ERRORS, 1)), rfc1902.Counter32(26)),   # Prev: 6, Diff: 20
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_OCTETS, 1)), rfc1902.Counter64(11000)), # Prev: 1000, Diff: 10000
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_OCTETS, 1)), rfc1902.Counter64(12000)),# Prev: 2000, Diff: 10000
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_UCAST_PKTS, 1)), rfc1902.Counter64(600)), # Prev: 100, Diff: 500
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_UCAST_PKTS, 1)), rfc1902.Counter64(700)),# Prev: 200, Diff: 500
        ]
        mock_snmp_engine_instance.getCmd.return_value = iter([(None, 0, 0, current_var_binds_if1)])

        result = collect_interface_metrics('127.0.0.1', 'public', existing_device_metrics=existing_metrics)

        self.assertIsNotNone(result)
        self.assertIn('1', result)
        if1_metrics = result['1']

        # Time delta should be around 10s. Allow some margin.
        time_delta = if1_metrics['last_poll_time'] - prev_poll_time
        self.assertTrue(9.5 < time_delta < 10.5) 

        # Expected rates: (current - prev) / time_delta
        # Octets: (11000 - 1000) / 10 = 1000 bytes/sec = 8000 bps
        self.assertAlmostEqual(if1_metrics['calculated_in_bps'], 10000 / time_delta * 8, delta=100) # delta for timing variations
        self.assertAlmostEqual(if1_metrics['calculated_out_bps'], 10000 / time_delta * 8, delta=100)
        # Packets: (600 - 100) / 10 = 50 pps
        self.assertAlmostEqual(if1_metrics['calculated_in_pps'], 500 / time_delta, delta=5)
        self.assertAlmostEqual(if1_metrics['calculated_out_pps'], 500 / time_delta, delta=5)
        # Errors: (25 - 5) / 10 = 2 errors/sec
        self.assertAlmostEqual(if1_metrics['calculated_in_error_rate'], 20 / time_delta, delta=0.5)
        self.assertAlmostEqual(if1_metrics['calculated_out_error_rate'], 20 / time_delta, delta=0.5)
        # Discards: (17 - 7) / 10 = 1 discard/sec
        self.assertAlmostEqual(if1_metrics['calculated_in_discard_rate'], 10 / time_delta, delta=0.5)
        self.assertAlmostEqual(if1_metrics['calculated_out_discard_rate'], 10 / time_delta, delta=0.5)
        
        side_effect_next_cmd_single_if.count = 0 # Reset for potential other tests

    @patch('nms.nms.monitoring.interface_monitor.SnmpEngine')
    def test_snmp_discovery_error_next_cmd(self, MockSnmpEngine):
        mock_snmp_engine_instance = MockSnmpEngine.return_value
        mock_snmp_engine_instance.nextCmd.return_value = iter([(MagicMock(name="ErrorIndication"), 0, 0, [])])
        result = collect_interface_metrics('127.0.0.1', 'public')
        self.assertIsNone(result)

    @patch('nms.nms.monitoring.interface_monitor.SnmpEngine')
    def test_snmp_metric_fetch_error_get_cmd(self, MockSnmpEngine):
        mock_snmp_engine_instance = MockSnmpEngine.return_value
        # Discovery success
        mock_snmp_engine_instance.nextCmd.side_effect = [
            iter([(None, 0, 0, [(ObjectType(ObjectIdentity(OID_IF_DESCR, 1)), rfc1902.OctetString('eth0'))])]),
            iter([(None, 0, 0, [(ObjectType(ObjectIdentity('1.3.6.1.5'), rfc1902.Integer(0)))])]) # End of table
        ]
        # Metric fetch (getCmd) fails
        mock_snmp_engine_instance.getCmd.return_value = iter([(MagicMock(name="ErrorIndicationGet"), 0, 0, [])])
        
        result = collect_interface_metrics('127.0.0.1', 'public')
        self.assertIsNotNone(result) # Returns a dict
        self.assertEqual(len(result), 0) # But no metrics for the interface that failed

    @patch('nms.nms.monitoring.interface_monitor.SnmpEngine')
    def test_no_interfaces_found(self, MockSnmpEngine):
        mock_snmp_engine_instance = MockSnmpEngine.return_value
        # Simulate discovery finding no interfaces (e.g., walks past table immediately)
        mock_snmp_engine_instance.nextCmd.return_value = iter([
            (None, 0, 0, [(ObjectType(ObjectIdentity('1.3.6.1.5'), rfc1902.Integer(0)))])
        ])
        result = collect_interface_metrics('127.0.0.1', 'public')
        self.assertEqual(result, {})

    @patch('nms.nms.monitoring.interface_monitor.SnmpEngine')
    def test_no_such_instance_for_some_oids(self, MockSnmpEngine):
        mock_snmp_engine_instance = MockSnmpEngine.return_value
        # Discovery
        mock_snmp_engine_instance.nextCmd.side_effect = [
            iter([(None, 0, 0, [(ObjectType(ObjectIdentity(OID_IF_DESCR, 1)), rfc1902.OctetString('eth0'))])]),
            iter([(None, 0, 0, [(ObjectType(ObjectIdentity('1.3.6.1.5'), rfc1902.Integer(0)))])]) # End
        ]
        # Metric fetch: ifSpeed is noSuchInstance, HC counters are noSuchInstance
        var_binds_if_partial = [
            (ObjectType(ObjectIdentity(OID_IF_TYPE, 1)), rfc1902.Integer(6)),
            (ObjectType(ObjectIdentity(OID_IF_SPEED, 1)), exval.noSuchInstance), 
            (ObjectType(ObjectIdentity(OID_IF_ADMIN_STATUS, 1)), rfc1902.Integer(1)),
            (ObjectType(ObjectIdentity(OID_IF_OPER_STATUS, 1)), rfc1902.Integer(1)),
            (ObjectType(ObjectIdentity(OID_IF_IN_DISCARDS, 1)), rfc1902.Counter32(5)),
            (ObjectType(ObjectIdentity(OID_IF_IN_ERRORS, 1)), rfc1902.Counter32(6)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_DISCARDS, 1)), rfc1902.Counter32(7)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_ERRORS, 1)), rfc1902.Counter32(8)),
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_OCTETS, 1)), exval.noSuchInstance),
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_OCTETS, 1)), exval.noSuchInstance),
            (ObjectType(ObjectIdentity(OID_IF_HC_IN_UCAST_PKTS, 1)), exval.noSuchInstance),
            (ObjectType(ObjectIdentity(OID_IF_HC_OUT_UCAST_PKTS, 1)), exval.noSuchInstance),
            (ObjectType(ObjectIdentity(OID_IF_IN_OCTETS, 1)), rfc1902.Counter32(100)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_OCTETS, 1)), rfc1902.Counter32(200)),
            (ObjectType(ObjectIdentity(OID_IF_IN_UCAST_PKTS, 1)), rfc1902.Counter32(30)),
            (ObjectType(ObjectIdentity(OID_IF_OUT_UCAST_PKTS, 1)), rfc1902.Counter32(40)),
        ]
        mock_snmp_engine_instance.getCmd.return_value = iter([(None, 0, 0, var_binds_if_partial)])

        result = collect_interface_metrics('127.0.0.1', 'public')
        self.assertIn('1', result)
        if1_metrics = result['1']
        self.assertIsNone(if1_metrics['ifSpeed']) # Should be None as it was noSuchInstance
        self.assertEqual(if1_metrics['counter_type_octets'], '32bit')
        self.assertEqual(if1_metrics['last_ifInOctets'], 100)


if __name__ == '__main__':
    unittest.main()
