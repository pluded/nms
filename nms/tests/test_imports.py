import unittest

class TestBasicImports(unittest.TestCase):

    def test_cli_module_importable(self):
        try:
            # Assumes tests are run from the project root (outer 'nms') directory
            # or that PYTHONPATH is set up so 'nms.cli' can be found.
            # For `python -m unittest discover nms.tests` from root, this should work.
            from nms import cli
            self.assertTrue(True, "Successfully imported nms.cli")
        except ImportError as e:
            self.fail(f"Failed to import nms.cli: {e}")

    def test_snmp_collector_importable(self):
        try:
            # This tests that snmp_collector.py and its own imports (including pysnmp)
            # are resolved correctly.
            from nms.nms.monitoring import snmp_collector
            self.assertTrue(True, "Successfully imported nms.nms.monitoring.snmp_collector")
        except ImportError as e:
            self.fail(f"Failed to import nms.nms.monitoring.snmp_collector: {e}")

if __name__ == '__main__':
    unittest.main()
