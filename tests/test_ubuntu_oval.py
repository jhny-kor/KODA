import unittest
from unittest.mock import patch
from security_scanner.ubuntu_oval import evaluate_definition


def definition():
    return {'supported': True, 'platforms': ['Ubuntu 22.04 LTS'],
            'criteria': {'supported': True, 'operator': 'AND', 'tests': [{'id': 'test'}]},
            'tests': {'test': {'supported': True, 'package': 'demo', 'checkExistence': 'at_least_one_exists', 'stateOperator': 'AND',
                               'states': [{'supported': True, 'operation': 'less than', 'version': '1:2.0-0ubuntu1'}]}}}


class UbuntuOvalTests(unittest.TestCase):
    def test_exact_platform_inventory_and_local_comparison_only(self):
        component = {'purl': 'pkg:deb/ubuntu/demo@1%3A1.0-0ubuntu1?distro=ubuntu-22.04'}
        called = []
        def compare(left, operation, right):
            called.append((left, operation, right))
            return True
        result = evaluate_definition(definition(), [component], comparator=compare)
        self.assertEqual(result['status'], 'affected_review')
        self.assertEqual(called, [('1:1.0-0ubuntu1', 'less than', '1:2.0-0ubuntu1')])
        self.assertFalse(result['changesScannerVerdict'])

    def test_incomplete_inventory_unsupported_and_no_dpkg_stay_unknown(self):
        value = definition()
        self.assertEqual(evaluate_definition(value, [], platform='Ubuntu 22.04 LTS', comparator=lambda *args: False)['status'], 'unknown')
        value['supported'] = False
        self.assertEqual(evaluate_definition(value, [], platform='Ubuntu 22.04 LTS', comparator=lambda *args: False)['status'], 'unknown')
        with patch('shutil.which', return_value=None):
            self.assertEqual(evaluate_definition(definition(), [], platform='Ubuntu 22.04 LTS')['reason'], 'dpkg_unavailable')

    def test_different_distro_cannot_be_joined_by_package_name(self):
        result = evaluate_definition(definition(), [{'purl': 'pkg:deb/debian/demo@1.0?distro=debian-12'}], comparator=lambda *args: True)
        self.assertEqual(result['status'], 'unknown')
