"""Regression tests for passive DHCP inspection and local port history."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from bloodsky_net import dhcp
from bloodsky_net.storage import Storage
from bloodsky_net.traffic import PortRate


class DHCPTests(unittest.TestCase):
    sample = {'Description': 'Intel Ethernet', 'IPAddress': ['192.168.10.45', 'fe80::2'],
              'DHCPEnabled': True, 'DHCPServer': '192.168.10.1',
              'DHCPLeaseObtained': '2026-10-28', 'DHCPLeaseExpires': '2026-10-29'}

    def test_single_adapter(self):
        adapters = dhcp.parse_dhcp_json(json.dumps(self.sample))
        self.assertEqual(len(adapters), 1)
        self.assertEqual(adapters[0].addresses, ('192.168.10.45',))
        self.assertEqual(adapters[0].server, '192.168.10.1')
        self.assertIn('НЕ доказывают IP-конфликт', dhcp.format_dhcp_report(adapters))

    def test_multiple_adapters_and_static_ip(self):
        row = {'Description': 'Wi-Fi', 'IPAddress': ['10.0.0.5'], 'DHCPEnabled': False}
        report = dhcp.format_dhcp_report(dhcp.parse_dhcp_json(json.dumps([self.sample, row])))
        self.assertIn('10.0.0.5', report)
        self.assertIn('статический адрес', report)
        self.assertEqual(report.count('Адаптер:'), 2)

    def test_empty_invalid_ip_does_not_crash(self):
        self.assertEqual(dhcp.parse_dhcp_json('[{"IPAddress":["not-an-ip", "ff::1"]}]'), [])
        self.assertEqual(dhcp.parse_dhcp_json('null'), [])

    def test_read_is_windows_only_without_calling_commands(self):
        runner = Mock()
        code, text = dhcp.read_dhcp_configuration(runner, windows=False)
        self.assertNotEqual(code, 0)
        self.assertIn('Windows', text)
        runner.assert_not_called()

    def test_read_success_uses_fixed_command_and_no_dhcp_traffic(self):
        runner = Mock(return_value=(0, json.dumps(self.sample)))
        code, report = dhcp.read_dhcp_configuration(runner, windows=True)
        self.assertEqual(code, 0)
        self.assertIn('Intel Ethernet', report)
        args = runner.call_args.args[0]
        self.assertEqual(args[0], 'powershell.exe')
        self.assertIn('Get-CimInstance', args[4])
        self.assertNotIn('Invoke-WebRequest', args[4])
        self.assertNotIn('Send', args[4])

    def test_failed_or_malformed_windows_response(self):
        self.assertNotEqual(dhcp.read_dhcp_configuration(lambda *a, **k: (1, 'secret'), windows=True)[0], 0)
        self.assertNotEqual(dhcp.read_dhcp_configuration(lambda *a, **k: (0, 'not json'), windows=True)[0], 0)


class PortHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Storage(Path(self.tmp.name) / 'metrics.db')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def sample(self, incoming=1.5, outgoing=2.5):
        return {7: PortRate(7, 'Gi1/0/7', incoming, outgoing, 1000, True)}

    def test_round_trip_order_and_numeric_measurements(self):
        self.assertEqual(self.db.save_port_rates('192.168.1.2', self.sample(), '2026-10-27T08:00:00+00:00'), 1)
        self.db.save_port_rates('192.168.1.2', self.sample(3, 4), '2026-10-27T08:01:00+00:00')
        self.assertEqual(self.db.port_history('192.168.1.2', 7), [
            ('2026-10-27T08:00:00+00:00', 1.5, 2.5),
            ('2026-10-27T08:01:00+00:00', 3.0, 4.0)])

    def test_missing_zero_and_reset_are_not_equivalent(self):
        self.assertEqual(self.db.save_port_rates('10.0.0.3', self.sample(None, None)), 0)
        self.assertEqual(self.db.port_history('10.0.0.3', 7), [])
        self.assertEqual(self.db.save_port_rates('10.0.0.3', self.sample(0, 0)), 1)
        self.assertEqual(self.db.port_history('10.0.0.3', 7)[0][1:], (0, 0))

    def test_reject_bad_values_and_external_address(self):
        for v in [float('nan'), float('inf'), -1, 1e9]:
            self.assertEqual(self.db.save_port_rates('10.0.0.2', self.sample(v, 1)), 0)
        self.assertEqual(self.db.save_port_rates('8.8.8.8', self.sample()), 0)
        self.assertEqual(self.db.save_port_rates('invalid', self.sample()), 0)

    def test_bounded_history_returns_latest_samples(self):
        for n in range(5):
            self.db.save_port_rates('192.168.1.3', self.sample(n, n))
        self.assertEqual([row[1] for row in self.db.port_history('192.168.1.3', 7, limit=2)], [3, 4])
        self.assertEqual(self.db.port_history('192.168.1.3', 8), [])

    def test_no_plaintext_secret_columns(self):
        cols = [x[1] for x in self.db.db.execute('PRAGMA table_info(port_traffic)')]
        self.assertFalse(any('secret' in name or 'password' in name or 'community' in name for name in cols))

    def test_retention_old_rows_expire_on_tenth_poll(self):
        for _ in range(10):
            self.db.save_port_rates('192.168.1.4', self.sample(), ts='2024-01-01T00:00:00+00:00')
        self.assertEqual(self.db.port_history('192.168.1.4', 7), [])


if __name__ == '__main__':
    unittest.main()
