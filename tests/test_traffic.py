import unittest
from unittest.mock import patch

from bloodsky_net import traffic, notifications


class PortTrafficTests(unittest.TestCase):
    def fixture(self):
        return {
            f'{traffic.IF_HC_IN}.4': '10000000', f'{traffic.IF_HC_OUT}.4': '9000000',
            f'{traffic.IF_NAME}.4': 'GigabitEthernet1/0/4',
            f'{traffic.IF_HIGH_SPEED}.4': '1000', f'{traffic.IF_OPER_STATUS}.4': '1',
            f'{traffic.IF_HC_IN}.5': '44', f'{traffic.IF_HC_OUT}.5': '55',
            f'{traffic.IF_OPER_STATUS}.5': '2',
        }

    def test_counters_and_port_names(self):
        result = traffic.parse_port_counters(self.fixture())
        self.assertEqual(result[4].name, 'GigabitEthernet1/0/4')
        self.assertEqual(result[4].speed_mbps, 1000)
        self.assertFalse(result[5].oper_up)

    def test_rates_measure_deltas_not_totals(self):
        before = traffic.parse_port_counters(self.fixture())
        values = self.fixture()
        values[f'{traffic.IF_HC_IN}.4'] = '16000000'
        values[f'{traffic.IF_HC_OUT}.4'] = '12000000'
        after = traffic.parse_port_counters(values)
        result = traffic.calculate_port_rates(before, after, 30)
        self.assertEqual(result[4].inbound_mbps, 1.6)
        self.assertEqual(result[4].outbound_mbps, 0.8)
        self.assertIsNone(result[5].inbound_mbps)

    def test_counter_reset_is_unknown_not_zero(self):
        before = traffic.parse_port_counters(self.fixture())
        values = self.fixture()
        values[f'{traffic.IF_HC_IN}.4'] = '20'
        after = traffic.parse_port_counters(values)
        self.assertIsNone(traffic.calculate_port_rates(before, after, 60)[4].inbound_mbps)

    def test_no_rates_on_missing_or_stale_samples(self):
        before = traffic.parse_port_counters(self.fixture())
        self.assertEqual(traffic.calculate_port_rates(before, before, 0), {})
        self.assertEqual(traffic.calculate_port_rates(before, before, 3601), {})
        self.assertEqual(traffic.calculate_port_rates({}, before, 30), {})

    def test_discard_invalid_and_32bit_only_counters(self):
        values = self.fixture()
        values[f'{traffic.IF_HC_IN}.4'] = '-100'
        values[f'{traffic.IF_HC_IN}.6'] = '30'
        values[f'{traffic.IF_HC_OUT}.6'] = str(2**64)
        self.assertEqual(set(traffic.parse_port_counters(values)), {5})

    def test_maximum_bounded_results(self):
        self.assertEqual(len(traffic.parse_port_counters(self.fixture(), limit=1)), 1)
        self.assertEqual(traffic.parse_port_counters(self.fixture(), limit=0), {})

    def test_notifier_is_silent_off_windows(self):
        with patch.object(notifications.os, 'name', 'posix'):
            self.assertFalse(notifications.send_windows_alert('x', 'y'))


if __name__ == '__main__':
    unittest.main()
