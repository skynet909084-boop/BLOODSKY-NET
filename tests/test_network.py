import ipaddress
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from bloodsky_net import network as n
from bloodsky_net.storage import Storage


class NetworkTests(unittest.TestCase):
    def test_arp_localized(self):
        raw = '''
Interface: 192.168.0.10 --- 0x12
  Internet Address      Physical Address      Type
  192.168.0.1           10-20-30-40-50-60     dynamic
  192.168.0.50          aA-bB-cC-dD-eE-fF     static
  224.0.0.22            01-00-5e-00-00-16     static
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
'''
        self.assertEqual(n.parse_arp(raw), {'192.168.0.1': '10:20:30:40:50:60',
                                            '192.168.0.50': 'AA:BB:CC:DD:EE:FF'})

    def test_ping_latency(self):
        self.assertEqual(n.parse_ping_latency('Reply from host: bytes=32 time<1ms TTL=128'), 1)
        self.assertEqual(n.parse_ping_latency('Ответ от 192.168.0.1: число байт=32 время=13мс TTL=64'), 13)
        self.assertEqual(n.parse_ping_latency('Reply: time=5.6ms'), 5.6)
        self.assertIsNone(n.parse_ping_latency('Request timed out'))

    def test_network_restrictions(self):
        adapters = [n.Adapter('eth', '192.168.10.40', '255.255.0.0', '192.168.0.0/16')]
        self.assertEqual(str(n.validate_scan_cidr('192.168.10.10/24', adapters)), '192.168.10.0/24')
        for invalid in ('8.8.8.0/24', '192.168.0.0/16', '10.0.0.0/24', '2001:db8::/64', 'oops'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                n.validate_scan_cidr(invalid, adapters)

    def test_suggested_limited_network(self):
        adapters = [n.Adapter('WLAN', '10.7.14.28', '255.255.0.0', '10.7.0.0/16')]
        self.assertEqual(n.suggested_network(adapters), '10.7.14.0/24')

    def test_mac_change_is_suspicion_only(self):
        history = n.MacHistory()
        self.assertEqual(history.ingest({'10.0.0.1': '11-22-33-44-55-66'}, 100), [])
        self.assertEqual(history.ingest({'10.0.0.1': '11:22:33:44:55:66'}, 105), [])
        changes = history.ingest({'10.0.0.1': '66:55:44:33:22:11'}, 110)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].ip, '10.0.0.1')
        self.assertEqual(history.ingest({'10.0.0.1': '66:55:44:33:22:11'}, 112), [])

    @patch.object(n, 'arp_table')
    @patch.object(n, 'ping_once')
    @patch.object(n, 'probe_ports')
    @patch.object(n, 'friendly_hostname', return_value='camera-hall')
    def test_discovery(self, name, ports, ping, arp):
        arp.side_effect = [
            {'192.168.3.1': '00:11:22:33:44:55'},
            {'192.168.3.1': '00:11:22:33:44:55', '192.168.3.2': 'AA:BB:CC:DD:EE:FF'}]
        ping.side_effect = lambda ip: n.PingResult(ip == '192.168.3.1', 2.3 if ip == '192.168.3.1' else None)
        ports.side_effect = lambda ip, ports, timeout=0.14: [554] if ip == '192.168.3.1' else []
        found, neighbors, count = n.scan_network('192.168.3.0/30', '192.168.3.1', threading.Event())
        self.assertEqual(count, 2)
        self.assertEqual(len(found), 2)
        self.assertEqual(next(d for d in found if d.ip == '192.168.3.1').kind, 'Маршрутизатор')
        self.assertFalse(next(d for d in found if d.ip == '192.168.3.2').online)
        self.assertEqual(neighbors['192.168.3.2'], 'AA:BB:CC:DD:EE:FF')

    @patch.object(n, 'ping_once', return_value=n.PingResult(False, None))
    @patch.object(n, 'probe_ports', return_value=[80])
    def test_monitor_tcp_fallback(self, ports, ping):
        self.assertTrue(n.poll_devices(['192.168.1.10'], threading.Event(), {'192.168.1.10': [80]})['192.168.1.10'].alive)

    def test_local_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = Storage(Path(tmp) / 'state.db')
            dev = n.Device('192.168.5.10', online=True, hostname='lab-pc')
            s.save_device(dev)
            self.assertFalse(s.load_devices()['192.168.5.10'].online)
            s.event('info', 'Тест', 'Описание')
            self.assertEqual(s.events()[0][2], 'Тест')
            csvpath = Path(tmp) / 'devices.csv'
            s.export_csv(str(csvpath), [dev])
            self.assertIn('lab-pc', csvpath.read_text(encoding='utf-8-sig'))
            jsonpath = Path(tmp) / 'devices.json'
            s.export_json(str(jsonpath), [dev], '192.168.5.0/24', '192.168.5.1', {})
            self.assertIn('192.168.5.10', jsonpath.read_text(encoding='utf-8'))
            s.close()

    def test_target_no_injection(self):
        for target in ('-n', '8.8.8.8 && whoami', '192.168.0.1;dir', 'a b', '../etc'):
            with self.assertRaises(ValueError):
                n.valid_target(target)
        self.assertEqual(n.valid_target('gateway.local'), 'gateway.local')


if __name__ == '__main__':
    unittest.main()
