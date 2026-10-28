"""LIVE MAP model tests: presentation must not silently invent physical links."""
import math
import unittest
from bloodsky_net.map_view import select_devices, ring_positions, lldp_edges
from bloodsky_net.network import Device
from bloodsky_net.topology import Neighbor, TopologySnapshot


class LiveMapViewTests(unittest.TestCase):
    def setUp(self):
        self.devices = [
            Device('192.168.5.20', hostname='camera', online=False, mac='AA:BB:CC:00:00:20'),
            Device('192.168.5.2', hostname='Switch-2', vendor='Vendor Example', online=True),
            Device('192.168.5.10', hostname='printer', online=True),
        ]

    def test_ip_sort_and_cap(self):
        view = select_devices(self.devices, limit=2)
        self.assertEqual([d.ip for d in view.devices], ['192.168.5.2', '192.168.5.10'])
        self.assertEqual(view.total_matched, 3)
        self.assertEqual(view.omitted, 1)

    def test_case_insensitive_search_across_fields(self):
        self.assertEqual(select_devices(self.devices, 'switch').devices[0].ip, '192.168.5.2')
        self.assertEqual(select_devices(self.devices, 'VENDOR').devices[0].ip, '192.168.5.2')
        self.assertEqual(select_devices(self.devices, 'cc:00:00:20').devices[0].ip, '192.168.5.20')
        self.assertEqual(select_devices(self.devices, '5.10').devices[0].ip, '192.168.5.10')

    def test_offline_filter_not_falsely_online(self):
        self.assertEqual([x.ip for x in select_devices(self.devices, status='Нет связи').devices], ['192.168.5.20'])
        self.assertEqual(len(select_devices(self.devices, status='В сети').devices), 2)
        self.assertFalse(self.devices[0].online is True)

    def test_ip_alert_filter_is_only_existing_suspicions(self):
        view = select_devices(self.devices, status='IP-подозрение', alert_ips={'192.168.5.10', '8.8.8.8'})
        self.assertEqual([d.ip for d in view.devices], ['192.168.5.10'])

    def test_unknown_filter_and_bad_limit(self):
        for options in ({'status':'broken'}, {'limit':0}, {'limit':1001}):
            with self.assertRaises(ValueError):
                select_devices(self.devices, **options)

    def test_stable_layout_and_bounded_zoom(self):
        p1 = ring_positions(self.devices)
        self.assertEqual(p1, ring_positions(self.devices))
        p2 = ring_positions(self.devices, 1.5)
        self.assertAlmostEqual(p2[0][2], p1[0][2]*1.5)
        for value in (0.3, 2.1, float('nan')):
            with self.assertRaises(ValueError):
                ring_positions(self.devices, value)

    def test_no_fabricated_llpd_links(self):
        snap = TopologySnapshot('192.168.5.2', neighbors=[Neighbor('192.168.5.2', 1, 'Gi1', remote_name='camera')])
        # With a resolved remote name, edge is a reported LLDP adjacency.
        self.assertEqual(len(lldp_edges({'192.168.5.2':snap}, self.devices)), 1)
        # Filtered out endpoint: never draw a link to an invisible/unknown node.
        self.assertEqual(lldp_edges({'192.168.5.2':snap}, self.devices[1:]), [])
        self.assertEqual(lldp_edges({}, self.devices), [])


if __name__ == '__main__':
    unittest.main()
