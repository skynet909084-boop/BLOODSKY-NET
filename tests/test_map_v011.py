"""LIVE MAP grouped view, evidence, positions and SQLite upgrade tests."""
import math
from pathlib import Path
import tempfile
import unittest

from bloodsky_net.fdb import FDBEntry
from bloodsky_net.map_view import (GROUP_OPTIONS, group_centers, layout_positions,
                                   learned_ports, passport, valid_position)
from bloodsky_net.network import Device
from bloodsky_net.storage import Storage
from bloodsky_net.topology import Neighbor, TopologySnapshot


class MapDetailTests(unittest.TestCase):
    def setUp(self):
        self.devices = [
            Device('192.168.1.12', mac='AA:BB:CC:11:22:33', hostname='cam', kind='Камера', online=True),
            Device('192.168.2.20', mac='AA:BB:CC:11:22:34', hostname='uplink', kind='Коммутатор', online=False),
            Device('192.168.1.2', mac='AA:BB:CC:11:22:35', kind='Камера', online=True),
        ]

    def test_grouping_is_deterministic_independent_of_scan_order(self):
        for group in GROUP_OPTIONS:
            first = {d.ip: (x, y) for d, x, y in layout_positions(self.devices, group_by=group)}
            second = {d.ip: (x, y) for d, x, y in layout_positions(list(reversed(self.devices)), group_by=group)}
            self.assertEqual(first, second)
            self.assertEqual(len(first), 3)

    def test_grouping_clusters_without_fabricating_edges(self):
        by_group = layout_positions(self.devices, group_by='Подсеть /24')
        headings = group_centers(by_group, 'Подсеть /24')
        self.assertEqual(set(headings), {'192.168.1.0/24', '192.168.2.0/24'})
        self.assertEqual(group_centers(by_group, 'Без групп'), {})
        self.assertNotEqual({d.ip: (x, y) for d,x,y in by_group},
                            {d.ip: (x, y) for d,x,y in layout_positions(self.devices)})

    def test_manual_position_persists_under_zoom_and_filters(self):
        manual = {'192.168.1.12': (140.0, -220.0)}
        for group in GROUP_OPTIONS:
            result = layout_positions(self.devices, 1.5, group, manual)
            self.assertEqual(next((x,y) for d,x,y in result if d.ip == '192.168.1.12'), (210., -330.))
        self.assertFalse(valid_position(float('nan'), 10))
        self.assertFalse(valid_position(5000, 0))
        self.assertFalse(valid_position('10', 0))
        with self.assertRaises(ValueError):
            layout_positions(self.devices, group_by='VLAN')

    def test_mac_only_matches_unique_device_and_no_direct_cable_claim(self):
        entries = [FDBEntry('AA:BB:CC:11:22:33', 12, 12, 'Gi0/12', 30),
                   FDBEntry('AA:BB:CC:11:22:33', 9, 9, 'Gi0/9', None)]
        snaps = {'192.168.1.254': TopologySnapshot('192.168.1.254', fdb_entries=entries)}
        matches = learned_ports(snaps, self.devices)
        self.assertEqual(len(matches['192.168.1.12']), 2)
        self.assertEqual({r.vlan for r in matches['192.168.1.12']}, {30, None})
        label = passport(self.devices[0], matches['192.168.1.12'])
        self.assertIn('НЕ кабель', label)
        self.assertIn('VLAN 30', label)
        self.assertIn('VLAN ?', label)
        # Duplicate discovered MAC is ambiguous: do not assign FDB to either IP.
        twins = self.devices + [Device('192.168.1.100', mac='AA:BB:CC:11:22:33')]
        self.assertEqual(learned_ports(snaps, twins), {})

    def test_unknown_fdb_remains_unknown_and_lldp_is_labelled(self):
        dev = self.devices[1]
        txt = passport(dev, links=[Neighbor('192.168.1.2',1,'Gi1',remote_port='Gi2')])
        self.assertIn('Не отвечает', txt)
        self.assertIn('LLDP', txt)
        self.assertIn('нет однозначно', txt)

    def test_database_positions_survive_restart_not_in_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.db'
            s = Storage(path)
            self.assertEqual(s.map_positions(), {})
            s.save_map_position('192.168.1.12', 120, -45)
            for value in [(float('nan'), 0), (100000, 0), (0, float('inf')), ('oops', 0)]:
                with self.assertRaises(ValueError):
                    s.save_map_position('192.168.1.12', *value)
            with self.assertRaises(ValueError):
                s.save_map_position('not-an-ip', 1, 2)
            s.close()
            s = Storage(path)
            self.assertEqual(s.map_positions()['192.168.1.12'], (120.0, -45.0))
            self.assertEqual(s.db.execute('PRAGMA quick_check').fetchone()[0], 'ok')
            s.clear_map_positions()
            self.assertEqual(s.map_positions(), {})
            s.close()

    def test_sqlite_ignores_corrupted_position(self):
        with tempfile.TemporaryDirectory() as directory:
            s = Storage(Path(directory) / 'db.sqlite')
            s.db.execute("INSERT INTO map_positions(ip,x,y) VALUES('192.168.1.2',99999,0)")
            s.db.execute("INSERT INTO map_positions(ip,x,y) VALUES('not-ip',1,2)")
            self.assertEqual(s.map_positions(), {})
            s.close()


if __name__ == '__main__':
    unittest.main()
