"""Evidence-safe LLDP observation timelines, atomic storage, TTL and privacy."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bloodsky_net.storage import Storage
from bloodsky_net.topology import Neighbor, TopologySnapshot
from bloodsky_net.topology_history import observations, compare_links


class TopologyHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'history.sqlite'
        self.db = Storage(self.path)
        self.switch = '192.168.10.2'

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def capture(self, port=4, chassis='AA:BB:CC:DD:EE:FF', name='camera', remote_port='eth1', ts=None):
        n = Neighbor(source_ip=self.switch, local_port_num=port, local_port=f'Gi1/0/{port}',
                     remote_name=name, remote_port=remote_port, remote_chassis=chassis,
                     remote_description='danger_secret_authkey_forbidden')
        snap = TopologySnapshot(source_ip=self.switch, system_name='Switch', neighbors=[n], observed_at='')
        return self.db.save_lldp_capture(snap, ts=ts)

    def test_reopens_history(self):
        first = self.capture()
        self.db.close()
        self.db = Storage(self.path)
        self.assertEqual(self.db.lldp_captures()[0][0], first)
        self.assertEqual(self.db.lldp_capture_neighbors(first)[0].local_port, 'Gi1/0/4')
        self.assertEqual(self.db.db.execute('PRAGMA quick_check').fetchone()[0], 'ok')

    def test_port_moved_is_an_observation_not_cable_certainty(self):
        first = self.capture()
        second = self.capture(port=5)
        changes = self.db.compare_lldp_captures(first, second)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].category, 'local_port_changed')
        self.assertIn('не доказано', changes[0].explanation)

    def test_empty_successful_capture_is_not_cable_down(self):
        first = self.capture()
        second = self.db.save_lldp_capture(TopologySnapshot(self.switch))
        changes = self.db.compare_lldp_captures(first, second)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].category, 'not_reported')
        self.assertIn('не доказательство', changes[0].explanation)

    def test_new_llpd_neighbor_not_proof_new_physical_equipment(self):
        first = self.db.save_lldp_capture(TopologySnapshot(self.switch))
        second = self.capture()
        change = self.db.compare_lldp_captures(first, second)[0]
        self.assertEqual(change.category, 'new_observation')
        self.assertIn('не подтверждает', change.explanation)

    def test_device_name_changed_without_false_replug(self):
        first = self.capture(name='Camera1')
        second = self.capture(name='Camera2')
        changes = self.db.compare_lldp_captures(first, second)
        self.assertEqual([c.category for c in changes], ['name_changed'])

    def test_ambiguous_id_no_invented_port_move(self):
        snap1 = TopologySnapshot(self.switch, neighbors=[
            Neighbor(self.switch, 4, 'A', 'cam', 'eth1', 'AA:BB'),
            Neighbor(self.switch, 5, 'B', 'cam', 'eth1', 'AA:BB')])
        snap2 = TopologySnapshot(self.switch, neighbors=[
            Neighbor(self.switch, 6, 'C', 'cam', 'eth1', 'AA:BB')])
        x = self.db.save_lldp_capture(snap1)
        y = self.db.save_lldp_capture(snap2)
        self.assertNotIn('local_port_changed', {c.category for c in self.db.compare_lldp_captures(x,y)})

    def test_other_switch_does_not_compare(self):
        x = self.capture()
        y = self.db.save_lldp_capture(TopologySnapshot('192.168.10.3'))
        with self.assertRaises(ValueError):
            self.db.compare_lldp_captures(x,y)
        with self.assertRaises(ValueError):
            self.db.compare_lldp_captures(x,x)

    def test_secrets_and_arbitrary_attributes_not_persisted(self):
        first = self.capture()
        raw = '\n'.join(str(row) for row in self.db.db.execute('SELECT * FROM lldp_observations'))
        self.assertNotIn('danger_secret_authkey_forbidden',raw)
        self.assertEqual(self.db.db.execute('SELECT count(*) FROM lldp_observations').fetchone()[0],1)
        self.assertEqual(self.db.lldp_capture_neighbors(first)[0].remote_chassis, 'AA:BB:CC:DD:EE:FF')

    def test_neighbor_limit_is_atomic(self):
        nodes = [Neighbor(self.switch, i+1, str(i), f'host{i}', 'eth', str(i)) for i in range(513)]
        with self.assertRaises(ValueError):
            self.db.save_lldp_capture(TopologySnapshot(self.switch, neighbors=nodes))
        self.assertEqual(self.db.lldp_captures(),[])

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            self.capture(ts='2026-10-28T08:00:00')
        with self.assertRaises(ValueError):
            self.db.save_lldp_capture(TopologySnapshot('8.8.8.8'))

    def test_retention_cascades_children(self):
        with patch('bloodsky_net.storage.LLDP_CAPTURE_MAX_ROWS', 2):
            old = self.capture()
            self.capture(port=5)
            self.capture(port=6)
        self.assertEqual(len(self.db.lldp_captures()),2)
        self.assertEqual(self.db.lldp_capture_neighbors(old),[])
        self.assertEqual(self.db.db.execute('SELECT count(*) FROM lldp_observations').fetchone()[0],2)

    def test_retention_removes_old(self):
        first = self.capture(ts='2023-12-20T12:00:00+00:00')
        second = self.capture()
        self.assertEqual([x[0] for x in self.db.lldp_captures()], [second])
        self.assertEqual(self.db.lldp_capture_neighbors(first), [])

    def test_exact_duplicate_is_no_change(self):
        first = self.capture()
        second = self.capture()
        self.assertEqual(self.db.compare_lldp_captures(first,second),[])

if __name__=='__main__':
    unittest.main()
