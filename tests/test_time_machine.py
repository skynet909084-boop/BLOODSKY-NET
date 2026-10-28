"""Time Machine persistence, diff semantics, privacy and retention tests."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bloodsky_net.network import Device
from bloodsky_net.storage import Storage
from bloodsky_net.time_machine import SnapshotDevice, as_snapshot_device, diff, summary


class TimeMachineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'monitor.db'
        self.store = Storage(self.path)
        self.cam = Device('192.168.40.2', hostname='cam', kind='camera', mac='AA:BB:CC:00:00:02', online=True)
        self.sw = Device('192.168.40.1', hostname='switch', kind='switch', online=True)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_first_snapshot_unknown_not_offline(self):
        ident = self.store.save_network_snapshot([self.cam], scope='192.168.40.0/24')
        actual = self.store.network_snapshot_devices(ident)
        self.assertEqual(actual[self.cam.ip].state, 'unknown')
        self.assertEqual(self.store.network_snapshots()[0][4], 1)

    def test_reopens_without_losing_snapshots(self):
        old = self.store.save_network_snapshot([self.cam], {self.cam.ip:'up'}, source='scan')
        self.store.close()
        self.store = Storage(self.path)
        self.assertEqual(self.store.network_snapshot_devices(old)[self.cam.ip].state, 'up')
        self.assertEqual(self.store.db.execute('PRAGMA quick_check').fetchone()[0], 'ok')

    def test_availability_change_requires_two_known_states(self):
        old = self.store.save_network_snapshot([self.cam], {self.cam.ip:'up'})
        new = self.store.save_network_snapshot([self.cam], {self.cam.ip:'down'})
        changes = self.store.compare_network_snapshots(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].category, 'availability')
        self.assertEqual(changes[0].after, 'down')
        third = self.store.save_network_snapshot([self.cam])
        next_changes = self.store.compare_network_snapshots(new, third)
        self.assertEqual(next_changes[0].category, 'measurement')
        self.assertIn('не подтверждённая авария', next_changes[0].description.lower())

    def test_mac_and_hostname_changes(self):
        old = self.store.save_network_snapshot([self.cam])
        self.cam.mac = 'AA:BB:CC:00:00:03'
        self.cam.hostname = 'cam-updated'
        new = self.store.save_network_snapshot([self.cam])
        self.assertEqual({c.category for c in self.store.compare_network_snapshots(old,new)}, {'mac','hostname'})

    def test_new_inventory_is_not_claimed_new_physical_device(self):
        old = self.store.save_network_snapshot([self.sw])
        new = self.store.save_network_snapshot([self.sw,self.cam])
        changes = self.store.compare_network_snapshots(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].category, 'new_inventory')
        self.assertIn('инвентар', changes[0].description)
        removed = self.store.save_network_snapshot([self.cam])
        self.assertEqual(self.store.compare_network_snapshots(new, removed)[0].category, 'not_in_snapshot')
        self.assertIn('не доказательство', self.store.compare_network_snapshots(new, removed)[0].description)

    def test_deterministic_ipv4_numeric_order(self):
        left={'192.168.1.20':SnapshotDevice('192.168.1.20'), '192.168.1.2':SnapshotDevice('192.168.1.2')}
        self.assertEqual([c.ip for c in diff({},left)], ['192.168.1.2','192.168.1.20'])
        self.assertEqual(summary(diff({},left))['new_inventory'],2)

    def test_safe_columns_not_secrets(self):
        self.cam.snmp_auth_key = 'top-secret-password'  # unknown fields must not be serialized
        ident=self.store.save_network_snapshot([self.cam])
        text=' '.join(str(row) for row in self.store.db.execute('SELECT * FROM snapshot_devices').fetchall())
        self.assertNotIn('top-secret-password',text)
        self.assertNotIn('snmp',text)
        self.assertEqual(len(self.store.network_snapshot_devices(ident)),1)

    def test_invalid_state_source_scope_and_timestamp_rejected(self):
        for states in ({self.cam.ip:'offline'},{self.cam.ip:None}):
            with self.assertRaises(ValueError):
                self.store.save_network_snapshot([self.cam], states)
        with self.assertRaises(ValueError):
            self.store.save_network_snapshot([self.cam], source='secret')
        with self.assertRaises(ValueError):
            self.store.save_network_snapshot([self.cam],scope='not-cidr')
        with self.assertRaises(ValueError):
            self.store.save_network_snapshot([self.cam],ts='2026-10-28T11:00:00')
        self.assertEqual(self.store.network_snapshots(),[])

    def test_invalid_ids_rejected(self):
        a=self.store.save_network_snapshot([self.cam])
        with self.assertRaises(ValueError):
            self.store.compare_network_snapshots(a,a)
        with self.assertRaises(ValueError):
            self.store.compare_network_snapshots(a,345678)

    def test_dedupe_and_device_limit(self):
        ident=self.store.save_network_snapshot([self.cam,self.cam])
        self.assertEqual(len(self.store.network_snapshot_devices(ident)),1)
        many=[Device(f'10.3.{i//250}.{i%250+1}') for i in range(513)]
        with self.assertRaises(ValueError):
            self.store.save_network_snapshot(many)
        self.assertEqual(len(self.store.network_snapshots()),1)

    def test_retention_cascades_snapshot_children(self):
        with patch('bloodsky_net.storage.SNAPSHOT_MAX_ROWS',3):
            ids=[self.store.save_network_snapshot([self.cam], source='monitor') for _ in range(6)]
        self.assertEqual(len(self.store.network_snapshots()),3)
        self.assertEqual(len(self.store.network_snapshot_devices(ids[0])),0)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM snapshot_devices').fetchone()[0],3)

    def test_week_retention_cascades_old_snapshots(self):
        old=self.store.save_network_snapshot([self.cam], ts='2024-01-01T12:00:00+00:00')
        new=self.store.save_network_snapshot([self.cam])
        self.assertEqual([r[0] for r in self.store.network_snapshots()],[new])
        self.assertEqual(self.store.network_snapshot_devices(old),{})

    def test_bounded_list_and_readonly_unknown_ids(self):
        for _ in range(5):
            self.store.save_network_snapshot([self.cam])
        self.assertEqual(len(self.store.network_snapshots(2)),2)
        self.assertEqual(len(self.store.network_snapshot_devices(9999)),0)


if __name__=='__main__':
    unittest.main()
