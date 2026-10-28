"""Distributed offline probes: observational only, file data never trusted."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from bloodsky_net import distributed_probes as p
from bloodsky_net.storage import Storage

T = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)

def snapshot(label='office', ip='10.1.1.5', state='reply', offset=0):
    now = T + timedelta(seconds=offset)
    return p.create_snapshot(label, [(ip, state, now)], now)

class ProbeFileTests(unittest.TestCase):
    def test_roundtrip(self):
        x = snapshot()
        self.assertEqual(p.decode(p.encode(x)), x)

    def test_no_creds_inventory_or_ssid(self):
        raw = p.encode(snapshot()).decode()
        for secret in ('community','password','auth_key','priv_key','ssid','hostname','mac'):
            self.assertNotIn('"'+secret+'"', raw)

    def test_file_is_not_a_socket_transport(self):
        self.assertNotIn('socket', Path(p.__file__).read_text())

    def test_reject_large_file(self):
        with self.assertRaisesRegex(ValueError, 'Размер'):
            p.decode(b'X'*(p.MAX_BYTES+1))

    def test_invalid_utf8(self):
        with self.assertRaisesRegex(ValueError, 'JSON'):
            p.decode(b'\xff\xfe')

    def test_invalid_file_type(self):
        with self.assertRaises(ValueError):
            p.decode(json.dumps({'format':'garbage'}).encode())

    def test_invalid_reading_state(self):
        raw = json.loads(p.encode(snapshot())); raw['readings'][0]['state']='offline'
        with self.assertRaises(ValueError): p.decode(json.dumps(raw).encode())

    def test_duplicate_ip_rejected(self):
        raw = json.loads(p.encode(snapshot())); raw['readings'].append(raw['readings'][0])
        with self.assertRaises(ValueError): p.decode(json.dumps(raw).encode())

    def test_unknown_reading_rejected(self):
        with self.assertRaises(ValueError): p.create_snapshot('a', [('10.1.1.1','unknown',T)],T)

    def test_empty_measurements_rejected(self):
        with self.assertRaises(ValueError): p.create_snapshot('a',[],T)

    def test_too_many_readings_rejected(self):
        with self.assertRaises(ValueError): p.create_snapshot('a', [('10.1.1.'+str(i%255),'reply',T) for i in range(257)],T)

    def test_aged_at_export_rejected(self):
        with self.assertRaises(ValueError): p.create_snapshot('a',[('10.1.1.1','reply',T-timedelta(seconds=181))],T)

    def test_import_historical_package_accepted(self):
        self.assertEqual(p.decode(p.encode(snapshot())).created_at,T)

    def test_time_without_timezone_rejected(self):
        raw = json.loads(p.encode(snapshot()));raw['created_at']='2026-10-28T10:00:00'
        with self.assertRaises(ValueError):p.decode(json.dumps(raw).encode())

    def test_timestamp_in_future_at_export_rejected(self):
        with self.assertRaises(ValueError):p.create_snapshot('a',[('10.1.1.1','reply',T+timedelta(minutes=5))],T)

    def test_multiline_probe_label_rejected(self):
        with self.assertRaises(ValueError):p.create_snapshot('a\nb',[('10.1.1.1','reply',T)],T)

    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):p.create_snapshot('a',[('2001:db8::1','reply',T)],T)

    def test_duplicate_file_id_does_not_duplicate_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp)/'db.sqlite'
            store=Storage(db); item=snapshot()
            store.save_probe_package(item);store.save_probe_package(item)
            self.assertEqual(store.probe_packages(),(item,))
            store.close()
            store=Storage(db)
            self.assertEqual(store.probe_packages(),(item,));store.close()

    def test_corrupted_row_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Storage(Path(tmp)/'db.sqlite'); valid=snapshot()
            store.save_probe_package(valid)
            store.db.execute('INSERT INTO probe_packages VALUES (?,?,?,?)',('broken',T.isoformat(),'broken','<invalid>'))
            store.db.commit()
            self.assertEqual(store.probe_packages(),(valid,));store.close()

    def test_256_rows_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Storage(Path(tmp)/'db.sqlite')
            for i in range(275):
                item=p.create_snapshot('PC-'+str(i), [('10.1.1.1','reply',T)],T)
                store.save_probe_package(item)
            self.assertLessEqual(len(store.probe_packages(256)),256)
            store.close()

class CompareTests(unittest.TestCase):
    def test_disagreement(self):
        rows=p.compare([snapshot('office'),snapshot('warehouse',state='no_icmp',offset=45)])
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].outcome,'Разные результаты')
        self.assertIn('ACL',rows[0].note)

    def test_both_no_ping_not_claim_offline(self):
        rows=p.compare([snapshot('A',state='no_icmp'),snapshot('B',state='no_icmp',offset=1)])
        self.assertEqual(len(rows),1)
        self.assertIn('не доказывает отключение',rows[0].note)

    def test_same_label_no_independent_probe(self):
        self.assertEqual(p.compare([snapshot('office'),snapshot('office',state='no_icmp')]),())

    def test_long_gap_no_conclusion(self):
        self.assertEqual(p.compare([snapshot('office'),snapshot('warehouse',offset=301)]),())

    def test_different_targets_no_conclusion(self):
        self.assertEqual(p.compare([snapshot('office'),snapshot('warehouse',ip='10.1.1.6')]),())

    def test_two_replies(self):
        rows=p.compare([snapshot('office'),snapshot('warehouse',offset=20)])
        self.assertEqual(rows[0].outcome,'Ответ ICMP из нескольких точек')

    def test_latest_per_label(self):
        rows=p.compare([snapshot('office',state='no_icmp'),snapshot('office',state='reply',offset=30),snapshot('warehouse',state='reply',offset=32)])
        self.assertEqual(rows[0].outcome,'Ответ ICMP из нескольких точек')

    def test_5_minute_inclusive(self):
        self.assertEqual(len(p.compare([snapshot('a'),snapshot('b',offset=300)])),1)

if __name__=='__main__':unittest.main()
