"""Registry and chronology tests: pin destinations, never persist secrets or claim host offline."""
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bloodsky_net.probe_peers import (
    ALLOWED_EVENTS, ProbeActivity, recent_receive_state, timeline, validate_destination,
    MAX_PROFILES, safe_label)
from bloodsky_net.storage import Storage

T0=datetime(2026,10,28,12,0,tzinfo=timezone.utc)
FP='ab'*32

class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'network.db'
        self.store=Storage(self.path)
    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_write_load_restart_and_delete(self):
        p=self.store.upsert_trusted_destination('Ноутбук','192.168.10.8',18443,FP)
        self.assertEqual(p.alias,'Ноутбук')
        self.store.close()
        self.store=Storage(self.path)
        self.assertEqual(self.store.trusted_destinations(),(p,))
        self.store.delete_trusted_destination('Ноутбук')
        self.assertEqual(self.store.trusted_destinations(),())

    def test_update_existing_profile_without_duplicate(self):
        self.store.upsert_trusted_destination('desk','192.168.1.2',18443,FP)
        self.store.upsert_trusted_destination('desk','192.168.1.3',18444,'CD'*32)
        rows=self.store.trusted_destinations()
        self.assertEqual(len(rows),1)
        self.assertEqual((rows[0].host,rows[0].port,rows[0].fingerprint),
                         ('192.168.1.3',18444,'cd'*32))

    def test_never_persist_access_secret(self):
        p=self.store.upsert_trusted_destination('lab','127.0.0.1',18443,FP)
        self.assertEqual(len(p.fingerprint),64)
        tables=[r[1] for r in self.store.db.execute('PRAGMA table_info(probe_trusted_destinations)')]
        self.assertNotIn('token',tables)
        self.assertNotIn('key',tables)
        self.assertNotIn('secret',tables)
        dump='\n'.join(self.store.db.iterdump())
        self.assertNotIn('Bearer ',dump)

    def test_reject_public_and_wildcard(self):
        for host in ['0.0.0.0','8.8.8.8','224.0.0.1','localhost','192.168.10.888']:
            with self.subTest(host=host),self.assertRaises(ValueError):
                validate_destination('local',host,18443,FP)

    def test_reject_malformed_fingerprint(self):
        for fp in ['a'*62,'',FP+'x','00'*15+'\n'+'00'*17]:
            with self.subTest(fp=fp),self.assertRaises(ValueError):
                validate_destination('a','127.0.0.1',18443,fp)

    def test_reject_nonprintable_and_missing_alias(self):
        for name in ('','  ','bad\nname','a'*65,'x\x00y'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                safe_label(name)

    def test_max_32_profiles_and_update_allowed(self):
        for i in range(MAX_PROFILES):
            self.store.upsert_trusted_destination('peer'+str(i),'127.0.0.1',18443,FP)
        with self.assertRaises(ValueError):
            self.store.upsert_trusted_destination('another','127.0.0.1',18443,FP)
        self.store.upsert_trusted_destination('peer1','127.0.0.2',18444,FP)
        self.assertEqual(len(self.store.trusted_destinations()),32)

    def test_existing_database_migration(self):
        self.store.close()
        conn=sqlite3.connect(self.path)
        conn.execute('DROP TABLE probe_trusted_destinations')
        conn.execute('DROP TABLE probe_activity')
        conn.commit();conn.close()
        self.store=Storage(self.path)
        self.store.upsert_trusted_destination('test','127.0.0.1',18443,FP)
        self.assertEqual(len(self.store.trusted_destinations()),1)

    def test_activity_persists_across_restart(self):
        self.store.record_probe_activity('tls_received','remote-claimed',5,T0)
        self.store.record_probe_activity('file_imported','external',2,T0+timedelta(seconds=10))
        self.store.close();self.store=Storage(self.path)
        events=self.store.probe_activities()
        self.assertEqual([a.event for a in events],['file_imported','tls_received'])
        self.assertEqual(events[1].at,T0)

    def test_reject_invalid_activity_or_dates(self):
        for ev in ['unknown','tls_error','']:
            with self.assertRaises(ValueError):
                self.store.record_probe_activity(ev,'peer',4,T0)
        for n in [-1,257,2.5,True]:
            with self.assertRaises(ValueError):
                self.store.record_probe_activity('tls_received','peer',n,T0)
        with self.assertRaises(ValueError):
            self.store.record_probe_activity('tls_received','peer',1,T0.replace(tzinfo=None))

    def test_activity_retention_bounded(self):
        for i in range(2060):
            self.store.record_probe_activity('tls_received','peer',i%3,T0+timedelta(seconds=i))
        c=self.store.db.execute('SELECT count(*) FROM probe_activity').fetchone()[0]
        self.assertEqual(c,2048)

    def test_delete_profile_does_not_delete_history(self):
        self.store.upsert_trusted_destination('peer','127.0.0.1',18443,FP)
        self.store.record_probe_activity('tls_sent','peer',3,T0)
        self.store.delete_trusted_destination('peer')
        self.assertEqual(len(self.store.probe_activities()),1)

class TimelineTests(unittest.TestCase):
    def item(self,sec,ev='tls_received',label='claimed',count=4):
        return ProbeActivity(T0+timedelta(seconds=sec),ev,label,count)

    def test_no_measurements_means_unknown_not_disconnected(self):
        self.assertEqual(recent_receive_state((),T0)[1],'unknown')
        self.assertIn('нет входящих измерений',recent_receive_state((),T0)[0])

    def test_recent_measurement(self):
        self.assertEqual(recent_receive_state((self.item(-180),),T0)[1],'fresh')

    def test_stale_measurements_not_host_offline(self):
        status,nature=recent_receive_state((self.item(-181),),T0)
        self.assertEqual(nature,'stale')
        self.assertIn('не значит',status)

    def test_sent_and_file_import_do_not_claim_incoming(self):
        a=self.item(-30, 'tls_sent')
        b=self.item(-40, 'file_imported')
        self.assertEqual(recent_receive_state((a,b),T0)[1],'unknown')

    def test_old_and_future_data_excluded(self):
        self.assertEqual(recent_receive_state((self.item(-86401),self.item(6)),T0)[1],'unknown')

    def test_timeline_order_and_bounded_length(self):
        rows=tuple(self.item(i,'file_imported') for i in range(160))
        got=timeline(rows[::-1])
        self.assertEqual(len(got),100)
        self.assertEqual(got[0].at,T0+timedelta(seconds=60))

    def test_invalid_provenance_excluded(self):
        rows=(self.item(0,'invalid'),self.item(1,'tls_received'),self.item(2,'tls_received',count=257))
        self.assertEqual(len(timeline(rows)),1)

    def test_requires_aware_now(self):
        with self.assertRaises(ValueError):
            recent_receive_state((),datetime(2026,10,28))

if __name__=='__main__': unittest.main()
