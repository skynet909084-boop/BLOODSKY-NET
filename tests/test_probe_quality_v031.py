"""Distributed Probes 2.4: bounded request quality, truthful gaps, safe SQLite."""
import sqlite3
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from bloodsky_net import probe_quality as q
from bloodsky_net.storage import Storage

NOW=datetime(2026,10,28,12,tzinfo=timezone.utc)
def sample(offset,dest='office',outcome='accepted',ms=150):
    return q.TransferAttempt(NOW+timedelta(seconds=offset),dest,outcome,ms)

class TransferQualityTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(q.summarize((),NOW),())
    def test_timezone_required(self):
        with self.assertRaises(ValueError):q.summarize((),datetime(2026,10,28))
    def test_bad_outcomes(self):
        with self.assertRaises(ValueError):q.validate_attempt(sample(0,outcome='credentials'))
    def test_secrets_not_labels(self):
        with self.assertRaises(ValueError):q.validate_attempt(sample(0,dest='test\nsecret'))
    def test_invalid_duration(self):
        for duration in (-1,60001,True,float('nan'),'100'):
            with self.assertRaises(ValueError):q.validate_attempt(sample(0,ms=duration))
    def test_naive_clock_rejected(self):
        with self.assertRaises(ValueError):q.validate_attempt(q.TransferAttempt(datetime(2026,10,28),'x','accepted',0))
    def test_counts_and_percentages(self):
        r=q.summarize((sample(-30),sample(-20,outcome='network'),sample(-10,outcome='tls'),sample(0,outcome='rejected')),NOW)[0]
        self.assertEqual((r.total,r.accepted,r.network_failures,r.security_failures,r.acceptance_percent),(4,1,1,2,25))
    def test_latency_suppressed_until_three_good(self):
        self.assertIsNone(q.summarize((sample(-5),sample(0)),NOW)[0].median_ms)
    def test_nearest_rank_percentile(self):
        v=q.summarize((sample(-3,ms=300),sample(-2,ms=100),sample(-1,ms=200),sample(0,ms=800)),NOW)[0]
        self.assertEqual((v.median_ms,v.p95_ms),(200,800))
    def test_old_and_future_excluded(self):
        self.assertEqual(q.summarize((sample(-8*86400),sample(60)),NOW),())
    def test_no_claim_of_recovery_without_failed_attempt(self):
        self.assertFalse(q.summarize((sample(-3600),sample(0)),NOW)[0].accepted_after_error)
    def test_acceptance_after_failure(self):
        a=q.summarize((sample(-100,outcome='network'),sample(0)),NOW)[0]
        self.assertTrue(a.accepted_after_error)
    def test_gap_is_unobserved_minutes_not_outage(self):
        a=q.summarize((sample(-3600),sample(0)),NOW)[0]
        self.assertEqual(a.longest_unobserved_gap_minutes,60)
    def test_independent_destinations(self):
        self.assertEqual([x.destination for x in q.summarize((sample(0,'z'),sample(0,'a')),NOW)],['a','z'])

class StorageQualityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'legacy.db'
        self.store=Storage(self.path)
    def tearDown(self):
        self.store.close();self.tmp.cleanup()
    def test_persists_across_restart(self):
        self.store.record_probe_transfer(sample(0))
        self.store.close();self.store=Storage(self.path)
        got=self.store.probe_transfer_attempts()
        self.assertEqual(len(got),1)
        self.assertEqual(got[0].outcome,'accepted')
    def test_no_credentials_or_payload_columns(self):
        cols=[r[1] for r in self.store.db.execute('PRAGMA table_info(probe_transfer_attempts)')]
        self.assertEqual(cols,['id','ts','destination','outcome','elapsed_ms'])
    def test_invalid_row_is_skipped(self):
        self.store.db.execute("INSERT INTO probe_transfer_attempts(ts,destination,outcome,elapsed_ms) VALUES(?,?,?,?)",
                              ('unparseable','a','accepted',3))
        self.assertEqual(self.store.probe_transfer_attempts(),())
    def test_sql_rollback_if_validation_fails(self):
        with self.assertRaises(ValueError):self.store.record_probe_transfer(sample(0,ms=-1))
        self.assertEqual(self.store.probe_transfer_attempts(),())
    def test_bound_rows(self):
        row=sample(0)
        for _ in range(2075):self.store.record_probe_transfer(row)
        n=self.store.db.execute('SELECT count(*) FROM probe_transfer_attempts').fetchone()[0]
        self.assertEqual(n,2048)
    def test_storage_migration_preserves_existing_preferences(self):
        self.store.set_preference('alerts_enabled',True)
        self.store.close();self.store=Storage(self.path)
        self.assertTrue(self.store.get_preference('alerts_enabled'))

if __name__=='__main__': unittest.main()
