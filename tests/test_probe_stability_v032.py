"""Observed TLS-attempt patterns are never diagnoses of host/network uptime."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from bloodsky_net import probe_stability as s
from bloodsky_net.probe_quality import TransferAttempt

T = datetime(2026, 10, 28, 13, tzinfo=timezone.utc)

def a(offset, outcome='network', name='office', duration=140):
    return TransferAttempt(T+timedelta(seconds=offset),name,outcome,duration)

class StabilityTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(s.patterns([],T),())
    def test_naive_now_rejected(self):
        with self.assertRaises(ValueError):s.patterns([],T.replace(tzinfo=None))
    def test_burst_requires_three_distinct_times(self):
        self.assertEqual(s.patterns((a(-30),a(-20)),T),())
        result=s.patterns((a(-30),a(-20),a(-10)),T)
        self.assertEqual((len(result),result[0].kind,result[0].attempts),(1,'repeated_network_error',3))
    def test_duplicates_cannot_create_burst(self):
        self.assertEqual(s.patterns((a(-3),a(-3),a(-3),a(-3)),T),())
    def test_newest_security_result_wins_tied_timestamp(self):
        v=s.patterns((a(0,'accepted'),a(0,'tls')),T)
        self.assertEqual([x.kind for x in v],['security_stop'])
    def test_burst_requires_nearby_timestamps(self):
        self.assertEqual(s.patterns((a(-1000),a(-500),a(0)),T),())
    def test_burst_ends_on_acceptance(self):
        self.assertFalse(any(x.kind=='repeated_network_error' for x in s.patterns(
            (a(-80),a(-70),a(-60,'accepted'),a(-50),a(-40)),T)))
    def test_security_blocks_break_streak(self):
        v=s.patterns((a(-80),a(-70),a(-60,'rejected'),a(-50)),T)
        self.assertEqual([x.kind for x in v],['security_stop'])
    def test_confirm_acceptance_after_burst(self):
        v=s.patterns((a(-50),a(-40),a(-30),a(0,'accepted')),T)
        self.assertEqual({x.kind for x in v},{'repeated_network_error','accepted_after_errors'})
    def test_recovery_too_late_not_reported(self):
        v=s.patterns((a(-2400),a(-2390),a(-2380),a(0,'accepted')),T)
        self.assertNotIn('accepted_after_errors',{x.kind for x in v})
    def test_no_unobserved_time_flagged_as_outage(self):
        self.assertEqual(s.patterns((a(-86000,'accepted'),a(0,'accepted')),T),())
    def test_old_measurements_ignored(self):
        self.assertEqual(s.patterns((a(-700000),a(-699990),a(-699980)),T),())
    def test_future_ignored(self):
        self.assertEqual(s.patterns((a(1),a(2),a(3)),T),())
    def test_bad_and_naive_records_ignored(self):
        bad=a(-10); bad=TransferAttempt(bad.at.replace(tzinfo=None),bad.destination,bad.outcome,bad.elapsed_ms)
        self.assertEqual(s.patterns((bad,a(1)),T),())
    def test_per_destination_independence(self):
        self.assertEqual(len(s.patterns((a(-30),a(-20,'accepted','other'),a(-10)),T)),0)
    def test_bound_outputs(self):
        rows=[a(0,'tls',f'dest{n}') for n in range(100)]
        self.assertLessEqual(len(s.patterns(rows,T)),32)
    def test_stable_order(self):
        rows=(a(-30),a(-20),a(-10),a(-30,'tls','other'))
        self.assertEqual(s.patterns(rows,T),s.patterns(tuple(reversed(rows)),T))
    def test_report_contains_no_credentials(self):
        out=json.dumps(s.report((a(0,'tls'),),T),ensure_ascii=False)
        self.assertIn('security_stop',out)
        self.assertNotIn('token',out)
        self.assertNotIn('private_key',out)
        self.assertNotIn('password',out)
    def test_report_tz_aware(self):
        report=s.report((),T)
        self.assertIn('+00:00',report['generated_utc'])
    def test_wrong_outcome_does_not_create_incident(self):
        self.assertEqual(s.patterns((a(-10,'unexpected'),),T),())
    def test_corrupt_destination_does_not_leak(self):
        self.assertEqual(s.patterns((a(-10,'tls','secret\nkey'),),T),())
    def test_mixed_timezone(self):
        other=timezone(timedelta(hours=3))
        ts=T.astimezone(other)-timedelta(minutes=1)
        v=s.patterns((TransferAttempt(ts,'a','tls',100),),T)
        self.assertEqual(v[0].last_at.tzinfo,timezone.utc)

if __name__=='__main__':unittest.main()
