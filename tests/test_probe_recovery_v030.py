"""Distributed Probes 2.3 security and observation correctness."""
import ssl
import unittest
from datetime import datetime, timedelta, timezone
from bloodsky_net import probe_recovery as p
from bloodsky_net.probe_peers import ProbeActivity, TrustedDestination

NOW=datetime(2026,10,28,14,0,tzinfo=timezone.utc)

def event(seconds,typ='tls_received',peer='alice'):
    return ProbeActivity(NOW+timedelta(seconds=seconds),typ,peer,2)

class RetrySafetyTests(unittest.TestCase):
    def test_initial_allows_manual_auto(self):
        self.assertTrue(p.ready(p.RetryState(),100.0))

    def test_classification_of_network_failure(self):
        for exc in (ConnectionError('refused'), TimeoutError('timed out'), OSError('bad route'), ValueError('Получатель отклонил пакет (HTTP 503)')):
            self.assertEqual(p.failure_kind(exc),'transient')

    def test_failed_cert_is_fatal(self):
        self.assertEqual(p.failure_kind(ssl.SSLError('wrong leaf cert')),'tls_identity')
        self.assertFalse(p.ready(p.failed(p.RetryState(),'tls_identity',5),100000))

    def test_authentication_is_terminal(self):
        self.assertEqual(p.failure_kind(ValueError('Получатель отклонил пакет (HTTP 401)')),'blocked')
        self.assertFalse(p.ready(p.failed(p.RetryState(),'blocked',5),100000))

    def test_protocol_failure_is_terminal(self):
        self.assertEqual(p.failure_kind(ValueError('unexpected reply')),'blocked')

    def test_exponential_retry_is_bounded(self):
        s=p.RetryState()
        delays=[]
        for _ in range(8):
            s=p.failed(s,'transient',100)
            delays.append(s.next_at-100)
        self.assertEqual(delays,[15,30,60,120,300,300,300,300])
        self.assertFalse(p.ready(s,399))
        self.assertTrue(p.ready(s,400))

    def test_reject_bad_clock(self):
        for when in (float('inf'),float('nan'),-1,10**20,'now'):
            with self.assertRaises(ValueError):p.failed(p.RetryState(),'transient',when)

    def test_retry_never_undoes_blocked_failure(self):
        old=p.failed(p.RetryState(),'tls_identity',100)
        self.assertFalse(p.ready(old,10**9))

class PinRotationTests(unittest.TestCase):
    def setUp(self):
        self.profile=TrustedDestination('office','192.168.10.7',18443,'a'*64)

    def test_verified_new_fingerprint(self):
        new=p.approved_pin_rotation(self.profile,'a'*64,'b'*64,True)
        self.assertEqual(new.fingerprint,'b'*64)
        self.assertEqual(new.host,self.profile.host)
        self.assertEqual(self.profile.fingerprint,'a'*64)

    def test_rotation_requires_extra_confirmation(self):
        with self.assertRaisesRegex(ValueError,'подтверждения'):
            p.approved_pin_rotation(self.profile,'a'*64,'b'*64,False)

    def test_wrong_old_fingerprint_rejected(self):
        with self.assertRaises(ValueError):p.approved_pin_rotation(self.profile,'c'*64,'b'*64,True)

    def test_same_fingerprint_rejected(self):
        with self.assertRaises(ValueError):p.approved_pin_rotation(self.profile,'a'*64,'a'*64,True)

    def test_bad_fingerprint_rejected(self):
        with self.assertRaises(ValueError):p.approved_pin_rotation(self.profile,'a'*64,'unsafe',True)

    def test_plain_truthy_string_not_confirmation(self):
        with self.assertRaises(ValueError):p.approved_pin_rotation(self.profile,'a'*64,'b'*64,'yes')

class SenderFreshnessTests(unittest.TestCase):
    def test_no_history_is_unknown_not_disconnected(self):
        x=p.sender_states(['alice'],[],NOW)[0]
        self.assertEqual(x.state,'unknown')
        self.assertNotIn('отключён',x.note)

    def test_recent_success_fresh(self):
        x=p.sender_states(['alice'],[event(-120)],NOW)[0]
        self.assertEqual(x.state,'fresh')

    def test_expired_stale(self):
        x=p.sender_states(['alice'],[event(-181)],NOW)[0]
        self.assertEqual(x.state,'stale')
        self.assertEqual(x.last_received,NOW-timedelta(seconds=181))

    def test_only_accepts_authenticated_tls_inbound(self):
        x=p.sender_states(['alice'],[event(-10,'file_imported'),event(-10,'tls_sent')],NOW)[0]
        self.assertEqual(x.state,'unknown')

    def test_does_not_confuse_sender_ids(self):
        s=p.sender_states(['alice','bob'],[event(-10,peer='bob')],NOW)
        self.assertEqual({e.peer_id:e.state for e in s},{'alice':'unknown','bob':'fresh'})

    def test_ignore_future_and_too_old_events(self):
        x=p.sender_states(['alice'],[event(60),event(-86401)],NOW)[0]
        self.assertEqual(x.state,'unknown')

    def test_timezone_requirement(self):
        with self.assertRaises(ValueError):p.sender_states(['alice'],[],datetime(2026,10,28))

    def test_sorted_deduplicated_valid_ids(self):
        result=p.sender_states(['bob','bob','INVALID','alice'],[],NOW)
        self.assertEqual([r.peer_id for r in result],['alice','bob'])

if __name__=='__main__':unittest.main()
