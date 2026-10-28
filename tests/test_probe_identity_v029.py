"""Individual TLS sender credentials: persistence, revocation, and no false machine ID."""
import hashlib
import socket
import ssl
import sqlite3
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone

from bloodsky_net import distributed_probes as probes, probe_transport as tr
from bloodsky_net.storage import Storage


class TrustStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'network.db'
        self.store = Storage(self.path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_independent_random_tokens_only_hashes_in_database(self):
        a = self.store.create_trusted_sender('alice')
        b = self.store.create_trusted_sender('bob')
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 64)
        allowed = self.store.trusted_sender_hashes()
        self.assertEqual(allowed['alice'], hashlib.sha256(bytes.fromhex(a)).hexdigest())
        dump = '\n'.join(self.store.db.iterdump())
        self.assertNotIn(a, dump)
        self.assertNotIn(b, dump)
        self.assertNotIn('Bearer ', dump)

    def test_restart_retains_only_verifier(self):
        token = self.store.create_trusted_sender('peer_1')
        self.store.close()
        self.store = Storage(self.path)
        self.assertEqual(self.store.trusted_sender_hashes()['peer_1'], tr.fingerprint_token(token))

    def test_reissue_invalidates_old_key(self):
        before = self.store.create_trusted_sender('alice')
        after = self.store.create_trusted_sender('alice')
        self.assertNotEqual(before, after)
        self.assertNotEqual(self.store.trusted_sender_hashes()['alice'], tr.fingerprint_token(before))
        self.assertEqual(len(self.store.trusted_sender_hashes()), 1)

    def test_revoke_keeps_other_authorized_sender(self):
        self.store.create_trusted_sender('alice')
        self.store.create_trusted_sender('bob')
        self.store.revoke_trusted_sender('alice')
        self.assertEqual(list(self.store.trusted_sender_hashes()), ['bob'])
        self.store.revoke_trusted_sender('alice')

    def test_existing_database_schema_upgrade(self):
        self.store.close()
        db = sqlite3.connect(self.path)
        db.execute('DROP TABLE probe_trusted_senders')
        db.commit()
        db.close()
        self.store = Storage(self.path)
        self.assertEqual(self.store.trusted_sender_hashes(), {})

    def test_reject_invalid_ids(self):
        for candidate in ('', 'UPPER', '1start', 'space name', 'bad\nname', 'x'*33, '../file', 'юзер'):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.store.create_trusted_sender(candidate)

    def test_limit_32_and_rotation(self):
        for i in range(32):
            self.store.create_trusted_sender('user'+str(i))
        with self.assertRaises(ValueError):
            self.store.create_trusted_sender('overflow')
        self.store.create_trusted_sender('user1')
        self.assertEqual(len(self.store.trusted_sender_hashes()), 32)


class AuthenticatedTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        cls.alice = '1'*64
        cls.bob = '2'*64
        cls.server = tr.PeerReceiver('127.0.0.1', cls.port, strict_peers=True,
            trusted_peers={'alice': tr.fingerprint_token(cls.alice),
                           'bob': tr.fingerprint_token(cls.bob)}).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def fresh(self, name='unverified-claimed-name'):
        now = datetime.now(timezone.utc)
        return probes.create_snapshot(name, [('192.168.1.10', 'reply', now)], now)

    def send(self, token, peer='alice', snapshot=None):
        tr.send_snapshot('127.0.0.1', self.port, self.server.fingerprint,
                         token, snapshot or self.fresh(), peer_id=peer)

    def test_two_users_independent_and_labels_verified(self):
        self.send(self.alice)
        self.send(self.bob, peer='bob')
        self.assertEqual(self.server.incoming.get(timeout=2).label, 'alice')
        self.assertEqual(self.server.incoming.get(timeout=2).label, 'bob')

    def test_strict_never_accepts_legacy_session_key(self):
        self.assertEqual(self.server.token,'')
        with self.assertRaisesRegex(ValueError, '401'):
            self.send('a'*64)
        self.assertTrue(self.server.incoming.empty())

    def test_wrong_key_for_valid_sender(self):
        with self.assertRaisesRegex(ValueError, '401'):
            self.send(self.bob,peer='alice')

    def test_sender_key_revocation_live_and_reissue(self):
        self.server.revoke_peer('alice')
        with self.assertRaisesRegex(ValueError, '401'):
            self.send(self.alice)
        self.send(self.bob,peer='bob')
        self.assertEqual(self.server.incoming.get(timeout=2).label,'bob')
        new='3'*64
        self.server.add_peer_hash('alice',tr.fingerprint_token(new))
        with self.assertRaisesRegex(ValueError,'401'):
            self.send(self.alice)
        self.send(new)
        self.assertEqual(self.server.incoming.get(timeout=2).label,'alice')
        self.server.add_peer_hash('alice',tr.fingerprint_token(self.alice))

    def test_wrong_cert_does_not_send_sender_token(self):
        with self.assertRaises(ssl.SSLError):
            tr.send_snapshot('127.0.0.1',self.port,'0'*64,self.alice,self.fresh(),peer_id='alice')
        self.assertTrue(self.server.incoming.empty())

    def test_duplicate_snapshot_rejected(self):
        snap=self.fresh()
        self.send(self.alice,snapshot=snap)
        self.assertEqual(self.server.incoming.get(timeout=2).label,'alice')
        with self.assertRaisesRegex(ValueError,'409'):
            self.send(self.alice,snapshot=snap)

    def test_invalid_id_rejected_before_send(self):
        with self.assertRaises(ValueError):
            self.send(self.alice,peer='BAD')

    def test_unauthorized_labels_do_not_authenticate(self):
        snap=self.fresh(name='bob')
        self.send(self.alice,snapshot=snap)
        self.assertEqual(self.server.incoming.get(timeout=2).label,'alice')

    def test_expired_packet_rejected(self):
        now=datetime.now(timezone.utc)-timedelta(minutes=4)
        snap=probes.create_snapshot('a',[('192.168.1.1','reply',now)],now)
        with self.assertRaises(ValueError):
            self.send(self.alice,snapshot=snap)


class PeerValidationTests(unittest.TestCase):
    def test_invalid_hash(self):
        for value in ('', 'a'*63, 'A'*64, 'g'*64, 23):
            with self.assertRaises(ValueError):
                tr.validate_token_hash(value)

    def test_max_peer_ids_on_live_receiver(self):
        receiver=tr.PeerReceiver(strict_peers=True)
        for n in range(32):
            receiver.add_peer_hash('name'+str(n),tr.fingerprint_token('a'*64))
        with self.assertRaises(ValueError):
            receiver.add_peer_hash('name_overflow',tr.fingerprint_token('a'*64))

    def test_no_listener_or_shared_secret_in_strict_receiver(self):
        receiver=tr.PeerReceiver(strict_peers=True)
        self.assertEqual(receiver.token,'')
        self.assertIsNone(receiver._httpd)
        self.assertEqual(receiver._peers,{})
