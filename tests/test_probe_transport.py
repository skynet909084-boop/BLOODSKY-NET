"""Authenticated TLS multi-vantage exchange: local loopback end-to-end tests."""
from datetime import datetime, timedelta, timezone
import http.client
from pathlib import Path
import socket
import ssl
import unittest
from unittest.mock import patch

from bloodsky_net import distributed_probes as probes, probe_transport as tr


class PeerTransportTests(unittest.TestCase):
    @staticmethod
    def fresh(label='A'):
        now = datetime.now(timezone.utc)
        return probes.create_snapshot(label, [('192.168.12.6', 'reply', now)], now)

    @classmethod
    def setUpClass(cls):
        # OS selects a free loopback port, without exposing a public listener.
        with socket.socket() as temp:
            temp.bind(('127.0.0.1', 0))
            cls.port = temp.getsockname()[1]
            if cls.port < tr.PORT_MIN:
                raise unittest.SkipTest('OS assigned a privileged ephemeral port')
        cls.server = tr.PeerReceiver('127.0.0.1', cls.port).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _manual(self, data, token=None, method='POST', route='/probe'):
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection('127.0.0.1',self.port,context=ctx,timeout=3)
        try:
            conn.request(method,route,body=(data if len(data)<=probes.MAX_BYTES else b''),headers={'Authorization':'Bearer '+(self.server.token if token is None else token),
                   'Content-Length':str(len(data))})
            response=conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()

    def test_success_pinned_tls(self):
        snap = self.fresh('recipient-OK')
        tr.send_snapshot('127.0.0.1',self.port,self.server.fingerprint,self.server.token,snap)
        received=self.server.incoming.get(timeout=3)
        self.assertEqual(received,snap)

    def test_incorrect_fingerprint_does_not_send(self):
        self.server.incoming.queue.clear()
        with self.assertRaises(ssl.SSLError):
            tr.send_snapshot('127.0.0.1',self.port,'0'*64,self.server.token,self.fresh())
        self.assertTrue(self.server.incoming.empty())

    def test_incorrect_token_rejected(self):
        with self.assertRaisesRegex(ValueError,'401'):
            tr.send_snapshot('127.0.0.1',self.port,self.server.fingerprint,'1'*64,self.fresh())
        self.assertTrue(self.server.incoming.empty())

    def test_duplicate_package_rejected(self):
        s=self.fresh()
        self.assertEqual(self._manual(probes.encode(s)),202)
        self.assertEqual(self._manual(probes.encode(s)),409)
        self.assertEqual(self.server.incoming.get(timeout=3),s)

    def test_stale_package_rejected(self):
        then=datetime.now(timezone.utc)-timedelta(minutes=8)
        s=probes.create_snapshot('old',[('192.168.12.8','reply',then)],then)
        self.assertEqual(self._manual(probes.encode(s)),422)
        with self.assertRaisesRegex(ValueError,'свежие'):
            tr.send_snapshot('127.0.0.1',self.port,self.server.fingerprint,self.server.token,s)

    def test_reject_bad_payload(self):
        self.assertEqual(self._manual(b'{broken'),400)

    def test_reject_get_and_wrong_path(self):
        self.assertEqual(self._manual(b'',method='GET'),405)
        self.assertEqual(self._manual(b'{}',route='/'),404)

    def test_no_body_or_too_big(self):
        self.assertEqual(self._manual(b''),413)
        self.assertEqual(self._manual(b'X'*(probes.MAX_BYTES+1)),413)

    def test_secret_not_persisted_on_stop(self):
        with socket.socket() as f:
            f.bind(('127.0.0.1',0));p=f.getsockname()[1]
        receiver=tr.PeerReceiver('127.0.0.1',p).start()
        certificate_dir=Path(receiver._tmp.name)
        token=receiver.token
        self.assertTrue((certificate_dir/'peer-key.pem').exists())
        receiver.stop()
        self.assertFalse(certificate_dir.exists())
        self.assertEqual(receiver.token,'')
        self.assertNotEqual(token,'')

    def test_new_session_rotates_pairing(self):
        with socket.socket() as f:
            f.bind(('127.0.0.1',0));p=f.getsockname()[1]
        a=tr.PeerReceiver('127.0.0.1',p).start()
        old_cert,old_token=a.fingerprint,a.token
        a.stop()
        b=tr.PeerReceiver('127.0.0.1',p).start()
        try:
            self.assertNotEqual(old_cert,b.fingerprint)
            self.assertNotEqual(old_token,b.token)
        finally:
            b.stop()

    def test_no_auto_listener_on_import(self):
        self.assertIsNone(getattr(tr,'default_server',None))

    def test_mismatched_clock_stale(self):
        with patch.object(tr,'SESSION_AGE_SECONDS',5):
            ten=datetime.now(timezone.utc)-timedelta(seconds=15)
            s=probes.create_snapshot('old',[('192.168.12.8','reply',ten)],ten)
            self.assertEqual(self._manual(probes.encode(s)),422)


class PeerValidationTests(unittest.TestCase):
    def test_local_addresses_allowed(self):
        for ip in ('127.0.0.1','10.0.0.1','172.16.2.3','172.31.255.254','192.168.1.1'):
            self.assertEqual(tr.allowed_ip(ip),ip)

    def test_public_wildcard_and_ipv6_rejected(self):
        for ip in ('8.8.8.8','0.0.0.0','224.0.0.1','169.254.1.1','192.0.2.1','::1','localhost',''):
            with self.subTest(ip=ip),self.assertRaises(ValueError): tr.allowed_ip(ip)

    def test_invalid_auth_or_port(self):
        for port in (0,80,65536,True,'18443',None):
            with self.subTest(port=port),self.assertRaises(ValueError):tr.allowed_port(port)
        for v in ('x'*64,'0'*63,'0'*65,'','SHA:256'):
            with self.assertRaises(ValueError):tr.validate_fingerprint(v)
            with self.assertRaises(ValueError):tr.validate_token(v)

    def test_mixed_fingerprint_separator_is_valid(self):
        self.assertEqual(tr.validate_fingerprint(':'.join(['ab']*32)), 'ab'*32)

    def test_transport_has_no_implicit_discovery(self):
        text=Path(tr.__file__).read_text(encoding='utf-8')
        self.assertNotIn('socket.gethostbyname_ex',text)
        self.assertNotIn('UPnP',text)


if __name__ == '__main__':
    unittest.main()
