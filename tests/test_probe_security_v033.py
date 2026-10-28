"""Loopback-only regression tests for bounded TLS and replay protection."""
from datetime import datetime, timezone
import http.client
import socket
import ssl
import time
import unittest
from unittest.mock import patch
from bloodsky_net import distributed_probes as probes, probe_transport as tr


def fresh():
    now = datetime.now(timezone.utc)
    return probes.create_snapshot('test', [('192.168.25.10', 'reply', now)], now)


class HardenedReceiverTests(unittest.TestCase):
    def setUp(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.receiver = tr.PeerReceiver('127.0.0.1', port).start()

    def tearDown(self):
        self.receiver.stop()

    def send(self, snapshot):
        conn = http.client.HTTPSConnection(
            '127.0.0.1', self.receiver.port, timeout=3,
            context=ssl._create_unverified_context())
        try:
            conn.request('POST', '/probe', body=probes.encode(snapshot),
                         headers={'Authorization': 'Bearer ' + self.receiver.token})
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()

    def test_full_replay_cache_never_clears_old_ids(self):
        first = fresh()
        with patch.object(tr, 'MAX_REPLAY_IDS', 3):
            self.assertEqual(self.send(first), 202)
            self.receiver.incoming.get(timeout=2)
            for _ in range(2):
                self.assertEqual(self.send(fresh()), 202)
                self.receiver.incoming.get(timeout=2)
            self.assertEqual(self.send(fresh()), 503)
            self.assertEqual(self.send(first), 409)

    def test_replay_cache_expires_old_entries(self):
        first = fresh()
        with patch.object(tr, 'MAX_REPLAY_IDS', 1):
            self.assertEqual(self.send(first), 202)
            self.receiver.incoming.get(timeout=2)
            self.assertEqual(self.send(fresh()), 503)
            with self.receiver._ids_lock:
                self.receiver._ids[first.ident] = time.monotonic() - tr.REPLAY_TTL_SECONDS - 1
            self.assertEqual(self.send(fresh()), 202)
            self.receiver.incoming.get(timeout=2)

    def test_incomplete_post_body_does_not_block_other_clients(self):
        sock = socket.create_connection(('127.0.0.1', self.receiver.port), timeout=3)
        slow = ssl._create_unverified_context().wrap_socket(sock, server_hostname='localhost')
        try:
            slow.sendall(b'POST /probe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n'
                         + b'Authorization: Bearer ' + self.receiver.token.encode()
                         + b'\r\n\r\n{}')
            self.assertEqual(self.send(fresh()), 202)
            self.receiver.incoming.get(timeout=2)
        finally:
            slow.close()

    def test_unfinished_handshake_does_not_block_accept_loop(self):
        stalled = socket.create_connection(('127.0.0.1', self.receiver.port), timeout=3)
        try:
            self.assertEqual(self.send(fresh()), 202)
            self.receiver.incoming.get(timeout=2)
        finally:
            stalled.close()

    def test_bounded_active_connection_count(self):
        self.assertEqual(self.receiver._httpd._slots._value, tr.MAX_CONCURRENT_CLIENTS)
        self.assertEqual(self.receiver._httpd.request_queue_size, 8)


if __name__ == '__main__':
    unittest.main()
