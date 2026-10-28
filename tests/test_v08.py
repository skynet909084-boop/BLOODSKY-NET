"""v0.8 robustness / installer regression checks; no physical hardware required."""
from __future__ import annotations

from pathlib import Path
from queue import Queue
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bloodsky_net.storage import Storage, EVENT_MAX_ROWS, EVENT_RETENTION_DAYS
from bloodsky_net.ui import NetApp


class EventRetentionTests(unittest.TestCase):
    def test_event_history_is_bounded_and_old_events_expire(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Storage(Path(tmp) / 'events.db')
            # Seed an oversized old DB, as would be found after a 24/7 v0.7 deployment.
            store.db.executemany(
                'INSERT INTO events(ts, severity, title, detail) VALUES (?,?,?,?)',
                [('2020-01-01T00:00:00+00:00', 'info', 'old', 'prior')] * (EVENT_MAX_ROWS + 10),
            )
            store.db.commit()
            for i in range(100):
                store.event('info', 'test', f'event-{i}')
            count, oldest = store.db.execute('SELECT count(*), min(title) FROM events').fetchone()
            self.assertEqual(count, 100)
            self.assertEqual(oldest, 'test')
            self.assertEqual(len(store.events(10)), 10)
            store.close()

    def test_retention_never_persists_snmp_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Storage(Path(tmp) / 'events.db')
            store.event('info', 'Обзор', '10.1.1.1')
            cols = [row[1] for row in store.db.execute('PRAGMA table_info(events)')]
            for secret in ('password', 'community', 'secret'):
                self.assertFalse(any(secret in name for name in cols))
            store.close()


class WiFiPollingTests(unittest.TestCase):
    def test_slow_wifi_read_does_not_spawn_concurrent_workers(self):
        entered, release = threading.Event(), threading.Event()
        output = Queue()
        app = SimpleNamespace(_closed=False, _wifi_busy=threading.Event(), _wifi_lock=threading.Lock(), messages=output)
        calls = []
        def slow_wifi():
            calls.append(1)
            entered.set()
            self.assertTrue(release.wait(timeout=3))
            return 'report'
        with patch('bloodsky_net.ui.wifi.read_wifi', side_effect=slow_wifi):
            NetApp._read_wifi_background(app)
            self.assertTrue(entered.wait(timeout=3))
            for _ in range(10):
                NetApp._read_wifi_background(app)
            self.assertEqual(len(calls), 1)
            release.set()
            deadline = time.monotonic() + 3
            while app._wifi_busy.is_set() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertFalse(app._wifi_busy.is_set())
            self.assertEqual(output.get_nowait(), ('wifi', 'report'))

    def test_concurrent_wifi_requests_share_one_worker(self):
        entered, release = threading.Event(), threading.Event()
        app = SimpleNamespace(_closed=False, _wifi_busy=threading.Event(),
                              _wifi_lock=threading.Lock(), messages=Queue())
        count = []
        def slow_read():
            count.append(1)
            entered.set()
            release.wait(3)
            return 'ok'
        with patch('bloodsky_net.ui.wifi.read_wifi', side_effect=slow_read):
            callers = [threading.Thread(target=NetApp._read_wifi_background, args=(app,)) for _ in range(25)]
            for caller in callers:
                caller.start()
            self.assertTrue(entered.wait(3))
            for caller in callers:
                caller.join(3)
            self.assertEqual(len(count), 1)
            release.set()
            deadline = time.monotonic() + 3
            while app._wifi_busy.is_set() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertFalse(app._wifi_busy.is_set())

    def test_failed_wifi_query_does_not_leave_stuck_worker(self):
        app = SimpleNamespace(_closed=False, _wifi_busy=threading.Event(), _wifi_lock=threading.Lock(), messages=Queue())
        with patch('bloodsky_net.ui.wifi.read_wifi', side_effect=OSError('private diagnostic text')):
            NetApp._read_wifi_background(app)
            deadline = time.monotonic() + 3
            while app._wifi_busy.is_set() and time.monotonic() < deadline:
                time.sleep(.01)
        self.assertFalse(app._wifi_busy.is_set())
        self.assertTrue(app.messages.empty())


class InstallerTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]

    def test_per_user_installer_does_not_delete_database(self):
        cfg = (self.root / 'installer' / 'BLOODSKY-NET.iss').read_text('utf-8')
        self.assertIn('PrivilegesRequired=lowest', cfg)
        self.assertIn('DefaultDirName={localappdata}', cfg)
        self.assertIn('ArchitecturesAllowed=x64compatible', cfg)
        self.assertIn('BLOODSKY-NET.exe', cfg)
        self.assertNotIn('[UninstallDelete]', cfg)
        self.assertIn('RegQueryStringValue', cfg)
        self.assertIn('RegDeleteValue', cfg)
        self.assertNotIn('runascurrentuser', cfg)

    def test_ci_builds_and_uploads_both_exe_and_installer(self):
        config = (self.root / '.github' / 'workflows' / 'windows-build.yml').read_text('utf-8')
        self.assertIn('runs-on: windows-latest', config)
        self.assertIn('Inno Setup', config)
        self.assertIn('BLOODSKY-NET-Installer', config)
        self.assertIn('BLOODSKY-NET-Windows', config)
        self.assertIn('python -m unittest discover', config)


if __name__ == '__main__':
    unittest.main()
