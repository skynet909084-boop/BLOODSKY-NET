"""Regression checks for safe Windows background/user-session integration."""
from __future__ import annotations

from pathlib import Path
from queue import Queue
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from bloodsky_net import windows_integration as windows
from bloodsky_net.storage import Storage
from bloodsky_net.tray import TrayController
from bloodsky_net.ui import NetApp


class StartupTests(unittest.TestCase):
    def test_exe_arguments_quoted_and_no_secret(self):
        result = windows.startup_command(executable=r"C:\Program Files\BLOODSKY NET\BLOODSKY-NET.exe", frozen=True)
        self.assertEqual(result, '"C:\\Program Files\\BLOODSKY NET\\BLOODSKY-NET.exe" --minimized')
        self.assertNotIn('password', result.lower())

    def test_source_mode_quotes_script(self):
        result = windows.startup_command(executable=r"C:\Python312\python.exe",
                                         script=r"C:\Users\Some User\BLOODSKY NET\app.py", frozen=False)
        self.assertIn('python.exe', result)
        self.assertIn('--minimized', result)
        self.assertIn('app.py', result)

    def test_non_windows_refuses_registry_write(self):
        if windows.os.name != 'nt':
            with self.assertRaises(OSError):
                windows.set_autostart(True)
            self.assertFalse(windows.is_autostart_enabled())

    def test_autostart_writes_only_user_run_key(self):
        registry = {}
        class FakeKey:
            def __enter__(self): return self
            def __exit__(self, *args): return None
        fake = SimpleNamespace(HKEY_CURRENT_USER='HKCU', KEY_SET_VALUE=2, REG_SZ=1)
        def create_key(root, path, *_):
            self.assertEqual((root, path), ('HKCU', windows.RUN_KEY))
            return FakeKey()
        def set_value(key, name, reserved, kind, value):
            self.assertEqual(name, windows.RUN_NAME)
            registry[name] = (value, kind)
        def open_key(root, path, *args):
            self.assertEqual((root, path), ('HKCU', windows.RUN_KEY))
            return FakeKey()
        def query(key, name):
            if name not in registry: raise FileNotFoundError()
            return registry[name]
        def delete(key, name):
            if name not in registry: raise FileNotFoundError()
            registry.pop(name)
        fake.CreateKeyEx = create_key
        fake.SetValueEx = set_value
        fake.OpenKey = open_key
        fake.QueryValueEx = query
        fake.DeleteValue = delete
        with (patch.object(windows, 'os', SimpleNamespace(name='nt')),
              patch.dict('sys.modules', {'winreg': fake})): 
            self.assertTrue(windows.set_autostart(True))
            self.assertIn('--minimized', registry[windows.RUN_NAME][0])
            self.assertFalse(windows.set_autostart(False))
            self.assertNotIn(windows.RUN_NAME, registry)


class PersistentPreferenceTests(unittest.TestCase):
    def test_preferences_persist_but_secrets_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'test.db'
            with_db = Storage(path)
            self.assertFalse(with_db.get_preference('windows_alerts_enabled'))
            with_db.set_preference('monitor_enabled', False)
            with_db.set_preference('minimize_to_tray', True)
            with self.assertRaises(ValueError):
                with_db.set_preference('snmp_password', True)
            with self.assertRaises(ValueError):
                with_db.set_preference('monitor_enabled', 'yes')
            with_db.close()
            reopened = Storage(path)
            self.assertFalse(reopened.get_preference('monitor_enabled', True))
            self.assertTrue(reopened.get_preference('minimize_to_tray'))
            self.assertEqual(reopened.db.execute('SELECT COUNT(*) FROM preferences').fetchone()[0], 2)
            reopened.close()


class BackgroundSafetyTests(unittest.TestCase):
    def test_no_tray_outside_windows(self):
        if windows.os.name != 'nt':
            tray = TrayController(lambda: None, lambda: None)
            self.assertFalse(tray.start())
            self.assertFalse(tray.active)
            tray.stop()

    def test_closing_without_tray_exits(self):
        app = SimpleNamespace(minimize_to_tray=SimpleNamespace(get=lambda: True),
                              tray=None, withdraw=Mock(), shutdown=Mock())
        NetApp.close_window(app)
        app.shutdown.assert_called_once_with()
        app.withdraw.assert_not_called()

    def test_close_with_active_tray_hides_window(self):
        app = SimpleNamespace(minimize_to_tray=SimpleNamespace(get=lambda: True),
                              tray=SimpleNamespace(active=True), withdraw=Mock(), shutdown=Mock())
        NetApp.close_window(app)
        app.withdraw.assert_called_once_with()
        app.shutdown.assert_not_called()

    def test_monitor_crash_reports_sanitized_message(self):
        box = Queue()
        stop = threading.Event()
        app = SimpleNamespace(scanning=False, devices={'10.0.0.1': SimpleNamespace(ports=[])},
                              state_lock=threading.Lock(), gateway='', messages=box, monitor_interval=3,
                              monitor_failures=0, _read_wifi_background=Mock())
        with patch('bloodsky_net.ui.net.poll_devices', side_effect=RuntimeError('password=private!')):
            NetApp._monitor_worker(app, stop)
        self.assertEqual(box.get(), ('monitor_crashed', stop))
        self.assertEqual(box.get(), ('monitor_stopped', stop))

    def test_guard_restarts_only_when_requested(self):
        start = Mock()
        timer = Mock()
        app = SimpleNamespace(_closed=False, monitor_enabled=SimpleNamespace(get=lambda: True),
                              scanning=False, monitor_thread=None, monitor_restart_at=0,
                              devices={'10.0.0.2': object()}, gateway='', monitoring=False,
                              _start_monitor=start, after=timer, _monitor_guard=lambda: None)
        NetApp._monitor_guard(app)
        start.assert_called_once()
        app.monitor_enabled = SimpleNamespace(get=lambda: False)
        start.reset_mock()
        NetApp._monitor_guard(app)
        start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
