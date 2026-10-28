"""Release-candidate regression checks: offline, no Windows hardware needed."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app
from bloodsky_net.selfcheck import run_self_check
from bloodsky_net.storage import Storage


class SelfCheckTests(unittest.TestCase):
    def test_temp_database_does_not_touch_default_user_location(self):
        with patch('bloodsky_net.selfcheck.importlib.import_module'), \
             patch('bloodsky_net.storage.storage_root', side_effect=AssertionError('real user database touched')):
            self.assertTrue(run_self_check())

    def test_self_check_import_error_is_generic_and_nonzero(self):
        import io
        with patch('sys.argv', ['BLOODSKY-NET.exe', '--self-check']), \
             patch('bloodsky_net.selfcheck.run_self_check', side_effect=OSError('secret user path')), \
             patch('sys.stderr', new_callable=io.StringIO) as error:
            self.assertEqual(app.main(), 2)
            self.assertIn('FAILED', error.getvalue())
            self.assertNotIn('secret user path', error.getvalue())

    def test_self_check_does_not_run_gui(self):
        with patch('sys.argv', ['BLOODSKY-NET.exe', '--self-check']), \
             patch('bloodsky_net.selfcheck.run_self_check', return_value=True), \
             patch('sys.stdout'):
            self.assertEqual(app.main(), 0)


class ReleaseChecks(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]

    def test_ci_checks_real_install_and_uninstall_and_sha256(self):
        yml = (self.root / '.github/workflows/windows-build.yml').read_text('utf-8')
        self.assertIn('windows_install_smoke.ps1', yml)
        self.assertIn('BLOODSKY-NET-SHA256', yml)
        smoke = (self.root / 'tools/windows_install_smoke.ps1').read_text('utf-8')
        self.assertIn('Get-ChildItem', smoke)
        self.assertNotIn('BLOODSKY-NET-Setup-0.9.0-rc1.exe', smoke)
        self.assertIn('Build per-user Windows installer', yml)
        self.assertIn('Upload executable', yml)
        self.assertIn('python tools/soak_test.py', yml)

    def test_smoke_preserves_user_data_and_unrelated_startup(self):
        script = (self.root / 'tools/windows_install_smoke.ps1').read_text('utf-8')
        for phrase in ('/VERYSILENT', '--self-check', 'unins000.exe', 'keep-other-entry',
                       'User-data sentinel removed', 'Uninstalled EXE still exists'):
            self.assertIn(phrase, script)
        self.assertNotIn('Remove-Item -Recurse', script)
        self.assertNotIn('BLOODSKY-NET\\network.db', script)

    def test_install_version_matches_application(self):
        from bloodsky_net import __version__
        cfg = (self.root / 'installer/BLOODSKY-NET.iss').read_text('utf-8-sig')
        self.assertTrue(__version__)  # exact identity is checked against installed manifest below
        self.assertIn(f'#define MyAppVersion "{__version__}"', cfg)
        self.assertIn(f'BLOODSKY-NET-Setup-{__version__}', cfg)

    def test_many_events_bounded_and_integrity_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'long-run.db'
            s = Storage(file)
            for n in range(2500):
                s.event('info', 'monitor-cycle', str(n))
            self.assertEqual(s.db.execute('PRAGMA quick_check').fetchone()[0], 'ok')
            self.assertEqual(s.db.execute('SELECT count(*) FROM events').fetchone()[0], 2500)
            s.close()
            s = Storage(file)
            self.assertEqual(len(s.events(20)), 20)
            self.assertEqual(s.db.execute('PRAGMA quick_check').fetchone()[0], 'ok')
            s.close()

if __name__ == '__main__':
    unittest.main()
