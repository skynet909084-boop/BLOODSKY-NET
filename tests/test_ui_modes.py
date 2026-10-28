"""UI-only regression checks. Never inspect LAN, secrets or real profiles."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bloodsky_net.storage import Storage
from bloodsky_net.ui_easy import SIMPLE_PAGES, SIMPLE_NAMES, NetApp
from bloodsky_net.ui_modes import read_ui_flag, write_ui_flag


class ModePreferencesTests(unittest.TestCase):
    def test_no_database_migration_or_default_profile_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'app.db'
            store = Storage(db)
            self.assertFalse(read_ui_flag(store, 'advanced_ui'))
            self.assertFalse(read_ui_flag(store, 'onboarding_seen'))
            write_ui_flag(store, 'advanced_ui', True)
            write_ui_flag(store, 'onboarding_seen', True)
            store.close()
            store = Storage(db)
            self.assertTrue(read_ui_flag(store, 'advanced_ui'))
            self.assertTrue(read_ui_flag(store, 'onboarding_seen'))
            self.assertFalse(store.get_preference('windows_alerts_enabled'))
            store.close()

    def test_cannot_store_arbitrary_keys_or_non_boolean_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Storage(Path(tmp)/'app.db')
            for key in ('tls_token','probe_secret','unknown', 'advanced_ui;drop table preferences'):
                with self.assertRaises(ValueError):
                    write_ui_flag(store,key,True)
                with self.assertRaises(ValueError):
                    read_ui_flag(store,key)
            with self.assertRaises(ValueError):
                write_ui_flag(store,'advanced_ui','password')
            store.close()

    def test_modes_have_five_unique_simple_pages(self):
        self.assertEqual(len(SIMPLE_PAGES), 5)
        self.assertEqual(len(set(SIMPLE_PAGES)), 5)
        self.assertEqual(set(SIMPLE_PAGES), set(SIMPLE_NAMES))
        self.assertIn('Детектив', SIMPLE_PAGES)

    def test_entrypoint_uses_friendly_shell_and_selfcheck_remains(self):
        app = (Path(__file__).resolve().parents[1] / 'app.py').read_text('utf-8')
        self.assertIn('from bloodsky_net.ui_easy import NetApp', app)
        self.assertIn('"--self-check" in sys.argv', app)


if __name__=='__main__':
    unittest.main()
