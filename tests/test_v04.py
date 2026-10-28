import tempfile
import unittest
from pathlib import Path
from bloodsky_net.network import MacHistory
from bloodsky_net.storage import Storage

A = '11:22:33:44:55:66'
B = '66:55:44:33:22:11'

class ConflictTests(unittest.TestCase):
    def test_first_change_only_informational(self):
        h = MacHistory()
        self.assertEqual(h.ingest({'10.0.0.2': A}, 100), [])
        out = h.ingest({'10.0.0.2': B}, 110)
        self.assertEqual((out[0].severity, out[0].switches), ('info', 1))

    def test_rapid_flip_flop_elevates_but_does_not_confirm(self):
        h = MacHistory()
        h.ingest({'10.0.0.2': A}, 100)
        h.ingest({'10.0.0.2': B}, 110)
        out = h.ingest({'10.0.0.2': A}, 125)
        self.assertEqual((out[0].severity, out[0].switches), ('warning', 2))

    def test_stable_binding_does_not_spam(self):
        h = MacHistory()
        h.ingest({'10.0.0.2': A}, 100)
        h.ingest({'10.0.0.2': B}, 110)
        self.assertEqual(h.ingest({'10.0.0.2': B}, 120), [])

    def test_old_transition_cannot_elevate(self):
        h = MacHistory()
        h.ingest({'10.0.0.2': A}, 100)
        h.ingest({'10.0.0.2': B}, 110)
        out = h.ingest({'10.0.0.2': A}, 500)
        self.assertEqual(out[0].severity, 'info')

    def test_stale_arp_binding_not_alerted(self):
        h = MacHistory()
        h.ingest({'10.0.0.2': A}, 100)
        self.assertEqual(h.ingest({'10.0.0.2': B}, 1200), [])

    def test_invalid_mac_ignored(self):
        h = MacHistory()
        self.assertEqual(h.ingest({'10.0.0.2': 'INVALID'}, 100), [])

class WiFiHistoryTests(unittest.TestCase):
    def test_samples_and_persistence(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'local.db'
            s = Storage(p)
            s.save_wifi_sample(True, 'Lab WiFi', 'AA:BB:CC:DD:EE:FF', 88, 36)
            s.save_wifi_sample(False, '', '', 0, 0)
            self.assertEqual(s.wifi_signal_history(), [88., None])
            s.close()
            s2 = Storage(p)
            self.assertEqual(s2.wifi_signal_history(1), [None])
            s2.close()

    def test_sample_limits(self):
        with tempfile.TemporaryDirectory() as td:
            s = Storage(Path(td) / 'local.db')
            s.save_wifi_sample(True, 'x' * 200, 'm'*100, 900, 1)
            row = s.db.execute('SELECT ssid, bssid, signal FROM wifi_samples').fetchone()
            self.assertEqual((len(row[0]),len(row[1]),row[2]), (128,32,100))
            s.close()

if __name__ == '__main__':
    unittest.main()
