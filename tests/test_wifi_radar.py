"""Wi-Fi RADAR verifies observed state and refuses inference over missing data."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from bloodsky_net import wifi, wifi_radar
from bloodsky_net.storage import Storage

NOW = datetime(2026, 10, 28, 8, 0, tzinfo=timezone.utc)
MAC1 = 'AA:BB:CC:DD:EE:01'
MAC2 = 'AA:BB:CC:DD:EE:02'

def row(seconds, connected=1, ssid='Office', bssid=MAC1, signal=75, channel=36):
    return ((NOW+timedelta(seconds=seconds)).isoformat(), connected, ssid, bssid, signal, channel)

def summary(*rows):
    return wifi_radar.analyze(wifi_radar.normalize_rows(rows, NOW+timedelta(seconds=240)))

class RadarTests(unittest.TestCase):
    def test_roam_same_ssid_with_fresh_measurements(self):
        result = summary(row(0), row(30, bssid=MAC2))
        self.assertEqual(result.roams, 1)
        self.assertEqual(result.events[0].kind, 'roam')

    def test_network_switch_not_called_roam(self):
        result = summary(row(0), row(30, ssid='Guest', bssid=MAC2))
        self.assertEqual(result.roams, 0)
        self.assertEqual(result.events[0].kind, 'network_change')

    def test_no_roaming_for_large_gap(self):
        result = summary(row(0), row(200, bssid=MAC2))
        self.assertEqual(result.roams, 0)
        self.assertEqual(result.events, ())

    def test_disconnection_only_explicit_recent_measurement(self):
        result = summary(row(0), row(30, connected=0, ssid='', bssid='', signal=0))
        self.assertEqual(result.disconnections, 1)
        self.assertIsNone(wifi_radar.normalize_rows([row(30,connected=0)], NOW+timedelta(seconds=240))[0].signal)

    def test_disconnection_not_assumed_over_gap(self):
        result = summary(row(0), row(200, connected=0, ssid='', bssid='', signal=0))
        self.assertEqual(result.disconnections, 0)

    def test_two_weak_samples_one_period(self):
        result = summary(row(0,signal=42),row(30,signal=39),row(60,signal=40),row(90,signal=35))
        self.assertEqual(result.low_signal_periods, 1)
        self.assertEqual(len([x for x in result.events if x.kind=='weak_signal']),1)

    def test_one_weak_sample_not_a_period(self):
        result = summary(row(0,signal=30),row(30,signal=70))
        self.assertEqual(result.low_signal_periods, 0)

    def test_weak_samples_on_two_bssid_not_contiguous(self):
        result = summary(row(0,signal=35),row(30,signal=30,bssid=MAC2))
        self.assertEqual(result.low_signal_periods, 0)
        self.assertEqual(result.roams, 1)

    def test_invalid_or_unauthorized_data_dropped(self):
        rows=[row(0,bssid='unknown'),row(10,signal=101),row(20,channel=-1),row(30,signal=-5),row(40)]
        self.assertEqual(len(wifi_radar.normalize_rows(rows, NOW+timedelta(seconds=240))),1)

    def test_naive_future_and_old_timestamps_rejected(self):
        data=[('2026-10-28T08:00:00',1,'Office',MAC1,50,36),row(241),
              ('2026-10-01T00:00:00+00:00',1,'Office',MAC1,60,36),row(0)]
        self.assertEqual(len(wifi_radar.normalize_rows(data, NOW+timedelta(seconds=240))),1)

    def test_empty_data_no_health_score_fabricated(self):
        r=summary();self.assertEqual(r.sample_count,0);self.assertIsNone(r.mean_signal)

    def test_channel_zero_unknown_preserved(self):
        s=wifi_radar.normalize_rows([row(0,channel=0)],NOW+timedelta(seconds=240))[0]
        self.assertIsNone(s.channel)

    def test_offset_timestamps_work_and_sort(self):
        rows=[('2026-10-28T11:00:30+03:00',1,'Office',MAC2,70,36),
              ('2026-10-28T08:00:00+00:00',1,'Office',MAC1,80,36)]
        self.assertEqual(wifi_radar.analyze(wifi_radar.normalize_rows(rows,NOW+timedelta(seconds=40))).roams,1)

    def test_historical_storage_bound_and_persistence(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'network.db'
            store=Storage(path)
            store.save_wifi_sample(True,'Office', MAC1,75,36)
            store.save_wifi_sample(False,'','',0,0)
            rows=store.wifi_radar_rows(1)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0][1],0)
            self.assertEqual(store.wifi_radar_rows(500000)[-1][1],0)
            store.close()
            another=Storage(path)
            self.assertEqual(len(another.wifi_radar_rows()),2)
            another.close()

    def test_windows_wlan_error_unmeasured(self):
        with patch.object(wifi.os,'name','nt'),patch.object(wifi,'command',return_value=(1,'')):
            got=wifi.read_wifi()
            self.assertTrue(got.status.issue)
            self.assertFalse(got.status.adapter)

    def test_no_adapter_is_not_proven_disconnected(self):
        with patch.object(wifi.os,'name','nt'),patch.object(wifi,'command',return_value=(0,'')):
            got=wifi.read_wifi()
            self.assertIn('Нет достоверного статуса WLAN',got.status.issue)

if __name__=='__main__':
    unittest.main()
