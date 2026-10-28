"""Manual Wi-Fi survey: measurable points, no phantom heatmap or inferred faults."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bloodsky_net.wifi_survey import (validate_point, zone_quality, signal_color, spreadsheet_safe,
                                      MAX_POINTS)
from bloodsky_net.storage import Storage
from bloodsky_net import wifi_radar

STAMP = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
MAC1='AA:BB:CC:DD:EE:01'
MAC2='AA:BB:CC:DD:EE:02'


def point(zone='Этаж 1', x=20., y=60., signal=71, bssid=MAC1, ts=STAMP):
    return validate_point(zone, x, y, 'Office', bssid, signal, 36, ts)

class SurveyValidationTests(unittest.TestCase):
    def test_valid_point_normalizes_zone_and_bssid(self):
        p=validate_point(' Hall  ',1,2,'Office',MAC1.lower(),80,36,STAMP)
        self.assertEqual((p.zone,p.bssid,p.signal,p.x,p.y),('Hall',MAC1,80,1.,2.))
    def test_coordinate_bounds_and_non_numeric_rejected(self):
        for x,y in [(-1,0),(0,101),(float('nan'),10),(float('inf'),20),('0',20),(True,1)]:
            with self.subTest(x=x,y=y),self.assertRaises(ValueError): point(x=x,y=y)
    def test_bad_zone_rejected(self):
        for z in ['', '  ','A'*61,'Foo\nBar',None]:
            with self.subTest(z=z),self.assertRaises(ValueError): point(zone=z)
    def test_unverified_bssid_and_ssid_rejected(self):
        for mac in ('unknown','',MAC1[:-2]+'ZZ'):
            with self.subTest(mac=mac),self.assertRaises(ValueError):point(bssid=mac)
        with self.assertRaises(ValueError): validate_point('Hall',5,5,'',MAC1,70,5,STAMP)
    def test_invalid_percentage_and_channel_rejected(self):
        for signal in (-1,101,True,50.5):
            with self.subTest(signal=signal),self.assertRaises(ValueError):point(signal=signal)
        with self.assertRaises(ValueError):validate_point('Hall',5,5,'Office',MAC1,70,234,STAMP)
    def test_missing_timezone_rejected(self):
        with self.assertRaises(ValueError):point(ts='2026-10-28T10:00:00')
    def test_grouping_does_not_interpolate(self):
        result=zone_quality([point('A',0,0,40),point('A',100,100,80,MAC2),point('B',50,50,70)])
        self.assertEqual([(x.zone,x.samples,x.mean_signal,x.min_signal,x.max_signal,x.distinct_bssids) for x in result],
                         [('A',2,60.0,40,80,2),('B',1,70.0,70,70,1)])
    def test_empty_never_fabricates_score(self):
        self.assertEqual(zone_quality(()),())
    def test_color_thresholds(self):
        self.assertEqual(signal_color(44),'#FF6D7D')
        self.assertEqual(signal_color(45),'#FFBD60')
        self.assertEqual(signal_color(70),'#4CD4A5')
    def test_csv_formula_safe_network_names(self):
        self.assertEqual(spreadsheet_safe('=HYPERLINK("abc")')[0], "'")
        self.assertEqual(spreadsheet_safe('  @evil')[0], "'")
        self.assertEqual(spreadsheet_safe('Office'),'Office')

class SurveyStorageTests(unittest.TestCase):
    def test_persistence_and_zone_filter(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'net.db'
            store=Storage(path)
            store.save_wifi_survey_point('A',11,22,'Office',MAC1,83,36)
            store.save_wifi_survey_point('B',33,44,'Office',MAC2,25,1)
            self.assertEqual(len(store.wifi_survey_points()),2)
            self.assertEqual(store.wifi_survey_points('A')[0].zone,'A')
            self.assertEqual(store.wifi_survey_points('C'),())
            store.close()
            store=Storage(path)
            self.assertEqual(store.wifi_survey_points()[-1].bssid,MAC2)
            store.close()
    def test_rejects_credentials_by_schema(self):
        with tempfile.TemporaryDirectory() as td:
            store=Storage(Path(td)/'net.db')
            cols=[row[1] for row in store.db.execute('PRAGMA table_info(wifi_survey)')]
            self.assertNotIn('password',cols)
            self.assertNotIn('community',cols)
            store.close()
    def test_retention_cleans_old_rows_on_insert(self):
        with tempfile.TemporaryDirectory() as td:
            store=Storage(Path(td)/'net.db')
            old=(datetime.now(timezone.utc)-timedelta(days=32)).isoformat()
            store.save_wifi_survey_point('Old',1,1,'Office',MAC1,40,1,ts=old)
            store.save_wifi_survey_point('New',1,1,'Office',MAC1,40,1)
            self.assertEqual([p.zone for p in store.wifi_survey_points()], ['New'])
            store.close()
    def test_max_rows_bound(self):
        with tempfile.TemporaryDirectory() as td:
            store=Storage(Path(td)/'net.db')
            # Fast bulk insertion mirrors a long-running session; next new sample prunes.
            store.db.executemany('INSERT INTO wifi_survey (ts,zone,x,y,ssid,bssid,signal,channel) VALUES (?,?,?,?,?,?,?,?)',
                                 [(STAMP,'A',1,1,'Office',MAC1,50,1)]*(MAX_POINTS+25))
            store.db.commit()
            store.save_wifi_survey_point('New',1,1,'Office',MAC1,80,1)
            self.assertEqual(len(store.wifi_survey_points()),MAX_POINTS)
            store.close()

class RoamBounceTests(unittest.TestCase):
    def sample(self,t,bssid,ssid='Office'):
        return wifi_radar.WifiSample(datetime(2026,10,28,8,0,tzinfo=timezone.utc)+timedelta(seconds=t),True,ssid,bssid,65,1)
    def test_back_and_forth_is_observation(self):
        r=wifi_radar.analyze((self.sample(0,MAC1),self.sample(30,MAC2),self.sample(60,MAC1)))
        self.assertEqual(r.roams,2)
        self.assertEqual([e.kind for e in r.events].count('roam_bounce'),1)
    def test_missing_or_large_gap_is_not_bounce(self):
        r=wifi_radar.analyze((self.sample(0,MAC1),self.sample(160,MAC2),self.sample(330,MAC1)))
        self.assertEqual([e.kind for e in r.events].count('roam_bounce'),0)
    def test_ssid_changed_not_bounce(self):
        r=wifi_radar.analyze((self.sample(0,MAC1),self.sample(30,MAC2,'Other'),self.sample(60,MAC1)))
        self.assertEqual([e.kind for e in r.events].count('roam_bounce'),0)

if __name__=='__main__': unittest.main()
