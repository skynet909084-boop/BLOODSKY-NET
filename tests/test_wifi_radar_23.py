"""Wi-Fi RADAR 2.3: named repeat visits, per-SSID evidence, safe local reports."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bloodsky_net.storage import Storage
from bloodsky_net.wifi_survey import (SurveyPoint, compare_phases, survey_html_report,
                                      survey_report, ssid_room_quality, validate_point)

T='2026-10-28T08:00:00+00:00'
MAC='AA:BB:CC:DD:EE:11'


def row(phase='До', signal=40, series='Посещение 1', ssid='Office', room='Кабинет', zone='Этаж 1'):
    return validate_point(zone,20,60,ssid,MAC,signal,36,T,room=room,phase=phase,series=series)


class RepeatVisitsTests(unittest.TestCase):
    def test_valid_named_series_and_default_migration_label(self):
        self.assertEqual(row().series,'Посещение 1')
        self.assertEqual(validate_point('Этаж 1',0,0,'Office',MAC,45,36,T).series,'Без серии')
        self.assertEqual(row(series='  Измерение 2  ').series,'Измерение 2')

    def test_reject_invalid_series(self):
        for s in ('',' ','a'*61,'x\ny',None,42):
            with self.subTest(s=s),self.assertRaises(ValueError):
                row(series=s)

    def test_isolated_series_even_without_explicit_filter(self):
        rows=[row('До',30),row('До',35),row('После',80,series='Посещение 2'),
              row('После',70,series='Посещение 2')]
        self.assertEqual(compare_phases(rows,'Этаж 1'),())
        self.assertEqual(compare_phases(rows,'Этаж 1',series='Посещение 1'),())

    def test_before_after_within_one_series(self):
        rows=[row('До',30),row('До',50),row('После',70),row('После',90),
              row('До',10,series='Посещение 2'),row('До',10,series='Посещение 2')]
        got=compare_phases(rows,'Этаж 1',series='Посещение 1')
        self.assertEqual(len(got),1)
        self.assertEqual((got[0].delta,got[0].series),(40,'Посещение 1'))

    def test_do_not_mix_ssid_room_or_floor(self):
        rows=[row('До',30),row('До',40),row('После',90,ssid='Guest'),row('После',85,ssid='Guest'),
              row('После',95,room='Прихожая'),row('После',95,zone='Этаж 2')]
        self.assertEqual(compare_phases(rows,'Этаж 1'),())

    def test_per_ssid_and_phase_aggregation(self):
        rows=[row('До',10),row('До',50),row('После',90),row('До',70,ssid='Guest'),
              row('До',5,room='Кухня'),row('До',99,zone='Этаж 2'),row('До',0,series='Посещение 2')]
        quality=ssid_room_quality(rows,'Этаж 1','Посещение 1')
        self.assertEqual(len(quality),4)
        office=[x for x in quality if x.room=='Кабинет' and x.ssid=='Office' and x.phase=='До'][0]
        self.assertEqual((office.samples,office.mean_signal,office.min_signal),(2,30,10))

    def test_bad_sensor_or_unmeasured_ssid_does_not_create_false_low(self):
        invalid=SurveyPoint(T,'Этаж 1',30,20,'Unknown',MAC,150,36,'Кабинет','До','Посещение 1')
        rows=[row('До',10),invalid]
        report=survey_report(rows,'Этаж 1','Посещение 1')
        self.assertEqual(len(report['rooms']),1)
        self.assertEqual(report['review_candidates'],[])

    def test_low_signal_candidate_needs_three_samples_in_same_group(self):
        rows=[row('До',40)]*2+[row('После',20)]*3+[row('После',90,ssid='Guest')]*3
        report=survey_report(rows,'Этаж 1','Посещение 1')
        self.assertEqual(len(report['review_candidates']),1)
        self.assertEqual((report['review_candidates'][0]['ssid'],report['review_candidates'][0]['phase']),('Office','После'))
        self.assertEqual(len(report['rooms']),3)
        self.assertEqual(len(report['comparisons']),1)

    def test_reports_are_explicitly_limited_to_selected_series(self):
        report=survey_report([row('До',5,series='Hidden'),row('До',80)],'Этаж 1','Посещение 1')
        self.assertEqual(len(report['rooms']),1)
        self.assertEqual(report['rooms'][0]['mean_windows_percent'],80)

    def test_html_escapes_untrusted_zone_room_ssid_and_has_no_remote_resources(self):
        rows=[row(room='<script>alert(1)</script>',ssid='WiFi & <img src=x onerror=alert(1)>')]*3
        report=survey_report(rows,'Этаж 1','Посещение 1')
        html=survey_html_report(report)
        self.assertNotIn('<script>',html)
        self.assertNotIn('<img',html)
        self.assertIn('&lt;script&gt;',html)
        self.assertIn('&amp;',html)
        self.assertIn('Content-Security-Policy',html)
        self.assertNotIn('<script src',html)
        self.assertNotIn('AA:BB:CC',html)
        json_str=json.dumps(report,ensure_ascii=False)
        self.assertNotIn('AA:BB:CC',json_str)
        self.assertNotIn('password',json_str)

    def test_no_unmeasured_areas_assessed(self):
        report=survey_report([],'Этаж 1','Посещение 1')
        self.assertEqual((report['rooms'],report['review_candidates'],report['comparisons']),([],[],[]))


class StorageTests(unittest.TestCase):
    def test_save_and_reopen_multiple_series(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'network.db'
            a=Storage(path)
            a.save_wifi_survey_point('Этаж 1',20,20,'Office',MAC,44,36,room='A',phase='До',series='Первый')
            a.save_wifi_survey_point('Этаж 1',20,20,'Office',MAC,72,36,room='A',phase='После',series='Второй')
            a.close()
            b=Storage(path)
            self.assertEqual([p.series for p in b.wifi_survey_points()],['Первый','Второй'])
            b.close()

    def test_migrate_legacy_v022_with_explicit_phase(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'network.db'
            db=sqlite3.connect(path)
            db.execute('CREATE TABLE wifi_survey (id INTEGER PRIMARY KEY,ts TEXT NOT NULL,zone TEXT NOT NULL,x REAL NOT NULL,y REAL NOT NULL,ssid TEXT NOT NULL,bssid TEXT NOT NULL,signal INTEGER NOT NULL,channel INTEGER NOT NULL,room TEXT NOT NULL,phase TEXT NOT NULL)')
            db.execute('INSERT INTO wifi_survey VALUES (1,?,?,?,?,?,?,?,?,?,?)',(T,'Этаж 1',10,20,'Office',MAC,50,36,'Кухня','До'))
            db.commit();db.close()
            store=Storage(path)
            self.assertEqual(store.wifi_survey_points()[0].series,'Без серии')
            self.assertEqual(store.wifi_survey_points()[0].phase,'До')
            store.close()

    def test_invalid_series_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            store=Storage(Path(td)/'network.db')
            with self.assertRaises(ValueError):
                store.save_wifi_survey_point('Этаж 1',20,20,'Office',MAC,44,36,series='bad\nseries')
            self.assertEqual(store.wifi_survey_points(),())
            store.close()

    def test_storage_no_credentials(self):
        with tempfile.TemporaryDirectory() as td:
            store=Storage(Path(td)/'network.db')
            store.save_wifi_survey_point('Этаж 1',20,20,'Office',MAC,44,36,series='Визит')
            cols=[r[1] for r in store.db.execute('PRAGMA table_info(wifi_survey)')]
            self.assertNotIn('password',cols)
            self.assertNotIn('community',cols)
            store.close()


if __name__=='__main__': unittest.main()
