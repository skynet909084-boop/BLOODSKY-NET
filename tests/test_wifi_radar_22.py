"""RADAR 2.2: explicit phases, conservative room comparisons, zoom/pan fidelity."""
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from bloodsky_net.wifi_floorplan import zoomed_bounds, canvas_to_percent, percent_to_canvas
from bloodsky_net.wifi_survey import (SurveyPoint, ZoneQuality, validate_point,
                                      compare_phases, room_signal_status)
from bloodsky_net.storage import Storage

STAMP='2026-10-28T08:00:00+00:00'
MAC='AA:BB:CC:DD:EE:11'


def point(phase='До', signal=30, room='Кухня', ssid='Office', zone='Этаж 1'):
    return validate_point(zone, 25, 30, ssid, MAC, signal, 36, STAMP, room=room, phase=phase)


class PhaseAndComparisonTests(unittest.TestCase):
    def test_explicit_phases_and_old_default(self):
        self.assertEqual(point().phase, 'До')
        self.assertEqual(point('После').phase, 'После')
        self.assertEqual(point('Без этапа').phase, 'Без этапа')
        self.assertEqual(validate_point('Этаж 1', 0, 0, 'Office', MAC, 50, 36, STAMP).phase, 'Без этапа')

    def test_reject_invalid_phase(self):
        for phase in ('', 'after', 'до', 'До\n', '../До', None, 1):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                point(phase)

    def test_no_pairs_no_comparison(self):
        self.assertEqual(compare_phases([point('До'), point('После')], 'Этаж 1'), ())
        self.assertEqual(compare_phases([point('До')]*3, 'Этаж 1'), ())
        self.assertEqual(compare_phases([point('Без этапа')]*8, 'Этаж 1'), ())

    def test_comparison_same_room_and_ssid(self):
        p=[point('До',30), point('До',50), point('После',70), point('После',90)]
        comparisons=compare_phases(p,'Этаж 1')
        self.assertEqual(len(comparisons),1)
        self.assertEqual((comparisons[0].before_mean,comparisons[0].after_mean,comparisons[0].delta),(40,80,40))
        self.assertEqual((comparisons[0].before_samples,comparisons[0].after_samples),(2,2))

    def test_different_ssid_and_rooms_never_pooled(self):
        p=[point('До',40),point('До',40),point('После',80,ssid='Other'),point('После',80,ssid='Other'),
           point('После',80,room='Гостиная'),point('После',80,room='Гостиная')]
        self.assertEqual(compare_phases(p,'Этаж 1'),())

    def test_only_selected_floor(self):
        p=[point('До')]*2+[point('После',80)]*2
        self.assertEqual(compare_phases(p,'Этаж 2'),())

    def test_old_points_not_counted_as_before(self):
        p=[point('Без этапа')]*7+[point('После')]*3
        self.assertEqual(compare_phases(p,'Этаж 1'),())

    def test_invalid_sample_values_are_skipped(self):
        fake=SurveyPoint(STAMP,'Этаж 1',10,10,'Office',MAC,110,36,'Кухня','До')
        p=[point('До',35),fake,point('После',80),point('После',90)]
        self.assertEqual(compare_phases(p,'Этаж 1'),())

    def test_minimum_sample_requirement(self):
        p=[point('До')]*2+[point('После')]*2
        for n in (0,1,31,2.1,True):
            with self.subTest(n=n), self.assertRaises(ValueError):
                compare_phases(p,'Этаж 1',n)

    def test_room_highlight_only_with_enough_measurements(self):
        self.assertEqual(room_signal_status(ZoneQuality('A',1,20,20,20,1)),'insufficient')
        self.assertEqual(room_signal_status(ZoneQuality('A',3,20,20,20,1)),'low')
        self.assertEqual(room_signal_status(ZoneQuality('A',4,60,50,70,1)),'moderate')
        self.assertEqual(room_signal_status(ZoneQuality('A',4,80,70,90,1)),'observed_good')


class ZoomTests(unittest.TestCase):
    def test_default_matches_aspect_fit(self):
        self.assertEqual(zoomed_bounds(800,600,1000,500),(0,100,800,400))

    def test_roundtrip_at_all_zoom_levels(self):
        for scale in (75,100,125,150,200):
            with self.subTest(scale=scale):
                b=zoomed_bounds(800,600,1200,600,scale,50,-20)
                x,y=percent_to_canvas(60,30,b)
                self.assertEqual(canvas_to_percent(x,y,b),(60,30))

    def test_click_outside_image_not_recorded(self):
        b=zoomed_bounds(800,600,1000,500,75)
        self.assertIsNone(canvas_to_percent(0,0,b))

    def test_pan_is_bounded(self):
        b=zoomed_bounds(800,600,1000,500,200,100000,100000)
        self.assertLess(b[0],800)
        self.assertLess(b[1],600)

    def test_invalid_zoom_rejected(self):
        for zoom in (0,50,199,201,'100',True):
            with self.subTest(zoom=zoom), self.assertRaises(ValueError):
                zoomed_bounds(800,600,1000,500,zoom)


class StoragePhaseTests(unittest.TestCase):
    def test_save_reopen_and_filter_same_phase(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'survey.db'
            s=Storage(path)
            s.save_wifi_survey_point('Этаж 1',10,20,'Office',MAC,45,36,room='Кабинет',phase='До')
            s.save_wifi_survey_point('Этаж 1',10,20,'Office',MAC,85,36,room='Кабинет',phase='После')
            s.close()
            s=Storage(path)
            self.assertEqual([p.phase for p in s.wifi_survey_points()],['До','После'])
            s.close()

    def test_legacy_migration_without_room_or_phase(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'old.db'
            c=sqlite3.connect(path)
            c.execute('CREATE TABLE wifi_survey (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, zone TEXT NOT NULL, x REAL NOT NULL, y REAL NOT NULL, ssid TEXT NOT NULL, bssid TEXT NOT NULL, signal INTEGER NOT NULL, channel INTEGER NOT NULL)')
            c.execute('INSERT INTO wifi_survey VALUES (1,?,?,?,?,?,?,?,?)',(STAMP,'Этаж 1',10,20,'Office',MAC,65,36))
            c.commit();c.close()
            s=Storage(path)
            self.assertEqual((s.wifi_survey_points()[0].room,s.wifi_survey_points()[0].phase),('Без комнаты','Без этапа'))
            s.close()

    def test_migration_from_room_only(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'old.db'
            c=sqlite3.connect(path)
            c.execute('CREATE TABLE wifi_survey (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, zone TEXT NOT NULL, x REAL NOT NULL, y REAL NOT NULL, ssid TEXT NOT NULL, bssid TEXT NOT NULL, signal INTEGER NOT NULL, channel INTEGER NOT NULL, room TEXT NOT NULL)')
            c.execute('INSERT INTO wifi_survey VALUES (1,?,?,?,?,?,?,?,?,?)',(STAMP,'Этаж 1',10,20,'Office',MAC,65,36,'Зал'))
            c.commit();c.close()
            s=Storage(path)
            self.assertEqual((s.wifi_survey_points()[0].room,s.wifi_survey_points()[0].phase),('Зал','Без этапа'))
            s.close()
