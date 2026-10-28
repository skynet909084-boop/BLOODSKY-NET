"""RADAR 2.1: user-imported image, measured room labels and SQLite migration."""
from io import BytesIO
from pathlib import Path
import sqlite3
import tempfile
import unittest

from PIL import Image

from bloodsky_net.wifi_floorplan import (sanitize_floorplan, image_bounds, canvas_to_percent,
    percent_to_canvas, MAX_SOURCE_BYTES, MAX_STORED_BYTES)
from bloodsky_net.wifi_survey import validate_point, room_quality
from bloodsky_net.storage import Storage

STAMP = '2026-10-28T08:00:00+00:00'
MAC = 'AA:BB:CC:DD:EE:11'


def sample_image(mode='RGB', fmt='PNG', size=(1000, 500)):
    f = BytesIO()
    Image.new(mode, size, (50, 80, 160)).save(f, fmt)
    return f.getvalue()


class PlanImportTests(unittest.TestCase):
    def test_png_jpeg_normalized_and_dims_preserved(self):
        for fmt in ('PNG', 'JPEG'):
            with self.subTest(fmt=fmt):
                p = sanitize_floorplan(sample_image(fmt=fmt))
                self.assertTrue(p.jpeg.startswith(b'\xff\xd8'))
                self.assertEqual((p.width, p.height), (1000, 500))
                self.assertLessEqual(len(p.jpeg), MAX_STORED_BYTES)

    def test_no_original_exif_retained(self):
        img = Image.new('RGB', (20, 20), 'white')
        exif = Image.Exif()
        exif[270] = 'CONFIDENTIAL-PLAN-METADATA'
        b = BytesIO()
        img.save(b, 'JPEG', exif=exif)
        self.assertNotIn(b'CONFIDENTIAL-PLAN-METADATA', sanitize_floorplan(b.getvalue()).jpeg)

    def test_alpha_image_has_no_hidden_metadata(self):
        p = sanitize_floorplan(sample_image(mode='RGBA'))
        self.assertTrue(p.jpeg.startswith(b'\xff\xd8'))

    def test_reject_unsupported_corrupt_empty_and_large(self):
        for bad in (b'', b'GIF89a' + b'X'*50, b'fake', b'X'*(MAX_SOURCE_BYTES+1), 'hello'):
            with self.subTest(type=type(bad), length=len(bad)), self.assertRaises(ValueError):
                sanitize_floorplan(bad)

    def test_reject_oversized_pixel_count_before_decode(self):
        with self.assertRaises(ValueError):
            sanitize_floorplan(sample_image(size=(5000, 5000)))

    def test_aspect_fit_transform_and_click_margin(self):
        bounds = image_bounds(1000, 700, 1000, 500)
        self.assertEqual(bounds, (0, 100, 1000, 500))
        self.assertIsNone(canvas_to_percent(50, 50, bounds))
        self.assertIsNone(canvas_to_percent(50, 601, bounds))
        self.assertEqual(canvas_to_percent(500, 350, bounds), (50, 50))
        self.assertEqual(percent_to_canvas(50, 50, bounds), (500, 350))
        self.assertEqual(canvas_to_percent(0, 100, bounds), (0, 0))

    def test_no_zero_geometry(self):
        with self.assertRaises(ValueError):
            image_bounds(0, 100, 1000, 1000)
        with self.assertRaises(ValueError):
            percent_to_canvas(101, 0, (0, 0, 200, 100))


class RoomPersistenceTests(unittest.TestCase):
    def test_room_validation_and_quality(self):
        a = validate_point('Этаж 1', 20, 30, 'Office', MAC, 35, 36, STAMP, room='Кухня')
        b = validate_point('Этаж 1', 20, 30, 'Office', MAC, 85, 36, STAMP, room='Кухня')
        c = validate_point('Этаж 1', 20, 30, 'Office', MAC, 70, 36, STAMP, room='Кабинет')
        self.assertEqual([(q.zone, q.mean_signal, q.samples) for q in room_quality((a,b,c), 'Этаж 1')],
                         [('Кабинет',70,1),('Кухня',60,2)])
        self.assertEqual(room_quality((a,b,c), 'Другой этаж'), ())

    def test_reject_bad_room_labels(self):
        for room in ('', '   ', 'X'*61, 'Bad\nRoom', None):
            with self.subTest(room=room), self.assertRaises(ValueError):
                validate_point('Этаж', 1, 1, 'SSID', MAC, 50, 36, STAMP, room=room)

    def test_room_stored_after_reopen(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'net.db'
            s = Storage(path)
            s.save_wifi_survey_point('Этаж 1', 25, 50, 'Office', MAC, 70, 36, room='Зал')
            s.close()
            s = Storage(path)
            self.assertEqual(s.wifi_survey_points()[0].room, 'Зал')
            s.close()

    def test_old_survey_migrates_with_default_room(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'old.db'
            con = sqlite3.connect(path)
            con.execute('CREATE TABLE wifi_survey (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, zone TEXT NOT NULL, x REAL NOT NULL, y REAL NOT NULL, ssid TEXT NOT NULL, bssid TEXT NOT NULL, signal INTEGER NOT NULL, channel INTEGER NOT NULL)')
            con.execute('INSERT INTO wifi_survey(ts,zone,x,y,ssid,bssid,signal,channel) VALUES (?,?,?,?,?,?,?,?)',
                        (STAMP, 'Old', 10, 20, 'Wifi', MAC, 80, 36))
            con.commit(); con.close()
            s = Storage(path)
            self.assertEqual(s.wifi_survey_points()[0].room, 'Без комнаты')
            s.save_wifi_survey_point('New', 10, 20, 'Wifi', MAC, 50, 36, room='Кабинет')
            s.close()

    def test_floorplan_persistence_independence_and_delete(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'plan.db'
            s = Storage(path)
            p = s.save_wifi_floorplan('Этаж 1', sample_image())
            s.save_wifi_survey_point('Этаж 1', 50, 50, 'Office', MAC, 77, 36, room='Зал')
            self.assertEqual(s.wifi_floorplan('Этаж 1'), p)
            self.assertIsNone(s.wifi_floorplan('Этаж 2'))
            s.close()
            s = Storage(path)
            self.assertEqual(s.wifi_floorplan('Этаж 1'), p)
            s.delete_wifi_floorplan('Этаж 1')
            self.assertIsNone(s.wifi_floorplan('Этаж 1'))
            self.assertEqual(s.wifi_survey_points()[0].room, 'Зал')
            s.close()

    def test_floorplan_invalid_zone_does_not_change_db(self):
        with tempfile.TemporaryDirectory() as td:
            s = Storage(Path(td)/'net.db')
            with self.assertRaises(ValueError):
                s.save_wifi_floorplan('../\n', sample_image())
            self.assertEqual(s.db.execute('SELECT COUNT(*) FROM wifi_floorplans').fetchone()[0], 0)
            s.close()


if __name__=='__main__':
    unittest.main()
