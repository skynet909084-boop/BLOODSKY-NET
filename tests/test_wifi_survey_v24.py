"""Multi-visit survey comparisons must preserve provenance and not infer coverage."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

from bloodsky_net.wifi_survey import validate_point, survey_report, survey_html_report
from bloodsky_net.wifi_survey_compare import compare_visits, comparison_html
from bloodsky_net.storage import Storage
from bloodsky_net.wifi_floorplan import sanitize_floorplan

NOW = datetime(2026, 10, 28, 10, tzinfo=timezone.utc)
MAC = 'AA:BB:CC:DD:EE:AB'

def point(series, time, signal, room='Кухня', ssid='Office', phase='До', zone='Этаж 1', x=25, y=35):
    return validate_point(zone,x,y,ssid,MAC,signal,36,(NOW+timedelta(minutes=time)).isoformat(),room=room,phase=phase,series=series)

def points():
    return [point('1 сентября',i,40+i) for i in range(3)] + [point('25 октября',10+i,70+i) for i in range(4)]

class SurveyVisitTests(unittest.TestCase):
    def test_compares_only_same_room_ssid_zone(self):
        data = compare_visits(points()+[point('1 сентября',20,1,room='Коридор'),point('25 октября',21,100,ssid='Other'),point('1 сентября',22,1,zone='Этаж 2')], 'Этаж 1', '1 сентября','25 октября')
        self.assertEqual(len(data['comparable_rooms']),1)
        self.assertEqual(data['comparable_rooms'][0]['delta_percentage_points'],30.5)
        self.assertEqual((data['baseline_samples'],data['followup_samples']),(4,5))
        self.assertEqual(data['comparable_rooms'][0]['baseline_samples'],3)
        self.assertEqual(data['comparable_rooms'][0]['followup_samples'],4)

    def test_actual_observation_dates(self):
        data=compare_visits(points(),'Этаж 1','1 сентября','25 октября')
        self.assertIn('2026-10-28T10:00:00+00:00', data['baseline_dates_utc'])
        self.assertIn('2026-10-28T10:13:00+00:00', data['followup_dates_utc'])
        self.assertNotIn('2026-09-01', json.dumps(data))

    def test_below_three_samples_never_reports_change(self):
        data=compare_visits(points()[:2]+points()[3:],'Этаж 1','1 сентября','25 октября')
        self.assertEqual(data['comparable_rooms'],[])
        self.assertEqual(data['baseline_samples'],2)

    def test_other_ssid_not_combined(self):
        rows = points()[:3]+[point('25 октября',i+10,90,ssid='Else') for i in range(4)]
        self.assertEqual(compare_visits(rows,'Этаж 1','1 сентября','25 октября')['comparable_rooms'],[])

    def test_other_room_not_combined(self):
        rows=points()[:3]+[point('25 октября',i+10,90,room='Гостиная') for i in range(4)]
        self.assertFalse(compare_visits(rows,'Этаж 1','1 сентября','25 октября')['comparable_rooms'])

    def test_rejects_same_series_empty_and_invalid_minimum(self):
        for a,b in [('a','a'),('','b'),('b',' '),('b','b ')]:
            with self.subTest(a=a,b=b), self.assertRaises(ValueError):
                compare_visits(points(),'Этаж 1',a,b)
        for n in [True,1,31,0]:
            with self.subTest(n=n),self.assertRaises(ValueError):
                compare_visits(points(),'Этаж 1','a','b',n)

    def test_missing_series_does_not_fabricate_survey_or_ap_outage(self):
        data=compare_visits(points(),'Этаж 1','Нет посещения','25 октября')
        self.assertEqual(data['comparable_rooms'],[])
        self.assertEqual(data['baseline_dates_utc'],('',''))
        self.assertIn('не значит сеть отсутствует',data['limitations'])

    def test_different_phases_comparable_as_explicit_visits(self):
        rows=points()[:3]+[point('25 октября',i+10,80,phase='После') for i in range(3)]
        self.assertEqual(len(compare_visits(rows,'Этаж 1','1 сентября','25 октября')['comparable_rooms']),1)

    def test_invalid_corrupted_points_not_used(self):
        good=points()
        corrupt=SimpleNamespace(zone='Этаж 1',series='25 октября',room='Кухня',ssid='Office',signal=100)
        self.assertEqual(len(compare_visits(good+[corrupt],'Этаж 1','1 сентября','25 октября')['comparable_rooms']),1)

    def test_json_does_not_embed_mac_or_password_or_image(self):
        report=survey_report(points(),'Этаж 1','25 октября')
        report['other_visit_comparison']=compare_visits(points(),'Этаж 1','1 сентября','25 октября')
        raw=json.dumps(report,ensure_ascii=False)
        self.assertNotIn(MAC,raw)
        self.assertNotIn('base64',raw)
        self.assertNotIn('password',raw)

    def test_csv_labels_and_html_escaped(self):
        suspicious='Room <svg onload="x"> &'
        rows=[point('A',i,40,room=suspicious) for i in range(3)]+[point('B',10+i,50,room=suspicious) for i in range(3)]
        data=compare_visits(rows,'Этаж 1','A','B')
        html=comparison_html(data,rows[:3],rows[3:])
        self.assertNotIn('<svg onload=',html)
        self.assertIn('&lt;svg onload=',html)
        self.assertIn('Room',html)
        self.assertNotIn('<script',html)

    def test_report_has_two_real_maps_and_no_interpolation(self):
        rows=points()
        data=compare_visits(rows,'Этаж 1','1 сентября','25 октября')
        html=comparison_html(data,rows[:3],rows[3:])
        self.assertEqual(html.count('<figure>'),2)
        self.assertEqual(html.count('<circle'),7)
        self.assertIn('Измерения не подтверждают скорость',html)
        self.assertIn('Точки:',html)

    def test_plan_embedding_requires_valid_sanitized_data(self):
        from PIL import Image
        image=Image.new('RGB',(80,50),(250,250,240));buf=BytesIO();image.save(buf,format='PNG')
        plan=sanitize_floorplan(buf.getvalue())
        data=compare_visits(points(),'Этаж 1','1 сентября','25 октября')
        html=comparison_html(data,points()[:3],points()[3:],plan)
        self.assertEqual(html.count('data:image/jpeg;base64,'),2)
        self.assertNotIn('https://',html)
        invalid=SimpleNamespace(jpeg=b'javascript:alert(1)',width=80,height=50)
        self.assertNotIn('data:image/jpeg;base64,',comparison_html(data,[],[],invalid))

    def test_corrupt_timestamp_does_not_create_false_date(self):
        rows=points(); altered=[*rows[:3],point('25 октября',10,40)]
        altered.append(SimpleNamespace(zone='Этаж 1',series='25 октября',room='Кухня',ssid='Office',signal=60,x=20.,y=40.,observed_at='nonsense'))
        data=compare_visits(altered,'Этаж 1','1 сентября','25 октября')
        self.assertEqual(data['followup_dates_utc'][0],'2026-10-28T10:10:00+00:00')

    def test_sqlite_survives_reopen_and_compares_only_same_floor(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/'network.db';store=Storage(db)
            for p in points():
                store.save_wifi_survey_point(p.zone,p.x,p.y,p.ssid,p.bssid,p.signal,p.channel,
                                             ts=p.observed_at,room=p.room,phase=p.phase,series=p.series)
            store.db.close()
            reopened=Storage(db)
            data=compare_visits(reopened.wifi_survey_points(),'Этаж 1','1 сентября','25 октября')
            self.assertEqual(len(data['comparable_rooms']),1)
            reopened.db.close()

if __name__=='__main__': unittest.main()
