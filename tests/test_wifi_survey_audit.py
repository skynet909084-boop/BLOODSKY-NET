"""Wi-Fi survey completeness and repeated spot observations are evidence-limited."""
import unittest
from datetime import datetime,timedelta,timezone
from bloodsky_net.wifi_survey import validate_point
from bloodsky_net.wifi_survey_audit import audit_floors,audit_html_report

T = datetime(2026,10,28,10,tzinfo=timezone.utc)
MAC1='AA:BB:CC:DD:EE:01';MAC2='AA:BB:CC:DD:EE:02'

def point(seconds, signal, x=20, y=30, floor='1', room='A',ssid='Office',series='Visit',phase='До',bssid=MAC1):
    return validate_point(floor,x,y,ssid,bssid,signal,36,(T+timedelta(seconds=seconds)).isoformat(),room=room,series=series,phase=phase)

class SurveyAuditTests(unittest.TestCase):
    def test_floor_and_ssid_not_blended(self):
        data=audit_floors([point(0,70),point(40,65),point(80,80,x=30),point(0,10,ssid='Other'),point(0,20,floor='2')],'Visit')
        self.assertEqual(len(data['floors']),2)
        self.assertEqual(len(data['room_checks']),3)
        self.assertEqual(data['sample_count'],5)
        self.assertEqual(data['floors'][0]['observed_ssids'],2)
    def test_repeat_spread_at_same_place_same_bssid_and_30_seconds(self):
        samples=[point(0,80),point(40,53),point(80,75,x=30)]
        report=audit_floors(samples,'Visit')['room_checks'][0]
        self.assertEqual(report['repeat_spread_percentage_points'],27)
        self.assertEqual(report['positions'],2)
        self.assertIn('≥20', ''.join(report['checks']))
    def test_no_repeat_for_different_bssid(self):
        d=audit_floors([point(0,80),point(40,50,bssid=MAC2),point(80,70,x=30)],'Visit')['room_checks'][0]
        self.assertIsNone(d['repeat_spread_percentage_points'])
    def test_repetition_less_than_30_sec_not_valid(self):
        d=audit_floors([point(0,70),point(5,45),point(65,70,x=30)],'Visit')['room_checks'][0]
        self.assertIsNone(d['repeat_spread_percentage_points'])
    def test_three_at_same_spot_is_not_room_coverage(self):
        d=audit_floors([point(0,70),point(40,70),point(80,70)],'Visit')['room_checks'][0]
        self.assertIn('разнесённые точки',','.join(d['checks']))
    def test_short_span_not_sufficient(self):
        d=audit_floors([point(0,70),point(20,70),point(40,70,x=30)],'Visit')['room_checks'][0]
        self.assertIn('короче',','.join(d['checks']))
    def test_adequate_primary_but_never_full_floor_claim(self):
        d=audit_floors([point(0,70),point(40,71),point(80,69,x=30)],'Visit')
        self.assertEqual(d['room_checks'][0]['sampling_status'],'достаточно для первичного обзора')
        self.assertIn('не означает покрытие всего этажа',d['limitations'])
    def test_unknown_series_not_invented(self):
        d=audit_floors([point(0,70)],'Nonexistent')
        self.assertEqual(d['sample_count'],0)
        self.assertEqual(d['floors'],[])
    def test_phase_filter(self):
        p=[point(0,50),point(40,50,phase='После')]
        self.assertEqual(audit_floors(p,'Visit','До')['sample_count'],1)
        self.assertEqual(audit_floors(p,'Visit')['sample_count'],2)
    def test_invalid_and_other_series_excluded(self):
        p=[point(0,50),point(0,90,series='Other')]
        self.assertEqual(audit_floors(p,'Visit')['sample_count'],1)
    def test_bad_time_excluded(self):
        from dataclasses import replace
        p=point(0,50)
        self.assertEqual(audit_floors([replace(p,observed_at='broken')],'Visit')['sample_count'],0)
    def test_html_escaped_no_remote_assets(self):
        r=audit_floors([point(0,40,room='<script>alert(1)</script>')],'Visit')
        html=audit_html_report(r)
        self.assertNotIn('<script>',html)
        self.assertIn('&lt;script&gt;',html)
        self.assertIn('default-src &apos;none&apos;',html)
    def test_malformed_series_and_phase_rejected(self):
        for name in ('', ' '*5, 'x'*61):
            with self.assertRaises(ValueError):audit_floors([],name)
        with self.assertRaises(ValueError):audit_floors([],'Visit','Incorrect')
    def test_nonfinite_coordinates_excluded(self):
        from dataclasses import replace
        good=point(0,50)
        self.assertEqual(audit_floors([replace(good,x=float('nan'))],'Visit')['sample_count'],0)
    def test_separation_at_spatial_threshold(self):
        d=audit_floors([point(0,80),point(40,82),point(80,77,x=25)],'Visit')['room_checks'][0]
        self.assertEqual(d['positions'],2)

if __name__=='__main__':unittest.main()
