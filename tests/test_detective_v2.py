"""Deterministic evidence tests for v2 without SNMP hardware or network access."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest
from types import SimpleNamespace

from bloodsky_net.port_health import (IF_IN_ERRORS, IF_IN_DISCARDS, IF_OUT_DISCARDS,
                                      IF_OUT_ERRORS, parse_error_counters,
                                      calculate_error_deltas)
from bloodsky_net.detective import (DeviceEvent, Observation, diagnose,
                                    recent_device_events, export_html_report, Finding, Evidence)
from bloodsky_net.topology import parse_lldp

NOW = datetime(2026, 10, 28, 10, 10, tzinfo=timezone.utc)
SWITCH = '192.168.10.2'


class PortHealthTests(unittest.TestCase):
    def test_supported_optional_counter_fields(self):
        values = {f'{IF_IN_ERRORS}.4':'100', f'{IF_OUT_ERRORS}.4':'12',
                  f'{IF_IN_DISCARDS}.4':'20', f'{IF_OUT_DISCARDS}.4':'0'}
        got = parse_error_counters(values)
        self.assertEqual((got[4].in_errors, got[4].out_errors, got[4].in_discards, got[4].out_discards), (100, 12, 20, 0))
        self.assertEqual(parse_lldp(SWITCH,values).error_counters,got)

    def test_reject_invalid_values_and_indices(self):
        got = parse_error_counters({f'{IF_IN_ERRORS}.4':'-1', f'{IF_IN_ERRORS}.5':'4294967296',
                                    f'{IF_IN_ERRORS}.6':'13.4', f'{IF_IN_ERRORS}.7.3':'7',
                                    f'{IF_OUT_ERRORS}.8':'12'})
        self.assertEqual(list(got),[8])
        self.assertEqual(got[8].out_errors,12)
        self.assertIsNone(got[8].in_errors)

    def test_two_observations_and_delta_dont_invent_zero(self):
        old=parse_error_counters({f'{IF_IN_ERRORS}.4':'100', f'{IF_OUT_ERRORS}.4':'30'})
        new=parse_error_counters({f'{IF_IN_ERRORS}.4':'110'})
        d=calculate_error_deltas(SWITCH,old,new,60,{4:'Gi1/0/4'})
        self.assertEqual(len(d),1)
        self.assertEqual((d[0].in_errors, d[0].out_errors),(10,None))
        self.assertEqual(d[0].name,'Gi1/0/4')
        self.assertIsNone(d[0].in_discards)

    def test_counter_reset_not_false_wrap(self):
        old=parse_error_counters({f'{IF_IN_ERRORS}.4':'4294967290'})
        new=parse_error_counters({f'{IF_IN_ERRORS}.4':'7'})
        self.assertEqual(calculate_error_deltas(SWITCH,old,new,60),())

    def test_reject_stale_or_invalid_interval(self):
        x=parse_error_counters({f'{IF_IN_ERRORS}.4':'100'})
        y=parse_error_counters({f'{IF_IN_ERRORS}.4':'120'})
        for secs in (0, 0.5, 3601, float('nan'), float('inf')):
            self.assertEqual(calculate_error_deltas(SWITCH,x,y,secs),())

    def test_only_common_port_indices(self):
        x=parse_error_counters({f'{IF_IN_ERRORS}.4':'3'})
        y=parse_error_counters({f'{IF_IN_ERRORS}.9':'17'})
        self.assertEqual(calculate_error_deltas(SWITCH,x,y,60),())


class DetectiveV2Tests(unittest.TestCase):
    def make_event(self, ip, seconds=0):
        return DeviceEvent(ip,NOW+timedelta(seconds=seconds))

    def test_close_together_two_independent_hosts_are_only_suspicion(self):
        events=(self.make_event('192.168.1.4'),self.make_event('192.168.1.5',80))
        f=next(x for x in diagnose(Observation(recent_events=events)) if x.code=='temporal_cluster')
        self.assertEqual(f.confidence,'низкая')
        self.assertIn('не подтверждает', f.interpretation)
        self.assertEqual(len(f.evidence),2)

    def test_same_host_or_distant_times_not_cluster(self):
        for events in ((self.make_event('192.168.1.4'),self.make_event('192.168.1.4',80)),
                       (self.make_event('192.168.1.4'),self.make_event('192.168.1.5',121)),
                       (self.make_event('192.168.1.4'),self.make_event('192.168.2.5',60))):
            self.assertFalse(any(x.code=='temporal_cluster' for x in diagnose(Observation(recent_events=events))))

    def test_extract_recent_device_events_only_from_monitor_journal(self):
        good=(NOW-timedelta(seconds=20)).isoformat()
        old=(NOW-timedelta(seconds=601)).isoformat()
        rows=[(good,'error','Устройство не отвечает','192.168.1.5 some-host'),
              (good,'warning','SNMP/LLDP','192.168.1.6: auth key'),
              (old,'error','Устройство не отвечает','192.168.1.4 host'),
              (good,'error','Устройство не отвечает','256.0.0.1 invalid'),
              (good,'error','Устройство не отвечает','192.168.1.7')]
        got=recent_device_events(rows,now=NOW)
        self.assertEqual({x.ip for x in got},{'192.168.1.5','192.168.1.7'})

    def test_older_or_future_event_does_not_correlate(self):
        rows=[((NOW-timedelta(seconds=601)).isoformat(),'error','Устройство не отвечает','192.168.1.4'),
              ((NOW+timedelta(seconds=200)).isoformat(),'error','Устройство не отвечает','192.168.1.5')]
        self.assertEqual(recent_device_events(rows, now=NOW),())

    def test_real_counter_growth_generates_evidence_not_cable_claim(self):
        a=parse_error_counters({f'{IF_IN_ERRORS}.7':'100',f'{IF_IN_DISCARDS}.7':'50'})
        b=parse_error_counters({f'{IF_IN_ERRORS}.7':'113',f'{IF_IN_DISCARDS}.7':'55'})
        delta=calculate_error_deltas(SWITCH,a,b,60,{7:'Gi1/0/7'})
        f=next(x for x in diagnose(Observation(port_error_deltas=delta)) if x.code=='port_errors')
        self.assertEqual(f.confidence,'средняя')
        self.assertIn('ifIndex 7',f.evidence[0].observation)
        self.assertIn('не доказывают',f.interpretation)

    def test_missing_and_unchanged_counters_do_not_alert(self):
        prev=parse_error_counters({f'{IF_IN_ERRORS}.7':'100'})
        same=parse_error_counters({f'{IF_IN_ERRORS}.7':'100'})
        delta=calculate_error_deltas(SWITCH,prev,same,60)
        self.assertFalse(any(x.code=='port_errors' for x in diagnose(Observation(port_error_deltas=delta))))

    def test_html_escapes_untrusted_user_labels_and_no_scripts(self):
        item=Finding('test','notice','низкая','<script>alert(1)</script>','<img src=x>',
                     (Evidence('custom','a & b "<unsafe>"'),),('<iframe>',))
        report=export_html_report([item])
        self.assertNotIn('<script>',report)
        self.assertNotIn('<iframe>',report)
        self.assertIn('&lt;script&gt;',report)
        self.assertIn('Content-Security-Policy',report)
        self.assertIn('&amp;',report)
        self.assertNotIn('https://', report)

    def test_limited_report_and_ui_hook(self):
        item=Finding('c','info','низкая','name','reason',(),('check',))
        html=export_html_report([item]*100)
        self.assertEqual(html.count('<section>'),30)
        ui=(Path(__file__).resolve().parents[1]/'bloodsky_net/ui.py').read_text('utf-8')
        self.assertIn('def _detective_export_html(self):',ui)
        self.assertIn('port_error_deltas=tuple(',ui)
        self.assertIn('events = detective.recent_device_events(',ui)


if __name__ == '__main__': unittest.main()
