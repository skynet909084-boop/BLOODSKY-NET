"""DETECTIVE 2.2: cautious history-correlations, absence of fabricated causes."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from bloodsky_net.detective import DeviceEvent, Observation, diagnose, export_report, export_html_report, triage_steps
from bloodsky_net.topology_history import LinkObservation, compare_links
from bloodsky_net.topology_incidents import LldpWindow, correlate_history, history_moments

T0 = datetime(2026, 10, 28, 8, tzinfo=timezone.utc)
SW = '192.168.40.2'
HOST = '192.168.40.51'
MAC = 'AA:BB:CC:DD:EE:01'


def link(port='Gi1/0/7', name='camera-a'):
    return LinkObservation(SW, 7, port, MAC, 'eth0', name)


def window(left=None, right=(), seconds=90):
    left = (link(),) if left is None else left
    return LldpWindow(SW, T0, T0 + timedelta(seconds=seconds),
                      tuple(compare_links(left, right)), tuple(left))


def devices(*extra):
    return (SimpleNamespace(ip=HOST, mac=MAC), *extra)


def event(when=30, ip=HOST):
    return DeviceEvent(ip, T0 + timedelta(seconds=when))


class HistoricalLinkTests(unittest.TestCase):
    def test_missing_lldp_row_correlates_only_by_unique_chassis_mac(self):
        got = correlate_history((event(),), (window(),), devices())
        self.assertEqual(len(got), 1)
        x = got[0]
        self.assertEqual((x.switch_ip, x.device_ip, x.reported_port), (SW, HOST, 'Gi1/0/7'))
        self.assertEqual((x.before_at, x.after_at), (T0, T0 + timedelta(seconds=90)))
        self.assertIn('не доказывают неисправность кабеля', x.description)

    def test_reported_port_change_has_bracket_not_false_physical_time(self):
        after = (LinkObservation(SW, 8, 'Gi1/0/8', MAC, 'eth0', 'camera-a'),)
        w = window(right=after)
        self.assertEqual([c.category for c in w.changes], ['local_port_changed'])
        matches = correlate_history((event(),), (w,), devices())
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].reported_port, 'Gi1/0/7')
        self.assertEqual([m.source for m in history_moments((w,))], ['LLDP (снимок)'])
        self.assertIn('момент изменения неизвестен', history_moments((w,))[0].description)
        self.assertEqual(history_moments((w,))[0].observed_at, w.after_at)

    def test_two_distinct_devices_same_mac_ambiguous(self):
        self.assertEqual(correlate_history((event(),), (window(),),
            devices(SimpleNamespace(ip='192.168.40.52', mac=MAC))), ())

    def test_unknown_chassis_or_fake_id_not_used(self):
        bogus = LinkObservation(SW, 7, 'Gi1/0/7', 'switch-id-A', 'eth0', 'camera-a')
        self.assertEqual(correlate_history((event(),), (window(left=(bogus,)),), devices()), ())
        self.assertEqual(correlate_history((event(),), (window(),),
            (SimpleNamespace(ip=HOST, mac=''),)), ())

    def test_not_near_event_is_no_evidence(self):
        self.assertEqual(correlate_history((event(-1),), (window(),), devices()), ())
        self.assertEqual(correlate_history((event(136),), (window(),), devices()), ())
        self.assertEqual(len(correlate_history((event(135),), (window(),), devices())), 1)

    def test_too_large_or_inverted_capture_interval(self):
        self.assertEqual(correlate_history((event(),), (window(seconds=301),), devices()), ())
        self.assertEqual(history_moments((window(seconds=301),)), ())
        self.assertEqual(correlate_history((event(),), (window(seconds=-5),), devices()), ())

    def test_naive_timestamps_rejected(self):
        w = window()
        wrong = LldpWindow(w.switch_ip, w.before_at.replace(tzinfo=None),
                           w.after_at, w.changes, w.before_links)
        self.assertEqual(correlate_history((event(),), (wrong,), devices()), ())
        self.assertEqual(correlate_history((DeviceEvent(HOST, T0.replace(tzinfo=None)),),
                                          (w,), devices()), ())

    def test_new_observation_without_old_row_does_not_correlate(self):
        self.assertEqual(correlate_history((event(),),
            (window(left=(), right=(link(),)),), devices()), ())
        self.assertEqual(history_moments((window(left=(), right=(link(),)),)), ())

    def test_duplicate_llpd_rows_are_ambiguous(self):
        same_chassis = LinkObservation(SW, 7, 'Gi1/0/7', MAC, 'eth0', 'camera-a')
        w = window(left=(same_chassis, same_chassis))
        self.assertEqual(correlate_history((event(),), (w,), devices()), ())

    def test_unrelated_host_does_not_correlate(self):
        self.assertEqual(correlate_history((event(ip='192.168.40.77'),),
                                           (window(),), devices()), ())

    def test_de_duplicate_and_bounded(self):
        found = correlate_history(tuple(event() for _ in range(100)), (window(),), devices())
        self.assertEqual(len(found), 1)
        with self.assertRaises(ValueError):
            correlate_history((), (), (), margin_seconds=70)

    def test_no_port_correlation_from_non_lldp_inventory(self):
        self.assertEqual(correlate_history((event(),), (), devices()), ())

    def test_confidence_and_detailed_read_only_checks_in_engine(self):
        observed = correlate_history((event(),), (window(),), devices())
        findings = diagnose(Observation(topology_history_matches=observed))
        item = next(f for f in findings if f.code == 'historical_lldp_overlap')
        self.assertEqual(item.confidence, 'низкая')
        self.assertIn('два успешных снимка', item.evidence[0].source)
        self.assertIn('Сверить', item.checks[-1])
        self.assertIn('уникальный MAC', item.evidence[1].observation)
        self.assertLessEqual(len(triage_steps(findings)), 8)
        structured = export_report(findings, history_moments((window(),)))
        self.assertEqual(structured['engine'], 'DETECTIVE rules v2.3')
        self.assertTrue(structured['recommended_checks'])
        self.assertTrue(structured['timeline'])
        self.assertTrue(json.dumps(structured, ensure_ascii=False))
        html = export_html_report(findings, history_moments((window(),)))
        self.assertIn('Порядок проверок инженера', html)
        self.assertIn('LLDP (снимок)', html)
        self.assertNotIn('<script>', html)

    def test_report_escapes_untrusted_labels(self):
        malicious = link('<script>alert(1)</script>')
        w = window(left=(malicious,))
        got = correlate_history((event(),), (w,), devices())
        report = export_html_report(diagnose(Observation(topology_history_matches=got)),
                                    history_moments((w,)))
        self.assertNotIn('<script>', report)
        self.assertIn('&lt;script&gt;', report)

    def test_integration_hook_in_ui(self):
        ui = (Path(__file__).resolve().parents[1] / 'bloodsky_net/ui.py').read_text('utf-8')
        self.assertIn('def _detective_history_windows(self):', ui)
        self.assertIn('topology_incidents.correlate_history(', ui)
        self.assertIn('topology_incidents.history_moments(', ui)


if __name__ == '__main__':
    unittest.main()
