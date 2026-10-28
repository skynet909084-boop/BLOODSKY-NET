"""DETECTIVE v2.1: chronology, strict port-name correlation and anti-fabrication."""
import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from bloodsky_net.detective import (DeviceEvent, Observation, diagnose, export_report,
                                    export_html_report)
from bloodsky_net.detective_timeline import (LldpEndpoint, TimedPortFault,
    verified_lldp_endpoints, correlate, timeline)
from bloodsky_net.port_health import ErrorDelta
from bloodsky_net.topology import Neighbor

NOW = datetime(2026, 10, 28, 10, 20, tzinfo=timezone.utc)
SWITCH = '192.168.1.2'
A = '192.168.1.10'
B = '192.168.1.11'


class DetectiveV21Tests(unittest.TestCase):
    def event(self, ip, offset=0):
        return DeviceEvent(ip, NOW + timedelta(seconds=offset))

    def fault(self, port='Gi1/0/7', offset=20, count=9):
        return TimedPortFault(ErrorDelta(SWITCH, 7, port, 60, count, None, None, None),
                              NOW + timedelta(seconds=offset))

    def endpoints(self):
        return (LldpEndpoint(SWITCH,A,'Gi1/0/7'), LldpEndpoint(SWITCH,B,'Gi1/0/8'))

    def test_unique_reported_lldp_neighbors_only(self):
        peers = (SimpleNamespace(ip=A,mac='AA:BB:CC:DD:EE:01',hostname='camera-a'),
                 SimpleNamespace(ip=B,mac='AA:BB:CC:DD:EE:02',hostname='camera-b'))
        n = Neighbor(SWITCH,1,'Gi1/0/7',remote_chassis='AA:BB:CC:DD:EE:01',remote_port='eth0')
        s = SimpleNamespace(neighbors=(n,))
        result = verified_lldp_endpoints({SWITCH:s},peers)
        self.assertEqual(result,(LldpEndpoint(SWITCH,A,'Gi1/0/7'),))

    def test_reject_ambiguous_lldp_ports_and_unresolved(self):
        peers = (SimpleNamespace(ip=A,mac='AA:BB:CC:DD:EE:01',hostname='camera-a'),)
        ns = (Neighbor(SWITCH,1,'Gi1/0/7',remote_chassis='AA:BB:CC:DD:EE:01'),
              Neighbor(SWITCH,2,'Gi1/0/8',remote_chassis='AA:BB:CC:DD:EE:01'),
              Neighbor(SWITCH,3,'Gi1/0/9',remote_chassis='unresolved'))
        self.assertEqual(verified_lldp_endpoints({SWITCH:SimpleNamespace(neighbors=ns)}, peers),())

    def test_common_switch_correlation_never_claims_uplink(self):
        matches=correlate((self.event(A),self.event(B,45)),self.endpoints(),())
        shared=[x for x in matches if x.code=='common_lldp_source']
        self.assertEqual(len(shared),1)
        self.assertEqual(shared[0].target_ips,(A,B))
        self.assertIn('не установлены',shared[0].description)

    def test_different_sources_or_distant_times_not_correlated(self):
        endpoints = (LldpEndpoint(SWITCH,A,'Gi1/0/7'),
                     LldpEndpoint('192.168.1.3',B,'Gi1/0/8'))
        self.assertFalse(correlate((self.event(A),self.event(B,12)),endpoints,()))
        self.assertFalse(correlate((self.event(A),self.event(B,121)),self.endpoints(),()))

    def test_repeated_events_of_same_host_do_not_create_cluster(self):
        self.assertFalse(correlate((self.event(A),self.event(A,25)), self.endpoints(),()))

    def test_port_correlation_requires_exact_name_not_lldp_port_number(self):
        matches=correlate((self.event(A),),self.endpoints(),(self.fault(),))
        self.assertEqual([x.code for x in matches],['lldp_port_temporal_match'])
        self.assertEqual(matches[0].port_name,'Gi1/0/7')
        self.assertFalse(correlate((self.event(A),),self.endpoints(),(self.fault('Ethernet7'),)))

    def test_port_name_is_case_insensitive_but_unique(self):
        self.assertEqual(len(correlate((self.event(A),),self.endpoints(),(self.fault('gi1/0/7'),))),1)
        same_port=(LldpEndpoint(SWITCH,A,'Gi1/0/7'), LldpEndpoint(SWITCH,B,'Gi1/0/7'))
        self.assertFalse(correlate((self.event(A),self.event(B,10)),same_port,(self.fault(),))[-1].code == 'lldp_port_temporal_match')

    def test_outside_time_window_no_port_match(self):
        self.assertEqual(correlate((self.event(A),),self.endpoints(),(self.fault(offset=121),)),())
        self.assertEqual(correlate((self.event(A),),self.endpoints(),(self.fault(offset=-121),)),())

    def test_missing_or_reset_counter_produces_no_false_fault(self):
        for count in (0,4,None):
            bad = self.fault(count=count)
            self.assertEqual(correlate((self.event(A),),self.endpoints(),(bad,)),())
            self.assertEqual(timeline((),(bad,)),())

    def test_timeline_sorted_utc_bounded(self):
        rows=timeline((self.event(B,20),self.event(A)),(self.fault(offset=10),))
        self.assertEqual([x.source for x in rows],['ICMP','SNMP','ICMP'])
        self.assertEqual([x.observed_at.tzinfo for x in rows],[timezone.utc]*3)
        self.assertEqual(len(timeline((self.event(A),self.event(B,10)),(),limit=1)),1)
        with self.assertRaises(ValueError):timeline((),(),limit=0)

    def test_untimed_events_and_unsolicited_rows_rejected(self):
        bad=DeviceEvent(A,NOW.replace(tzinfo=None))
        rows=(bad,DeviceEvent('999.1.2.3',NOW),DeviceEvent(B,NOW,kind='other'))
        self.assertEqual(correlate(rows,self.endpoints(),(self.fault(),)),())
        self.assertEqual(timeline(rows,()),())

    def test_findings_report_with_html_escaping_and_chronology(self):
        obs=Observation(recent_events=(self.event(A),),lldp_endpoints=self.endpoints(),
                        timed_port_faults=(self.fault(),))
        findings=diagnose(obs)
        item=next(x for x in findings if x.code=='lldp_port_temporal_match')
        self.assertEqual(item.confidence,'средняя')
        self.assertIn('не подтверждённая',item.interpretation)
        moments=timeline(obs.recent_events,obs.timed_port_faults)
        j=export_report(findings,moments)
        self.assertEqual(j['engine'],'DETECTIVE rules v2.2')
        self.assertEqual(len(j['timeline']),2)
        self.assertIn('2026',json.dumps(j))
        html=export_html_report(findings,moments)
        self.assertIn('Временная шкала',html)
        self.assertNotIn('<script>',html)

    def test_html_timeline_escapes_port_labels(self):
        evil=self.fault(port='<script>alert(1)</script>')
        html=export_html_report((),timeline((),(evil,)))
        self.assertIn('&lt;script&gt;',html)
        self.assertNotIn('<script>',html)


if __name__ == '__main__':unittest.main()
