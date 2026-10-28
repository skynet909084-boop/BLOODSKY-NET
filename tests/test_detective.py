"""Evidence assertions: never convert unmeasured state into confirmed incident."""
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bloodsky_net.detective import Observation, diagnose, export_report


class DetectiveTests(unittest.TestCase):
    def types(self, **kwargs):
        return {item.code: item for item in diagnose(Observation(**kwargs))}

    def test_unmeasured_returns_insufficient_evidence(self):
        result = self.types(gateway='192.168.1.1', availability={'192.168.1.1':'unknown'})
        self.assertEqual(list(result), ['insufficient_evidence'])
        self.assertEqual(result['insufficient_evidence'].confidence, 'нет оценки')

    def test_gateway_not_responding_not_confirmed_down(self):
        finding = self.types(gateway='192.168.1.1', availability={'192.168.1.1':'down'})['gateway_no_icmp']
        self.assertIn('ICMP', finding.interpretation)
        self.assertIn('не подтверждены', finding.interpretation)
        self.assertEqual(finding.confidence, 'низкая')

    def test_gateway_and_children_down_raises_correlated_observation(self):
        f = self.types(gateway='192.168.1.1', availability={
            '192.168.1.1':'down', '192.168.1.20':'down', '192.168.1.3':'down'})['gateway_no_icmp']
        self.assertEqual(len(f.evidence),3)
        self.assertEqual(f.confidence, 'средняя')

    def test_multi_node_no_ping_gateway_up_is_low_confidence(self):
        f=self.types(gateway='192.168.1.1', availability={
            '192.168.1.1':'up', '192.168.1.10':'down', '192.168.1.20':'down'})['segment_suspected']
        self.assertEqual(f.confidence,'низкая')
        self.assertIn('не установлены',f.interpretation)
        self.assertNotIn('gateway_no_icmp',self.types(gateway='192.168.1.1',availability={
            '192.168.1.1':'up', '192.168.1.10':'down', '192.168.1.20':'down'}))

    def test_single_host_does_not_create_segment_conclusion(self):
        result=self.types(availability={'192.168.2.10':'down'})
        self.assertIn('device_no_icmp',result)
        self.assertNotIn('segment_suspected',result)

    def test_unknown_reading_is_not_down(self):
        result=self.types(gateway='192.168.1.1',availability={'192.168.1.1':'unknown','192.168.1.2':'down'})
        self.assertNotIn('gateway_no_icmp',result)
        self.assertNotIn('segment_suspected',result)

    def test_arp_churn_only_suspicion(self):
        f=self.types(arp_suspicions=['192.168.1.20'])['arp_mac_churn']
        self.assertEqual(f.confidence,'низкая')
        self.assertIn('лишь подозрение',f.interpretation)
        self.assertIn('DHCP',f.checks[0])

    def test_no_wifi_measurement_does_not_raise_alarm(self):
        self.assertNotIn('wifi_disconnected',self.types(wifi_connected=None))
        self.assertIn('wifi_disconnected',self.types(wifi_connected=False))
        self.assertNotIn('wifi_disconnected',self.types(wifi_connected=True))

    def test_snmp_failure_not_cable_down(self):
        f=self.types(snmp_errors=['192.168.2.3'])['snmp_unavailable']
        self.assertIn('не означает потерю связи',f.interpretation)
        self.assertEqual(f.severity,'info')

    def test_lldp_historical_port_move_is_not_cable_claim(self):
        change=SimpleNamespace(category='local_port_changed',source_ip='192.168.1.2',
             neighbor='cam1',before='Gi1/0/4',after='Gi1/0/5')
        f=self.types(lldp_changes=[change])['lldp_history']
        self.assertIn('историческое',f.interpretation)
        self.assertIn('не доказательство',f.interpretation)
        self.assertIn('Gi1/0/5',f.evidence[0].observation)

    def test_lldp_new_observation_does_not_raise_warning(self):
        change=SimpleNamespace(category='new_observation',source_ip='192.168.1.2',
             neighbor='cam1',before='',after='Gi1/0/5')
        self.assertNotIn('lldp_history',self.types(lldp_changes=[change]))

    def test_invalid_ips_ignored_instead_of_crashing(self):
        f=self.types(gateway='bad',availability={'not-an-ip':'down'},
                     arp_suspicions=['invalid'],snmp_errors=['invalid'])
        self.assertEqual(list(f),['insufficient_evidence'])

    def test_deterministic_and_bounded_evidence(self):
        rows={f'192.168.1.{i}':'down' for i in range(3,150)}
        rows['192.168.1.1']='up'
        one=diagnose(Observation(gateway='192.168.1.1',availability=rows))
        two=diagnose(Observation(gateway='192.168.1.1',availability=dict(reversed(list(rows.items())))))
        self.assertEqual(one,two)
        self.assertLessEqual(len(one[0].evidence),5)

    def test_report_whitelists_opaque_input(self):
        o=Observation(arp_suspicions=['192.168.2.8'])
        report=export_report(diagnose(o))
        encoded=json.dumps(report, ensure_ascii=False)
        self.assertIn('содержит сетевые идентификаторы',encoded)
        self.assertIn('192.168.2.8',encoded)
        self.assertNotIn('snmp_auth',encoded.lower())
        self.assertNotIn('community',encoded.lower())

    def test_ui_has_one_click_and_does_not_auto_scan(self):
        s=(Path(__file__).resolve().parents[1]/'bloodsky_net/ui.py').read_text('utf-8')
        self.assertIn('def _detective_analyze(self):',s)
        self.assertIn('self._timeline_seen_at.get(ip',s)
        self.assertIn('self._gateway_failures >= 2',s)
        self.assertIn('self._detective_lldp_changes()',s)
        self.assertNotIn('net.scan_network(',s[s.index('    def _detective_analyze(self):'):s.index('    def _detective_export(self):')])


if __name__=='__main__': unittest.main()
