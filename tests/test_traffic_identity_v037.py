"""0.37: conservative SNMP/FDB chart and bounded UPnP identification."""
import unittest
from unittest.mock import Mock, patch
from bloodsky_net import device_traffic as dt, device_identity as di
from bloodsky_net.network import Device
from bloodsky_net.fdb import FDBEntry
from bloodsky_net.topology import TopologySnapshot, Neighbor
from bloodsky_net.traffic import PortCounter, PortRate

def device(ip, mac, name=''):
    return Device(ip, mac=mac, user_label=name)

def sw(rows, neighbor_ports=()):
    entries = [FDBEntry(mac, ix, ix, f'Gi{ix}') for mac, ix in rows]
    counters = {ix: PortCounter(ix, f'Gi{ix}', 200, 400, 1000, True) for _, ix in rows}
    neighbors = [Neighbor('192.168.1.2', 0, x) for x in neighbor_ports]
    return TopologySnapshot('192.168.1.2', neighbors=neighbors, fdb_entries=entries, port_counters=counters)

def rates(*indices):
    return {ix: PortRate(ix, f'Gi{ix}', 25.0, 75.0, 1000, True) for ix in indices}

class PortAttributionTests(unittest.TestCase):
    mac1 = '00:11:22:33:44:55'
    mac2 = '00:11:22:33:44:66'

    def test_unique_port_matching_and_direction(self):
        d=[device('192.168.1.51', self.mac1, 'Консоль')]
        u=dt.measured_usage(d, {'192.168.1.2':sw([(self.mac1, 4)])},
                            {'192.168.1.2':rates(4)})
        self.assertEqual(len(u), 1)
        self.assertEqual((u[0].download_mbps, u[0].upload_mbps, u[0].mbps),(75,25,100))
        self.assertEqual(u[0].label, 'Консоль')

    def test_no_fdb_means_unknown(self):
        self.assertEqual(dt.measured_usage([device('192.168.1.51', self.mac1)],
            {'192.168.1.2':sw([])}, {'192.168.1.2':rates(4)}), ())

    def test_shared_hub_port_is_not_one_host(self):
        d=[device('192.168.1.51',self.mac1),device('192.168.1.52',self.mac2)]
        self.assertEqual(dt.measured_usage(d, {'192.168.1.2':sw([(self.mac1,4),(self.mac2,4)])},
                          {'192.168.1.2':rates(4)}), ())

    def test_lldp_uplink_excluded(self):
        self.assertEqual(dt.measured_usage([device('192.168.1.51',self.mac1)],
            {'192.168.1.2':sw([(self.mac1,4)],neighbor_ports=('Gi4',))},
            {'192.168.1.2':rates(4)}), ())

    def test_two_hosts_one_mac_is_ambiguous(self):
        d=[device('192.168.1.51',self.mac1),device('192.168.1.60',self.mac1)]
        self.assertEqual(dt.measured_usage(d, {'192.168.1.2':sw([(self.mac1,4)])},
                          {'192.168.1.2':rates(4)}), ())

    def test_same_mac_seen_on_two_switches_is_ambiguous(self):
        self.assertEqual(dt.measured_usage([device('192.168.1.51',self.mac1)],
            {'192.168.1.2':sw([(self.mac1,4)]), '192.168.1.3':sw([(self.mac1,5)])},
            {'192.168.1.2':rates(4), '192.168.1.3':rates(5)}), ())

    def test_locally_administered_mac_excluded(self):
        mac='02:11:22:33:44:55'
        self.assertEqual(dt.measured_usage([device('192.168.1.51',mac)],
            {'192.168.1.2':sw([(mac,4)])}, {'192.168.1.2':rates(4)}), ())

    def test_reset_down_invalid_or_excess_speed_excluded(self):
        d=[device('192.168.1.51',self.mac1)]
        s={'192.168.1.2':sw([(self.mac1,4)])}
        for rate in (PortRate(4,'Gi4',None,1,1000,True),
                     PortRate(4,'Gi4',1,1,1000,False),
                     PortRate(4,'Gi4',10000,1,1000,True),
                     PortRate(4,'Gi4',-1,1,1000,True)):
            with self.subTest(rate=rate):
                self.assertEqual(dt.measured_usage(d,s,{'192.168.1.2':{4:rate}}),())

    def test_valid_measured_zero_not_unknown(self):
        result=dt.measured_usage([device('192.168.1.51',self.mac1)],
            {'192.168.1.2':sw([(self.mac1,4)])},
            {'192.168.1.2':{4:PortRate(4,'Gi4',0,0,1000,True)}})
        self.assertEqual(result[0].mbps,0)

XML = b'''<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>Hall Camera</friendlyName><manufacturer>Maker Inc</manufacturer><modelName>IPCAM-15</modelName></device></root>'''

class IdentityTests(unittest.TestCase):
    def test_model_vendor_friendly_name_are_claims(self):
        d=di.parse_description(XML,'192.168.1.55')
        self.assertEqual((d.model,d.manufacturer,d.friendly_name),
                         ('IPCAM-15','Maker Inc','Hall Camera'))
        self.assertIn('заявлено',d.source)

    def test_no_doctype_or_entity_expansion(self):
        x=b'<!DOCTYPE x [<!ENTITY xx SYSTEM "file:///etc/passwd">]><root/>'
        self.assertIsNone(di.parse_description(x,'192.168.1.55'))

    def test_oversized_description_is_rejected(self):
        self.assertIsNone(di.parse_description(b'X'*(di.MAX_XML+1),'192.168.1.55'))

    def test_no_external_dns_redirect_or_credentials_url(self):
        for url in ('http://8.8.8.8/a.xml','http://example.org/a.xml',
                    'http://192.168.1.55@192.168.1.66/a','https://192.168.1.55/a',
                    'http://192.168.1.55:65536/a'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    di.description_target(url,'192.168.1.55')

    def test_same_ip_description_is_allowed(self):
        self.assertEqual(di.description_target('http://192.168.1.55:1990/root.xml','192.168.1.55'),
                         ('192.168.1.55',1990,'/root.xml'))

    def test_ssdp_requires_success_response(self):
        d=di.parse_ssdp_headers(b'HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.55/root.xml\r\n\r\n')
        self.assertIn('location',d)
        self.assertFalse(di.parse_ssdp_headers(b'HTTP/1.1 301 Moved\r\nLOCATION: http://192.168.1.55/\r\n\r\n'))

    def test_description_redirect_not_followed(self):
        c=Mock()
        c.getresponse.return_value.status=302
        with patch.object(di.http.client,'HTTPConnection',return_value=c):
            self.assertIsNone(di.fetch_description('http://192.168.1.55/root.xml','192.168.1.55'))
        c.getresponse.return_value.read.assert_not_called()
        c.close.assert_called_once()

    def test_control_whitespace_in_device_name(self):
        xml=b'<root><device><friendlyName>Foo\nBar</friendlyName><modelName>X</modelName></device></root>'
        self.assertEqual(di.parse_description(xml,'192.168.1.55').friendly_name,'Foo Bar')
