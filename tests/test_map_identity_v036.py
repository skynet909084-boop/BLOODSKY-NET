"""Network discovery identity and full-screen map regression tests."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from bloodsky_net import network as net, map_view
from bloodsky_net.storage import Storage


class IdentityTests(unittest.TestCase):
    def test_private_random_mac_never_claims_vendor(self):
        with patch.object(net,'_oui_lookup',return_value='Incorrect Company') as lookup:
            self.assertIn('случайный',net.mac_vendor('DA:11:22:33:44:55'))
            lookup.assert_not_called()

    def test_invalid_mac(self):
        self.assertEqual(net.mac_vendor('bad'),'Не определён')

    def test_offline_oui_lookup(self):
        with patch.object(net,'_oui_lookup',return_value='Raspberry Pi Foundation'):
            self.assertEqual(net.mac_vendor('B8:27:EB:01:02:03'),'Raspberry Pi Foundation')

    def test_netbios_unique_not_group(self):
        raw='WORKGROUP <00> GROUP Registered\nLIVINGROOM-PC <00> UNIQUE Registered'
        self.assertEqual(net.parse_netbios_hostname(raw),'LIVINGROOM-PC')
        self.assertEqual(net.parse_netbios_hostname('WORKGROUP <00> GROUP Registered'),'')

    @patch.object(net,'friendly_hostname',return_value='')
    @patch.object(net,'netbios_hostname',return_value='KITCHEN-TV')
    @patch.object(net,'arp_table',return_value={})
    @patch.object(net,'probe_ports',return_value=[80])
    @patch.object(net,'ping_once',return_value=net.PingResult(True,2.0))
    def test_scan_uses_netbios_fallback_when_dns_unknown(self,*_):
        found,_,_ = net.scan_network('192.168.1.0/30','192.168.1.1',threading.Event())
        self.assertEqual(len(found),2)
        self.assertTrue(all(x.hostname=='KITCHEN-TV' and x.hostname_source=='Windows NetBIOS'
                            for x in found))

    def test_saved_user_name_does_not_replace_network_name(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/'test.db'
            store=Storage(db)
            obj=net.Device('192.168.1.42',hostname='ptr-host',user_label='Телевизор в зале')
            store.save_device(obj)
            store.close()
            store=Storage(db)
            restored=store.load_devices()[obj.ip]
            self.assertEqual(restored.user_label,'Телевизор в зале')
            self.assertEqual(restored.hostname,'ptr-host')
            store.close()

    def test_map_allows_full_scan(self):
        ds=[net.Device(f'192.168.{i//250}.{i%250+1}') for i in range(180)]
        self.assertEqual(len(map_view.select_devices(ds).devices),180)

    def test_search_by_manual_label(self):
        device=net.Device('192.168.1.23',user_label='Камера у ворот')
        self.assertEqual(map_view.select_devices([device],'ворот').devices,(device,))
        self.assertIn('Камера у ворот',map_view.passport(device))


if __name__=='__main__':
    unittest.main()
