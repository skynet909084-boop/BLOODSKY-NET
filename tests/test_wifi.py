import unittest
from bloodsky_net import wifi


class WiFiTests(unittest.TestCase):
    INTERFACES_EN = '''
    Name                   : Wi-Fi
    Description            : Wireless Adapter
    State                  : connected
    SSID                   : MyOffice
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11ax
    Channel                : 36
    Signal                 : 72%
'''
    NETWORKS_EN = '''
SSID 1 : MyOffice
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 72%
         Radio type         : 802.11ax
         Channel            : 36
    BSSID 2                 : 02:03:04:05:06:07
         Signal             : 31%
         Radio type         : 802.11n
         Channel            : 6
SSID 2 : Guest
    Authentication          : Open
    BSSID 1                 : 03:04:05:06:07:08
         Signal             : 55%
         Channel            : 1
'''
    INTERFACES_RU = '''
    Имя                    : Беспроводная сеть
    Состояние              : подключено
    SSID                   : Офис
    BSSID                  : 11:22:33:44:55:66
    Тип радиомодуля        : 802.11ac
    Канал                  : 11
    Сигнал                 : 38%
'''

    def test_interfaces_en(self):
        state = wifi.parse_wifi_connection(self.INTERFACES_EN)
        self.assertTrue(state.connected)
        self.assertEqual(state.ssid, 'MyOffice')
        self.assertEqual(state.signal, 72)
        self.assertEqual(state.channel, 36)

    def test_interfaces_ru(self):
        state = wifi.parse_wifi_connection(self.INTERFACES_RU)
        self.assertTrue(state.connected)
        self.assertEqual(state.ssid, 'Офис')
        self.assertEqual(state.signal, 38)
        self.assertTrue(wifi.wifi_warnings(state, []))

    def test_networks_en(self):
        rows = wifi.parse_wifi_aps(self.NETWORKS_EN)
        self.assertEqual(len(rows), 3)
        self.assertEqual([r.ssid for r in rows], ['MyOffice', 'MyOffice', 'Guest'])
        self.assertEqual(rows[1].channel, 6)
        self.assertEqual(rows[0].signal, 72)
        self.assertEqual(rows[0].auth, 'WPA2-Personal')

    def test_unknown_band(self):
        self.assertEqual(wifi.get_channel_band(0), 'Неизвестно')
        self.assertEqual(wifi.get_channel_band(6), '2,4 ГГц')


if __name__ == '__main__':
    unittest.main()
