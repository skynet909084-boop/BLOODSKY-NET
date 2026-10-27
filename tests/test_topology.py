import unittest
from unittest.mock import patch

from bloodsky_net.network import Device
from bloodsky_net.topology import (
    LLDP_REMOTE, LLDP_LOCAL_PORT, SYS_NAME, SNMPCredentials, parse_lldp,
    resolve_neighbor_ip, physical_links, Neighbor, TopologySnapshot, read_lldp,
)


class TopologyTests(unittest.TestCase):
    def fixture(self):
        return {
            SYS_NAME: 'core-switch',
            f'{LLDP_LOCAL_PORT}.3.4': 'Gi1/0/4',
            f'{LLDP_LOCAL_PORT}.4.4': 'GigabitEthernet1/0/4',
            f'{LLDP_REMOTE}.5.1000.4.1': '0x001122334455',
            f'{LLDP_REMOTE}.7.1000.4.1': 'eth0',
            f'{LLDP_REMOTE}.8.1000.4.1': 'Ethernet1',
            f'{LLDP_REMOTE}.9.1000.4.1': 'access-switch',
            f'{LLDP_REMOTE}.10.1000.4.1': 'edge hardware',
            '1.0.8802.1.1.2.1.4.1.1.9.1000.9': 'invalid suffix',
            f'{LLDP_REMOTE}.9.1000.8.2': 'unknown-edge',
        }

    def test_read_remote_join_by_exact_index(self):
        snap = parse_lldp('192.168.9.1', self.fixture(), '2026-10-28T10:00:00+02:00')
        self.assertEqual(snap.system_name, 'core-switch')
        self.assertEqual(len(snap.neighbors), 2)
        found = next(n for n in snap.neighbors if n.remote_name == 'access-switch')
        self.assertEqual(found.local_port_num, 4)
        self.assertEqual(found.local_port, 'GigabitEthernet1/0/4')
        self.assertEqual(found.remote_port, 'Ethernet1')
        self.assertEqual(found.remote_chassis, '00:11:22:33:44:55')

    def test_unique_match_by_mac(self):
        neighbor = parse_lldp('192.168.9.1', self.fixture()).neighbors[0]
        devices = [Device('192.168.9.1'), Device('192.168.9.2', mac='00-11-22-33-44-55'),
                   Device('192.168.9.3', hostname='unrelated')]
        self.assertEqual(resolve_neighbor_ip(neighbor, devices), '192.168.9.2')
        physical = physical_links({'192.168.9.1': parse_lldp('192.168.9.1', self.fixture())}, devices)
        self.assertEqual(len(physical), 1)
        self.assertEqual(physical[0][:2], ('192.168.9.1', '192.168.9.2'))

    def test_ambiguous_short_hostname_never_draws_link(self):
        neighbor = Neighbor('10.1.2.1', 1, 'eth1', remote_name='switch')
        devices = [Device('10.1.2.2', hostname='switch.office.local'),
                   Device('10.1.2.3', hostname='switch.factory.local')]
        self.assertEqual(resolve_neighbor_ip(neighbor, devices), '')
        self.assertEqual(physical_links({'10.1.2.1': TopologySnapshot('10.1.2.1', neighbors=[neighbor])}, devices), [])

    def test_duplicate_observation_only_one_line(self):
        row = Neighbor('10.0.0.1', 1, 'Gi0/1', remote_name='edge')
        devices = [Device('10.0.0.1'), Device('10.0.0.2', hostname='edge.example.org')]
        self.assertEqual(len(physical_links({'10.0.0.1': TopologySnapshot('10.0.0.1', neighbors=[row, row])}, devices)), 1)

    def test_credentials_validation(self):
        for credentials in [SNMPCredentials(), SNMPCredentials(version='v2c'),
                            SNMPCredentials(version='v1', community='public'),
                            SNMPCredentials('v3', 'u', 'short', 'password_long'),
                            SNMPCredentials('v2c', community='pub', port=70000)]:
            with self.subTest(credentials.version), self.assertRaises(ValueError):
                credentials.validate()
        SNMPCredentials('v3', 'user', 'authpass123', 'privpass123').validate()
        SNMPCredentials('v2c', community='not-public').validate()

    def test_unsupported_targets_rejected_before_transport(self):
        credentials = SNMPCredentials('v2c', community='read-only')
        for ip in ('8.8.8.8', '127.0.0.1', '169.254.1.2', 'example.com'):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                read_lldp(ip, credentials)

    @patch('bloodsky_net.topology._snmp_walk')
    def test_explicit_target_and_snapshot(self, walk):
        from unittest.mock import AsyncMock
        walk.side_effect = AsyncMock(return_value=self.fixture())
        snap = read_lldp('192.168.9.1', SNMPCredentials('v2c', community='read-only'))
        self.assertEqual(snap.source_ip, '192.168.9.1')
        self.assertEqual(len(snap.neighbors), 2)


if __name__ == '__main__':
    unittest.main()
