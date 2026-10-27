import unittest
from bloodsky_net.fdb import (
    parse_fdb, resolve_fdb_ip, BRIDGE_PORT_IFINDEX, DOT1D_FDB_PORT,
    DOT1D_FDB_STATUS, DOT1Q_FDB_PORT, DOT1Q_VLAN_FDB_ID, IF_NAME, IF_DESCR,
)
from bloodsky_net.network import Device


class FDBTests(unittest.TestCase):
    def test_qbridge_fdb_id_is_not_a_vlan(self):
        mac = '0.17.34.51.68.85'
        values = {f'{DOT1Q_FDB_PORT}.99.{mac}': '3',
                  f'{BRIDGE_PORT_IFINDEX}.3': '104', f'{IF_NAME}.104': 'Gi1/0/4'}
        result = parse_fdb(values)
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0].vlan)
        self.assertEqual(result[0].fdb_id, 99)
        self.assertEqual(result[0].interface, 'Gi1/0/4')
        values[f'{DOT1Q_VLAN_FDB_ID}.20'] = '99'
        self.assertEqual(parse_fdb(values)[0].vlan, 20)
        values[f'{DOT1Q_VLAN_FDB_ID}.30'] = '99'
        self.assertIsNone(parse_fdb(values)[0].vlan)

    def test_bridge_ifdescr_fallback(self):
        values = {f'{DOT1D_FDB_PORT}.0.1.2.3.4.5': '7',
                  f'{BRIDGE_PORT_IFINDEX}.7': '22', f'{IF_DESCR}.22': 'Ethernet22'}
        row, = parse_fdb(values)
        self.assertEqual((row.mac, row.interface, row.vlan), ('00:01:02:03:04:05', 'Ethernet22', None))

    def test_never_infer_host_or_physical_link(self):
        values = {f'{DOT1D_FDB_PORT}.0.1.2.3.4.5': '7'}
        row, = parse_fdb(values)
        self.assertEqual(resolve_fdb_ip(row, [Device('10.0.0.1')]), '')
        self.assertEqual(resolve_fdb_ip(row, [Device('10.0.0.1', mac='00:01:02:03:04:05')]), '10.0.0.1')
        self.assertEqual(resolve_fdb_ip(row, [Device('10.0.0.1', mac='00:01:02:03:04:05'),
                                              Device('10.0.0.2', mac='00:01:02:03:04:05')]), '')

    def test_no_local_multicast_invalid_status_or_unlearned_port(self):
        vals = {f'{DOT1D_FDB_PORT}.1.0.0.0.0.1': '1',
                f'{DOT1D_FDB_PORT}.0.1.2.3.4.5': '0',
                f'{DOT1D_FDB_PORT}.0.1.2.3.4.6': '5',
                f'{DOT1D_FDB_STATUS}.0.1.2.3.4.6': '4',
                f'{DOT1D_FDB_PORT}.0.1.2.3.4.7': '5'}
        self.assertEqual([r.mac for r in parse_fdb(vals)], ['00:01:02:03:04:07'])

    def test_bounded_and_priority_of_qbridge(self):
        octets='0.1.2.3.4.5'
        values = {f'{DOT1Q_FDB_PORT}.123.{octets}':'4',
                  f'{DOT1D_FDB_PORT}.{octets}': '4'}
        rows=parse_fdb(values)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].origin, 'Q-BRIDGE-MIB')
        self.assertEqual(parse_fdb(values, limit=0), [])


if __name__ == '__main__':
    unittest.main()
