"""Read-only Ethernet forwarding database observations (NOT physical-cable links).

Q-BRIDGE-MIB dot1qTpFdbPort indexes by FDB ID, NOT by VLAN ID.
Map FDB IDs through dot1qVlanFdbId and report VLAN only if unambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

BRIDGE_PORT_IFINDEX = '1.3.6.1.2.1.17.1.4.1.2'
DOT1D_FDB_PORT = '1.3.6.1.2.1.17.4.3.1.2'
DOT1D_FDB_STATUS = '1.3.6.1.2.1.17.4.3.1.3'
DOT1Q_FDB_PORT = '1.3.6.1.2.1.17.7.1.2.2.1.2'
DOT1Q_FDB_STATUS = '1.3.6.1.2.1.17.7.1.2.2.1.3'
DOT1Q_VLAN_FDB_ID = '1.3.6.1.2.1.17.7.1.4.2.1.3'
IF_NAME = '1.3.6.1.2.1.31.1.1.1.1'
IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
FDB_WALK_ROOTS = (BRIDGE_PORT_IFINDEX, DOT1D_FDB_PORT, DOT1D_FDB_STATUS,
                  DOT1Q_FDB_PORT, DOT1Q_FDB_STATUS, DOT1Q_VLAN_FDB_ID,
                  IF_NAME, IF_DESCR)
MAX_FDB_ROWS = 1500


@dataclass(frozen=True)
class FDBEntry:
    mac: str
    bridge_port: int
    if_index: int | None
    interface: str
    vlan: int | None = None
    fdb_id: int | None = None
    origin: str = 'BRIDGE-MIB'


def _suffix(oid: str, root: str) -> tuple[int, ...] | None:
    if not oid.startswith(root + '.'):
        return None
    bits = oid[len(root) + 1:].split('.')
    if not bits or any(not p.isdigit() for p in bits):
        return None
    return tuple(int(p) for p in bits)


def _port(value: str) -> int | None:
    if not value.isdecimal():
        return None
    number = int(value)
    return number if 0 < number <= 65535 else None


def _mac(octets: tuple[int, ...]) -> str:
    if len(octets) != 6 or any(x > 255 for x in octets):
        return ''
    if octets[0] & 1 or all(x == 0 for x in octets):
        return ''  # multicast, broadcast and all-zero are not host identities
    return ':'.join(f'{x:02X}' for x in octets)


def parse_fdb(values: Mapping[str, str], limit: int = MAX_FDB_ROWS) -> list[FDBEntry]:
    """Parse bounded BRIDGE/Q-BRIDGE tables with safe VLAN, MAC, port mapping."""
    if limit < 1:
        return []
    bridge_to_if: dict[int, int] = {}
    if_labels: dict[int, str] = {}
    if_descriptions: dict[int, str] = {}
    fdb_to_vlans: dict[int, set[int]] = {}
    for oid, value in values.items():
        suffix = _suffix(oid, BRIDGE_PORT_IFINDEX)
        if suffix and len(suffix) == 1 and _port(value):
            bridge_to_if[suffix[0]] = int(value)
        suffix = _suffix(oid, IF_NAME)
        if suffix and len(suffix) == 1 and value.strip():
            if_labels[suffix[0]] = value.strip()[:100]
        suffix = _suffix(oid, IF_DESCR)
        if suffix and len(suffix) == 1 and value.strip():
            if_descriptions[suffix[0]] = value.strip()[:100]
        suffix = _suffix(oid, DOT1Q_VLAN_FDB_ID)
        if suffix and len(suffix) == 1 and 1 <= suffix[0] <= 4094 and value.isdecimal():
            fdb_to_vlans.setdefault(int(value), set()).add(suffix[0])

    entries: list[FDBEntry] = []
    # Q-BRIDGE rows take precedence when the same MAC/port exists in BRIDGE-MIB.
    qbridge_pairs: set[tuple[str, int]] = set()
    for root, status_root, origin in (
        (DOT1Q_FDB_PORT, DOT1Q_FDB_STATUS, 'Q-BRIDGE-MIB'),
        (DOT1D_FDB_PORT, DOT1D_FDB_STATUS, 'BRIDGE-MIB'),
    ):
        for oid, value in sorted(values.items()):
            suffix = _suffix(oid, root)
            if suffix is None:
                continue
            if origin == 'Q-BRIDGE-MIB':
                if len(suffix) != 7:
                    continue
                fdb_id, octets = suffix[0], suffix[1:]
            else:
                if len(suffix) != 6:
                    continue
                fdb_id, octets = None, suffix
            mac, port = _mac(octets), _port(value)
            if not mac or port is None:
                continue
            status = values.get(status_root + '.' + '.'.join(map(str, suffix)), '3')
            if status != '3':
                continue  # only dynamically learned entries, not local/static/invalid
            pair = (mac, port)
            if origin == 'BRIDGE-MIB' and pair in qbridge_pairs:
                continue
            if origin == 'Q-BRIDGE-MIB':
                qbridge_pairs.add(pair)
            index = bridge_to_if.get(port)
            label = (if_labels.get(index) or if_descriptions.get(index) or
                     (f'ifIndex {index}' if index else f'bridgePort {port}'))
            vlans = fdb_to_vlans.get(fdb_id, set()) if fdb_id is not None else set()
            vlan = next(iter(vlans)) if len(vlans) == 1 else None
            entries.append(FDBEntry(mac, port, index, label, vlan, fdb_id, origin))
            if len(entries) >= limit:
                return entries
    return entries


def resolve_fdb_ip(entry: FDBEntry, devices: Sequence) -> str:
    """Correlate a learned MAC with one scanned IP; still NOT a direct link."""
    from .network import normalize_mac
    matches = {d.ip for d in devices if normalize_mac(d.mac) == entry.mac}
    return next(iter(matches)) if len(matches) == 1 else ''
