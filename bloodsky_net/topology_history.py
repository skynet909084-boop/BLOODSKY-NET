"""LLDP observation history, not an assertion that cables were added/removed.

A vanished LLDP row is only a change in the switch's reported neighbor table.
Never infer a remote IP, VLAN, port state or confirmed link from FDB entries.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Sequence

MAX_NEIGHBORS = 512


@dataclass(frozen=True)
class LinkObservation:
    source_ip: str
    local_port_num: int
    local_port: str
    remote_chassis: str
    remote_port: str
    remote_name: str


@dataclass(frozen=True)
class LinkChange:
    source_ip: str
    category: str
    neighbor: str
    before: str
    after: str
    explanation: str


def observations(snapshot) -> tuple[LinkObservation, ...]:
    """Whitelist metadata from one successful read, without SNMP secrets or descriptions."""
    source = str(ipaddress.IPv4Address(snapshot.source_ip))
    if len(snapshot.neighbors) > MAX_NEIGHBORS:
        raise ValueError('Too many LLDP neighbors in a capture')
    seen = set()
    links = []
    for n in snapshot.neighbors:
        if n.source_ip != source or not 1 <= int(n.local_port_num) <= 2_147_483_647:
            raise ValueError('Invalid LLDP source/port')
        link = LinkObservation(source, int(n.local_port_num), str(n.local_port)[:90],
                               str(n.remote_chassis)[:128], str(n.remote_port)[:120],
                               str(n.remote_name)[:120])
        # A neighbor without an identity is ambiguous and must not be compared.
        if not (link.remote_chassis or link.remote_name):
            continue
        if link not in seen:
            seen.add(link)
            links.append(link)
    return tuple(sorted(links, key=lambda x: (x.local_port_num, x.remote_chassis, x.remote_name, x.remote_port)))


def compare_links(before: Sequence[LinkObservation], after: Sequence[LinkObservation]) -> list[LinkChange]:
    """Conservative comparison: detect port move only with a unique chassis+remote port.

    Disambiguation deliberately avoids using names alone to claim a port move.
    """
    a = set(before)
    b = set(after)
    if any(x.source_ip != y.source_ip for x in a for y in b):
        raise ValueError('Only compare LLDP data for the same switch')
    changes = []
    before_only = a - b
    after_only = b - a
    key = lambda x: (x.remote_chassis.lower(), x.remote_port.lower()) if x.remote_chassis and x.remote_port else None
    left_by_id = {}
    right_by_id = {}
    for x in before:
        k = key(x)
        if k:
            left_by_id.setdefault(k, []).append(x)
    for x in after:
        k = key(x)
        if k:
            right_by_id.setdefault(k, []).append(x)
    for k in sorted(set(left_by_id) & set(right_by_id)):
        left = left_by_id[k]
        right = right_by_id[k]
        if len(left) != 1 or len(right) != 1:
            continue
        old, new = left[0], right[0]
        if old.local_port_num != new.local_port_num or old.local_port != new.local_port:
            changes.append(LinkChange(new.source_ip, 'local_port_changed',
                new.remote_name or new.remote_chassis, f'{old.local_port} (#{old.local_port_num})',
                f'{new.local_port} (#{new.local_port_num})',
                'Изменился порт в LLDP-таблице; переподключение кабеля не доказано'))
        elif old.remote_name != new.remote_name:
            changes.append(LinkChange(new.source_ip, 'name_changed', new.remote_chassis,
                old.remote_name or '—', new.remote_name or '—', 'Изменилось имя LLDP-соседа'))
        if old in before_only:
            before_only.remove(old)
        if new in after_only:
            after_only.remove(new)
    for x in sorted(before_only, key=lambda p: (p.source_ip,p.local_port_num,p.remote_chassis,p.remote_name)):
        changes.append(LinkChange(x.source_ip, 'not_reported', x.remote_name or x.remote_chassis,
            x.local_port, '—', 'Больше не сообщается в успешном LLDP-опросе; это не доказательство обрыва кабеля'))
    for x in sorted(after_only, key=lambda p: (p.source_ip,p.local_port_num,p.remote_chassis,p.remote_name)):
        changes.append(LinkChange(x.source_ip, 'new_observation', x.remote_name or x.remote_chassis,
            '—', x.local_port, 'Впервые отмечен в выбранных LLDP-снимках; не подтверждает время подключения'))
    return changes
