"""Deterministic, evidence-labelled network inventory timeline. Never infer cables.

A missing measurement is NOT an outage. A device absent from a historical
inventory is NOT proof it disappeared from the network.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Mapping


KNOWN_STATES = frozenset({'up', 'down', 'unknown'})


@dataclass(frozen=True)
class SnapshotDevice:
    ip: str
    state: str = 'unknown'
    mac: str = ''
    hostname: str = ''
    kind: str = ''
    vendor: str = ''


@dataclass(frozen=True)
class Change:
    ip: str
    category: str
    before: str
    after: str
    description: str


def as_snapshot_device(device, state: str = 'unknown') -> SnapshotDevice:
    """Deliberately whitelist inventory fields: no credentials or arbitrary attrs."""
    ip = str(ipaddress.IPv4Address(device.ip))
    if state not in KNOWN_STATES:
        raise ValueError('Invalid observed status')
    return SnapshotDevice(ip=ip, state=state,
                          mac=str(device.mac or '').upper()[:32],
                          hostname=str(device.hostname or '')[:120],
                          kind=str(device.kind or '')[:120],
                          vendor=str(device.vendor or '')[:120])


def diff(left: Mapping[str, SnapshotDevice], right: Mapping[str, SnapshotDevice]) -> list[Change]:
    """Only compare known observations. 'No row' means not in inventory, not offline."""
    result: list[Change] = []
    for ip in sorted(set(left) | set(right), key=lambda x: int(ipaddress.IPv4Address(x))):
        old, new = left.get(ip), right.get(ip)
        if old is None:
            result.append(Change(ip, 'new_inventory', '—', 'в инвентаре',
                                 'Новое в сохранённом инвентаре (не подтверждает время подключения)'))
            continue
        if new is None:
            result.append(Change(ip, 'not_in_snapshot', 'в инвентаре', '—',
                                 'Отсутствует в новом снимке (не доказательство отключения)'))
            continue
        if old.state != new.state:
            if old.state in ('up', 'down') and new.state in ('up', 'down'):
                result.append(Change(ip, 'availability', old.state, new.state,
                                     'Изменение наблюдаемой доступности'))
            else:
                result.append(Change(ip, 'measurement', old.state, new.state,
                                     'Изменение полноты измерений (не подтверждённая авария)'))
        for field, category, label in (
            ('mac', 'mac', 'MAC'), ('hostname', 'hostname', 'DNS-имя'),
            ('kind', 'kind', 'тип'), ('vendor', 'vendor', 'производитель')
        ):
            a, b = getattr(old, field), getattr(new, field)
            # Unknown -> known is enrichment, not evidence of replacement.
            if a != b:
                result.append(Change(ip, category, a or '—', b or '—',
                                     f'Изменилось поле {label}' if a and b else f'Уточнено поле {label}'))
    return result


def summary(changes: list[Change]) -> dict[str, int]:
    cats = {'new_inventory': 0, 'not_in_snapshot': 0, 'availability': 0,
            'measurement': 0, 'mac': 0, 'hostname': 0, 'kind': 0, 'vendor': 0}
    for item in changes:
        cats[item.category] += 1
    return cats
