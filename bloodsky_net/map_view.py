"""Pure, deterministic LIVE MAP view model; never guess physical connections.

Only already discovered local devices participate. This module performs no I/O.
Links are provided separately from current, confirmed LLDP observations.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
from typing import Sequence


STATUS_OPTIONS = ("Все", "В сети", "Нет связи", "IP-подозрение")
MAX_MAP_NODES = 120


@dataclass(frozen=True)
class MapSelection:
    devices: tuple
    total_matched: int
    total_inventory: int

    @property
    def omitted(self) -> int:
        return self.total_matched - len(self.devices)


def select_devices(devices: Sequence, query: str = "", status: str = "Все",
                   alert_ips=(), limit: int = MAX_MAP_NODES) -> MapSelection:
    """Filter already-known nodes; never scan, or claim a cached node is online."""
    if status not in STATUS_OPTIONS:
        raise ValueError("Unknown map status filter")
    if not 1 <= limit <= 1000:
        raise ValueError("Invalid map limit")
    needle = query.strip().casefold()[:128]
    alerts = set(alert_ips)
    filtered = []
    for device in devices:
        if status == "В сети" and not device.online:
            continue
        if status == "Нет связи" and device.online:
            continue
        if status == "IP-подозрение" and device.ip not in alerts:
            continue
        if needle and not any(needle in str(getattr(device, key, '') or '').casefold()
                              for key in ('ip', 'mac', 'hostname', 'vendor', 'kind')):
            continue
        filtered.append(device)
    # Numeric IPv4 ordering; deterministic even when discovery order differs.
    filtered.sort(key=lambda device: int(ipaddress.IPv4Address(device.ip)))
    return MapSelection(tuple(filtered[:limit]), len(filtered), len(devices))


def ring_positions(devices: Sequence, zoom: float = 1.0):
    """Return stable relative coordinates for canvas and SVG views."""
    if not 0.5 <= zoom <= 2.0 or not math.isfinite(zoom):
        raise ValueError("Map zoom must be 0.5..2.0")
    positions = []
    cursor = 0
    ring = 0
    while cursor < len(devices):
        count = min(len(devices) - cursor, 18 + ring * 12)
        radius = (185 + ring * 145) * zoom
        for idx in range(count):
            angle = (2 * math.pi * idx / count) - math.pi / 2
            positions.append((devices[cursor + idx], radius * math.cos(angle), radius * math.sin(angle)))
        cursor += count
        ring += 1
    return positions


def lldp_edges(snapshots, devices: Sequence):
    """Only observed LLDP links with uniquely resolved discovered endpoints."""
    from .topology import physical_links
    return physical_links(snapshots, devices)

# Grouping and manually positioned nodes are local-only layout hints, not topology.
GROUP_OPTIONS = ('Без групп', 'Подсеть /24', 'Тип')
MAX_POSITION = 2500.0


def group_name(device, group_by: str) -> str:
    if group_by == 'Без групп':
        return ''
    if group_by == 'Подсеть /24':
        return str(ipaddress.IPv4Network(f'{device.ip}/24', strict=False))
    if group_by == 'Тип':
        return (device.kind or 'Не определён')[:60]
    raise ValueError('Unknown grouping')


def valid_position(x, y) -> bool:
    return (all(type(v) in (int, float) and math.isfinite(v) for v in (x, y))
            and all(abs(v) <= MAX_POSITION for v in (x, y)))


def layout_positions(devices: Sequence, zoom: float = 1.0,
                     group_by: str = 'Без групп', manual=None):
    """Deterministic map positions; persisted offsets are unzoomed canvas units."""
    if group_by not in GROUP_OPTIONS:
        raise ValueError('Unknown grouping')
    if not 0.5 <= zoom <= 2.0 or not math.isfinite(zoom):
        raise ValueError('Invalid zoom')
    manual = manual or {}
    order = sorted(devices, key=lambda d: int(ipaddress.IPv4Address(d.ip)))
    if group_by == 'Без групп':
        positions = ring_positions(order)
    else:
        groups = {}
        for d in order:
            groups.setdefault(group_name(d, group_by), []).append(d)
        keys = sorted(groups)
        if len(keys) == 1:
            positions = ring_positions(order)
        else:
            count_col = math.ceil(math.sqrt(len(keys)))
            positions = []
            for index, group in enumerate(keys):
                members = groups[group]
                columns = min(count_col, len(keys))
                x0 = (index % count_col - (columns - 1) / 2) * 480
                y0 = (index // count_col - (math.ceil(len(keys) / count_col)-1)/2) * 430
                for j, dev in enumerate(members):
                    # At most 12 around each local ring. Deliberate layout, not a link.
                    layer, pos = divmod(j, 12)
                    slots = min(len(members) - layer*12, 12)
                    angle = 2*math.pi*pos/max(slots, 1) - math.pi/2
                    radius = 105 + layer * 105
                    positions.append((dev, x0 + radius*math.cos(angle), y0 + radius*math.sin(angle)))
    result = []
    for dev, x, y in positions:
        override = manual.get(dev.ip)
        if override and len(override) == 2 and valid_position(*override):
            x, y = override
        result.append((dev, x * zoom, y * zoom))
    return result


def group_centers(positions, group_by: str):
    """Group header locations for the current map, not SNMP assertions."""
    if group_by == 'Без групп':
        return {}
    by_group = {}
    for dev, x, y in positions:
        by_group.setdefault(group_name(dev, group_by), []).append((x, y))
    return {key: (sum(p[0] for p in pts)/len(pts), min(p[1] for p in pts)-78)
            for key, pts in by_group.items()}


@dataclass(frozen=True)
class LearnedPort:
    switch_ip: str
    interface: str
    vlan: int | None


def learned_ports(snapshots, devices: Sequence):
    """Correlate fresh FDB observations to a unique MAC; never call it a cable.

    A MAC learned on multiple switches is deliberately kept as multiple observations.
    Unknown VLAN remains None and does not imply untagged membership.
    """
    from .fdb import resolve_fdb_ip
    found = {}
    for switch_ip, snap in sorted(snapshots.items()):
        for row in snap.fdb_entries[:1500]:
            ip = resolve_fdb_ip(row, devices)
            if not ip:
                continue
            entry = LearnedPort(switch_ip, row.interface[:100], row.vlan)
            items = found.setdefault(ip, set())
            if len(items) < 16:
                items.add(entry)
    return {ip: tuple(sorted(items, key=lambda r:(r.switch_ip, r.interface, r.vlan or -1)))
            for ip, items in found.items()}


def passport(device, learned=(), links=()):
    """Human-readable device details with explicitly labelled evidence."""
    state = 'В сети (текущий опрос)' if device.online else 'Не отвечает / последнее известное устройство'
    pieces = [f'{device.ip} · {device.hostname or device.kind}',
              f'Состояние: {state} · MAC: {device.mac or "неизвестен"} · Производитель: {device.vendor or "не определён"}',
              f'Тип: {device.kind} · последний ответ: {device.seen or "неизвестен"} · Ping: {f"{device.latency_ms:.1f} мс" if device.latency_ms is not None else "нет измерения"}']
    if links:
        ports = [f'{n.local_port} ↔ {n.remote_port or "?"}' for n in links[:3]]
        pieces.append('LLDP-наблюдения портов: ' + '; '.join(ports))
    if learned:
        samples = [f'{r.switch_ip} / {r.interface} / VLAN {r.vlan if r.vlan is not None else "?"}'
                   for r in learned[:3]]
        pieces.append('FDB (изученный MAC, НЕ кабель): ' + '; '.join(samples))
        if len(learned)>3:
            pieces.append(f'И ещё {len(learned)-3} FDB-наблюдений')
    else:
        pieces.append('FDB: нет однозначно сопоставленных свежих наблюдений')
    return '\n'.join(pieces)
