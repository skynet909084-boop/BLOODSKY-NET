"""Auditable, offline incident timeline and *tentative* LLDP/port correlations.

Only trusted, recent monitor events and fresh LLDP/SNMP observations from the UI
may be passed here. An LLDP neighbor is not proof of a healthy cable, and an
LLDP local port number MUST NOT be treated as an IF-MIB ifIndex.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Sequence


@dataclass(frozen=True)
class LldpEndpoint:
    switch_ip: str
    device_ip: str
    local_port: str  # reported LLDP port *name*, not a physical-cable verdict


@dataclass(frozen=True)
class TimedPortFault:
    delta: object
    observed_at: datetime


@dataclass(frozen=True)
class IncidentMoment:
    observed_at: datetime
    source: str
    description: str


@dataclass(frozen=True)
class CorrelatedIncident:
    code: str
    switch_ip: str
    target_ips: tuple[str, ...]
    port_name: str
    description: str
    evidence: tuple[str, ...]


def verified_lldp_endpoints(snapshots, devices) -> tuple[LldpEndpoint, ...]:
    """Map only uniquely resolved neighbors from fresh snapshots supplied by UI.

    Ambiguous multiple LLDP ports for the same (switch, target) are excluded.
    FDB is deliberately ignored; its learned MAC is not a cable observation.
    """
    from .topology import resolve_neighbor_ip
    endpoints = {}
    for switch_ip, snapshot in sorted(snapshots.items()):
        try:
            switch = str(ipaddress.IPv4Address(switch_ip))
        except (ValueError, TypeError):
            continue
        for neighbor in list(snapshot.neighbors)[:512]:
            target = resolve_neighbor_ip(neighbor, devices)
            if not target or target == switch:
                continue
            name = str(neighbor.local_port or '').strip()[:100]
            if not name:
                continue
            endpoints.setdefault((switch, target), set()).add(name)
    result = [LldpEndpoint(sw, target, next(iter(names)))
              for (sw, target), names in sorted(endpoints.items()) if len(names) == 1]
    return tuple(result[:512])


def _valid_time(value) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _event_data(events: Sequence[object]):
    out = {}
    for row in list(events)[:200]:
        stamp = getattr(row, 'observed_at', None)
        ip = getattr(row, 'ip', None)
        if getattr(row, 'kind', None) != 'no_icmp' or not _valid_time(stamp):
            continue
        try:
            addr = str(ipaddress.IPv4Address(ip))
        except (ValueError, TypeError):
            continue
        # Preserve the first timestamp: subsequent repeated ICMP probes don't
        # provide multiple independent incidents.
        out.setdefault(addr, stamp.astimezone(timezone.utc))
        if stamp < out[addr]:
            out[addr] = stamp.astimezone(timezone.utc)
    return out


def _has_errors(delta) -> bool:
    return any(type(getattr(delta, field, None)) is int and getattr(delta, field) >= 5
               for field in ('in_errors', 'out_errors', 'in_discards', 'out_discards'))


def _fault_data(faults: Sequence[TimedPortFault]):
    result = []
    for item in list(faults)[:300]:
        stamp = getattr(item, 'observed_at', None)
        d = getattr(item, 'delta', None)
        if not _valid_time(stamp) or not _has_errors(d):
            continue
        try:
            switch = str(ipaddress.IPv4Address(d.switch_ip))
            name = str(d.name).strip()[:100]
            seconds = float(d.seconds)
            if not name or not 1 <= seconds <= 3600:
                continue
        except (ValueError, TypeError, AttributeError):
            continue
        result.append((switch, name, stamp.astimezone(timezone.utc), d))
    return result


def timeline(events: Sequence[object], faults: Sequence[TimedPortFault], limit: int = 60) -> tuple[IncidentMoment, ...]:
    """Chronological, bounded display. A counter delta is a measurement, not a failure."""
    if not 1 <= limit <= 100:
        raise ValueError('Invalid timeline limit')
    moments = [IncidentMoment(stamp, 'ICMP', f'{ip}: нет ответа по журналу мониторинга')
               for ip, stamp in _event_data(events).items()]
    for switch, name, stamp, delta in _fault_data(faults):
        counters = ', '.join(f'{key}: +{getattr(delta, attr)}' for key, attr in
                             (('inErr','in_errors'), ('outErr','out_errors'),
                              ('inDrop','in_discards'), ('outDrop','out_discards'))
                             if type(getattr(delta, attr, None)) is int and getattr(delta, attr) >= 5)
        moments.append(IncidentMoment(stamp, 'SNMP', f'{switch} · {name}: {counters}'))
    return tuple(sorted(moments, key=lambda m:(m.observed_at, m.source, m.description))[-limit:])


def correlate(events: Sequence[object], endpoints: Sequence[LldpEndpoint],
              faults: Sequence[TimedPortFault], window_seconds: int = 120) -> tuple[CorrelatedIncident, ...]:
    """Only attach a port when its *name* matches an unambiguous LLDP endpoint.

    No ifIndex == LLDP port-id assumptions, no FDB-derived links, and no
    invented root cause, even when two indicators happen close together.
    """
    if not 10 <= window_seconds <= 300:
        raise ValueError('Invalid correlation window')
    events_by_ip = _event_data(events)
    valid = []
    endpoint_groups = {}
    for e in list(endpoints)[:512]:
        try:
            sw = str(ipaddress.IPv4Address(e.switch_ip))
            ip = str(ipaddress.IPv4Address(e.device_ip))
        except (ValueError, TypeError):
            continue
        name = str(e.local_port).strip()[:100]
        if sw == ip or not name:
            continue
        endpoint_groups.setdefault((sw, ip), set()).add(name)
    for (sw, ip), names in sorted(endpoint_groups.items()):
        if len(names) == 1 and ip in events_by_ip:
            valid.append((sw, ip, next(iter(names)), events_by_ip[ip]))
    by_switch = {}
    for sw, ip, name, stamp in valid:
        by_switch.setdefault(sw, []).append((ip, name, stamp))
    findings = []
    # Common switch from uniquely observed LLDP adjacency does not identify an uplink.
    for sw, items in sorted(by_switch.items()):
        items = sorted(items, key=lambda x:(x[2],x[0]))
        best = []
        for row in items:
            burst = [x for x in items if 0 <= (x[2]-row[2]).total_seconds() <= window_seconds]
            if len(burst) > len(best):
                best = burst
        if len(best) >= 2:
            ips = tuple(sorted({x[0] for x in best}, key=lambda x:int(ipaddress.IPv4Address(x))))[:6]
            evidence = tuple(f'{x[2].isoformat(timespec="seconds")}: {x[0]} · LLDP {sw} / {x[1]}' for x in best[:6])
            findings.append(CorrelatedIncident('common_lldp_source',sw,ips,'',
                'Несколько LLDP-соседей одного коммутатора перестали отвечать на ICMP близко по времени. '
                'Общий uplink или причина не установлены.',evidence))
    # Match *named* port to *one* endpoint of this switch. Even if same ifIndex,
    # a mismatching name MUST NOT be correlated.
    port_endpoints = {}
    for sw, ip, name, stamp in valid:
        port_endpoints.setdefault((sw,name.casefold()), []).append((ip,name,stamp))
    for sw, name, seen_at, delta in _fault_data(faults):
        peers = port_endpoints.get((sw,name.casefold()), ())
        if len(peers) != 1:
            continue
        ip, reported_name, event_time = peers[0]
        if abs((seen_at-event_time).total_seconds()) > window_seconds:
            continue
        findings.append(CorrelatedIncident('lldp_port_temporal_match',sw,(ip,),reported_name,
            'Ошибки порта SNMP и событие ICMP LLDP-соседа произошли близко по времени. '
            'Проверить интерфейс, питание, ACL и сетевой путь; это не подтверждённая поломка порта или кабеля.',
            (f'ICMP: {ip} · {event_time.isoformat(timespec="seconds")}',
             f'LLDP: {sw} / {reported_name} → {ip} (однозначный сосед)',
             f'SNMP: {sw} / {name}, ifIndex {delta.index}, измерено {seen_at.isoformat(timespec="seconds")}')))
    return tuple(sorted(findings, key=lambda x:(x.code,x.switch_ip,x.target_ips,x.port_name))[:12])
