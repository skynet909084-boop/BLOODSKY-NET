"""Conservative incident correlation with *historical* LLDP capture windows.

LLDP snapshots only bracket a change in reported data. They cannot tell when a
cable changed, or whether the link failed. MAC matches to inventory must be
unique; no FDB entries, hostnames, inferred ports, or missing polls are used.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import ipaddress
import re
from typing import Sequence

from .detective_timeline import IncidentMoment


@dataclass(frozen=True)
class LldpWindow:
    switch_ip: str
    before_at: datetime
    after_at: datetime
    changes: tuple[object, ...]
    before_links: tuple[object, ...]


@dataclass(frozen=True)
class IncidentLink:
    switch_ip: str
    device_ip: str
    before_at: datetime
    after_at: datetime
    event_at: datetime
    reported_port: str
    change_kind: str
    description: str


def _aware(ts):
    return isinstance(ts, datetime) and ts.tzinfo is not None and ts.utcoffset() is not None


def _valid_window(w, max_span=300):
    if not _aware(w.before_at) or not _aware(w.after_at):
        return False
    try:
        addr = ipaddress.IPv4Address(w.switch_ip)
    except (ValueError, TypeError):
        return False
    seconds = (w.after_at - w.before_at).total_seconds()
    return 0 < seconds <= max_span and not addr.is_multicast and not addr.is_unspecified


def _mac(value):
    """Only explicit twelve-hex chassis/MAC identifiers; never match on names."""
    if not isinstance(value, str) or not re.fullmatch(
            r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', value.strip()):
        return None
    return re.sub('[:-]', '', value.strip()).upper()


def _unique_mac_inventory(devices):
    owners = {}
    for device in list(devices)[:1024]:
        try:
            ip = str(ipaddress.IPv4Address(device.ip))
            mac = _mac(device.mac)
        except (ValueError, TypeError, AttributeError):
            continue
        if mac:
            owners.setdefault(mac, set()).add(ip)
    return {mac: next(iter(ips)) for mac, ips in owners.items() if len(ips) == 1}


def _valid_changes(w):
    """Only link changes with exactly one matching prior LLDP observation."""
    for ch in list(w.changes)[:100]:
        kind = getattr(ch, 'category', '')
        if kind not in ('not_reported', 'local_port_changed'):
            continue
        if str(getattr(ch, 'source_ip', '')) != w.switch_ip:
            continue
        before = str(getattr(ch, 'before', ''))
        neighbor = str(getattr(ch, 'neighbor', ''))
        prior = []
        for link in list(w.before_links)[:512]:
            if str(getattr(link, 'source_ip', '')) != w.switch_ip:
                continue
            if (str(getattr(link, 'remote_name', '') or getattr(link, 'remote_chassis', '')) != neighbor):
                continue
            label = str(getattr(link, 'local_port', ''))
            num = getattr(link, 'local_port_num', None)
            if before in (label, f'{label} (#{num})'):
                prior.append(link)
        if len(prior) == 1:
            yield kind, prior[0]


def correlate_history(events: Sequence[object], windows: Sequence[LldpWindow],
                      devices: Sequence[object], margin_seconds: int = 45) -> tuple[IncidentLink, ...]:
    """A temporal overlap is a *lead to verify*, not proof of an outage cause.

    Bracket [before, after] is always preserved in evidence, never replaced
    with a guessed point-in-time change. Only previously known inventory MACs.
    """
    if not 0 <= margin_seconds <= 60:
        raise ValueError('Invalid observation tolerance')
    by_mac = _unique_mac_inventory(devices)
    events_by_ip = {}
    for ev in list(events)[:200]:
        if getattr(ev, 'kind', None) != 'no_icmp' or not _aware(getattr(ev, 'observed_at', None)):
            continue
        try:
            addr = str(ipaddress.IPv4Address(ev.ip))
        except (TypeError, ValueError, AttributeError):
            continue
        events_by_ip.setdefault(addr, []).append(ev.observed_at.astimezone(timezone.utc))
    matches = []
    dedup = set()
    for w in list(windows)[:30]:
        if not _valid_window(w):
            continue
        for kind, link in _valid_changes(w):
            ip = by_mac.get(_mac(getattr(link, 'remote_chassis', '')))
            if not ip:
                continue
            for when in events_by_ip.get(ip, ()):
                if not w.before_at <= when <= (w.after_at + timedelta(seconds=margin_seconds)):
                    continue
                key = (w.switch_ip, ip, kind, w.before_at, w.after_at)
                if key in dedup:
                    continue
                dedup.add(key)
                port = str(getattr(link, 'local_port', ''))[:90]
                matches.append(IncidentLink(w.switch_ip, ip, w.before_at, w.after_at,
                    when, port, kind,
                    'Временная связь между неответом ICMP и изменением опубликованной LLDP-таблицы. '
                    'Снимки ограничивают интервал, но не показывают точное время изменения и не доказывают неисправность кабеля.'))
    return tuple(sorted(matches, key=lambda x:(x.event_at,x.switch_ip,x.device_ip,x.reported_port))[:12])


def history_moments(windows: Sequence[LldpWindow]) -> tuple[IncidentMoment, ...]:
    """Show capture time as capture time, never as observed physical change time."""
    moments = []
    for w in list(windows)[:30]:
        if not _valid_window(w):
            continue
        for kind, link in _valid_changes(w):
            port = str(getattr(link, 'local_port', ''))[:90]
            moments.append(IncidentMoment(w.after_at.astimezone(timezone.utc),
                'LLDP (снимок)', f'{w.switch_ip}: {kind}, ранее сообщался порт {port}; '
                'момент изменения неизвестен'))
    return tuple(sorted(moments, key=lambda x:(x.observed_at,x.description))[-30:])
