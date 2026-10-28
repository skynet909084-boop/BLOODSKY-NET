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
