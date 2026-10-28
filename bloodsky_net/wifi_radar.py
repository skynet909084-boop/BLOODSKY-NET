"""Offline Wi-Fi RADAR: conservative, timestamped observations from Windows WLAN.

Signal is a Windows-reported percent, never RSSI dBm. No radio spectrum survey,
packet capture, location inference or password access. A gap is not an outage.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Sequence

BSSID_PATTERN = re.compile(r'^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
MAX_GAP_SECONDS = 180
MAX_DAYS = 7


@dataclass(frozen=True)
class WifiSample:
    observed_at: datetime
    connected: bool
    ssid: str
    bssid: str
    signal: int | None
    channel: int | None


@dataclass(frozen=True)
class RadarEvent:
    at: datetime
    kind: str
    detail: str
    confidence: str = 'наблюдение'


@dataclass(frozen=True)
class RadarSummary:
    sample_count: int
    connected_samples: int
    disconnected_samples: int
    mean_signal: float | None
    minimum_signal: int | None
    roams: int
    disconnections: int
    low_signal_periods: int
    events: tuple[RadarEvent, ...]


def normalize_rows(rows: Sequence[tuple], now: datetime | None = None) -> tuple[WifiSample, ...]:
    """Validate untrusted historical rows; do not infer absence from missing rows.

    Each row: (ts, connected, ssid, bssid, signal, channel).
    Unmeasured Wi-Fi (no WLAN adapter or query failed) must never be inserted.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('timezone-aware now required')
    now = now.astimezone(timezone.utc)
    result = []
    for row in list(rows)[-20160:]:
        try:
            stamp, connection, ssid, bssid, signal, channel = row
            stamp = datetime.fromisoformat(str(stamp).replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                continue
            stamp = stamp.astimezone(timezone.utc)
            if stamp > now or stamp < now - timedelta(days=MAX_DAYS):
                continue
            if type(connection) not in (bool, int) or int(connection) not in (0, 1):
                continue
            if not isinstance(ssid, str) or not isinstance(bssid, str):
                continue
            is_connected = bool(connection)
            bssid = bssid.upper()
            if is_connected:
                if not BSSID_PATTERN.fullmatch(bssid):
                    continue  # WLAN did not report unique AP identity.
                if type(signal) is not int or not (0 <= signal <= 100):
                    continue
                if type(channel) is not int or not (0 <= channel <= 233):
                    continue
            result.append(WifiSample(stamp, is_connected, ssid[:128],
                                     bssid if is_connected else '',
                                     signal if is_connected else None,
                                     channel if is_connected and channel else None))
        except (ValueError, TypeError, IndexError):
            continue
    return tuple(sorted(result, key=lambda x: x.observed_at))


def analyze(samples: Sequence[WifiSample]) -> RadarSummary:
    """Infer transitions only between consecutive, closely spaced observations.

    A roam means BSSID changed while SSID stayed the same; a disconnect is
    explicitly measured, never inferred from missing samples. Sustained weak
    signal requires two consecutive readings <45%, not one transient point.
    """
    ordered = sorted(samples, key=lambda x: x.observed_at)[-20160:]
    events: list[RadarEvent] = []
    connected = [s for s in ordered if s.connected and s.signal is not None]
    lows, roams, disc = 0, 0, 0
    for prev, current in zip(ordered, ordered[1:]):
        age = (current.observed_at - prev.observed_at).total_seconds()
        if not (0 < age <= MAX_GAP_SECONDS):
            continue
        if prev.connected and not current.connected:
            disc += 1
            events.append(RadarEvent(current.observed_at, 'disconnect',
                                     f'Windows WLAN: отключение после {prev.ssid or "неизвестной сети"}'))
        elif prev.connected and current.connected:
            if current.ssid != prev.ssid:
                events.append(RadarEvent(current.observed_at, 'network_change',
                                         f'Смена SSID: {prev.ssid} → {current.ssid}'))
            elif current.bssid != prev.bssid:
                roams += 1
                events.append(RadarEvent(current.observed_at, 'roam',
                                         f'{current.ssid}: BSSID {prev.bssid} → {current.bssid}'))
    # Distinct sustained low-signal periods (at least two measured points).
    streak = 0
    last: WifiSample | None = None
    for current in ordered:
        contiguous = (last is not None and current.connected and last.connected and
                      current.ssid == last.ssid and current.bssid == last.bssid and
                      0 < (current.observed_at-last.observed_at).total_seconds() <= MAX_GAP_SECONDS)
        if current.connected and current.signal is not None and current.signal < 45:
            streak = streak+1 if contiguous and last.signal is not None and last.signal < 45 else 1
            if streak == 2:
                lows += 1
                events.append(RadarEvent(current.observed_at, 'weak_signal',
                                         f'Два подряд измерения ниже 45% ({last.signal}%, {current.signal}%)'))
        else:
            streak = 0
        last = current
    values = [s.signal for s in connected if s.signal is not None]
    return RadarSummary(len(ordered), len(connected), sum(not s.connected for s in ordered),
                        round(sum(values)/len(values), 1) if values else None,
                        min(values) if values else None, roams, disc, lows,
                        tuple(sorted(events, key=lambda e:(e.at,e.kind))[-100:]))
