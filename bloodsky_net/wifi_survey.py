"""Manual Wi-Fi coverage points, NOT a radio survey or interpolated heatmap.

Positions are user-entered normalized coordinates on an abstract 2D grid;
there is no GPS, floorplan scale, path-loss model or measured RSSI in dBm.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Sequence

BSSID = re.compile(r'(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')
MAX_POINTS = 2000
MAX_ZONES = 50


@dataclass(frozen=True)
class SurveyPoint:
    observed_at: str
    zone: str
    x: float
    y: float
    ssid: str
    bssid: str
    signal: int  # percentage provided by Windows WLAN; not dBm
    channel: int
    room: str = 'Без комнаты'
    phase: str = 'Без этапа'


@dataclass(frozen=True)
class ZoneQuality:
    zone: str
    samples: int
    mean_signal: float
    min_signal: int
    max_signal: int
    distinct_bssids: int


def validate_point(zone: str, x: float, y: float, ssid: str,
                   bssid: str, signal: int, channel: int, observed_at: str,
                   room: str = 'Без комнаты', phase: str = 'Без этапа') -> SurveyPoint:
    if not isinstance(zone, str) or not zone.strip() or len(zone.strip()) > 60 or any(ord(c) < 32 for c in zone):
        raise ValueError('Название зоны: от 1 до 60 символов без управляющих знаков')
    if not isinstance(room, str) or not room.strip() or len(room.strip()) > 60 or any(ord(c) < 32 for c in room):
        raise ValueError('Название комнаты: от 1 до 60 символов без управляющих знаков')
    if phase not in ('Без этапа', 'До', 'После'):
        raise ValueError('Неизвестный этап измерения')
    if type(x) not in (int, float) or type(y) not in (int, float) or not 0 <= x <= 100 or not 0 <= y <= 100:
        raise ValueError('Координаты должны быть в пределах 0–100')
    if not isinstance(ssid, str) or not ssid or len(ssid) > 128 or not BSSID.fullmatch(str(bssid)):
        raise ValueError('Для точки покрытия нужен достоверный SSID и BSSID')
    if type(signal) is not int or not 0 <= signal <= 100:
        raise ValueError('Недостоверное значение сигнала Wi-Fi')
    if type(channel) is not int or not 0 <= channel <= 233:
        raise ValueError('Недостоверный номер канала Wi-Fi')
    try:
        ts = datetime.fromisoformat(observed_at.replace('Z', '+00:00'))
    except (ValueError, AttributeError) as exc:
        raise ValueError('Неверная отметка времени') from exc
    if ts.tzinfo is None:
        raise ValueError('Отметка времени без часового пояса')
    return SurveyPoint(ts.astimezone(timezone.utc).isoformat(), zone.strip(),
                       round(float(x), 3), round(float(y), 3), ssid, bssid.upper(), signal, channel, room.strip(), phase)


def zone_quality(points: Sequence[SurveyPoint]) -> tuple[ZoneQuality, ...]:
    """Compare only directly sampled points; never invent values between them."""
    groups: dict[str, list[SurveyPoint]] = defaultdict(list)
    for point in points[:MAX_POINTS]:
        if isinstance(point, SurveyPoint) and point.zone:
            groups[point.zone].append(point)
    out = []
    for zone in sorted(groups)[:MAX_ZONES]:
        samples = groups[zone]
        values = [p.signal for p in samples]
        out.append(ZoneQuality(zone, len(values), round(sum(values)/len(values), 1),
                               min(values), max(values), len({p.bssid for p in samples})))
    return tuple(out)


def signal_color(signal: int) -> str:
    """A display-only threshold, not an assessment of throughput or reliability."""
    return '#FF6D7D' if signal < 45 else '#FFBD60' if signal < 70 else '#4CD4A5'


def spreadsheet_safe(value: str) -> str:
    """Prevent CSV formula execution from user zone labels and nearby SSIDs."""
    text = str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def room_quality(points: Sequence[SurveyPoint], zone: str) -> tuple[ZoneQuality, ...]:
    """Observed coverage per *user-labelled* room, never inferred from pixel colors."""
    groups: dict[str, list[SurveyPoint]] = defaultdict(list)
    for p in points[:MAX_POINTS]:
        if isinstance(p, SurveyPoint) and p.zone == zone and p.room:
            groups[p.room].append(p)
    result = []
    for room in sorted(groups)[:MAX_ZONES]:
        values = groups[room]
        signals = [p.signal for p in values]
        result.append(ZoneQuality(room, len(values), round(sum(signals)/len(signals), 1),
                                  min(signals), max(signals), len({p.bssid for p in values})))
    return tuple(result)


@dataclass(frozen=True)
class RoomComparison:
    room: str
    ssid: str
    before_samples: int
    after_samples: int
    before_mean: float
    after_mean: float
    delta: float


def compare_phases(points: Sequence[SurveyPoint], zone: str, min_samples: int = 2) -> tuple[RoomComparison, ...]:
    """Explicit before/after sample means for same floor, room, SSID. No inferred improvement.

    Samples are not paired in time or measurement position: this is descriptive only.
    Unlabelled historical samples and invalid sensor data never enter the comparison.
    """
    if type(min_samples) is not int or not 2 <= min_samples <= 30:
        raise ValueError('Нужно не менее двух измерений в каждом этапе')
    groups: dict[tuple[str, str], dict[str, list[int]]] = defaultdict(
        lambda: {'До': [], 'После': []})
    for p in points[:MAX_POINTS]:
        if not isinstance(p, SurveyPoint) or p.zone != zone or p.phase not in ('До', 'После'):
            continue
        if type(p.signal) is not int or not 0 <= p.signal <= 100 or not p.room or not p.ssid:
            continue
        groups[(p.room, p.ssid)][p.phase].append(p.signal)
    out = []
    for (room, ssid), phases in sorted(groups.items())[:MAX_POINTS]:
        before, after = phases['До'], phases['После']
        if len(before) < min_samples or len(after) < min_samples:
            continue
        before_avg, after_avg = sum(before)/len(before), sum(after)/len(after)
        out.append(RoomComparison(room, ssid, len(before), len(after),
                                  round(before_avg, 1), round(after_avg, 1), round(after_avg-before_avg, 1)))
    return tuple(out[:MAX_ZONES])


def room_signal_status(quality: ZoneQuality, minimum: int = 3) -> str:
    """Coloring requires repeated samples; not a confirmed throughput or connectivity issue."""
    if quality.samples < minimum:
        return 'insufficient'
    if quality.mean_signal < 45:
        return 'low'
    if quality.mean_signal < 70:
        return 'moderate'
    return 'observed_good'
