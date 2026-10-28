"""Offline patterns from locally saved, explicitly labelled ICMP monitor events.

These are observations of monitor responses, never proof of power, cable or
network failures. Incomplete journal coverage never implies there were no events.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import re
from typing import Mapping, Sequence

MAX_ROWS = 5000
WINDOW_DAYS = 7
EPISODE_GAP_SECONDS = 15 * 60
_IP_AT_START = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})(?:\s|$)')


@dataclass(frozen=True)
class RecurrentIncident:
    ip: str
    episodes: int
    distinct_utc_days: int
    first_at: datetime
    last_at: datetime
    recurring_utc_hour: int | None


@dataclass(frozen=True)
class AvailabilityIndex:
    score: int | None
    responsive: int
    unresponsive: int
    explanation: str


def availability_index(states: Mapping[str, str] | None, min_hosts: int = 3) -> AvailabilityIndex:
    """Ratio of *fresh* ICMP responses, not an overall network-health score.

    Caller must pass only freshly measured, valid observation states. With fewer
    than min_hosts samples, a numerical index would mislead and is omitted.
    """
    up = down = 0
    for ip, value in (states or {}).items():
        try:
            ipaddress.IPv4Address(ip)
        except (ValueError, TypeError):
            continue
        if value == 'up':
            up += 1
        elif value == 'down':
            down += 1
    total = up + down
    if total < min_hosts:
        return AvailabilityIndex(None, up, down,
            f'Недостаточно свежих ICMP-измерений ({total} из минимум {min_hosts}); индекс не рассчитывается.')
    score = round(100 * up / total)
    return AvailabilityIndex(score, up, down,
        f'Из {total} проверенных IPv4-адресов {up} ответили на ICMP. '
        'Это доля ответов на Ping, НЕ оценка общей исправности сети; ICMP может фильтроваться.')


def recurrent_incidents(rows: Sequence[tuple], now: datetime | None = None) -> tuple[RecurrentIncident, ...]:
    """Find repeated offline *transitions* visible in the bounded local log.

    Detect 3+ distinct episodes across 2+ UTC days within 7 days. Merge repeat
    rows for same IP within 15 minutes. Don't infer periodic outages from gaps.
    The optional same-UTC-hour hint is shown only for 3+ episodes across >=2 days.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('now must be timezone-aware')
    now = now.astimezone(timezone.utc)
    threshold = now - timedelta(days=WINDOW_DAYS)
    events: dict[str, set[datetime]] = {}
    for row in list(rows)[:MAX_ROWS]:
        try:
            timestamp, severity, title, detail = row
            if severity != 'error' or title != 'Устройство не отвечает' or not isinstance(detail, str):
                continue
            match = _IP_AT_START.match(detail)
            if not match:
                continue
            ip = str(ipaddress.IPv4Address(match.group(1)))
            stamp = datetime.fromisoformat(timestamp)
            if stamp.tzinfo is None:
                continue
            stamp = stamp.astimezone(timezone.utc)
            if not threshold <= stamp <= now:
                continue
            events.setdefault(ip, set()).add(stamp)
        except (TypeError, ValueError, IndexError, OverflowError):
            continue
    patterns = []
    for ip, recorded in events.items():
        starts: list[datetime] = []
        previous = None
        for stamp in sorted(recorded):
            if previous is None or (stamp - previous).total_seconds() > EPISODE_GAP_SECONDS:
                starts.append(stamp)
            previous = stamp
        distinct_days = {t.date() for t in starts}
        if len(starts) < 3 or len(distinct_days) < 2:
            continue
        hours = {}
        for t in starts:
            hours.setdefault(t.hour, []).append(t)
        candidates = [hour for hour, stamps in hours.items()
                      if len(stamps) >= 3 and len({s.date() for s in stamps}) >= 2]
        repeated_hour = min(candidates, key=lambda hour:(-len(hours[hour]),hour)) if candidates else None
        patterns.append(RecurrentIncident(ip,len(starts),len(distinct_days),starts[0],starts[-1],repeated_hour))
    return tuple(sorted(patterns, key=lambda item:(-item.episodes,item.ip))[:10])
