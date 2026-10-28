"""Local-only history of completed TLS transfer attempts, not device uptime.

We record outcomes and elapsed time, never tokens, certificate bytes, packet payloads
or claimed physical host availability. Gaps between attempts are unmeasured time.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
from typing import Sequence

OUTCOMES = frozenset(('accepted', 'network', 'tls', 'rejected'))
MAX_DURATION_MS = 60000
MAX_HISTORY = 2048


@dataclass(frozen=True)
class TransferAttempt:
    at: datetime
    destination: str
    outcome: str
    elapsed_ms: int


@dataclass(frozen=True)
class TransferSummary:
    destination: str
    total: int
    accepted: int
    network_failures: int
    security_failures: int
    acceptance_percent: int
    median_ms: int | None
    p95_ms: int | None
    last_accepted: datetime | None
    accepted_after_error: bool
    longest_unobserved_gap_minutes: int | None


def validate_attempt(a: TransferAttempt) -> TransferAttempt:
    if not isinstance(a,TransferAttempt) or not isinstance(a.at,datetime) or a.at.tzinfo is None:
        raise ValueError('Нужна корректная временная метка с часовым поясом')
    if type(a.destination) is not str or not 1 <= len(a.destination) <= 64 or any(ord(c) < 32 or ord(c) == 127 for c in a.destination):
        raise ValueError('Неверное имя получателя')
    if a.outcome not in OUTCOMES:
        raise ValueError('Недопустимый результат передачи')
    if type(a.elapsed_ms) is not int or not 0 <= a.elapsed_ms <= MAX_DURATION_MS:
        raise ValueError('Неверное время операции')
    return a


def _percentile(sorted_values: list[int], percentile: float) -> int:
    return sorted_values[math.ceil(percentile * len(sorted_values)) - 1]


def summarize(attempts: Sequence[TransferAttempt], now: datetime) -> tuple[TransferSummary, ...]:
    """Seven-day *observed request* metrics, not SLA or internet availability.

    Median and p95 are suppressed for fewer than three accepted requests.
    Recovery flag means acceptance after a recorded error, not continuous outage.
    """
    if not isinstance(now,datetime) or now.tzinfo is None:
        raise ValueError('Нужны часы с часовым поясом')
    now=now.astimezone(timezone.utc)
    grouped: dict[str,list[TransferAttempt]]={}
    for a in list(attempts)[:MAX_HISTORY]:
        try:
            validate_attempt(a)
            stamp=a.at.astimezone(timezone.utc)
            if not timedelta(0) <= now-stamp <= timedelta(days=7):
                continue
            grouped.setdefault(a.destination,[]).append(a)
        except (ValueError,TypeError,OverflowError):
            continue
    output=[]
    for destination,records in sorted(grouped.items()):
        records.sort(key=lambda a:a.at)
        good=sorted(a.elapsed_ms for a in records if a.outcome=='accepted')
        accepted=sum(a.outcome=='accepted' for a in records)
        network=sum(a.outcome=='network' for a in records)
        blocked=sum(a.outcome in ('tls','rejected') for a in records)
        last=next((a.at.astimezone(timezone.utc) for a in reversed(records) if a.outcome=='accepted'),None)
        gaps=[(b.at-a.at).total_seconds() for a,b in zip(records,records[1:])]
        recovered=any(a.outcome!='accepted' and b.outcome=='accepted' for a,b in zip(records,records[1:]))
        output.append(TransferSummary(destination,len(records),accepted,network,blocked,
            round(100*accepted/len(records)),
            _percentile(good,0.5) if len(good)>=3 else None,
            _percentile(good,0.95) if len(good)>=3 else None,last,recovered,
            int(max(gaps)//60) if gaps else None))
    return tuple(output[:32])
