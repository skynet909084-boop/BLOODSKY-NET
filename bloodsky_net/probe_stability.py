"""Evidence-bounded patterns in local TLS transfer ATTEMPTS, not device outages.

Do not infer host, cabling, WAN or network availability from missing attempts.
Never handle credentials, payloads, IP inventory or unobserved intervals here.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

from .probe_quality import TransferAttempt, validate_attempt, MAX_HISTORY

MAX_WINDOW = timedelta(minutes=10)
MAX_AGE = timedelta(days=7)
MAX_RECORDS = 32


@dataclass(frozen=True)
class AttemptPattern:
    destination: str
    kind: str
    first_at: datetime
    last_at: datetime
    attempts: int
    description: str
    check: str


def patterns(attempts: Sequence[TransferAttempt], now: datetime) -> tuple[AttemptPattern, ...]:
    """Return only directly observed security stops, repeated failures, or recovery.

    A burst requires >=3 different times of network failure within 10 min.
    A recovery requires accepted request AFTER a burst and within 10 min.
    A TLS/auth failure is a security block, never retried as a transient issue.
    Same timestamps are collapsed, so duplicates cannot manufacture a burst.
    """
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError('Требуется время с часовым поясом')
    now = now.astimezone(timezone.utc)
    groups: dict[str, list[TransferAttempt]] = {}
    for attempt in list(attempts)[:MAX_HISTORY]:
        try:
            validate_attempt(attempt)
            when = attempt.at.astimezone(timezone.utc)
            if not timedelta(0) <= now - when <= MAX_AGE:
                continue
            groups.setdefault(attempt.destination, []).append(
                TransferAttempt(when, attempt.destination, attempt.outcome, attempt.elapsed_ms))
        except (ValueError, TypeError, OverflowError):
            continue
    found: list[AttemptPattern] = []
    for name, rows in sorted(groups.items())[:32]:
        # Collapse redundant timestamps conservatively; security blocks win ties.
        priority = {'accepted': 0, 'network': 1, 'rejected': 2, 'tls': 3}
        distinct: dict[datetime, TransferAttempt] = {}
        for a in rows:
            if a.at not in distinct or priority[a.outcome] > priority[distinct[a.at].outcome]:
                distinct[a.at] = a
        rows = sorted(distinct.values(), key=lambda a: a.at)
        # Authentication or certificate failure is a hard stop for that attempt.
        for a in rows:
            if a.outcome in ('tls', 'rejected'):
                found.append(AttemptPattern(name, 'security_stop', a.at, a.at, 1,
                    'Один запрос отклонён из-за TLS или авторизации; автоотправка должна остановиться.',
                    'Проверить PIN сертификата и разрешение ID отправителя по доверенному каналу; не повторять автоматически.'))
        # Only contiguous network-failure runs; one accepted request terminates the run.
        i = 0
        while i < len(rows):
            if rows[i].outcome != 'network':
                i += 1
                continue
            j = i
            while j+1 < len(rows) and rows[j+1].outcome == 'network' and rows[j+1].at-rows[i].at <= MAX_WINDOW:
                j += 1
            if j - i + 1 >= 3:
                start,end=rows[i],rows[j]
                found.append(AttemptPattern(name, 'repeated_network_error',start.at,end.at,j-i+1,
                    'Наблюдались не менее трёх ошибок отправки за 10 минут; причина и состояние удалённого ПК неизвестны.',
                    'Проверить разрешённый порт, маршрутизацию, DNS/брандмауэр и журнал TLS на обоих ПК.'))
                if j+1 < len(rows) and rows[j+1].outcome == 'accepted' and rows[j+1].at-end.at <= MAX_WINDOW:
                    found.append(AttemptPattern(name,'accepted_after_errors',end.at,rows[j+1].at,j-i+2,
                        'После серии ошибок зафиксирована принятая TLS-передача; непрерывность связи неизвестна.',
                        'Сопоставить временные метки с журналами получателя и повторить тест с другого ПК.'))
            i = j+1
    found.sort(key=lambda p:(p.last_at,p.destination,p.kind),reverse=True)
    return tuple(found[:MAX_RECORDS])


def report(attempts: Sequence[TransferAttempt], now: datetime) -> dict:
    """Safe, bounded JSON-friendly report; destinations are local user-supplied aliases."""
    items = patterns(attempts,now)
    return {'product':'BLOODSKY NET','engine':'Distributed Probes stability 2.5',
            'generated_utc':now.astimezone(timezone.utc).isoformat(timespec='seconds'),
            'warning':'Проверяются только попытки TLS-передачи. Нет пакетов ≠ ПК отключён; это не измерение SLA.',
            'patterns':[{'destination':p.destination,'kind':p.kind,
                         'first_at':p.first_at.isoformat(timespec='seconds'),
                         'last_at':p.last_at.isoformat(timespec='seconds'),
                         'attempts':p.attempts,'description':p.description,'check':p.check}
                        for p in items]}
