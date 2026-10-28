"""Opt-in probe reconnection, explicit TLS pin rotation and observed sender activity.

No background discovery, automatic certificate trust or claims of hardware liveness.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hmac
import ssl
from typing import Sequence

from . import probe_transport
from .probe_peers import ProbeActivity, TrustedDestination

# A slow/failed connection never triggers a tight retry loop. The caller owns opt-in.
BACKOFF_SECONDS = (15, 30, 60, 120, 300)


@dataclass(frozen=True)
class RetryState:
    attempts: int = 0
    next_at: float = 0.0
    blocked: bool = False
    reason: str = ''


def failure_kind(exc: BaseException) -> str:
    """Fail closed for cert/auth/protocol errors; retry only network and HTTP 503."""
    if isinstance(exc, ssl.SSLError):
        return 'tls_identity'
    if isinstance(exc, ValueError) and 'HTTP 503' in str(exc):
        return 'transient'
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return 'transient'
    return 'blocked'


def failed(state: RetryState, kind: str, now: float) -> RetryState:
    if not isinstance(now, (int, float)) or not 0 <= now < 10**15:
        raise ValueError('Неверные часы для повтора')
    if kind == 'transient':
        n = min(state.attempts+1, len(BACKOFF_SECONDS))
        return RetryState(n, now+BACKOFF_SECONDS[n-1], False,
                          'Сеть недоступна; попытка позже при включённой автоотправке')
    if kind == 'tls_identity':
        return RetryState(0, 0, True, 'TLS не подтверждён; проверьте отпечаток вручную')
    return RetryState(0, 0, True, 'Авторизация/протокол: автоотправка остановлена')


def ready(state: RetryState, now: float) -> bool:
    return not state.blocked and now >= state.next_at


def approved_pin_rotation(profile: TrustedDestination, old: str, new: str,
                          user_confirmed: bool) -> TrustedDestination:
    """Require knowledge of old saved pin plus an out-of-band verified new pin.

    A changed TLS certificate is never accepted from the untrusted connection itself.
    """
    old_pin = probe_transport.validate_fingerprint(old)
    new_pin = probe_transport.validate_fingerprint(new)
    if not hmac.compare_digest(profile.fingerprint, old_pin):
        raise ValueError('Старый отпечаток не совпадает с сохранённым')
    if hmac.compare_digest(old_pin, new_pin):
        raise ValueError('Новый отпечаток совпадает со старым')
    if user_confirmed is not True:
        raise ValueError('Смена сертификата требует отдельного подтверждения')
    return replace(profile, fingerprint=new_pin)


@dataclass(frozen=True)
class SenderState:
    peer_id: str
    last_received: datetime | None
    state: str
    note: str


def sender_states(trusted_ids: Sequence[str], events: Sequence[ProbeActivity],
                  now: datetime) -> tuple[SenderState, ...]:
    """Report arrival of accepted measurements, never network host uptime.

    Only local tls_received entries count; imported JSON and sent events do not.
    """
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError('Нужны часы с часовым поясом')
    now = now.astimezone(timezone.utc)
    result = []
    for peer_id in sorted(set(trusted_ids))[:32]:
        try:
            probe_transport.validate_peer_id(peer_id)
        except ValueError:
            continue
        times = [e.at.astimezone(timezone.utc) for e in events
                 if e.event == 'tls_received' and e.label == peer_id
                 and e.at.tzinfo is not None and 0 <= (now-e.at.astimezone(timezone.utc)).total_seconds() <= 86400]
        last = max(times, default=None)
        if last is None:
            result.append(SenderState(peer_id,None,'unknown','За 24 часа нет принятых данных; статус ПК неизвестен'))
        elif (now-last).total_seconds() <= 180:
            result.append(SenderState(peer_id,last,'fresh','Недавно приняты измерения; это не постоянный онлайн-статус'))
        else:
            result.append(SenderState(peer_id,last,'stale','Нет свежих измерений; ПК не объявлен отключённым'))
    return tuple(result)
