"""Explicitly trusted outbound TLS destinations and labelled session-activity notes.

A pinned receiver certificate authenticates an OUTBOUND destination only.
Incoming bearer-token access does not authenticate a sender machine: the
embedded probe label can be spoofed by anyone with the session token.
Missing packets are missing observations, NOT evidence a computer is offline.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from . import probe_transport

ALLOWED_EVENTS = frozenset(('tls_received', 'tls_sent', 'file_imported', 'local_exported'))
MAX_PROFILES = 32
MAX_ACTIVITY_ROWS = 2048


@dataclass(frozen=True)
class TrustedDestination:
    alias: str
    host: str
    port: int
    fingerprint: str


@dataclass(frozen=True)
class ProbeActivity:
    at: datetime
    event: str
    label: str
    count: int


def safe_label(value: str) -> str:
    if type(value) is not str:
        raise ValueError('Имя должно быть текстом')
    value = value.strip()
    if not 1 <= len(value) <= 64 or any(ord(x) < 32 or ord(x) == 127 for x in value):
        raise ValueError('Имя должно содержать 1–64 печатных символа')
    return value


def validate_destination(alias: str, host: str, port: int, fingerprint: str) -> TrustedDestination:
    return TrustedDestination(safe_label(alias), probe_transport.allowed_ip(host),
                              probe_transport.allowed_port(port),
                              probe_transport.validate_fingerprint(fingerprint))


def recent_receive_state(events: Sequence[ProbeActivity], now: datetime) -> tuple[str, str]:
    """Status is *of observations*, never a statement about host connectivity."""
    if now.tzinfo is None:
        raise ValueError('Нужны дата/время UTC с часовым поясом')
    valid = [e for e in events if e.event == 'tls_received' and e.at.tzinfo is not None
             and 0 <= (now-e.at.astimezone(timezone.utc)).total_seconds() <= 86400]
    if not valid:
        return ('нет входящих измерений за 24 часа', 'unknown')
    latest = max(valid,key=lambda e:e.at)
    age = (now-latest.at).total_seconds()
    if age <= 180:
        return ('получены свежие измерения', 'fresh')
    return ('нет свежих измерений (это не значит, что датчик отключён)', 'stale')


def timeline(rows: Sequence[ProbeActivity]) -> tuple[ProbeActivity, ...]:
    """Conservative chronology from accepted local events, not remote declarations."""
    return tuple(sorted((a for a in rows if a.event in ALLOWED_EVENTS and
                         a.at.tzinfo is not None and 0 <= a.count <= 256),
                        key=lambda a:(a.at,a.label,a.event))[-100:])
