"""Opt-in offline multi-vantage ICMP observations; no remote listener or credentials.

This file exchange is NOT authenticated: an imported label and readings are
claims in a user-selected file. Never describe them as cryptographic proof.
No ICMP reply is not evidence that an endpoint is powered off.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import ipaddress
import json
import re
import uuid
from typing import Sequence

FORMAT = 'BLOODSKY-NET-PROBE'
MAX_BYTES = 512 * 1024
MAX_ITEMS = 256
MAX_AGE_SECONDS = 180
COMPARE_WINDOW_SECONDS = 300
MAX_LABEL = 64
ID_PATTERN = re.compile(r'^[0-9a-f]{32}$')
STATES = frozenset(('reply', 'no_icmp'))


@dataclass(frozen=True)
class ProbeReading:
    ip: str
    state: str
    at: datetime


@dataclass(frozen=True)
class ProbeSnapshot:
    ident: str
    label: str
    created_at: datetime
    readings: tuple[ProbeReading, ...]


@dataclass(frozen=True)
class ProbeComparison:
    ip: str
    outcome: str
    observations: tuple[tuple[str, str], ...]
    note: str


def _timestamp(text: str) -> datetime:
    if not isinstance(text, str) or len(text) > 40:
        raise ValueError('Неверная метка времени')
    try:
        value = datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('Неверная метка времени') from exc
    if value.tzinfo is None or abs(value.utcoffset().total_seconds()) > 14 * 3600:
        raise ValueError('Нужна временная метка с часовым поясом')
    return value.astimezone(timezone.utc)


def _label(text: str) -> str:
    if not isinstance(text, str):
        raise ValueError('Имя точки наблюдения должно быть текстом')
    name = text.strip()
    if not name or len(name) > MAX_LABEL or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError('Укажите имя точки наблюдения (до 64 символов)')
    return name


def create_snapshot(label: str, observations: Sequence[tuple[str, str, datetime]],
                    at: datetime | None = None) -> ProbeSnapshot:
    now = at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('Временная метка должна иметь часовой пояс')
    now = now.astimezone(timezone.utc)
    if not isinstance(observations, (list, tuple)) or not 1 <= len(observations) <= MAX_ITEMS:
        raise ValueError('Нужны от 1 до 256 свежих ICMP-измерений')
    seen: set[str] = set()
    rows = []
    for ip, state, stamp in observations:
        ip = str(ipaddress.IPv4Address(ip))
        if ip in seen or state not in STATES or not isinstance(stamp, datetime) or stamp.tzinfo is None:
            raise ValueError('Дублирующееся, неизвестное или недатированное ICMP-измерение')
        measured = stamp.astimezone(timezone.utc)
        if not -5 <= (now - measured).total_seconds() <= MAX_AGE_SECONDS:
            raise ValueError('Измерения устарели или относятся к будущему')
        seen.add(ip)
        rows.append(ProbeReading(ip, state, measured))
    return ProbeSnapshot(uuid.uuid4().hex, _label(label), now,
                         tuple(sorted(rows, key=lambda x: int(ipaddress.IPv4Address(x.ip)))))


def encode(snapshot: ProbeSnapshot) -> bytes:
    data = {'format': FORMAT, 'version': 1, 'id': snapshot.ident, 'probe': snapshot.label,
            'created_at': snapshot.created_at.isoformat(),
            'readings': [{'ip': r.ip, 'state': r.state, 'at': r.at.isoformat()} for r in snapshot.readings],
            'warning': 'Нет ответа ICMP ≠ отключённое устройство. Данные файла не аутентифицированы.'}
    payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(payload) > MAX_BYTES:
        raise ValueError('Слишком большой файл')
    return payload


def decode(payload: bytes) -> ProbeSnapshot:
    if not isinstance(payload, bytes) or len(payload) > MAX_BYTES or not payload:
        raise ValueError('Размер пакета наблюдений недопустим')
    try:
        source = json.loads(payload.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('Неверный JSON') from exc
    if not isinstance(source, dict) or source.get('format') != FORMAT or type(source.get('version')) is not int or source['version'] != 1:
        raise ValueError('Неподдерживаемый формат наблюдений')
    ident = source.get('id')
    if not isinstance(ident, str) or not ID_PATTERN.fullmatch(ident):
        raise ValueError('Неверный идентификатор')
    name = _label(source.get('probe'))
    stamp = _timestamp(source.get('created_at'))
    readings = source.get('readings')
    if not isinstance(readings, list) or not 1 <= len(readings) <= MAX_ITEMS:
        raise ValueError('Неверное количество измерений')
    raw = []
    for item in readings:
        if not isinstance(item, dict):
            raise ValueError('Неверная запись измерения')
        raw.append((item.get('ip'), item.get('state'), _timestamp(item.get('at'))))
    # Snapshot time is historical and need not be recent at import, but readings
    # MUST have been fresh when the sender exported them.
    return _with_id(ident, name, stamp, raw)


def _with_id(ident: str, label: str, stamp: datetime, observations):
    snapshot = create_snapshot(label, observations, stamp)
    return ProbeSnapshot(ident, snapshot.label, snapshot.created_at, snapshot.readings)


def compare(snapshots: Sequence[ProbeSnapshot]) -> tuple[ProbeComparison, ...]:
    """Compare latest snapshot for each user-supplied probe label, only when close in time.

    Imported files can lie; report agreement and disagreement, never a verified
    root cause. A missing target or old reading is simply not comparable.
    """
    latest: dict[str, ProbeSnapshot] = {}
    for snapshot in snapshots[:256]:
        if snapshot.label not in latest or snapshot.created_at > latest[snapshot.label].created_at:
            latest[snapshot.label] = snapshot
    if len(latest) < 2:
        return ()
    targets: dict[str, list[tuple[str, ProbeReading]]] = {}
    for label, snapshot in latest.items():
        for row in snapshot.readings:
            targets.setdefault(row.ip, []).append((label, row))
    results = []
    for ip in sorted(targets, key=lambda v: int(ipaddress.IPv4Address(v))):
        candidates = sorted(targets[ip], key=lambda x: x[1].at, reverse=True)
        # Pick the largest 5-minute observation window. Old/off-window points
        # are NOT treated as concurrent failures or contradictory evidence.
        groups = [[v for v in candidates if 0 <= (candidates[i][1].at - v[1].at).total_seconds() <= COMPARE_WINDOW_SECONDS]
                  for i in range(len(candidates))]
        best = max(groups, key=lambda g: (len(g), max((v[1].at for v in g), default=datetime.min.replace(tzinfo=timezone.utc))))
        if len(best) < 2:
            continue
        by_probe = tuple(sorted((label, reading.state) for label, reading in best))
        flags = {state for _, state in by_probe}
        if len(flags) > 1:
            outcome = 'Разные результаты'
            note = 'Один узел отвечал на ICMP из некоторых точек, но не из других. Проверьте маршруты, ACL и время измерений.'
        elif flags == {'reply'}:
            outcome = 'Ответ ICMP из нескольких точек'
            note = 'Есть ответы ICMP из нескольких точек; это не подтверждает доступность всех сервисов.'
        else:
            outcome = 'Нет ответа ICMP из нескольких точек'
            note = 'Таймаут ICMP из нескольких точек не доказывает отключение устройства или повреждение сети.'
        results.append(ProbeComparison(ip, outcome, by_probe, note))
    return tuple(results[:MAX_ITEMS])
