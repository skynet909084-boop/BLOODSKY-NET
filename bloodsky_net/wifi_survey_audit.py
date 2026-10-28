"""Wi-Fi RADAR 2.5: offline multi-floor survey completeness and repeatability.

Only direct, user-positioned Windows WLAN percentage readings are used.
Readiness describes sampling completeness, NOT signal quality or network health.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from math import hypot, isfinite
from typing import Sequence
from .wifi_survey import SurveyPoint, MAX_POINTS

MIN_ROOM_SAMPLES = 3
MIN_SPOT_SECONDS = 30
MIN_SURVEY_SECONDS = 60
DISTINCT_POSITION_DISTANCE = 5.0
SAME_SPOT_DISTANCE = 2.0
SPREAD_TO_REVIEW = 20

def _eligible(p) -> bool:
    return (isinstance(p, SurveyPoint) and
            all(isinstance(v, str) and 0 < len(v) <= 128 for v in
                (p.zone, p.room, p.ssid, p.series, p.phase)) and
            type(p.signal) is int and 0 <= p.signal <= 100 and
            type(p.x) in (int, float) and type(p.y) in (int, float) and
            all(isfinite(float(v)) and 0 <= v <= 100 for v in (p.x, p.y)))

def _parse_time(p):
    try:
        dt = datetime.fromisoformat(p.observed_at.replace('Z', '+00:00'))
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        pass
    return None

def _distinct_positions(points):
    anchors = []
    for p in sorted(points, key=lambda r:(r.x, r.y)):
        if all(hypot(p.x-x, p.y-y) >= DISTINCT_POSITION_DISTANCE for x,y in anchors):
            anchors.append((p.x, p.y))
    return len(anchors)

def _repeat_spread(points):
    """Only same BSSID, near same user-position, >=30 sec apart."""
    candidates = sorted(((t,p) for p in points if (t := _parse_time(p)) is not None),
                        key=lambda x:x[0])
    spreads = []
    for i,(at,p) in enumerate(candidates):
        if not p.bssid:
            continue
        for bt,q in candidates[i+1:]:
            if (bt-at).total_seconds() < MIN_SPOT_SECONDS:
                continue
            if (p.bssid == q.bssid and
                hypot(p.x-q.x, p.y-q.y) <= SAME_SPOT_DISTANCE):
                spreads.append(abs(p.signal-q.signal))
                break
    return max(spreads) if spreads else None

def audit_floors(points: Sequence[SurveyPoint], series: str, phase: str | None = None) -> dict:
    """Evaluate measured rooms without guessing unmeasured floor coverage."""
    if not isinstance(series, str) or not series.strip() or len(series.strip()) > 60:
        raise ValueError('Выберите серию обследования (1–60 символов)')
    if phase not in (None, 'До', 'После', 'Без этапа'):
        raise ValueError('Неизвестный этап обследования')
    series = series.strip()
    groups = defaultdict(list)
    for p in list(points)[:MAX_POINTS]:
        if _eligible(p) and p.series == series and (phase is None or p.phase == phase):
            if _parse_time(p) is not None:
                groups[(p.zone,p.room,p.ssid,p.phase)].append(p)
    rooms = []
    for (zone,room,ssid,stage),samples in sorted(groups.items())[:MAX_POINTS]:
        moments = sorted(_parse_time(p) for p in samples)
        duration = round((moments[-1]-moments[0]).total_seconds()) if moments else 0
        locations = _distinct_positions(samples)
        spread = _repeat_spread(samples)
        problems = []
        if len(samples) < MIN_ROOM_SAMPLES:
            problems.append('нужно минимум 3 замера')
        if locations < 2:
            problems.append('нужно минимум 2 разнесённые точки')
        if duration < MIN_SURVEY_SECONDS:
            problems.append('наблюдение короче 60 секунд')
        if spread is None:
            problems.append('нет повторной проверки той же точки с тем же BSSID')
        elif spread >= SPREAD_TO_REVIEW:
            problems.append('замечен разброс сигнала ≥20 п.п. на повторе')
        values = [p.signal for p in samples]
        rooms.append({
            'floor':zone,'room':room,'ssid':ssid,'phase':stage,
            'samples':len(samples),'positions':locations,'duration_seconds':duration,
            'mean_windows_percent':round(sum(values)/len(values),1),
            'min_windows_percent':min(values),'max_windows_percent':max(values),
            'repeat_spread_percentage_points':spread,
            'sampling_status':'достаточно для первичного обзора' if not problems else 'проверить замеры',
            'checks':problems,'first_seen_utc':moments[0].isoformat(timespec='seconds'),
            'last_seen_utc':moments[-1].isoformat(timespec='seconds')})
    floors = []
    for floor in sorted({r['floor'] for r in rooms}):
        floor_rows = [r for r in rooms if r['floor'] == floor]
        floors.append({
            'floor':floor,'room_ssid_phases':len(floor_rows),
            'observed_rooms':len({r['room'] for r in floor_rows}),
            'observed_ssids':len({r['ssid'] for r in floor_rows}),
            'samples':sum(r['samples'] for r in floor_rows),
            'sampling_review_groups':sum(r['sampling_status'] != 'достаточно для первичного обзора' for r in floor_rows)})
    return {'feature':'Wi-Fi RADAR 2.5','series':series,'phase':phase or 'Все',
            'floors':floors,'room_checks':rooms,
            'sample_count':sum(r['samples'] for r in rooms),
            'limitations':('Это проверка полноты и повторяемости фактических точек, а не карта радиопокрытия, '
                           'измерение скорости, дБм или заключение об исправности Wi-Fi. '
                           'Комнаты и координаты введены пользователем. Нет точек — нет данных; '
                           '«достаточно» не означает покрытие всего этажа. Разные точки и BSSID не смешиваются.')}

def audit_html_report(report: dict) -> str:
    """Printable self-contained escaped offline report (no scripts/assets)."""
    e = lambda val: escape(str(val), quote=True)
    keys = ('floor','room','ssid','phase','samples','positions','duration_seconds',
            'mean_windows_percent','repeat_spread_percentage_points','sampling_status','checks')
    rows = []
    for item in report.get('room_checks', ())[:MAX_POINTS]:
        rows.append('<tr>'+''.join('<td>'+e(', '.join(item[k]) if k == 'checks' else item.get(k,'—'))+'</td>'
                                    for k in keys)+'</tr>')
    summ = ''.join('<li>'+e(f["floor"])+': '+e(f['observed_rooms'])+' наблюдаемых комнат; '+
                   e(f['samples'])+' замеров; проверить групп: '+e(f['sampling_review_groups'])+'</li>'
                   for f in report.get('floors', ())[:50])
    return ('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src &apos;none&apos;; style-src &apos;unsafe-inline&apos;">'
            '<title>BLOODSKY NET — обследование этажей</title><style>body{font:14px Arial,sans-serif;margin:24px}'
            'table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd;padding:6px;text-align:left}'
            'h1{color:#174a80}</style></head><body><h1>Wi-Fi RADAR 2.5 · отчёт по этажам</h1>'
            '<p>Серия: '+e(report.get('series',''))+' · Этап: '+e(report.get('phase',''))+'</p>'
            '<ul>'+summ+'</ul><table><thead><tr>'+''.join('<th>'+e(k)+'</th>' for k in keys)+'</tr></thead><tbody>'+''.join(rows)+'</tbody></table>'
            '<p>'+e(report.get('limitations',''))+'</p></body></html>')
