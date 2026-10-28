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
    series: str = 'Без серии'


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
                   room: str = 'Без комнаты', phase: str = 'Без этапа',
                   series: str = 'Без серии') -> SurveyPoint:
    if not isinstance(zone, str) or not zone.strip() or len(zone.strip()) > 60 or any(ord(c) < 32 for c in zone):
        raise ValueError('Название зоны: от 1 до 60 символов без управляющих знаков')
    if not isinstance(room, str) or not room.strip() or len(room.strip()) > 60 or any(ord(c) < 32 for c in room):
        raise ValueError('Название комнаты: от 1 до 60 символов без управляющих знаков')
    if not isinstance(series, str) or not series.strip() or len(series.strip()) > 60 or any(ord(c)<32 for c in series):
        raise ValueError('Имя серии: 1–60 символов без управляющих знаков')
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
                       round(float(x), 3), round(float(y), 3), ssid, bssid.upper(), signal, channel, room.strip(), phase, series.strip())


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
    series: str = 'Без серии'


def compare_phases(points: Sequence[SurveyPoint], zone: str, min_samples: int = 2,
                   series: str | None = None) -> tuple[RoomComparison, ...]:
    """Explicit before/after sample means for same floor, room, SSID. No inferred improvement.

    Samples are not paired in time or measurement position: this is descriptive only.
    Unlabelled historical samples and invalid sensor data never enter the comparison.
    """
    if type(min_samples) is not int or not 2 <= min_samples <= 30:
        raise ValueError('Нужно не менее двух измерений в каждом этапе')
    groups: dict[tuple[str, str, str], dict[str, list[int]]] = defaultdict(
        lambda: {'До': [], 'После': []})
    for p in points[:MAX_POINTS]:
        if not isinstance(p, SurveyPoint) or p.zone != zone or p.phase not in ('До', 'После') or (series is not None and p.series != series):
            continue
        if type(p.signal) is not int or not 0 <= p.signal <= 100 or not p.room or not p.ssid:
            continue
        groups[(p.series, p.room, p.ssid)][p.phase].append(p.signal)
    out = []
    for (campaign, room, ssid), phases in sorted(groups.items())[:MAX_POINTS]:
        before, after = phases['До'], phases['После']
        if len(before) < min_samples or len(after) < min_samples:
            continue
        before_avg, after_avg = sum(before)/len(before), sum(after)/len(after)
        out.append(RoomComparison(room, ssid, len(before), len(after),
                                  round(before_avg, 1), round(after_avg, 1), round(after_avg-before_avg, 1), campaign))
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


@dataclass(frozen=True)
class SsidRoomQuality:
    room: str
    ssid: str
    phase: str
    samples: int
    mean_signal: float
    min_signal: int
    max_signal: int
    bssid_count: int


def ssid_room_quality(points: Sequence[SurveyPoint], zone: str, series: str,
                      phase: str | None = None) -> tuple[SsidRoomQuality, ...]:
    """Separate measurements per SSID, room, survey series and phase.

    Missing SSIDs are not interpreted as AP outages. Each SSID needs own
    actual associated-WLAN samples; no scan-list RSSI interpolation.
    """
    if phase is not None and phase not in ('До', 'После', 'Без этапа'):
        raise ValueError('Неизвестный этап')
    groups: dict[tuple[str, str, str], list[SurveyPoint]] = defaultdict(list)
    for p in points[:MAX_POINTS]:
        if (isinstance(p, SurveyPoint) and p.zone == zone and p.series == series
                and (phase is None or p.phase == phase)
                and type(p.signal) is int and 0 <= p.signal <= 100
                and isinstance(p.room, str) and p.room and isinstance(p.ssid, str) and p.ssid):
            groups[(p.room, p.ssid, p.phase)].append(p)
    result=[]
    for (room, ssid, phase_name), samples in sorted(groups.items())[:MAX_POINTS]:
        values=[p.signal for p in samples]
        result.append(SsidRoomQuality(room, ssid, phase_name, len(values),
            round(sum(values)/len(values), 1), min(values), max(values),
            len({p.bssid for p in samples})))
    return tuple(result[:MAX_POINTS])


def survey_report(points: Sequence[SurveyPoint], zone: str, series: str) -> dict:
    """Offline evidence-only report; whitelist fields and never include credentials/BSSIDs.

    Low signal is a *review candidate*, not a proved throughput/outage issue.
    Only at least three actual samples identify a low-signal room.
    """
    if not isinstance(zone, str) or not 1 <= len(zone.strip()) <= 60:
        raise ValueError('Выберите этаж')
    if not isinstance(series, str) or not 1 <= len(series.strip()) <= 60:
        raise ValueError('Выберите серию')
    samples=ssid_room_quality(points,zone.strip(),series.strip())
    comparisons=compare_phases(points,zone.strip(),series=series.strip())
    rows=[]
    for q in samples:
        level = 'мало данных' if q.samples < 3 else ('слабый наблюдаемый сигнал' if q.mean_signal < 45 else
            'умеренный наблюдаемый сигнал' if q.mean_signal < 70 else 'наблюдаемый сигнал ≥70%')
        rows.append({'room':q.room,'ssid':q.ssid,'phase':q.phase,'samples':q.samples,
                     'mean_windows_percent':q.mean_signal,'min_windows_percent':q.min_signal,
                     'max_windows_percent':q.max_signal,'bssid_count':q.bssid_count,'assessment':level})
    deltas=[{'room':c.room,'ssid':c.ssid,'before_samples':c.before_samples,
             'after_samples':c.after_samples,'before_windows_percent':c.before_mean,
             'after_windows_percent':c.after_mean,'delta_percentage_points':c.delta}
            for c in comparisons]
    return {'product':'BLOODSKY NET','feature':'Wi-Fi RADAR 2.3',
            'floor':zone.strip(),'series':series.strip(),
            'source':'Ручные замеры текущего WLAN Windows, проценты (не dBm)',
            'limitations':'Не измеряет скорость, радиоспектр, стены или причинность. Неизмеренные SSID и комнаты неизвестны. '
                          'Оценка применима только к измеренным точкам. До/После не образуют контролируемый эксперимент.',
            'rooms':rows[:MAX_POINTS],'comparisons':deltas[:MAX_ZONES],
            'review_candidates':[{'room':q.room,'ssid':q.ssid,'phase':q.phase,'mean_windows_percent':q.mean_signal,
                                  'checks':['Повторить измерения в том же месте и на том же SSID.',
                                            'Проверить препятствия, размещение AP, канал и загрузку сети.']}
                                 for q in samples if q.samples >= 3 and q.mean_signal < 45][:MAX_ZONES]}


def survey_html_report(report: dict) -> str:
    """Static offline HTML; escaped user-controlled network identifiers, no JS/assets."""
    import html
    esc=lambda v: html.escape(str(v),quote=True)
    def table_rows(keys, items):
        return ''.join('<tr>'+''.join(f'<td>{esc(item.get(k, ""))}</td>' for k in keys)+'</tr>'
                       for item in items)
    columns=('room','ssid','phase','samples','mean_windows_percent','min_windows_percent','assessment')
    comparisons=('room','ssid','before_samples','after_samples','delta_percentage_points')
    return ("<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
      '<meta http-equiv="Content-Security-Policy" content="default-src &apos;none&apos;; style-src &apos;unsafe-inline&apos;">'
      '<title>Wi-Fi RADAR — отчёт</title><style>body{font:14px Arial,sans-serif;max-width:1050px;margin:24px auto;padding:10px} '
      'table{border-collapse:collapse;width:100%;margin-bottom:20px}td,th{border:1px solid #ccc;padding:8px}th{text-align:left}</style></head><body>'
      '<h1>Wi-Fi RADAR · обследование</h1><p>Этаж: '+esc(report['floor'])+' · Серия: '+esc(report['series'])+'</p>'
      '<p>'+esc(report['source'])+'</p><h2>Замеры по SSID и комнатам</h2><table><tr>'+
      ''.join('<th>'+esc(k)+'</th>' for k in columns)+'</tr>'+table_rows(columns,report['rooms'])+'</table>'
      '<h2>До / После (п.п.)</h2><table><tr>'+''.join('<th>'+esc(k)+'</th>' for k in comparisons)+'</tr>'+
      table_rows(comparisons,report['comparisons'])+'</table>'
      '<h2>Участки для повторной проверки</h2><ul>'+''.join('<li>'+esc(c['room'])+' · '+esc(c['ssid'])+
      ' · '+esc(c['phase'])+': '+esc(c['mean_windows_percent'])+'% — повторить измерения и проверить AP/канал.</li>'
      for c in report['review_candidates'])+'</ul><p>'+esc(report['limitations'])+'</p></body></html>')
