"""Wi-Fi RADAR 2.4: compare distinct, explicitly labelled survey visits.

Only locally observed Windows WLAN percentages; no inferred signal between
points, unmeasured coverage, causal claims or invented sampling dates.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from base64 import b64encode
from math import isfinite
from typing import Sequence
from .wifi_survey import SurveyPoint, MAX_POINTS, MAX_ZONES, signal_color

MIN_SAMPLES = 3


def _date_range(points: Sequence[SurveyPoint]) -> tuple[str, str]:
    dates = []
    for p in points:
        try:
            t = datetime.fromisoformat(p.observed_at.replace('Z', '+00:00'))
            if t.tzinfo is not None:
                dates.append(t.astimezone(timezone.utc))
        except (ValueError, AttributeError):
            continue
    if not dates:
        return '', ''
    return min(dates).isoformat(timespec='seconds'), max(dates).isoformat(timespec='seconds')


def compare_visits(points: Sequence[SurveyPoint], zone: str, baseline: str,
                   followup: str, min_samples: int = MIN_SAMPLES) -> dict:
    """Only same floor, room and SSID; never blend other surveys or infer outages.

    Two labelled series can be compared even if their phase labels differ; the
    user is responsible for measuring comparable positions and equipment.
    """
    if not isinstance(zone, str) or not zone.strip() or len(zone.strip()) > 60:
        raise ValueError('Выберите этаж')
    if (not isinstance(baseline, str) or not isinstance(followup, str)
            or not baseline.strip() or not followup.strip()
            or len(baseline.strip()) > 60 or len(followup.strip()) > 60
            or baseline.strip() == followup.strip()):
        raise ValueError('Для сравнения нужны две разные именованные серии')
    if type(min_samples) is not int or not 2 <= min_samples <= 30:
        raise ValueError('Некорректный минимум замеров')
    zone, baseline, followup = zone.strip(),baseline.strip(),followup.strip()
    grouped = defaultdict(list)
    for p in list(points)[:MAX_POINTS]:
        if (isinstance(p, SurveyPoint) and p.zone == zone
                and p.series in (baseline, followup) and p.room and p.ssid
                and type(p.signal) is int and 0 <= p.signal <= 100
                and type(p.x) in (int, float) and type(p.y) in (int, float)
                and isfinite(p.x) and isfinite(p.y) and 0 <= p.x <= 100 and 0 <= p.y <= 100):
            grouped[(p.series, p.room, p.ssid)].append(p)
    before = [p for (series, _, _), rows in grouped.items() if series == baseline for p in rows]
    after = [p for (series, _, _), rows in grouped.items() if series == followup for p in rows]
    rooms = []
    keys = sorted({(room, ssid) for _,room,ssid in grouped})
    for room, ssid in keys[:MAX_POINTS]:
        a, b = grouped.get((baseline,room,ssid),()),grouped.get((followup,room,ssid),())
        if len(a) < min_samples or len(b) < min_samples:
            continue
        x, y = sum(p.signal for p in a)/len(a),sum(p.signal for p in b)/len(b)
        rooms.append({'room':room,'ssid':ssid,'baseline_samples':len(a),'followup_samples':len(b),
                      'baseline_mean_windows_percent':round(x,1),
                      'followup_mean_windows_percent':round(y,1),
                      'delta_percentage_points':round(y-x,1),
                      'baseline_dates_utc':_date_range(a), 'followup_dates_utc':_date_range(b)})
    return {'feature':'Wi-Fi RADAR 2.4','floor':zone,'baseline_series':baseline,
            'followup_series':followup,'baseline_dates_utc':_date_range(before),
            'followup_dates_utc':_date_range(after),
            'baseline_samples':len(before),'followup_samples':len(after),
            'min_samples_per_room_ssid':min_samples,'comparable_rooms':rooms[:MAX_ZONES],
            'limitations':('Сравниваются средние зарегистрированные проценты сигнала Windows. '
                'Разные серии не являются контролируемым экспериментом: положения клиента, адаптер, '
                'условия эфира и нагрузка могут различаться. Нет данных — не значит сеть отсутствует. '
                'Измерения не подтверждают скорость или исправность AP.')}


def comparison_html(comparison: dict, baseline: Sequence[SurveyPoint],
                    followup: Sequence[SurveyPoint], floorplan=None) -> str:
    """Printable static offline section with real measured dots over local image.

    The floorplan is already metadata-stripped on import. No scripts, URLs or
    external resources; names and SSIDs are always HTML-escaped.
    """
    esc = lambda x: escape(str(x), quote=True)
    def map_svg(rows, title):
        image = ''
        if floorplan is not None:
            from .wifi_floorplan import MAX_STORED_BYTES
            if (type(floorplan.width) is int and type(floorplan.height) is int
                    and 0 < floorplan.width <= 1800 and 0 < floorplan.height <= 1800
                    and isinstance(floorplan.jpeg, bytes) and floorplan.jpeg.startswith(b'\xff\xd8')
                    and len(floorplan.jpeg) <= MAX_STORED_BYTES):
                raw=b64encode(floorplan.jpeg).decode('ascii')
                image = f'<image width="100" height="100" preserveAspectRatio="none" href="data:image/jpeg;base64,{raw}"/>'
        dots=[]
        for p in list(rows)[:MAX_POINTS]:
            if (not isinstance(p, SurveyPoint) or type(p.x) not in (int,float)
                    or type(p.y) not in (int,float) or not all(isfinite(v) for v in (p.x,p.y))
                    or not 0 <= p.x <= 100 or not 0 <= p.y <= 100 or type(p.signal) is not int
                    or not 0 <= p.signal <= 100):
                continue
            dots.append(f'<circle cx="{p.x:.3f}" cy="{p.y:.3f}" r="1.8" '
                        f'fill="{signal_color(p.signal)}" stroke="#16253a" stroke-width="0.35">'
                        f'<title>{esc(p.room)} · {esc(p.ssid)} · {p.signal}%</title></circle>')
        return ('<figure><figcaption>'+esc(title)+'</figcaption><svg role="img" aria-label="'+esc(title)+'" '
                'viewBox="0 0 100 100" width="100%" preserveAspectRatio="none" style="aspect-ratio:' + str(floorplan.width if floorplan else 1) + '/' + str(floorplan.height if floorplan else 1) + '" xmlns="http://www.w3.org/2000/svg">'
                '<rect width="100" height="100" fill="#edf2f7"/>'+image+''.join(dots)+'</svg></figure>')
    columns=('room','ssid','baseline_samples','followup_samples','baseline_mean_windows_percent',
             'followup_mean_windows_percent','delta_percentage_points')
    trs=''.join('<tr>'+''.join('<td>'+esc(row.get(key,''))+'</td>' for key in columns)+'</tr>'
                for row in comparison.get('comparable_rooms',())[:MAX_ZONES])
    return ('<section><h2>Сравнение разных обследований (фактические даты UTC)</h2>'
      '<p>Этаж: '+esc(comparison['floor'])+' · '+esc(comparison['baseline_series'])+' ('+
      esc(comparison['baseline_dates_utc'])+') → '+esc(comparison['followup_series'])+' ('+
      esc(comparison['followup_dates_utc'])+')</p>'
      '<div style="display:flex;gap:10px">'+map_svg(baseline, comparison['baseline_series'])+
      map_svg(followup,comparison['followup_series'])+'</div>'
      '<p>Точки: красный &lt;45%, жёлтый 45–69%, зелёный ≥70%. Пустые места не измерены.</p>'
      '<table><tr>'+''.join('<th>'+esc(k)+'</th>' for k in columns)+'</tr>'+trs+'</table><p>'+
      esc(comparison['limitations'])+'</p></section>')
