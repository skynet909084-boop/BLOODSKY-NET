"""Offline, deterministic BLOODSKY DETECTIVE v1: measured evidence, not guesses.

No network I/O, credentials, packet capture, AI inference or configuration changes.
A failed ICMP probe is *not* proof that hardware, a cable or WAN is down.
"""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress
import html
import re
from datetime import datetime, timezone
from typing import Mapping, Sequence

from . import detective_timeline
from . import topology_incidents
from . import incident_patterns


@dataclass(frozen=True)
class Evidence:
    source: str
    observation: str


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    confidence: str
    title: str
    interpretation: str
    evidence: tuple[Evidence, ...]
    checks: tuple[str, ...]


@dataclass(frozen=True)
class Observation:
    gateway: str = ''
    availability: Mapping[str, str] | None = None  # FRESH, consecutive ICMP readings only
    wifi_connected: bool | None = None  # None = unmeasured
    wifi_ssid: str = ''
    arp_suspicions: Sequence[str] = ()  # Only previously classified repeated MAC churn
    snmp_errors: Sequence[str] = ()
    lldp_changes: Sequence[object] = ()  # Historical LinkChange from successful snapshots
    recent_events: Sequence[object] = ()  # Timestamped, whitelisted monitor events
    port_error_deltas: Sequence[object] = ()  # Delta between fresh SNMP IF-MIB polls
    lldp_endpoints: Sequence[detective_timeline.LldpEndpoint] = ()
    timed_port_faults: Sequence[detective_timeline.TimedPortFault] = ()
    topology_history_matches: Sequence[topology_incidents.IncidentLink] = ()


@dataclass(frozen=True)
class DeviceEvent:
    ip: str
    observed_at: datetime
    kind: str = 'no_icmp'


def recent_device_events(rows: Sequence[tuple], now: datetime | None = None) -> tuple[DeviceEvent, ...]:
    """Extract only recent, explicitly labelled monitor events from SQLite.

    Log lines are not network measurements. Caller must only supply events from
    the app's local monitoring journal. Never parse arbitrary SNMP error details.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('now must have timezone')
    result = []
    for row in list(rows)[:500]:
        try:
            ts, severity, title, detail = row
            if severity != 'error' or title != 'Устройство не отвечает':
                continue
            stamp = datetime.fromisoformat(ts)
            if stamp.tzinfo is None:
                continue
            age = (now - stamp.astimezone(timezone.utc)).total_seconds()
            if not 0 <= age <= 600:
                continue
            m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})(?:\s|$)', detail)
            if not m:
                continue
            ip = str(ipaddress.IPv4Address(m.group(1)))
            result.append(DeviceEvent(ip, stamp.astimezone(timezone.utc)))
        except (ValueError, TypeError, IndexError):
            continue
    return tuple(sorted(result, key=lambda e:(e.observed_at,e.ip))[-100:])


def _event_clusters(events: Sequence[DeviceEvent], window_seconds: int = 120):
    """Only simultaneous independent IPv4 hosts within one /24 observation group.

    /24 is an *analysis grouping*, not a discovered VLAN or shared switch.
    """
    grouped = {}
    for e in events:
        if e.kind != 'no_icmp' or not isinstance(e.observed_at, datetime) or e.observed_at.tzinfo is None:
            continue
        try:
            net = str(ipaddress.IPv4Network(f'{e.ip}/24', strict=False))
        except ValueError:
            continue
        grouped.setdefault(net, []).append(e)
    result = []
    for net, group in sorted(grouped.items()):
        group.sort(key=lambda e:(e.observed_at, e.ip))
        best = ()
        for e in group:
            burst = [v for v in group if 0 <= (v.observed_at-e.observed_at).total_seconds() <= window_seconds]
            unique = {}
            for v in burst:
                unique[v.ip] = v
            if len(unique) > len(best):
                best = tuple(sorted(unique.values(), key=lambda x:x.ip))
        if len(best) >= 2:
            result.append((net, best[:6]))
    return result[:5]


SEVERITY_ORDER = {'warning': 0, 'notice': 1, 'info': 2}


def diagnose(o: Observation) -> tuple[Finding, ...]:
    """Generate bounded, human-auditable findings from fresh and labelled data.

    The application must remove stale observations before calling this function.
    Missing measurements and timeouts are not converted to a confirmed outage.
    """
    observed = {}
    for ip, state in (o.availability or {}).items():
        try:
            address = str(ipaddress.IPv4Address(ip))
        except (ValueError, TypeError):
            continue
        if state in ('up', 'down'):
            observed[address] = state
    gateway = ''
    try:
        if o.gateway:
            gateway = str(ipaddress.IPv4Address(o.gateway))
    except (ValueError, TypeError):
        pass
    downs = sorted((ip for ip, state in observed.items() if state == 'down' and ip != gateway),
                   key=lambda x: int(ipaddress.IPv4Address(x)))
    findings: list[Finding] = []
    if gateway and observed.get(gateway) == 'down':
        shared = tuple(Evidence('ICMP', f'{ip}: два последовательных опроса без ответа')
                       for ip in downs[:3])
        findings.append(Finding('gateway_no_icmp', 'warning', 'средняя' if downs else 'низкая',
            'Шлюз не отвечает на ICMP',
            'Возможна проблема доступа к шлюзу. Фильтрация ICMP также даёт такой результат; связь и WAN не подтверждены как неисправные.',
            (Evidence('ICMP', f'{gateway}: два последовательных опроса без ответа'),) + shared,
            ('Проверить шлюз с другого узла и таблицу маршрутов.',
             'Проверить питание, порт и ACL шлюза; при наличии SNMP — состояние интерфейса.')))
    elif gateway and observed.get(gateway) == 'up' and len(downs) >= 2:
        findings.append(Finding('segment_suspected', 'warning', 'низкая',
            'Несколько узлов не отвечают, шлюз отвечает',
            'Есть признаки общей проблемы сегмента или фильтрации ICMP, но общий коммутатор и причина не установлены.',
            (Evidence('ICMP', f'{gateway}: отвечает'),) +
            tuple(Evidence('ICMP', f'{ip}: два последовательных опроса без ответа') for ip in downs[:4]),
            ('Проверить маршруты и VLAN недоступных узлов.',
             'Сопоставить LLDP и журналы коммутаторов; повторить тест с другой точки.')))
    elif downs:
        findings.append(Finding('device_no_icmp', 'notice', 'низкая',
            'Устройства не отвечают на ICMP',
            'Это не подтверждает, что устройства выключены: возможны firewall, сон и запрет Ping.',
            tuple(Evidence('ICMP', f'{ip}: два последовательных опроса без ответа') for ip in downs[:5]),
            ('Проверить доступность TCP-сервиса и настройки ICMP.',
             'Проверить питание и порт оборудования при наличии доступа.')))
    for ip in sorted(set(o.arp_suspicions))[:12]:
        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ValueError:
            continue
        findings.append(Finding('arp_mac_churn', 'warning', 'низкая',
            'Возможный IP-конфликт: повторная смена MAC',
            'Повторные изменения IP→MAC — лишь подозрение; DHCP, VRRP и обновление ARP могут выглядеть похоже.',
            (Evidence('ARP', f'{ip}: повторное переключение MAC за короткий интервал'),),
            ('Сопоставить DHCP-аренды и журнал коммутатора.',
             'Проверить статические назначения IP и VRRP на этом адресе.')))
    if o.wifi_connected is False:
        findings.append(Finding('wifi_disconnected', 'notice', 'средняя',
            'Wi-Fi адаптер сообщает отсутствие подключения',
            'Измерен статус отключения Wi-Fi; причины (сигнал, пароль, точка доступа, отключённый адаптер) пока неизвестны.',
            (Evidence('Windows WLAN', 'Текущее состояние: нет подключения'),),
            ('Проверить состояние WLAN AutoConfig и сетевого адаптера.',
             'Посмотреть доступные SSID и историю переходов BSSID.')))
    for ip in sorted(set(o.snmp_errors))[:10]:
        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ValueError:
            continue
        findings.append(Finding('snmp_unavailable', 'info', 'низкая',
            'Нет актуальных данных SNMP',
            'Ошибка чтения SNMP не означает потерю связи или повреждение кабеля.',
            (Evidence('SNMP', f'{ip}: последний опрос завершился ошибкой'),),
            ('Проверить разрешения SNMP, ACL, версию и сетевую доступность устройства.',)))
    for item in list(o.lldp_changes)[:8]:
        if getattr(item, 'category', '') not in ('local_port_changed', 'not_reported'):
            continue
        source = str(getattr(item, 'source_ip', ''))[:45]
        neighbor = str(getattr(item, 'neighbor', ''))[:90]
        if item.category == 'local_port_changed':
            message = f'{source}: {neighbor}, {str(item.before)[:90]} → {str(item.after)[:90]}'
            title = 'Изменение порта в сохранённых LLDP-таблицах'
        else:
            message = f'{source}: сосед {neighbor} не найден во втором LLDP-снимке'
            title = 'Изменение списка LLDP-соседей'
        findings.append(Finding('lldp_history', 'notice', 'низкая', title,
            'Это историческое изменение *сообщаемых* коммутатором данных, не доказательство обрыва или физической перекоммутации.',
            (Evidence('LLDP (два успешных исторических опроса)', message),),
            ('Проверить актуальный LLDP и физические порты на устройстве.',)))
    # A common timestamp is circumstantial: monitored /24 does NOT imply VLAN,
    # shared uplink, or that the switch is broken.
    for subnet, burst in _event_clusters(o.recent_events):
        times = sorted(e.observed_at.isoformat(timespec='seconds') for e in burst)
        findings.append(Finding('temporal_cluster', 'notice', 'низкая',
            f'Близкие по времени сбои ICMP: {subnet}',
            'Несколько узлов одной /24-группы перестали отвечать примерно одновременно. '
            'Это не подтверждает общую неисправность коммутатора, VLAN или кабеля.',
            tuple(Evidence('Локальный журнал ICMP', f'{e.observed_at.isoformat(timespec="seconds")}: {e.ip}')
                  for e in burst),
            ('Сопоставить отметки времени с доступностью шлюза и состоянием uplink.',
             'Проверить журналы коммутаторов и результаты измерений с другого узла.')))
    for d in list(o.port_error_deltas)[:100]:
        try:
            counts = tuple(getattr(d, field, None) for field in
                           ('in_errors','out_errors','in_discards','out_discards'))
            if not any(type(v) is int and v >= 5 for v in counts):
                continue
            source = str(ipaddress.IPv4Address(d.switch_ip))
            port = int(d.index)
            if not 1 <= port <= 2147483647 or not 1 <= float(d.seconds) <= 3600:
                continue
            observed = ', '.join(f'{name}: +{v}' for name,v in zip(
                ('inErrors','outErrors','inDiscards','outDiscards'), counts)
                if type(v) is int and v >= 5)
            findings.append(Finding('port_errors', 'warning', 'средняя',
                f'Рост ошибок/сбросов на порту {source} #{port}',
                'SNMP-счётчики порта выросли между двумя удачными измерениями. '
                'Ошибки и отбрасывания пакетов не доказывают неисправность кабеля.',
                (Evidence('SNMP IF-MIB', f'{source} / {str(d.name)[:100]} (ifIndex {port}), '
                          f'за {float(d.seconds):.0f} с: {observed}'),),
                ('Проверить физический порт, дуплекс, интерфейсные ошибки и загрузку.',
                 'Сравнить с исправным портом и журналом коммутатора.')))
        except (AttributeError, ValueError, TypeError):
            continue
    for linked in detective_timeline.correlate(o.recent_events, o.lldp_endpoints, o.timed_port_faults):
        findings.append(Finding(linked.code,
            'warning' if linked.code == 'lldp_port_temporal_match' else 'notice',
            'средняя' if linked.code == 'lldp_port_temporal_match' else 'низкая',
            ('ICMP и ошибки порта LLDP-соседа' if linked.code == 'lldp_port_temporal_match'
             else 'Одновременные сбои LLDP-соседей коммутатора'),
            linked.description,
            tuple(Evidence('Временная корреляция', x) for x in linked.evidence),
            ('Сверить журналы коммутатора и текущие статусы интерфейсов.',
             'Проверить связь другим протоколом или с другой точки; ICMP может фильтроваться.')))
    for match in list(o.topology_history_matches)[:12]:
        findings.append(Finding('historical_lldp_overlap', 'notice', 'низкая',
            f'Изменение LLDP рядом со сбоем ICMP: {match.device_ip}',
            match.description,
            (Evidence('LLDP (два успешных снимка)',
                f'{match.switch_ip} / {match.reported_port}: изменение таблицы между '
                f'{match.before_at.isoformat(timespec="seconds")} и '
                f'{match.after_at.isoformat(timespec="seconds")}'),
             Evidence('Локальный журнал ICMP',
                f'{match.device_ip}: нет ответа {match.event_at.isoformat(timespec="seconds")}; '
                'IP сопоставлен через уникальный MAC инвентаря')),
            ('Перепроверить LLDP-соседей и административное состояние порта.',
             'Проверить питание/ACL/маршруты и диагностику другим протоколом.',
             'Сверить изменения конфигурации, если доступен журнал коммутатора.')))
    if not findings:
        findings.append(Finding('insufficient_evidence', 'info', 'нет оценки',
            'Нет достаточных данных для диагноза',
            'Это не означает, что сеть исправна. Нужны свежие наблюдения и/или подтверждённые изменения.',
            (Evidence('Мониторинг', 'Подходящих свежих событий для диагностики нет'),),
            ('Включить мониторинг и дождаться нескольких измерений.',
             'При наличии прав опросить управляемые коммутаторы через LLDP/SNMP.')))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.code, f.title))
    return tuple(findings[:30])


def triage_steps(findings: Sequence[Finding], limit: int = 8) -> tuple[str, ...]:
    """Ordered, read-only field checks. Evidence first, no automatic remediation."""
    if not 1 <= limit <= 20:
        raise ValueError('Invalid triage limit')
    by_code = {f.code: f for f in findings}
    priority = ('lldp_port_temporal_match', 'historical_lldp_overlap',
                'port_errors', 'common_lldp_source', 'gateway_no_icmp',
                'temporal_cluster', 'segment_suspected', 'arp_mac_churn',
                'wifi_disconnected', 'device_no_icmp', 'snmp_unavailable')
    result = []
    for code in priority:
        f = by_code.get(code)
        if f:
            for step in f.checks[:3]:
                if step not in result:
                    result.append(step)
    return tuple(result[:limit])


def recurrence_findings(rows: Sequence[tuple], now: datetime | None = None) -> tuple[Finding, ...]:
    """Low-confidence, log-limited patterns; no outage or periodicity claims."""
    result = []
    for item in incident_patterns.recurrent_incidents(rows, now)[:5]:
        hour = (f' Частые события около {item.recurring_utc_hour:02d}:00 UTC; '
                'это наблюдаемое совпадение, а не доказанный график сбоев.'
                if item.recurring_utc_hour is not None else '')
        result.append(Finding('recurrent_no_icmp', 'notice', 'низкая',
            f'Повторные пропуски ICMP: {item.ip}',
            f'В доступной локальной истории отмечено {item.episodes} отдельных эпизодов '
            f'на {item.distinct_utc_days} днях (UTC). Нет данных о периодах, когда мониторинг не работал. '
            'Нет доказательства, что узел действительно отключался.' + hour,
            (Evidence('Локальный журнал мониторинга',
                      f'{item.first_at.isoformat(timespec="minutes")} — '
                      f'{item.last_at.isoformat(timespec="minutes")}; '
                      f'{item.episodes} отдельных записанных эпизодов'),),
            ('Проверить доступность TCP-сервиса и разрешение ICMP у этого узла.',
             'Сопоставить события с логами коммутатора и временными окнами обслуживания.')))
    return tuple(result)


def export_report(findings: Sequence[Finding], timeline: Sequence[detective_timeline.IncidentMoment] = (),
                  health: incident_patterns.AvailabilityIndex | None = None) -> dict:
    """Explicit, bounded whitelist. Contains network IDs; caller must obtain user action."""
    return {
        'product': 'BLOODSKY NET',
        'engine': 'DETECTIVE rules v2.3',
        'icmp_index': ({'score': health.score, 'responsive': health.responsive,
                        'unresponsive': health.unresponsive, 'explanation': health.explanation}
                       if health is not None else None),
        'recommended_checks': list(triage_steps(findings)),
        'timeline': [{'timestamp': m.observed_at.isoformat(timespec='seconds'),
                      'source': m.source, 'observation': m.description} for m in list(timeline)[-60:]],
        'disclaimer': 'Предположения по измерениям; отсутствие ICMP/LLDP не доказывает поломку. Отчёт содержит сетевые идентификаторы.',
        'findings': [{
            'code': f.code, 'severity': f.severity, 'confidence': f.confidence,
            'title': f.title, 'interpretation': f.interpretation,
            'evidence': [{'source': e.source, 'observation': e.observation} for e in f.evidence],
            'checks': list(f.checks),
        } for f in findings[:30]],
    }


def export_html_report(findings: Sequence[Finding], timeline: Sequence[detective_timeline.IncidentMoment] = (),
                       health: incident_patterns.AvailabilityIndex | None = None) -> str:
    """Offline printable HTML report. No remote assets or script execution."""
    esc = lambda value: html.escape(str(value), quote=True)
    incident_rows = ''.join(f'<tr><td>{esc(m.observed_at.isoformat(timespec="seconds"))}</td>'
                            f'<td>{esc(m.source)}</td><td>{esc(m.description)}</td></tr>'
                            for m in list(timeline)[-60:])
    history_html = ('<h2>Временная шкала наблюдений</h2><table><thead><tr>'
                    '<th>UTC</th><th>Источник</th><th>Наблюдение</th></tr></thead><tbody>'
                    + incident_rows + '</tbody></table>') if incident_rows else ''
    health_html = ('<section><h2>Индекс ответов ICMP</h2><p>'
                   + esc('Не рассчитан' if health.score is None else str(health.score) + '/100')
                   + ' · ' + esc(health.explanation) + '</p></section>') if health is not None else ''
    advice = ''.join(f'<li>{esc(a)}</li>' for a in triage_steps(findings))
    plan_html = '<h2>Порядок проверок инженера</h2><ol>' + advice + '</ol>' if advice else ''
    sections = []
    for f in list(findings)[:30]:
        evidence = ''.join(f'<li><b>{esc(e.source)}:</b> {esc(e.observation)}</li>' for e in f.evidence[:10])
        checks = ''.join(f'<li>{esc(x)}</li>' for x in f.checks[:8])
        sections.append(f'<section><h2>{esc(f.title)}</h2><p>Важность: {esc(f.severity)} '
                        f'| Уверенность: {esc(f.confidence)}</p><p>{esc(f.interpretation)}</p>'
                        f'<h3>Наблюдения</h3><ul>{evidence}</ul><h3>Что проверить</h3><ol>{checks}</ol></section>')
    return ("<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            "<title>BLOODSKY NET — отчёт DETECTIVE</title>"
            "<style>body{font:15px Arial,sans-serif;max-width:900px;margin:36px auto;color:#203044;}"
            "section{border:1px solid #ced5de;border-radius:8px;padding:14px 18px;margin:18px 0}"
            "h1,h2{color:#174a80}li{margin:6px 0}th,td{padding:7px;text-align:left;border-bottom:1px solid #ccd;}</style></head><body>"
            "<h1>BLOODSKY NET · DETECTIVE v2.3</h1>"
            "<p>Локальный отчёт. Выводы вероятностны; ICMP/LLDP и счётчики не доказывают физическую поломку. "
            "Содержит сетевые идентификаторы — передавайте только уполномоченным получателям.</p>"
            + health_html + plan_html + history_html + ''.join(sections) + '</body></html>')
