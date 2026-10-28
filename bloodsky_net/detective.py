"""Offline, deterministic BLOODSKY DETECTIVE v1: measured evidence, not guesses.

No network I/O, credentials, packet capture, AI inference or configuration changes.
A failed ICMP probe is *not* proof that hardware, a cable or WAN is down.
"""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress
from typing import Mapping, Sequence


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
    if not findings:
        findings.append(Finding('insufficient_evidence', 'info', 'нет оценки',
            'Нет достаточных данных для диагноза',
            'Это не означает, что сеть исправна. Нужны свежие наблюдения и/или подтверждённые изменения.',
            (Evidence('Мониторинг', 'Подходящих свежих событий для диагностики нет'),),
            ('Включить мониторинг и дождаться нескольких измерений.',
             'При наличии прав опросить управляемые коммутаторы через LLDP/SNMP.')))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.code, f.title))
    return tuple(findings[:30])


def export_report(findings: Sequence[Finding]) -> dict:
    """Explicit, bounded whitelist. Contains network IDs; caller must obtain user action."""
    return {
        'product': 'BLOODSKY NET',
        'engine': 'DETECTIVE rules v1',
        'disclaimer': 'Предположения по измерениям; отсутствие ICMP/LLDP не доказывает поломку. Отчёт содержит сетевые идентификаторы.',
        'findings': [{
            'code': f.code, 'severity': f.severity, 'confidence': f.confidence,
            'title': f.title, 'interpretation': f.interpretation,
            'evidence': [{'source': e.source, 'observation': e.observation} for e in f.evidence],
            'checks': list(f.checks),
        } for f in findings[:30]],
    }
