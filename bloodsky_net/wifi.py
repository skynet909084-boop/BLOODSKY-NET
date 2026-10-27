"""Windows built-in Wi-Fi diagnostics using netsh (no driver or password access)."""
from __future__ import annotations
from dataclasses import dataclass, asdict
import os
import re
from .network import command


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    signal: int = 0
    channel: int = 0
    auth: str = ""
    radio: str = ""
    band: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class WifiStatus:
    connected: bool = False
    ssid: str = ""
    bssid: str = ""
    signal: int = 0
    channel: int = 0
    radio: str = ""
    adapter: str = ""
    state: str = ""
    issue: str = ""


@dataclass
class WifiReport:
    status: WifiStatus
    aps: list[AccessPoint]
    warnings: list[str]


def field_value(line: str) -> tuple[str, str] | None:
    if ":" not in line:
        return None
    key, value = line.split(":", 1)
    return key.strip().casefold(), value.strip()


def get_channel_band(channel: int) -> str:
    if 1 <= channel <= 14:
        return "2,4 ГГц"
    if 32 <= channel <= 177:
        return "5/6 ГГц (ориентир)"
    if 1 <= channel <= 233:
        return "6 ГГц / другое"  # 6 GHz channel indices overlap: cannot infer from channel alone
    return "Неизвестно"


def parse_wifi_connection(text: str) -> WifiStatus:
    status = WifiStatus()
    for line in text.splitlines():
        parsed = field_value(line)
        if not parsed:
            continue
        key, value = parsed
        if key in ("name", "имя") and not status.adapter:
            status.adapter = value
        elif key in ("state", "состояние"):
            status.state = value
            status.connected = value.casefold() in ("connected", "подключено")
        elif key == "ssid":
            status.ssid = value
        elif key == "bssid":
            status.bssid = value.upper()
        elif key in ("signal", "сигнал"):
            status.signal = percent(value)
        elif key in ("channel", "канал"):
            status.channel = integer(value)
        elif key in ("radio type", "тип радиомодуля", "тип радио"):
            status.radio = value
    return status


def percent(text: str) -> int:
    m = re.search(r"\d+", text)
    return min(100, max(0, int(m.group()))) if m else 0


def integer(text: str) -> int:
    m = re.search(r"\d+", text)
    return int(m.group()) if m else 0


def parse_wifi_aps(text: str) -> list[AccessPoint]:
    result: list[AccessPoint] = []
    ssid = ""
    auth = ""
    radio = ""
    current: AccessPoint | None = None
    for line in text.splitlines():
        new_ssid = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*?)\s*$", line, re.I)
        if new_ssid:
            ssid = new_ssid.group(1) or "(скрытая сеть)"
            auth, radio, current = "", "", None
            continue
        bssid = re.match(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-f:]{17})", line, re.I)
        if bssid:
            current = AccessPoint(ssid, bssid.group(1).upper(), auth=auth, radio=radio)
            result.append(current)
            continue
        kv = field_value(line)
        if not kv:
            continue
        key, value = kv
        if key in ("authentication", "проверка подлинности", "аутентификация"):
            auth = value
            if current:
                current.auth = value
        elif key in ("radio type", "тип радиомодуля", "тип радио"):
            radio = value
            if current:
                current.radio = value
        elif current and key in ("signal", "сигнал"):
            current.signal = percent(value)
        elif current and key in ("channel", "канал"):
            current.channel = integer(value)
            current.band = get_channel_band(current.channel)
    return result


def wifi_warnings(status: WifiStatus, aps: list[AccessPoint]) -> list[str]:
    warnings = []
    if not status.connected:
        warnings.append("Wi-Fi не подключён или адаптер недоступен")
        return warnings
    if status.signal and status.signal < 45:
        warnings.append("Слабый сигнал Wi-Fi — возможны обрывы или высокая задержка")
    if status.channel:
        same = sum(1 for ap in aps if ap.channel == status.channel and ap.bssid != status.bssid)
        if same >= 4:
            warnings.append(f"На канале {status.channel} видны ещё {same} точек доступа: возможна перегрузка эфира")
    return warnings


def read_wifi() -> WifiReport:
    if os.name != "nt":
        return WifiReport(WifiStatus(issue="Диагностика Wi-Fi поддерживается на Windows 10/11"), [],
                          ["Для сканирования Wi-Fi запустите приложение на Windows"])
    code, interface_text = command(["netsh", "wlan", "show", "interfaces"], timeout=10)
    status = parse_wifi_connection(interface_text)
    code2, networks_text = command(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=15)
    aps = parse_wifi_aps(networks_text)
    if code or code2:
        status.issue = "Не удалось получить Wi-Fi сведения. Проверьте адаптер, службу WLAN AutoConfig и доступ к геолокации Windows."
    warnings = wifi_warnings(status, aps)
    if status.issue:
        warnings.insert(0, status.issue)
    return WifiReport(status, aps, warnings)
