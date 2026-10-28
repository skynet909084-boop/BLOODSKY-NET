"""Passive, read-only inspection of local Windows DHCP adapter settings.

No packet capture, DHCP requests or scanning: observed configuration cannot
prove an address conflict or detect a rogue DHCP server on the wire.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from typing import Callable

from .network import command

# Use fixed program arguments, never interpolate user input into shell commands.
POWERSHELL = ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
              "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | "
              "Select-Object Description,DHCPEnabled,DHCPServer,IPAddress,DHCPLeaseObtained,DHCPLeaseExpires | "
              "ConvertTo-Json -Depth 3 -Compress")


@dataclass(frozen=True)
class DHCPAdapter:
    name: str
    addresses: tuple[str, ...]
    enabled: bool
    server: str
    lease_start: str = ""
    lease_expiry: str = ""


def _ipv4(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        address = ipaddress.ip_address(value.strip())
        return str(address) if isinstance(address, ipaddress.IPv4Address) else ""
    except ValueError:
        return ""


def parse_dhcp_json(output: str) -> list[DHCPAdapter]:
    """Accept both PowerShell single-object and array JSON responses."""
    content = json.loads(output.lstrip("\ufeff"))
    rows = content if isinstance(content, list) else [content]
    result = []
    for row in rows[:256]:
        if not isinstance(row, dict):
            continue
        addresses = row.get("IPAddress") or []
        if isinstance(addresses, str):
            addresses = [addresses]
        if not isinstance(addresses, list):
            addresses = []
        ips = tuple(filter(None, (_ipv4(addr) for addr in addresses[:32])))
        if not ips:
            continue
        result.append(DHCPAdapter(
            name=str(row.get("Description") or "Адаптер")[:128],
            addresses=ips,
            enabled=row.get("DHCPEnabled") is True,
            server=_ipv4(row.get("DHCPServer")),
            lease_start=str(row.get("DHCPLeaseObtained") or "")[:80],
            lease_expiry=str(row.get("DHCPLeaseExpires") or "")[:80],
        ))
    return result


def format_dhcp_report(adapters: list[DHCPAdapter]) -> str:
    if not adapters:
        return "Активные IPv4-адаптеры с DHCP не найдены."
    lines = ["DHCP: локальная конфигурация сетевых адаптеров Windows", ""]
    for adapter in adapters:
        lines.extend([
            f"Адаптер: {adapter.name}",
            f"IPv4: {', '.join(adapter.addresses)}",
            f"DHCP: {'включён' if adapter.enabled else 'выключен (статический адрес)'}",
            f"Сервер DHCP: {adapter.server or 'не указан'}" if adapter.enabled else "",
            f"Аренда с: {adapter.lease_start}" if adapter.enabled and adapter.lease_start else "",
            f"Аренда до: {adapter.lease_expiry}" if adapter.enabled and adapter.lease_expiry else "",
            "",
        ])
    lines.append("Сведения получены из конфигурации Windows. Они НЕ доказывают IP-конфликт "
                 "и не обнаруживают посторонний DHCP-сервер в сети. Для подтверждения "
                 "нужны логи DHCP, коммутатора либо разрешённый анализ пакетов.")
    return "\n".join(x for x in lines if x is not None)


def read_dhcp_configuration(runner: Callable = command, windows: bool | None = None) -> tuple[int, str]:
    if (os.name == "nt" if windows is None else windows) is False:
        return 1, "Диагностика DHCP доступна только в Windows."
    code, output = runner(list(POWERSHELL), timeout=12)
    if code:
        return code, "Не удалось прочитать параметры DHCP Windows. Проверьте PowerShell/CIM."
    try:
        return 0, format_dhcp_report(parse_dhcp_json(output))
    except (ValueError, TypeError, json.JSONDecodeError):
        return 1, "Ответ Windows о DHCP не распознан. IP-конфликт не установлен."
