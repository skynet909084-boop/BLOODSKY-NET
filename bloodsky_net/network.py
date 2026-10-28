"""Local-network diagnostics. No raw sockets, packet injection or admin rights required."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import ctypes
import ipaddress
import os
import platform
import re
import socket
import subprocess
import threading
import time
from typing import Callable, Iterable

import psutil

PORTS = (22, 80, 443, 445, 554, 3389, 9100)
MAC_RX = r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
VENDORS = {
    # Examples, not a complete registry: report only positively matched prefixes.
    "00:1A:2B": "Ayecom Technology", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1B:21": "Intel", "3C:52:82": "Hewlett Packard",
    "00:11:32": "Synology", "00:1A:79": "D-Link",
    "00:18:E7": "Cameo Communications", "74:DA:38": "Edimax",
    "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "00:0C:29": "VMware", "F4:F2:6D": "TP-Link",
    "00:1D:0F": "TP-Link", "00:1E:58": "D-Link",
}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def output_encoding() -> str:
    if os.name == "nt":
        try:
            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            return "cp866"
    return "utf-8"


def command(args: list[str], timeout: float = 10) -> tuple[int, str]:
    """Run fixed executable arguments, without a shell and without command injection."""
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, check=False, creationflags=(0x08000000 if os.name == "nt" else 0))
        return p.returncode, p.stdout.decode(output_encoding(), errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 124, str(exc)


def normalize_mac(mac: str) -> str:
    m = mac.replace("-", ":").upper()
    if not re.fullmatch(MAC_RX, m):
        return ""
    return m


def parse_arp(text: str) -> dict[str, str]:
    """Parse localized `arp -a` output using only numeric columns."""
    result = {}
    rx = re.compile(rf"^\s*(\d{{1,3}}(?:\.\d{{1,3}}){{3}})\s+({MAC_RX})(?=\s|$)", re.M)
    for ip, mac in rx.findall(text):
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_multicast and not addr.is_unspecified and not mac.lower().startswith("ff-ff-ff"):
                result[ip] = normalize_mac(mac)
        except ValueError:
            continue
    return result


def arp_table() -> dict[str, str]:
    return parse_arp(command(["arp", "-a"], timeout=5)[1])


def default_gateway() -> tuple[str, str]:
    """Return (gateway IPv4, local interface IPv4) based on OS route table."""
    if os.name == "nt":
        _, out = command(["route", "print", "-4"], timeout=6)
        candidates = []
        regex = r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+(?:\.\d+){3})\s+(\d+(?:\.\d+){3})\s+(\d+)\s*$"
        for gateway, interface, metric in re.findall(regex, out, re.M):
            candidates.append((int(metric), gateway, interface))
        if candidates:
            _, gw, local = min(candidates)
            return gw, local
    else:
        try:
            with open("/proc/net/route", encoding="ascii") as fd:
                for line in fd:
                    fields = line.split()
                    if len(fields) >= 4 and fields[1] == "00000000" and (int(fields[3], 16) & 2):
                        num = int(fields[2], 16)
                        return socket.inet_ntoa(num.to_bytes(4, "little")), ""
        except (OSError, ValueError):
            pass
    return "", ""


@dataclass
class Adapter:
    name: str
    address: str
    subnet: str
    cidr: str
    speed: int = 0
    status: str = "up"


def get_adapters() -> list[Adapter]:
    adapters = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for addr in addrs:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            try:
                interface = ipaddress.ip_interface(f"{addr.address}/{addr.netmask}")
            except ValueError:
                continue
            if interface.ip.is_loopback or interface.ip.is_link_local or interface.ip.is_unspecified:
                continue
            adapters.append(Adapter(name, addr.address, addr.netmask, str(interface.network),
                                    stats[name].speed if name in stats else 0))
    return adapters


def suggested_network(adapters: list[Adapter], local_route_ip: str = "") -> str:
    chosen = next((a for a in adapters if a.address == local_route_ip), None)
    chosen = chosen or (adapters[0] if adapters else None)
    if not chosen:
        return "192.168.1.0/24"
    network = ipaddress.ip_network(chosen.cidr)
    if network.num_addresses > 512:
        return str(ipaddress.ip_network(f"{chosen.address}/24", strict=False))
    return str(network)


def validate_scan_cidr(value: str, adapters: list[Adapter], max_hosts: int = 512) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Некорректная подсеть. Пример: 192.168.1.0/24") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Поддерживаются только подсети IPv4")
    if network.num_addresses > max_hosts + 2:
        raise ValueError(f"Для одного сканирования допустимо не более {max_hosts} адресов; выберите меньшую подсеть")
    if not network.is_private:
        raise ValueError("Сканирование разрешено только для частных локальных IPv4-сетей")
    if adapters and not any(network.subnet_of(ipaddress.ip_network(a.cidr)) for a in adapters):
        raise ValueError("Указанная подсеть не принадлежит активному локальному адаптеру")
    return network


@dataclass
class PingResult:
    alive: bool
    rtt_ms: float | None


def parse_ping_latency(text: str) -> float | None:
    expressions = [
        r"\btime\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms",
        r"\bвремя\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*мс",
        r"\btime\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*milliseconds",
    ]
    for expr in expressions:
        match = re.search(expr, text, flags=re.I)
        if match:
            return float(match.group(1).replace(",", "."))
    return None


def ping_once(ip: str, timeout_ms: int = 800) -> PingResult:
    if os.name == "nt":
        args = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        args = ["ping", "-n", "-c", "1", "-W", str(max(1, (timeout_ms + 999) // 1000)), ip]
    start = time.monotonic()
    code, out = command(args, timeout=max(3, timeout_ms / 1000 + 2))
    if code != 0:
        return PingResult(False, None)
    elapsed = (time.monotonic() - start) * 1000
    return PingResult(True, parse_ping_latency(out) or round(elapsed, 1))


def probe_ports(ip: str, ports: Iterable[int], timeout: float = 0.16) -> list[int]:
    found = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                found.append(port)
        except OSError:
            pass
    return found


def friendly_hostname(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name[:80]
    except (OSError, UnicodeError):
        return ""


def classify_device(gateway: str, ip: str, hostname: str, ports: list[int]) -> str:
    h = hostname.lower()
    if ip == gateway:
        return "Маршрутизатор"
    if 9100 in ports or "printer" in h or "print" in h:
        return "Принтер"
    if 554 in ports or "camera" in h or "cam-" in h or "ipcam" in h:
        return "Камера (вероятно)"
    if "nas" in h or "synology" in h or "storage" in h:
        return "NAS (вероятно)"
    if 3389 in ports or 445 in ports:
        return "Компьютер/сервер (вероятно)"
    if 22 in ports and (80 in ports or 443 in ports):
        return "Сетевое устройство (вероятно)"
    if any(port in ports for port in (80, 443)):
        return "Устройство с веб-интерфейсом"
    return "Устройство (тип не определён)"


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    kind: str = "Устройство (тип не определён)"
    vendor: str = ""
    ports: list[int] = field(default_factory=list)
    online: bool = True
    latency_ms: float | None = None
    seen: str = ""
    failures: int = 0
    is_gateway: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Device":
        return cls(**{key: data[key] for key in cls.__dataclass_fields__ if key in data})


def mac_vendor(mac: str) -> str:
    return VENDORS.get(normalize_mac(mac)[:8], "Не определён") if mac else "Не определён"


def scan_network(cidr: str, gateway: str, stop: threading.Event,
                 on_found: Callable[[Device], None] | None = None,
                 progress: Callable[[int, int], None] | None = None) -> tuple[list[Device], dict[str, str], int]:
    """Concurrent ICMP + small TCP fallback discovery, with ARP enrichment."""
    hosts = list(ipaddress.ip_network(cidr, strict=False).hosts())
    before = arp_table()
    count = 0
    found: dict[str, Device] = {}

    def worker(addr: ipaddress.IPv4Address):
        if stop.is_set():
            return None
        ip = str(addr)
        ping = ping_once(ip)
        minimal_ports = [] if ping.alive else probe_ports(ip, (80, 443, 445), 0.14)
        if not ping.alive and not minimal_ports and ip not in before:
            return None
        ports = sorted(set(minimal_ports + probe_ports(ip, PORTS, 0.14)))
        hostname = friendly_hostname(ip)
        device = Device(ip=ip, hostname=hostname, ports=ports,
                        online=(ping.alive or bool(ports)), latency_ms=ping.rtt_ms,
                        kind=classify_device(gateway, ip, hostname, ports),
                        seen=now_iso(), is_gateway=ip == gateway)
        return device

    with ThreadPoolExecutor(max_workers=48, thread_name_prefix="discover") as pool:
        futures = {pool.submit(worker, addr): str(addr) for addr in hosts}
        for future in as_completed(futures):
            count += 1
            if not stop.is_set():
                try:
                    item = future.result()
                except Exception:
                    item = None
                if item:
                    found[item.ip] = item
                    if on_found:
                        on_found(item)
            if progress and count % 5 == 0:
                progress(count, len(hosts))
    neighbors = dict(before)
    neighbors.update(arp_table())  # latest MAC observations take precedence
    for ip, mac in neighbors.items():
        if ip not in found and ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
            found[ip] = Device(ip=ip, mac=mac, vendor=mac_vendor(mac),
                               online=False, seen=now_iso(), is_gateway=ip == gateway)
            if on_found:
                on_found(found[ip])
        elif ip in found:
            found[ip].mac = mac
            found[ip].vendor = mac_vendor(mac)
    return list(found.values()), neighbors, count


def poll_devices(ips: list[str], stop: threading.Event, fallback_ports: dict[str, list[int]] | None = None) -> dict[str, PingResult]:
    if not ips or stop.is_set():
        return {}
    result = {}
    fallback_ports = fallback_ports or {}

    def check(ip: str) -> PingResult:
        ping = ping_once(ip)
        if ping.alive:
            return ping
        if fallback_ports.get(ip) and probe_ports(ip, fallback_ports[ip][:2], timeout=0.24):
            return PingResult(True, None)  # service reachable, ICMP blocked
        return ping

    with ThreadPoolExecutor(max_workers=32, thread_name_prefix="monitor") as pool:
        jobs = {pool.submit(check, ip): ip for ip in ips}
        for future in as_completed(jobs):
            if stop.is_set():
                break
            try:
                result[jobs[future]] = future.result()
            except Exception:
                result[jobs[future]] = PingResult(False, None)
    return result


@dataclass
class MacChange:
    ip: str
    previous: str
    current: str
    observed_at: str
    severity: str = "info"  # one change is not evidence of an IP conflict
    switches: int = 1


class MacHistory:
    """Classify ARP MAC changes, never equate them with proven IP conflicts.

    An isolated reassignment is informational. Two or more changes within three
    minutes are elevated, but still only *suspected*: DHCP, VRRP and stale ARP
    can produce the same observations. Old samples and dedupe keys expire.
    """
    def __init__(self, window_s: int = 180, cooldown_s: int = 120):
        self.known: dict[str, tuple[str, float]] = {}
        self.transitions: dict[str, list[float]] = {}
        self.last_alert: dict[tuple[str, str, str, str], float] = {}
        self.window_s = window_s
        self.cooldown_s = cooldown_s

    def ingest(self, rows: dict[str, str], timestamp: float | None = None) -> list[MacChange]:
        t = timestamp if timestamp is not None else time.time()
        alerts = []
        self.last_alert = {key: at for key, at in self.last_alert.items()
                           if 0 <= t - at < self.cooldown_s}
        for ip, raw_mac in rows.items():
            mac = normalize_mac(raw_mac)
            if not mac:
                continue
            prior = self.known.get(ip)
            times = [at for at in self.transitions.get(ip, []) if 0 <= t - at <= self.window_s]
            if prior and prior[0] != mac:
                if 0 <= t - prior[1] <= 900:
                    times.append(t)
                    level = "warning" if len(times) >= 2 else "info"
                    key = (ip, prior[0], mac, level)
                    if key not in self.last_alert:
                        alerts.append(MacChange(ip, prior[0], mac, now_iso(), level, len(times)))
                        self.last_alert[key] = t
                else:
                    times = []  # old bindings cannot establish a rapid change
            self.transitions[ip] = times[-24:]
            self.known[ip] = (mac, t)
        # Prevent unbounded growth when scanned hosts leave the network.
        for ip in list(self.known):
            if t - self.known[ip][1] > 3600:
                self.known.pop(ip, None)
                self.transitions.pop(ip, None)
        return alerts


def trace_target(target: str, max_hops: int = 18) -> tuple[int, str]:
    valid_target(target)
    if os.name == "nt":
        return command(["tracert", "-d", "-h", str(max_hops), "-w", "500", target], timeout=max_hops * 2 + 8)
    return command(["traceroute", "-n", "-m", str(max_hops), "-w", "1", target], timeout=max_hops * 3 + 8)


def valid_target(target: str) -> str:
    target = target.strip()
    if len(target) > 253 or not target or any(ch.isspace() for ch in target) or target.startswith("-"):
        raise ValueError("Введите IP-адрес или имя узла без пробелов")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if not re.fullmatch(r"(?i)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", target) or ".." in target:
        raise ValueError("Некорректное имя узла")
    return target


def network_counters() -> dict[str, tuple[int, int]]:
    return {name: (counter.bytes_recv, counter.bytes_sent)
            for name, counter in psutil.net_io_counters(pernic=True).items()}
