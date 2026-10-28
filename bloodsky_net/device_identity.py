"""Opt-in LAN-only UPnP/SSDP identification. Strings are untrusted device claims.

No background discovery, online lookup, password access, redirects or third-party
description URLs. Only fetch same-host HTTP from a private RFC1918 responder.
"""
from __future__ import annotations
from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
import time
from urllib.parse import urlsplit
from xml.etree import ElementTree

MAX_XML = 65536
MAX_RESPONSES = 64
SEARCH_ADDRESS = ('239.255.255.250', 1900)
MSEARCH = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
           b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n')
RFC1918 = (ipaddress.IPv4Network('10.0.0.0/8'),
           ipaddress.IPv4Network('172.16.0.0/12'),
           ipaddress.IPv4Network('192.168.0.0/16'))

@dataclass(frozen=True)
class Identity:
    ip: str
    friendly_name: str = ''
    manufacturer: str = ''
    model: str = ''
    source: str = 'UPnP description (заявлено устройством)'

def _private(ip: str) -> str:
    address = ipaddress.IPv4Address(ip)
    if not any(address in lan for lan in RFC1918):
        raise ValueError('Только RFC1918 локальный IPv4')
    return str(address)

def parse_ssdp_headers(packet: bytes) -> dict[str, str]:
    if len(packet) > 8192:
        return {}
    try:
        text = packet.decode('iso-8859-1')
        lines = text.split('\r\n')
        if not re.fullmatch(r'HTTP/1\.[01] 200(?: .*)?', lines[0], re.I):
            return {}
        result = {}
        for line in lines[1:]:
            if not line:
                break
            if ':' not in line:
                return {}
            key, value = line.split(':', 1)
            key = key.strip().lower()
            if key in ('location', 'st', 'usn', 'server') and key not in result:
                result[key] = value.strip()
        return result
    except (UnicodeError, IndexError):
        return {}

def description_target(location: str, sender_ip: str) -> tuple[str, int, str]:
    ip = _private(sender_ip)
    if len(location) > 1024 or any(ord(x) < 32 for x in location):
        raise ValueError('Некорректный URL описания')
    parsed = urlsplit(location)
    if (parsed.scheme != 'http' or parsed.hostname != ip or
            parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise ValueError('Описание должно находиться на том же IPv4')
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise ValueError('Некорректный порт') from exc
    if not 1 <= port <= 65535:
        raise ValueError('Некорректный порт')
    path = (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')
    if len(path) > 1024:
        raise ValueError('Слишком длинный путь')
    return ip, port, path

def _safe(value: str | None, limit: int) -> str:
    if not isinstance(value, str):
        return ''
    return ''.join(' ' if ord(c) < 32 else c for c in value).strip()[:limit]

def parse_description(xml: bytes, ip: str) -> Identity | None:
    if not xml or len(xml) > MAX_XML or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():
        return None
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None
    device = next((e for e in root.iter() if e.tag.split('}')[-1] == 'device'), None)
    if device is None:
        return None
    data = {c.tag.split('}')[-1]: c.text for c in device}
    name = _safe(data.get('friendlyName'), 100)
    maker = _safe(data.get('manufacturer'), 100)
    model = _safe(data.get('modelName'), 100) or _safe(data.get('modelNumber'), 100)
    return Identity(_private(ip), name, maker, model) if any((name, maker, model)) else None

def fetch_description(location: str, sender_ip: str, timeout: float = 1.5) -> Identity | None:
    ip, port, path = description_target(location, sender_ip)
    conn = http.client.HTTPConnection(ip, port, timeout=min(2.5, max(0.2, timeout)))
    try:
        conn.request('GET', path, headers={'Accept': 'text/xml, application/xml', 'Connection': 'close'})
        res = conn.getresponse()
        if res.status != 200:
            return None
        return parse_description(res.read(MAX_XML + 1), ip)
    finally:
        conn.close()

def discover(subnet: str, timeout: float = 2.8) -> dict[str, Identity]:
    network = ipaddress.IPv4Network(subnet, strict=False)
    if network.num_addresses > 514 or not any(network.subnet_of(lan) for lan in RFC1918):
        raise ValueError('Разрешена только локальная RFC1918 сеть до 512 адресов')
    timeout = min(4.0, max(0.5, float(timeout)))
    endpoints: dict[str, str] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(0.2)
        sock.sendto(MSEARCH, SEARCH_ADDRESS)
        deadline = time.monotonic() + timeout
        responses = 0
        while time.monotonic() < deadline and responses < MAX_RESPONSES:
            try:
                packet, (sender_ip, _port) = sock.recvfrom(8193)
            except socket.timeout:
                continue
            responses += 1
            try:
                if ipaddress.IPv4Address(sender_ip) not in network:
                    continue
                location = parse_ssdp_headers(packet).get('location', '')
                description_target(location, sender_ip)
                endpoints.setdefault(sender_ip, location)
            except (ValueError, TypeError):
                continue
    finally:
        sock.close()
    found = {}
    for ip, location in list(endpoints.items())[:32]:
        try:
            identity = fetch_description(location, ip)
            if identity:
                found[ip] = identity
        except (OSError, ValueError, TimeoutError, http.client.HTTPException):
            continue
    return found
