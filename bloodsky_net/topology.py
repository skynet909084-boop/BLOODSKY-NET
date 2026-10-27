"""Read-only LLDP topology from explicitly configured SNMP agents.

LLDP observations reflect the equipment's management information, not guaranteed
physical cable health. Never assume that an unresolved neighbor has a known IP.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import ipaddress
import re
from typing import Mapping, Sequence

from .fdb import FDBEntry, FDB_WALK_ROOTS, parse_fdb

# Numeric OIDs intentionally avoid dependency on vendor MIB files.
LLDP_REMOTE = '1.0.8802.1.1.2.1.4.1.1'
LLDP_LOCAL_PORT = '1.0.8802.1.1.2.1.3.7.1'
SYS_NAME = '1.3.6.1.2.1.1.5.0'
COL_CHASSIS = 5
COL_PORT_ID = 7
COL_PORT_DESC = 8
COL_SYS_NAME = 9
COL_SYS_DESC = 10


@dataclass(frozen=True)
class SNMPCredentials:
    version: str = 'v3'
    username: str = ''
    auth_key: str = ''
    priv_key: str = ''
    community: str = ''
    port: int = 161

    def validate(self):
        if self.version not in ('v3', 'v2c'):
            raise ValueError('Поддерживаются только SNMPv3 и SNMPv2c')
        if not 1 <= self.port <= 65535:
            raise ValueError('Порт SNMP должен быть от 1 до 65535')
        if self.version == 'v3':
            if not self.username.strip() or len(self.auth_key) < 8 or len(self.priv_key) < 8:
                raise ValueError('SNMPv3: введите имя пользователя и пароли SHA-256/AES от 8 символов')
        elif not self.community:
            raise ValueError('SNMPv2c: укажите community только для чтения')


@dataclass(frozen=True)
class Neighbor:
    source_ip: str
    local_port_num: int
    local_port: str
    remote_name: str = ''
    remote_port: str = ''
    remote_chassis: str = ''
    remote_description: str = ''
    remote_ip: str = ''  # Never inferred from free-form description.


@dataclass
class TopologySnapshot:
    source_ip: str
    system_name: str = ''
    neighbors: list[Neighbor] = field(default_factory=list)
    observed_at: str = ''
    fdb_entries: list[FDBEntry] = field(default_factory=list)


def _as_mac(value: str) -> str:
    """Decode a 6-byte LLDP chassis ID; preserve other chassis IDs as-is."""
    text = value.strip()
    if re.fullmatch(r'(?i)0x(?:[a-f0-9]{2}){6}', text):
        return ':'.join(text[2 + i:4 + i].upper() for i in range(0, 12, 2))
    if re.fullmatch(r'(?i)(?:[a-f0-9]{2}[:-]){5}[a-f0-9]{2}', text):
        return text.replace('-', ':').upper()
    return text[:128]


def parse_lldp(source_ip: str, values: Mapping[str, str], observed_at: str = '') -> TopologySnapshot:
    """Join LLDP remote columns by (timeMark, localPortNum, remoteIndex)."""
    ipaddress.IPv4Address(source_ip)
    system_name = values.get(SYS_NAME, '')[:120]
    local_ports: dict[int, str] = {}
    remote: dict[tuple[int, int, int], dict[int, str]] = {}
    for oid, value in values.items():
        parts = oid.strip('.').split('.')
        if oid.startswith(LLDP_LOCAL_PORT + '.'):
            suffix = oid[len(LLDP_LOCAL_PORT) + 1:].split('.')
            if len(suffix) == 2 and suffix[0] in ('3', '4') and suffix[1].isdigit():
                # lldpLocPortId / lldpLocPortDesc; prefer human readable description.
                index = int(suffix[1])
                if suffix[0] == '4' or index not in local_ports:
                    local_ports[index] = value[:90]
            continue
        if oid.startswith(LLDP_REMOTE + '.'):
            suffix = oid[len(LLDP_REMOTE) + 1:].split('.')
            if len(suffix) != 4 or not all(piece.isdigit() for piece in suffix):
                continue
            column, timemark, port_no, rem_idx = map(int, suffix)
            if column in (COL_CHASSIS, COL_PORT_ID, COL_PORT_DESC, COL_SYS_NAME, COL_SYS_DESC):
                remote.setdefault((timemark, port_no, rem_idx), {})[column] = value[:250]
    neighbors = []
    for (_timemark, port_no, _rem_idx), cols in sorted(remote.items()):
        if not any(cols.get(k) for k in (COL_CHASSIS, COL_PORT_ID, COL_SYS_NAME)):
            continue
        neighbors.append(Neighbor(
            source_ip=source_ip, local_port_num=port_no,
            local_port=local_ports.get(port_no) or str(port_no),
            remote_name=cols.get(COL_SYS_NAME, '').strip(),
            remote_port=(cols.get(COL_PORT_DESC) or cols.get(COL_PORT_ID, '')).strip(),
            remote_chassis=_as_mac(cols.get(COL_CHASSIS, '')),
            remote_description=cols.get(COL_SYS_DESC, '').strip(),
        ))
    return TopologySnapshot(source_ip, system_name, neighbors, observed_at, parse_fdb(values))


def _hostname_keys(name: str) -> set[str]:
    name = name.strip().rstrip('.').lower()
    if not name:
        return set()
    return {name, name.split('.')[0]}


def resolve_neighbor_ip(neighbor: Neighbor, devices: Sequence) -> str:
    """Return a match only if unique; never match vendor or generic device kind."""
    from .network import normalize_mac
    matches = []
    wanted_mac = normalize_mac(neighbor.remote_chassis)
    wanted_names = _hostname_keys(neighbor.remote_name)
    for device in devices:
        if device.ip == neighbor.source_ip:
            continue
        if wanted_mac and normalize_mac(device.mac) == wanted_mac:
            matches.append(device.ip)
        elif wanted_names and _hostname_keys(device.hostname) & wanted_names:
            matches.append(device.ip)
    return matches[0] if len(matches) == 1 else ''


def physical_links(snapshots: Mapping[str, TopologySnapshot], devices: Sequence) -> list[tuple[str, str, Neighbor]]:
    """Deduplicated observed links with uniquely identified endpoints."""
    result = []
    seen = set()
    for source, snapshot in snapshots.items():
        for neighbor in snapshot.neighbors:
            target = resolve_neighbor_ip(neighbor, devices)
            if not target:
                continue
            pair = tuple(sorted((source, target)))
            if pair not in seen:
                result.append((source, target, neighbor))
                seen.add(pair)
    return result


async def _snmp_walk(host: str, credentials: SNMPCredentials) -> dict[str, str]:
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, get_cmd, walk_cmd,
            USM_AUTH_HMAC192_SHA256, USM_PRIV_CFB128_AES,
        )
    except ImportError as exc:
        raise RuntimeError('SNMP недоступен: установите зависимости из requirements.txt') from exc
    engine = SnmpEngine()
    try:
        credentials.validate()
        auth = (UsmUserData(credentials.username, authKey=credentials.auth_key,
                            privKey=credentials.priv_key,
                            authProtocol=USM_AUTH_HMAC192_SHA256,
                            privProtocol=USM_PRIV_CFB128_AES)
                if credentials.version == 'v3'
                else CommunityData(credentials.community, mpModel=1))
        target = await UdpTransportTarget.create((host, credentials.port), timeout=1.5, retries=1)
        context = ContextData()
        values = {}
        # System name: optional (some agents deny this OID).
        status = await get_cmd(engine, auth, target, context,
                               ObjectType(ObjectIdentity(SYS_NAME)), lookupMib=False)
        if not status[0] and not status[1]:
            for oid, value in status[3]:
                values[oid.prettyPrint()] = value.prettyPrint()
        # Avoid unbounded remote walks. A large switch requires a deliberate limit.
        for root in (LLDP_LOCAL_PORT, LLDP_REMOTE, *FDB_WALK_ROOTS):
            async for error_ind, error_status, _error_idx, rows in walk_cmd(
                    engine, auth, target, context, ObjectType(ObjectIdentity(root)),
                    lookupMib=False, lexicographicMode=False, maxRows=700, maxCalls=700):
                if error_ind or error_status:
                    if root in (LLDP_LOCAL_PORT, LLDP_REMOTE):
                        raise RuntimeError('SNMP: нет ответа или отказ в чтении LLDP-MIB')
                    break  # An optional FDB/IF-MIB table may be absent or denied.
                for oid, value in rows:
                    key = oid.prettyPrint()
                    if key.startswith(root + '.'):
                        values[key] = value.prettyPrint()
        return values
    finally:
        engine.close_dispatcher()


def read_lldp(host: str, credentials: SNMPCredentials) -> TopologySnapshot:
    """Blocking one-target read; call from worker thread (never Tk main thread)."""
    from .network import now_iso
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as exc:
        raise ValueError('Для SNMP укажите точный IPv4-адрес устройства') from exc
    if not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError('SNMP доступен только для адресов частной локальной сети')
    credentials.validate()
    try:
        values = asyncio.run(asyncio.wait_for(_snmp_walk(str(address), credentials), timeout=30))
    except TimeoutError as exc:
        raise RuntimeError('SNMP: истёк тайм-аут опроса') from exc
    return parse_lldp(str(address), values, now_iso())
