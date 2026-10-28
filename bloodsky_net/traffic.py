"""Read-only IF-MIB port counters and conservative throughput estimation.

Requires two successive samples of 64-bit ifHC counters. Missing counters,
resets, invalid values, down ports, and excessive gaps never become zeros.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

IF_HC_IN = '1.3.6.1.2.1.31.1.1.1.6'
IF_HC_OUT = '1.3.6.1.2.1.31.1.1.1.10'
IF_OPER_STATUS = '1.3.6.1.2.1.2.2.1.8'
IF_HIGH_SPEED = '1.3.6.1.2.1.31.1.1.1.15'
IF_NAME = '1.3.6.1.2.1.31.1.1.1.1'
IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
TRAFFIC_WALK_ROOTS = (IF_HC_IN, IF_HC_OUT, IF_OPER_STATUS, IF_HIGH_SPEED)
MAX_COUNTER = 2 ** 64 - 1


@dataclass(frozen=True)
class PortCounter:
    index: int
    name: str
    received: int
    sent: int
    speed_mbps: int | None = None
    oper_up: bool | None = None


@dataclass(frozen=True)
class PortRate:
    index: int
    name: str
    inbound_mbps: float | None
    outbound_mbps: float | None
    speed_mbps: int | None = None
    oper_up: bool | None = None


def _indexed(values: Mapping[str, str], root: str) -> dict[int, str]:
    result: dict[int, str] = {}
    prefix = root + '.'
    for oid, value in values.items():
        if not oid.startswith(prefix):
            continue
        index = oid[len(prefix):]
        if index.isascii() and index.isdecimal() and 0 < int(index) <= 2147483647:
            result[int(index)] = str(value)
    return result


def _unsigned(value: str, maximum: int = MAX_COUNTER) -> int | None:
    if not value or not value.isascii() or not value.isdecimal():
        return None
    number = int(value)
    return number if 0 <= number <= maximum else None


def parse_port_counters(values: Mapping[str, str], limit: int = 500) -> dict[int, PortCounter]:
    """Ignore incomplete/unsupported 64-bit counters; no 32-bit fallback."""
    if limit <= 0:
        return {}
    incoming = _indexed(values, IF_HC_IN)
    outgoing = _indexed(values, IF_HC_OUT)
    names = _indexed(values, IF_NAME)
    descriptions = _indexed(values, IF_DESCR)
    speeds = _indexed(values, IF_HIGH_SPEED)
    states = _indexed(values, IF_OPER_STATUS)
    result = {}
    for idx in sorted(incoming.keys() & outgoing.keys()):
        rx, tx = _unsigned(incoming[idx]), _unsigned(outgoing[idx])
        if rx is None or tx is None:
            continue
        speed = _unsigned(speeds.get(idx, ''), maximum=400000)
        status = states.get(idx, '')
        result[idx] = PortCounter(idx, (names.get(idx) or descriptions.get(idx) or f'ifIndex {idx}')[:100],
                                  rx, tx, speed if speed else None,
                                  True if status == '1' else False if status == '2' else None)
        if len(result) >= limit:
            break
    return result


def calculate_port_rates(previous: Mapping[int, PortCounter], current: Mapping[int, PortCounter],
                         seconds: float) -> dict[int, PortRate]:
    """Mbps = delta octets * 8 / seconds / 1e6; resets produce unknown rates."""
    if not 1 <= seconds <= 3600:
        return {}
    result = {}
    for idx, after in current.items():
        before = previous.get(idx)
        if not before:
            continue
        inbound = outbound = None
        if after.oper_up is not False and before.oper_up is not False:
            if after.received >= before.received and after.sent >= before.sent:
                inbound = round((after.received - before.received) * 8 / seconds / 1e6, 3)
                outbound = round((after.sent - before.sent) * 8 / seconds / 1e6, 3)
        # A counter reset cannot safely be interpreted as 64-bit wrap; leave missing.
        result[idx] = PortRate(idx, after.name, inbound, outbound, after.speed_mbps, after.oper_up)
    return result
