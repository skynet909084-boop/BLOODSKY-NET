"""Read-only IF-MIB error/discard counter observations.

32-bit counters can wrap or reset. Neither a decrease nor a missing MIB entry
is translated into a zero delta; results are *measurements*, not diagnoses.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
import math

IF_IN_DISCARDS = '1.3.6.1.2.1.2.2.1.13'
IF_IN_ERRORS = '1.3.6.1.2.1.2.2.1.14'
IF_OUT_DISCARDS = '1.3.6.1.2.1.2.2.1.19'
IF_OUT_ERRORS = '1.3.6.1.2.1.2.2.1.20'
ERROR_WALK_ROOTS = (IF_IN_DISCARDS, IF_IN_ERRORS, IF_OUT_DISCARDS, IF_OUT_ERRORS)
MAX_32 = 2**32 - 1


@dataclass(frozen=True)
class ErrorCounters:
    index: int
    in_errors: int | None = None
    out_errors: int | None = None
    in_discards: int | None = None
    out_discards: int | None = None


@dataclass(frozen=True)
class ErrorDelta:
    switch_ip: str
    index: int
    name: str
    seconds: float
    in_errors: int | None
    out_errors: int | None
    in_discards: int | None
    out_discards: int | None


def _parse_unsigned(value) -> int | None:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or len(value) > 10:
        return None
    number = int(value)
    return number if 0 <= number <= MAX_32 else None


def parse_error_counters(values: Mapping[str, str], limit: int = 500) -> dict[int, ErrorCounters]:
    columns: dict[str, dict[int, int]] = {}
    for key, root in [('in_discards', IF_IN_DISCARDS), ('in_errors', IF_IN_ERRORS),
                      ('out_discards', IF_OUT_DISCARDS), ('out_errors', IF_OUT_ERRORS)]:
        vals: dict[int, int] = {}
        for oid, val in values.items():
            if not oid.startswith(root + '.'):
                continue
            tail = oid[len(root)+1:]
            if not tail.isascii() or not tail.isdecimal() or len(tail) > 10:
                continue
            idx = int(tail)
            num = _parse_unsigned(val)
            if 1 <= idx <= 2147483647 and num is not None:
                vals[idx] = num
        columns[key] = vals
    result = {}
    ids = sorted(set().union(*(col.keys() for col in columns.values())))
    for idx in ids[:max(0, min(limit, 500))]:
        result[idx] = ErrorCounters(idx, **{key: col.get(idx) for key, col in columns.items()})
    return result


def _delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None or after < before:
        return None
    return after - before


def calculate_error_deltas(switch_ip: str, previous: Mapping[int, ErrorCounters],
                           current: Mapping[int, ErrorCounters], seconds: float,
                           names: Mapping[int, str] | None = None) -> tuple[ErrorDelta, ...]:
    if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or not 1 <= seconds <= 3600:
        return ()
    result = []
    for idx in sorted(previous.keys() & current.keys())[:500]:
        a, b = previous[idx], current[idx]
        values = tuple(_delta(getattr(a, field), getattr(b, field)) for field in
                       ('in_errors', 'out_errors', 'in_discards', 'out_discards'))
        if all(v is None for v in values):
            continue
        name = (names or {}).get(idx, f'ifIndex {idx}')
        result.append(ErrorDelta(switch_ip, idx, str(name)[:100], round(seconds, 1), *values))
    return tuple(result)
