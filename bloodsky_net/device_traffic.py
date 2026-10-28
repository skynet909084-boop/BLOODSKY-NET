"""Port-based SNMP/FDB usage. Not exact host or whole-LAN traffic."""
from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
from math import isfinite
from typing import Mapping, Sequence
from .network import normalize_mac
from .topology import TopologySnapshot
from .traffic import PortRate

@dataclass(frozen=True)
class Usage:
    ip: str
    label: str
    switch_ip: str
    port: str
    download_mbps: float
    upload_mbps: float

    @property
    def mbps(self) -> float:
        return round(self.download_mbps + self.upload_mbps, 3)

def measured_usage(devices: Sequence, snapshots: Mapping[str, TopologySnapshot],
                   rates: Mapping[str, Mapping[int, PortRate]]) -> tuple[Usage, ...]:
    """Only fresh snapshots passed by caller; exclude shared/uplink/ambiguous ports."""
    by_mac = defaultdict(list)
    for d in devices:
        mac = normalize_mac(getattr(d, 'mac', '') or '')
        if mac and not (int(mac[:2], 16) & 3):
            by_mac[mac].append(d)
    port_macs = defaultdict(set)
    mac_locations = defaultdict(set)
    forbidden_ports = set()
    for switch, snap in snapshots.items():
        names = {n.local_port.casefold().strip() for n in snap.neighbors}
        for index, counter in snap.port_counters.items():
            if counter.name.casefold().strip() in names:
                forbidden_ports.add((switch, index))
        for row in snap.fdb_entries:
            mac = normalize_mac(row.mac)
            if mac and row.if_index is not None:
                port_macs[(switch, row.if_index)].add(mac)
                mac_locations[mac].add((switch, row.if_index))
    result = []
    for (switch, index), macs in sorted(port_macs.items()):
        if len(macs) != 1 or (switch, index) in forbidden_ports:
            continue
        mac = next(iter(macs))
        if len(mac_locations[mac]) != 1 or len(by_mac.get(mac, ())) != 1:
            continue
        rate = rates.get(switch, {}).get(index)
        if rate is None or rate.oper_up is not True:
            continue
        rx, tx = rate.inbound_mbps, rate.outbound_mbps
        if (rx is None or tx is None or not isfinite(rx) or not isfinite(tx)
                or rx < 0 or tx < 0 or rx > 1_000_000 or tx > 1_000_000):
            continue
        if rate.speed_mbps and max(rx, tx) > rate.speed_mbps * 1.1:
            continue
        device = by_mac[mac][0]
        label = getattr(device, 'user_label', '') or getattr(device, 'friendly_name', '') or getattr(device, 'hostname', '') or device.ip
        result.append(Usage(device.ip, str(label)[:72], switch, rate.name[:90], round(tx, 3), round(rx, 3)))
    return tuple(sorted(result, key=lambda d: (-d.mbps, d.ip))[:64])
