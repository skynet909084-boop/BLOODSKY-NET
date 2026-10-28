"""Local SQLite inventory and event history. No cloud transmission."""
from __future__ import annotations
import csv
import json
import os
from pathlib import Path
import sqlite3
import ipaddress
import math
from .network import Device, now_iso


def storage_root() -> Path:
    base = os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.environ.get("XDG_DATA_HOME")
    path = Path(base) if base else Path.home() / ".local" / "share"
    result = path / "BLOODSKY-NET"
    result.mkdir(parents=True, exist_ok=True)
    return result


EVENT_RETENTION_DAYS = 14
EVENT_MAX_ROWS = 25000


class Storage:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else storage_root() / "network.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS preferences (key TEXT PRIMARY KEY, value INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        self.db.execute("CREATE TABLE IF NOT EXISTS wifi_samples (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, connected INTEGER NOT NULL, ssid TEXT NOT NULL, bssid TEXT NOT NULL, signal INTEGER NOT NULL, channel INTEGER NOT NULL)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS port_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                switch_ip TEXT NOT NULL,
                if_index INTEGER NOT NULL,
                if_name TEXT NOT NULL,
                inbound_mbps REAL NOT NULL,
                outbound_mbps REAL NOT NULL)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_port_traffic_device ON port_traffic(switch_ip, if_index, id)")
        self.db.commit()
        self._wifi_writes = 0
        self._port_writes = 0
        self._event_writes = 0

    # Only harmless UI booleans are persisted. Never store SNMP credentials here.
    PREFERENCE_KEYS = frozenset({"monitor_enabled", "alerts_enabled", "windows_alerts_enabled", "minimize_to_tray"})

    def get_preference(self, name: str, default: bool = False) -> bool:
        if name not in self.PREFERENCE_KEYS:
            raise ValueError("Unknown preference")
        row = self.db.execute("SELECT value FROM preferences WHERE key=?", (name,)).fetchone()
        return bool(row[0]) if row else bool(default)

    def set_preference(self, name: str, value: bool) -> None:
        if name not in self.PREFERENCE_KEYS or type(value) is not bool:
            raise ValueError("Only safe boolean preferences may be saved")
        self.db.execute("INSERT INTO preferences(key,value) VALUES (?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (name, int(value)))
        self.db.commit()

    def save_device(self, device: Device):
        self.db.execute("INSERT INTO devices(ip, payload) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET payload=excluded.payload",
                        (device.ip, json.dumps(device.to_dict(), ensure_ascii=False)))
        self.db.commit()

    def load_devices(self) -> dict[str, Device]:
        result = {}
        for ip, payload in self.db.execute("SELECT ip, payload FROM devices"):
            try:
                device = Device.from_dict(json.loads(payload))
                device.online = False  # saved connectivity is not a current observation
                device.failures = 0
                device.latency_ms = None
                result[ip] = device
            except (TypeError, ValueError, KeyError):
                continue
        return result

    def event(self, severity: str, title: str, detail: str):
        """Bound 24/7 event history on disk; pruning does not affect live alerts."""
        self.db.execute("INSERT INTO events(ts, severity, title, detail) VALUES (?, ?, ?, ?)",
                        (now_iso(), severity, title, detail))
        self._event_writes += 1
        if self._event_writes % 100 == 0:
            self.db.execute("DELETE FROM events WHERE datetime(ts) < datetime('now', ?)",
                            (f'-{EVENT_RETENTION_DAYS} days',))
            self.db.execute("DELETE FROM events WHERE id NOT IN "
                            "(SELECT id FROM events ORDER BY id DESC LIMIT ?)", (EVENT_MAX_ROWS,))
        self.db.commit()

    def events(self, limit: int = 300):
        return self.db.execute("SELECT ts, severity, title, detail FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def export_csv(self, filename: str, devices: list[Device]):
        with open(filename, "w", newline="", encoding="utf-8-sig") as fd:
            writer = csv.DictWriter(fd, fieldnames=list(Device.__dataclass_fields__.keys()))
            writer.writeheader()
            for dev in sorted(devices, key=lambda d: tuple(int(a) for a in d.ip.split("."))):
                writer.writerow(dev.to_dict())

    def export_json(self, filename: str, devices: list[Device], network: str, gateway: str, wifi: dict):
        snapshot = {"app": "BLOODSKY NET", "exported_at": now_iso(), "network": network,
                    "gateway": gateway, "devices": [d.to_dict() for d in devices],
                    "wifi": wifi, "events": self.events(100)}
        with open(filename, "w", encoding="utf-8") as fd:
            json.dump(snapshot, fd, indent=2, ensure_ascii=False)

    def save_wifi_sample(self, connected: bool, ssid: str, bssid: str, signal: int, channel: int):
        """Local samples; discard old rows periodically to bound disk usage."""
        self.db.execute("INSERT INTO wifi_samples(ts, connected, ssid, bssid, signal, channel) VALUES (?, ?, ?, ?, ?, ?)",
                        (now_iso(), int(connected), ssid[:128], bssid[:32], max(0, min(100, int(signal))), int(channel)))
        self._wifi_writes += 1
        if self._wifi_writes % 60 == 0:
            self.db.execute("DELETE FROM wifi_samples WHERE datetime(ts) < datetime('now', '-7 days')")
            self.db.execute("DELETE FROM wifi_samples WHERE id NOT IN (SELECT id FROM wifi_samples ORDER BY id DESC LIMIT 20160)")
        self.db.commit()

    def wifi_signal_history(self, limit: int = 100) -> list[float | None]:
        count = max(1, min(int(limit), 1000))
        rows = self.db.execute("SELECT connected, signal FROM wifi_samples ORDER BY id DESC LIMIT ?", (count,)).fetchall()
        return [float(signal) if connected else None for connected, signal in reversed(rows)]

    def save_port_rates(self, switch_ip: str, rates, ts: str | None = None) -> int:
        """Persist bounded, measured port speeds only (no SNMP credentials).

        Missing/invalid measurements must never be interpreted as 0 Mbps.
        A single snapshot is capped at 256 interfaces, history at 100000 rows
        and seven days (pruned on each 10th non-empty polling cycle).
        """
        try:
            address = ipaddress.ip_address(switch_ip)
            if not isinstance(address, ipaddress.IPv4Address) or not address.is_private:
                return 0
        except ValueError:
            return 0
        entries = []
        for idx, rate in sorted(rates.items())[:256]:
            received, sent = rate.inbound_mbps, rate.outbound_mbps
            if (not isinstance(idx, int) or idx < 1 or idx > 2147483647 or
                    received is None or sent is None or
                    not all(isinstance(v, (float, int)) and math.isfinite(v) and 0 <= v <= 1e7
                            for v in (received, sent))):
                continue
            entries.append((ts or now_iso(), switch_ip, idx, str(rate.name)[:100],
                            float(received), float(sent)))
        if not entries:
            return 0
        self.db.executemany("INSERT INTO port_traffic(ts, switch_ip, if_index, if_name, inbound_mbps, outbound_mbps) "
                            "VALUES (?, ?, ?, ?, ?, ?)", entries)
        self._port_writes += 1
        if self._port_writes % 10 == 0:
            self.db.execute("DELETE FROM port_traffic WHERE datetime(ts) < datetime('now', '-7 days')")
            self.db.execute("DELETE FROM port_traffic WHERE id NOT IN "
                            "(SELECT id FROM port_traffic ORDER BY id DESC LIMIT 100000)")
        self.db.commit()
        return len(entries)

    def port_history(self, switch_ip: str, if_index: int, limit: int = 120):
        """Chronological samples for a known device/interface only."""
        if not 1 <= int(if_index) <= 2147483647:
            return []
        length = max(1, min(int(limit), 720))
        rows = self.db.execute(
            "SELECT ts, inbound_mbps, outbound_mbps FROM port_traffic "
            "WHERE switch_ip = ? AND if_index = ? ORDER BY id DESC LIMIT ?",
            (switch_ip, if_index, length)).fetchall()
        return list(reversed(rows))

    def close(self):
        self.db.close()
