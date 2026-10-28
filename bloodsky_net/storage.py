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
SNAPSHOT_RETENTION_DAYS = 7
SNAPSHOT_MAX_ROWS = 2016
SNAPSHOT_MAX_DEVICES = 512
LLDP_CAPTURE_MAX_ROWS = 2016
LLDP_RETENTION_DAYS = 7


class Storage:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else storage_root() / "network.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS preferences (key TEXT PRIMARY KEY, value INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS wifi_survey (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, zone TEXT NOT NULL,
            x REAL NOT NULL, y REAL NOT NULL, ssid TEXT NOT NULL, bssid TEXT NOT NULL,
            signal INTEGER NOT NULL, channel INTEGER NOT NULL)""")
        if 'room' not in {r[1] for r in self.db.execute('PRAGMA table_info(wifi_survey)')}:
            self.db.execute("ALTER TABLE wifi_survey ADD COLUMN room TEXT NOT NULL DEFAULT 'Без комнаты'")
        if 'phase' not in {r[1] for r in self.db.execute('PRAGMA table_info(wifi_survey)')}:
            self.db.execute("ALTER TABLE wifi_survey ADD COLUMN phase TEXT NOT NULL DEFAULT 'Без этапа'")
        self.db.execute("""CREATE TABLE IF NOT EXISTS wifi_floorplans (
            zone TEXT PRIMARY KEY, image BLOB NOT NULL, width INTEGER NOT NULL, height INTEGER NOT NULL)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_wifi_survey_ts ON wifi_survey(ts)")
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
        self.db.execute("CREATE TABLE IF NOT EXISTS map_positions (ip TEXT PRIMARY KEY, x REAL NOT NULL, y REAL NOT NULL)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS network_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                scope TEXT NOT NULL,
                source TEXT NOT NULL,
                device_count INTEGER NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS snapshot_devices (
                snapshot_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                state TEXT NOT NULL,
                mac TEXT NOT NULL,
                hostname TEXT NOT NULL,
                kind TEXT NOT NULL,
                vendor TEXT NOT NULL,
                PRIMARY KEY(snapshot_id, ip),
                FOREIGN KEY(snapshot_id) REFERENCES network_snapshots(id) ON DELETE CASCADE)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS lldp_captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
                source_ip TEXT NOT NULL, system_name TEXT NOT NULL, neighbor_count INTEGER NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS lldp_observations (
                capture_id INTEGER NOT NULL, local_port_num INTEGER NOT NULL,
                local_port TEXT NOT NULL, remote_chassis TEXT NOT NULL,
                remote_port TEXT NOT NULL, remote_name TEXT NOT NULL,
                FOREIGN KEY(capture_id) REFERENCES lldp_captures(id) ON DELETE CASCADE)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_lldp_captures_ip ON lldp_captures(source_ip, id)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_network_snapshots_ts ON network_snapshots(ts)")
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

    def save_wifi_survey_point(self, zone: str, x: float, y: float, ssid: str,
                               bssid: str, signal: int, channel: int,
                               ts: str | None = None, room: str = 'Без комнаты', phase: str = 'Без этапа'):
        """Save an explicit manual survey; never read or persist WLAN credentials."""
        from .wifi_survey import validate_point, MAX_POINTS
        point = validate_point(zone, x, y, ssid, bssid, signal, channel, ts or now_iso(), room=room, phase=phase)
        with self.db:
            self.db.execute("""INSERT INTO wifi_survey
                (ts, zone, x, y, ssid, bssid, signal, channel, room, phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (point.observed_at, point.zone, point.x, point.y, point.ssid,
                 point.bssid, point.signal, point.channel, point.room, point.phase))
            self.db.execute("DELETE FROM wifi_survey WHERE datetime(ts) < datetime('now', '-30 days')")
            self.db.execute("DELETE FROM wifi_survey WHERE id NOT IN (SELECT id FROM wifi_survey ORDER BY id DESC LIMIT ?)",
                            (MAX_POINTS,))
        return point

    def wifi_survey_points(self, zone: str | None = None):
        """Bounded, chronological survey records; only manually captured points."""
        from .wifi_survey import SurveyPoint, MAX_POINTS
        if zone is None:
            rows = self.db.execute("""SELECT ts, zone, x, y, ssid, bssid, signal, channel, room, phase
                                    FROM wifi_survey ORDER BY id DESC LIMIT ?""", (MAX_POINTS,)).fetchall()
        else:
            rows = self.db.execute("""SELECT ts, zone, x, y, ssid, bssid, signal, channel, room, phase
                                    FROM wifi_survey WHERE zone=? ORDER BY id DESC LIMIT ?""",
                                   (zone, MAX_POINTS)).fetchall()
        return tuple(SurveyPoint(*r) for r in reversed(rows))

    def save_wifi_floorplan(self, zone: str, source: bytes):
        """Explicit local image import; bounded and sanitized before SQLite commit."""
        from .wifi_survey import MAX_ZONES
        from .wifi_floorplan import sanitize_floorplan
        if not isinstance(zone, str) or not zone.strip() or len(zone.strip()) > 60 or any(ord(c) < 32 for c in zone):
            raise ValueError('Недопустимое название этажа/зоны')
        plan = sanitize_floorplan(source)
        with self.db:
            count = self.db.execute('SELECT COUNT(*) FROM wifi_floorplans').fetchone()[0]
            exists = self.db.execute('SELECT 1 FROM wifi_floorplans WHERE zone=?', (zone.strip(),)).fetchone()
            if not exists and count >= min(MAX_ZONES, 12):
                raise ValueError('Достигнут лимит: 12 планов помещений')
            self.db.execute('INSERT OR REPLACE INTO wifi_floorplans(zone,image,width,height) VALUES (?,?,?,?)',
                            (zone.strip(), plan.jpeg, plan.width, plan.height))
        return plan

    def wifi_floorplan(self, zone: str):
        from .wifi_floorplan import Floorplan, MAX_STORED_BYTES
        row = self.db.execute('SELECT image,width,height FROM wifi_floorplans WHERE zone=?',
                              (zone.strip(),)).fetchone()
        if not row:
            return None
        blob, width, height = row
        if not blob or len(blob) > MAX_STORED_BYTES or width <= 0 or height <= 0:
            return None
        return Floorplan(bytes(blob), int(width), int(height))

    def delete_wifi_floorplan(self, zone: str):
        with self.db:
            self.db.execute('DELETE FROM wifi_floorplans WHERE zone=?', (zone.strip(),))

    def wifi_radar_rows(self, limit: int = 20160) -> list[tuple]:
        """Historical Windows WLAN measurements. No scan, no credentials.

        Samples carry local time offsets; date comparisons are done in the
        pure radar engine, not with SQLite's text comparison.
        """
        n = max(1, min(20160, int(limit)))
        rows = self.db.execute(
            "SELECT ts, connected, ssid, bssid, signal, channel "
            "FROM wifi_samples ORDER BY id DESC LIMIT ?", (n,)).fetchall()
        return list(reversed(rows))

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

    def map_positions(self) -> dict[str, tuple[float, float]]:
        """Only user-arranged map coordinates; never credentials or inferred links."""
        from .map_view import valid_position
        result = {}
        for ip, x, y in self.db.execute("SELECT ip, x, y FROM map_positions"):
            try:
                ipaddress.IPv4Address(ip)
                if valid_position(x, y):
                    result[ip] = (x, y)
            except ValueError:
                continue
        return result

    def save_map_position(self, ip: str, x: float, y: float):
        from .map_view import valid_position
        ipaddress.IPv4Address(ip)
        if not valid_position(x, y):
            raise ValueError("Invalid map position")
        self.db.execute("INSERT INTO map_positions(ip,x,y) VALUES(?,?,?) "
                        "ON CONFLICT(ip) DO UPDATE SET x=excluded.x, y=excluded.y", (ip, float(x), float(y)))
        self.db.commit()

    def clear_map_positions(self):
        self.db.execute("DELETE FROM map_positions")
        self.db.commit()


    def save_network_snapshot(self, devices, states=None, scope: str = '',
                              source: str = 'manual', ts: str | None = None) -> int:
        """One atomic bounded inventory snapshot; only whitelisted safe columns.

        'unknown' means not measured recently, not offline. No SNMP credentials,
        port counters or unverified physical links are written here.
        """
        from datetime import datetime
        from .time_machine import as_snapshot_device
        if source not in ('manual', 'monitor', 'scan'):
            raise ValueError('Invalid snapshot source')
        if scope:
            scope = str(ipaddress.IPv4Network(scope, strict=False))
        if ts is not None:
            parsed = datetime.fromisoformat(ts)
            if parsed.tzinfo is None:
                raise ValueError('Timestamp must include timezone')
        observed = states or {}
        prepared = {}
        for d in devices:
            row = as_snapshot_device(d, observed.get(d.ip, 'unknown'))
            prepared[row.ip] = row
            if len(prepared) > SNAPSHOT_MAX_DEVICES:
                raise ValueError('Too many devices in one snapshot')
        stamp = ts or now_iso()
        with self.db:
            cur = self.db.execute(
                'INSERT INTO network_snapshots(ts,scope,source,device_count) VALUES (?,?,?,?)',
                (stamp, scope, source, len(prepared)))
            ident = cur.lastrowid
            self.db.executemany(
                'INSERT INTO snapshot_devices(snapshot_id,ip,state,mac,hostname,kind,vendor) VALUES (?,?,?,?,?,?,?)',
                [(ident, row.ip, row.state, row.mac, row.hostname, row.kind, row.vendor)
                 for row in prepared.values()])
            self.db.execute("DELETE FROM network_snapshots WHERE datetime(ts) < datetime('now', ?)",
                            (f'-{SNAPSHOT_RETENTION_DAYS} days',))
            self.db.execute('DELETE FROM network_snapshots WHERE id NOT IN '
                            '(SELECT id FROM network_snapshots ORDER BY id DESC LIMIT ?)',
                            (SNAPSHOT_MAX_ROWS,))
        return ident

    def network_snapshots(self, limit: int = 100):
        limit = max(1, min(int(limit), 500))
        return self.db.execute(
            'SELECT id,ts,scope,source,device_count FROM network_snapshots ORDER BY id DESC LIMIT ?',
            (limit,)).fetchall()

    def network_snapshot_devices(self, snapshot_id: int):
        from .time_machine import SnapshotDevice
        result = {}
        for row in self.db.execute(
            'SELECT ip,state,mac,hostname,kind,vendor FROM snapshot_devices '
            'WHERE snapshot_id=? ORDER BY ip', (int(snapshot_id),)):
            d = SnapshotDevice(*row)
            result[d.ip] = d
        return result

    def compare_network_snapshots(self, before_id: int, after_id: int):
        from .time_machine import diff
        known = {row[0] for row in self.db.execute(
            'SELECT id FROM network_snapshots WHERE id IN (?,?)', (int(before_id), int(after_id)))}
        if known != {int(before_id), int(after_id)} or before_id == after_id:
            raise ValueError('Select two different existing snapshots')
        return diff(self.network_snapshot_devices(before_id),
                    self.network_snapshot_devices(after_id))

    def save_lldp_capture(self, snapshot, ts: str | None = None) -> int:
        """Store only successful SNMP/LLDP observations, atomically.

        Caller must not invoke this on transport errors or incomplete polling.
        A successful empty neighbor table is a valid, empty observation.
        """
        from datetime import datetime
        from .topology_history import observations
        address = ipaddress.IPv4Address(snapshot.source_ip)
        if not address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError('Local private SNMP IPv4 required')
        if ts is not None:
            parsed = datetime.fromisoformat(ts)
            if parsed.tzinfo is None:
                raise ValueError('LLDP timestamp must have timezone')
        rows = observations(snapshot)
        stamp = ts or now_iso()
        with self.db:
            cur = self.db.execute(
                'INSERT INTO lldp_captures(ts,source_ip,system_name,neighbor_count) VALUES(?,?,?,?)',
                (stamp, str(address), str(snapshot.system_name)[:120], len(rows)))
            ident = cur.lastrowid
            self.db.executemany(
                'INSERT INTO lldp_observations(capture_id,local_port_num,local_port,remote_chassis,remote_port,remote_name) '
                'VALUES(?,?,?,?,?,?)', [(ident, row.local_port_num, row.local_port, row.remote_chassis,
                                          row.remote_port, row.remote_name) for row in rows])
            self.db.execute("DELETE FROM lldp_captures WHERE datetime(ts) < datetime('now', ?)",
                            (f'-{LLDP_RETENTION_DAYS} days',))
            self.db.execute('DELETE FROM lldp_captures WHERE id NOT IN '
                            '(SELECT id FROM lldp_captures ORDER BY id DESC LIMIT ?)',
                            (LLDP_CAPTURE_MAX_ROWS,))
        return ident

    def lldp_captures(self, limit: int = 120):
        n = max(1, min(int(limit), 500))
        return self.db.execute('SELECT id,ts,source_ip,system_name,neighbor_count FROM lldp_captures '
                               'ORDER BY id DESC LIMIT ?', (n,)).fetchall()

    def lldp_capture_neighbors(self, capture_id: int):
        from .topology_history import LinkObservation
        row = self.db.execute('SELECT source_ip FROM lldp_captures WHERE id=?', (int(capture_id),)).fetchone()
        if row is None:
            return []
        return [LinkObservation(row[0], *values) for values in self.db.execute(
            'SELECT local_port_num,local_port,remote_chassis,remote_port,remote_name '
            'FROM lldp_observations WHERE capture_id=? ORDER BY local_port_num,remote_chassis,remote_name',
            (int(capture_id),))]

    def compare_lldp_captures(self, before_id: int, after_id: int):
        from .topology_history import compare_links
        rows = self.db.execute('SELECT id,source_ip FROM lldp_captures WHERE id IN (?,?)',
                               (int(before_id), int(after_id))).fetchall()
        if before_id == after_id or len(rows) != 2 or rows[0][1] != rows[1][1]:
            raise ValueError('Select two different LLDP captures from the same switch')
        return compare_links(self.lldp_capture_neighbors(before_id), self.lldp_capture_neighbors(after_id))

    def close(self):
        self.db.close()
