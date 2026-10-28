"""Simple, explicit UI preferences in the existing local SQLite database.

No network access, additional telemetry, saved credentials, or migrations.
Keys are a fixed whitelist separate from scanner/runtime preferences.
"""
from __future__ import annotations

UI_KEYS = frozenset(("advanced_ui", "onboarding_seen"))


def read_ui_flag(store, key: str, default: bool = False) -> bool:
    if key not in UI_KEYS or type(default) is not bool:
        raise ValueError("Недопустимая настройка интерфейса")
    row = store.db.execute("SELECT value FROM preferences WHERE key=?", (key,)).fetchone()
    return bool(row[0]) if row is not None else default


def write_ui_flag(store, key: str, value: bool) -> None:
    if key not in UI_KEYS or type(value) is not bool:
        raise ValueError("Недопустимая настройка интерфейса")
    with store.db:
        store.db.execute("INSERT INTO preferences(key, value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, int(value)))
