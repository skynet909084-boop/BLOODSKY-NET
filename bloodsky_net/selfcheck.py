"""Offline packaged-app startup check. No networking, settings or user data touched."""
from __future__ import annotations

import importlib
from pathlib import Path
import sqlite3
import tempfile


def run_self_check() -> bool:
    """Verify the bundled runtime and local database using an isolated temp folder.

    This is a packaging smoke test, not a test of the GUI or the real network.
    """
    for dependency in ("psutil", "pysnmp", "Cryptodome", "pystray", "PIL", "winotify"):
        importlib.import_module(dependency)
    from .storage import Storage

    with tempfile.TemporaryDirectory(prefix="bloodsky-net-check-") as folder:
        path = Path(folder) / "check.db"
        store = Storage(path)
        try:
            store.set_preference("monitor_enabled", False)
            store.event("info", "self-check", "temporary database")
            if store.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return False
            if len(store.events(limit=1)) != 1:
                return False
        finally:
            store.close()
        # On Windows, sqlite WAL may leave sidecars; TemporaryDirectory removes them.
        check = sqlite3.connect(path)
        try:
            if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return False
        finally:
            check.close()
    return True
