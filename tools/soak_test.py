"""Offline bounded-load exercise: does NOT assert Windows uptime or SNMP hardware compatibility."""
from __future__ import annotations

from pathlib import Path
import tempfile
import time
import sys

# Running as `python tools/soak_test.py` must work on the Windows CI runner.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bloodsky_net.storage import Storage
from bloodsky_net.traffic import PortRate


def main():
    start = time.monotonic()
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / 'soak.db'
        store = Storage(db)
        for i in range(1000):
            store.event('info' if i % 5 else 'warning', 'soak', f'cycle {i}')
            if i % 3 == 0:
                rates = {1: PortRate(1, 'Gi1', float(i % 30), float(i % 12), 1000, True)}
                if store.save_port_rates('10.10.0.2', rates) != 1:
                    raise AssertionError('Port-rate persistence failed')
            if i % 5 == 0:
                store.save_wifi_sample(True, 'TestWifi', 'aa:bb:cc:dd:ee:ff', i % 101, 6)
        if len(store.events(100)) != 100:
            raise AssertionError('Event history failed')
        if len(store.port_history('10.10.0.2', 1, 720)) != 334:
            raise AssertionError('Port history sample count mismatch')
        if len(store.wifi_signal_history(300)) != 200:
            raise AssertionError('Wi-Fi history sample count mismatch')
        store.close()
        reopened = Storage(db)
        if not reopened.port_history('10.10.0.2', 1):
            raise AssertionError('Port history lost across reopen')
        integrity = reopened.db.execute('PRAGMA quick_check').fetchone()[0]
        reopened.close()
        if integrity != 'ok':
            raise AssertionError('SQLite integrity: ' + str(integrity))
    print(f'Offline SQLite bounded-load passed: 1000 events, 334 port and 200 Wi-Fi samples; elapsed {time.monotonic()-start:.2f}s')


if __name__ == '__main__':
    main()
