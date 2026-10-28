"""Minimal offline probe transport hardening smoke, not real-PC acceptance."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bloodsky_net import probe_transport as tr


def main():
    assert tr.MAX_REPLAY_IDS >= 512
    assert 0 < tr.MAX_CONCURRENT_CLIENTS <= 64
    assert 0 < tr.CONNECTION_TIMEOUT_SECONDS <= 30
    assert tr.REPLAY_TTL_SECONDS > tr.SESSION_AGE_SECONDS
    print('Probe TLS bounds OK; real-PC hardware acceptance NOT verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
