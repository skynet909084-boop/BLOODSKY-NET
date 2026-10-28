"""Deterministic in-memory stress; no LAN traffic and no hardware certification."""
from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bloodsky_net.probe_quality import TransferAttempt, summarize
from bloodsky_net.probe_stability import patterns, report

now=datetime(2026,10,28,12,0,tzinfo=timezone.utc)
rows=[]
for n in range(32):
    for j in range(64):
        rows.append(TransferAttempt(now-timedelta(minutes=120)+timedelta(seconds=5*j),
                                    f'sensor-{n:02d}','accepted',80+j%70))
assert len(rows)==2048
assert len(summarize(rows,now))==32
assert patterns(rows,now)==(), 'healthy observations must not produce incidents'
changed=list(rows)
for k,sec in enumerate((1210,1225,1240)):
    changed[k*32]=TransferAttempt(now-timedelta(seconds=sec),'sensor-00','network',200)
# 2048 rows bounded and no claims about unavailable hosts.
assert len(changed)==2048
assert len(patterns(changed,now)) <= 32
assert 'Нет пакетов ≠ ПК отключён' in report(changed,now)['warning']
print('PROBE STABILITY SOAK PASS: 2048 rows / 32 destinations (simulated, no real network)')
