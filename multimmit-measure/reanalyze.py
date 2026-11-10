#!/usr/bin/env python3
"""Re-analyses every archived attempt of a testbed with the current analyze.py.

The driver's original result is kept as result.driver.json (once); result.json is rewritten.
Prints any attempt whose verdict or headline latency changed.
"""
import json, shutil, subprocess, sys
from pathlib import Path

AR = Path(__file__).resolve().parent.parent
tb = sys.argv[1]
changed, n = [], 0
for a in sorted((AR / "runs").glob(f"{tb}.*/attempt-*")):
    res = a / "result.json"
    if not res.exists():
        continue
    orig = a / "result.driver.json"
    if not orig.exists():
        shutil.copy2(res, orig)
    before = json.load(open(orig))
    r = subprocess.run([sys.executable, str(AR / "tools" / "analyze.py"), str(a)], capture_output=True, text=True)
    if r.returncode != 0:
        changed.append((str(a), "analyze failed", r.stderr[-300:]))
        continue
    after = json.load(open(res))
    n += 1
    keys = ("verdict", "placement_p50_ms", "placement_p99_ms", "achieved_tps")
    if any(before.get(k) != after.get(k) for k in keys):
        changed.append((a.parent.name + "/" + a.name, {k: (before.get(k), after.get(k)) for k in keys}))
print(f"{n} attempts re-analysed; {len(changed)} changed")
for c in changed:
    print(" ", c)
