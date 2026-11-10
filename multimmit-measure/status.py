#!/usr/bin/env python3
"""Progress state and live page for the Multimmit paper re-measurement.

The driver calls this after every state change; each call rewrites plan.html atomically.

  status.py init                                  create progress.json with every run pending
  status.py build                                 rebuild plan.html only
  status.py state <not-started|running|paused|done> [--note TEXT]
  status.py testbed <global|na> [--state S] [--cluster C]
  status.py phase <testbed> <run_id> <phase> [--attempt N] [--seconds S] [--extensions K]
  status.py idle <testbed>                        no run in progress on the testbed
  status.py run <run_id> <status> [--attempts N] [--p50 MS] [--p99 MS] [--tps X] [--reason TEXT]
  status.py event <testbed|all> <info|warn|error> <text>
"""
import json, os, sys, time, argparse, tempfile, fcntl, contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
PROGRESS = os.path.join(HERE, "progress.json")
PAGE = os.path.join(os.path.dirname(HERE), "plan.html")

TESTBEDS = ["global", "na"]
RATES = ["50k", "100k", "250k", "500k", "1M"]
MAIN = ["healthy", "crash1", "crash9", "loss0.1"]
CENSOR = ["censor1-e8", "censor1-e0", "censor9-e8", "censor9-e0"]
STATUSES = ["pending", "running", "retry", "accepted", "failed", "unstable", "saturated", "skipped"]
PHASES = ["preflight", "configure", "warm-up", "gate", "extension", "cohort", "drain", "collect", "record"]

def runs():
    """Every run in execution order, per testbed: the hardest first, so a problem shows before cheap
    points are spent. First the 1M point of every scenario, then censorship at 500k, the 500k
    points, fsync on, 250k, 100k, censorship at 100k, and 50k."""
    def group(r):
        if r["mode"] == "base-fsync":
            return 3
        if r["scen"].startswith("censor"):
            return 1 if r["rate"] == "500k" else 6
        return {"1M": 0, "500k": 2, "250k": 4, "100k": 5, "50k": 7}[r["rate"]]
    listed = listing()
    return sorted(listed, key=lambda r: (r["tb"] != "global", group(r), listed.index(r)))


def listing():
    """Every run, testbed by testbed: the base and payment sweeps, censorship, then fsync."""
    out = []
    for tb in TESTBEDS:
        for mode in ["base", "payments"]:
            for scen in MAIN:
                for rate in RATES:
                    out.append(dict(id=f"{tb}.{mode}.{scen}.{rate}", tb=tb, mode=mode, scen=scen, rate=rate))
        for scen in CENSOR:
            for rate in ["100k", "500k"]:
                out.append(dict(id=f"{tb}.base.{scen}.{rate}", tb=tb, mode="base", scen=scen, rate=rate))
        out.append(dict(id=f"{tb}.base-fsync.healthy.500k", tb=tb, mode="base-fsync", scen="healthy", rate="500k"))
    return out

RUN_IDS = {r["id"] for r in runs()}

def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def fresh():
    return {
        "schema": 1, "updated_at": now(), "state": "not-started", "note": "",
        "testbeds": {tb: {"state": "idle", "cluster": "not created", "current": None} for tb in TESTBEDS},
        "runs": {r["id"]: {"status": "pending", "attempts": 0} for r in runs()},
        "events": [],
    }

def load():
    if not os.path.exists(PROGRESS):
        return fresh()
    with open(PROGRESS) as f:
        return json.load(f)

def write_atomic(path, data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)

@contextlib.contextmanager
def locked():
    """Serializes read-modify-write cycles across the per-testbed drivers."""
    with open(PROGRESS + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

def update(fn):
    """Applies fn to the progress state under the lock, then saves and rebuilds the page."""
    with locked():
        p = load()
        fn(p)
        save(p)

def network_notes(p):
    """{run_id: {node: share}} for accepted runs whose result records nodes retransmitting above 2%
    through the cohort."""
    out = {}
    for rid, r in p["runs"].items():
        if r.get("status") != "accepted" or not r.get("attempts"):
            continue
        f = os.path.join(os.path.dirname(HERE), "runs", rid, f"attempt-{r['attempts']}", "result.json")
        try:
            sick = (json.load(open(f)).get("network") or {}).get("sustained")
        except (OSError, ValueError):
            continue
        if sick:
            out[rid] = sick
    return out

def build(p):
    read = lambda name: open(os.path.join(SRC, name)).read()
    p = dict(p, network_notes=network_notes(p))
    head = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '<meta http-equiv="refresh" content="30">\n'
            '<title>Multimmit paper re-measurement</title>\n<style>' + read("plan_css.css") + '</style>\n</head>\n<body>\n')
    js = (read("plan_js.html").replace("__MAP__", read("map.json"))
          .replace("__PROGRESS__", json.dumps(p)).replace("__RUNS__", json.dumps(runs())))
    write_atomic(PAGE, head + read("plan_body.html") + js)

def save(p):
    p["updated_at"] = now()
    write_atomic(PROGRESS, json.dumps(p, indent=1))
    build(p)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init"); sub.add_parser("build")
    s = sub.add_parser("state"); s.add_argument("state", choices=["not-started", "running", "paused", "done"]); s.add_argument("--note")
    s = sub.add_parser("testbed"); s.add_argument("tb", choices=TESTBEDS); s.add_argument("--state"); s.add_argument("--cluster")
    s = sub.add_parser("phase"); s.add_argument("tb", choices=TESTBEDS); s.add_argument("run_id"); s.add_argument("phase", choices=PHASES)
    s.add_argument("--attempt", type=int, default=1); s.add_argument("--seconds", type=int, help="planned length of the phase"); s.add_argument("--extensions", type=int, default=0)
    s = sub.add_parser("idle"); s.add_argument("tb", choices=TESTBEDS)
    s = sub.add_parser("run"); s.add_argument("run_id"); s.add_argument("status", choices=STATUSES)
    s.add_argument("--attempts", type=int); s.add_argument("--p50", type=float); s.add_argument("--p99", type=float); s.add_argument("--tps", type=float); s.add_argument("--reason")
    s = sub.add_parser("event"); s.add_argument("tb", choices=TESTBEDS + ["all"]); s.add_argument("level", choices=["info", "warn", "error"]); s.add_argument("text")
    a = ap.parse_args()

    if a.cmd == "init":
        if os.path.exists(PROGRESS):
            sys.exit("progress.json exists; refusing to reset it")
        save(fresh()); return
    with locked():
        p = load()
        if a.cmd == "build":
            build(p); return
        apply(a, p)
        save(p)

def apply(a, p):
    if a.cmd == "state":
        p["state"] = a.state
        if a.note is not None: p["note"] = a.note
    elif a.cmd == "testbed":
        if a.state: p["testbeds"][a.tb]["state"] = a.state
        if a.cluster: p["testbeds"][a.tb]["cluster"] = a.cluster
    elif a.cmd == "phase":
        if a.run_id not in RUN_IDS: sys.exit(f"unknown run {a.run_id}")
        cur = p["testbeds"][a.tb].get("current") or {}
        started = cur.get("run_started_at") if cur.get("run_id") == a.run_id and cur.get("attempt") == a.attempt else now()
        p["testbeds"][a.tb]["current"] = dict(run_id=a.run_id, attempt=a.attempt, phase=a.phase, phase_started_at=now(),
                                              phase_seconds=a.seconds, extensions=a.extensions, run_started_at=started)
        p["testbeds"][a.tb]["state"] = "running"
        r = p["runs"][a.run_id]; r["status"] = "running"; r["attempts"] = max(r.get("attempts", 0), a.attempt)
    elif a.cmd == "idle":
        p["testbeds"][a.tb]["current"] = None
    elif a.cmd == "run":
        if a.run_id not in RUN_IDS: sys.exit(f"unknown run {a.run_id}")
        r = p["runs"][a.run_id]; r["status"] = a.status; r["finished_at" if a.status not in ("pending", "running", "retry") else "queued_at"] = now()
        for k, v in [("attempts", a.attempts), ("placement_p50_ms", a.p50), ("placement_p99_ms", a.p99), ("achieved_tps", a.tps), ("reason", a.reason)]:
            if v is not None: r[k] = v
    elif a.cmd == "event":
        p["events"].append(dict(at=now(), tb=a.tb, level=a.level, text=a.text))
        p["events"] = p["events"][-500:]

if __name__ == "__main__":
    main()
