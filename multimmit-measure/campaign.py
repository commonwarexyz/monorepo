#!/usr/bin/env python3
"""Campaign driver for the Multimmit paper re-measurement: one process per testbed.

  campaign.py setup <testbed>      discover hosts, stage the three binaries on every node
  campaign.py run <testbed>        run the testbed's queue until done or paused (resumable)
  campaign.py stop <testbed>       stop every binary on the testbed
  campaign.py check <testbed>      preflight every node without starting anything

Every run: preflight, configure (fresh data, fresh committee seed), warm-up with a stability gate
(at most two 60 s extensions), a 120 s cohort, a drain until the cohort is placed and delivered
(at most 120 s), collection, analysis, and a verdict. See README.md for the rules.
"""
import argparse, concurrent.futures as cf, gzip, hashlib, json, math, os, re, shutil, subprocess, sys, time, traceback
import urllib.parse, urllib.request
from pathlib import Path

import yaml

AR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AR / "status"))
import status as S  # noqa: E402

# Where attempts are archived; diagnostics runs point this elsewhere.
RUNS = AR / "runs"
TX_BYTES = 512
BODY = 262144
TX_PER_BLOCK = BODY // TX_BYTES
RATES = {"50k": 50_000, "100k": 100_000, "250k": 250_000, "500k": 500_000, "1M": 1_000_000}
NODES = 50
LEAD_S = 45          # schedule start after the binaries are started
WARMUP_S = 120
EXTENSION_S = 60
MAX_EXTENSIONS = 2
COHORT_S = 120
DRAIN_MAX_S = 120
DRAIN_MIN_S = 10
LOAD_S = 500         # covers both extensions, the cohort and the full drain
# A node retransmitting more than this share of its TCP segments in a window is recorded as retransmitting.
# At 1M tx/s on the global testbed, nodes outside Europe can lose 10-30% of their segments on every path;
# runs keep those conditions and report them, and the gate judges only what the protocol delivers.
GATE_RETRANS = 0.02
# After an attempt is abandoned for its network, wait this long and try again.
NETWORK_BACKOFF_S = 120
# A network that cannot carry a rate fails every run at that rate alike. After this many network
# failures in a row at a rate, the testbed's runs at that rate wait NETWORK_HOLD_S behind the others;
# then one attempt probes the network, and a failed probe renews the hold.
NETWORK_HOLD_AFTER = 3
NETWORK_HOLD_S = 45 * 60
# A rate whose network failures reach this total pauses the testbed for a decision.
NETWORK_MAX_FAILURES = 60
SCRAPE_S = 10
CLOCK_BOUND_MS = 2.0
MIN_LOCAL_FREE_GB = 50
GLOBAL_REGIONS = ["us-east-1", "us-west-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
                  "eu-north-1", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2"]
TESTBEDS = {
    # Nodes 0 and 1 bootstrap the network, so no fault ever takes them down.
    "global": dict(regions=GLOBAL_REGIONS, crash1=[13], crash9=list(range(13, 22)), victims=[26, 29, 33, 35, 36]),
    "na": dict(regions=["us-east-1", "us-east-2", "ca-central-1"], crash1=[3], crash9=list(range(3, 12)),
               victims=[12, 13, 14, 15, 16]),
}
MODES = {
    "base": dict(binary="base", pipeline_depth=32, extension_bound=8, pipeline_window=None),
    # With d = 0 the window must cover the DA-certificate lag at the block rate: 39 blocks/s per producer
    # at 1M and up to ~520 ms of lag from Sydney and Seoul on the global testbed need more than 16.
    "payments": dict(binary="payments", pipeline_depth=0, extension_bound=0, pipeline_window=32),
    "base-fsync": dict(binary="base-fsync", pipeline_depth=32, extension_bound=8, pipeline_window=None),
}
BINARIES = ["base", "payments", "base-fsync"]

# Gate thresholds.
GATE_TPS = 0.95
GATE_TPS_WINDOW = 0.80
GATE_QUEUE_P99_S = 1.0
GATE_P50_BAND = 0.15
GATE_P99_RISE = 0.10
# Views of different validators are compared across scrapes that land up to about a second apart.
GATE_VIEW_SPREAD = 25
GATE_VIEW_SPREAD_S = 2.0
GATE_MEM = 0.85
# Every live producer must build at least this share of its scheduled blocks in every window.
GATE_PRODUCTION = 0.90
# At most this many evidence logs are fetched per attempt.
MAX_EVIDENCE_LOGS = 10

# Metric families scraped from every live node each window (filled in from the binary's /metrics).
M = dict(
    placed="application_proposal_placement_latency",
    started="application_proposal_started_total",
    unplaced="application_proposal_unplaced",
    queue="application_input_queue_latency",
    view="engine_voter_current_view",
    nullified="engine_voter_nullifications_total",
    round="engine_voter_round_latency",
    dropped="network_injected_loss_dropped_total",
)


def tb_dir(tb):
    return AR / "testbeds" / tb


def now_ms():
    return int(time.time() * 1000)


def log(tb, msg):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} [{tb}] {msg}"
    print(line, flush=True)
    with open(tb_dir(tb) / "driver.log", "a") as f:
        f.write(line + "\n")


def run_log(attempt_dir, msg):
    with open(attempt_dir / "driver.log", "a") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}\n")


class Infra(Exception):
    """A failure of the testbed rather than the protocol: retried once from a fresh wipe."""


class Network(Infra):
    """A node's network lost packets on every path: retried after a pause, as often as needed."""


class Paused(Exception):
    """The testbed must stop and wait for a human."""


# ---------------------------------------------------------------- hosts and ssh

def config(tb):
    return yaml.safe_load(open(tb_dir(tb) / "deploy" / "config.yaml"))


def key(tb):
    tag = config(tb)["tag"]
    return str(Path.home() / ".commonware_deployer" / tag / f"id_rsa_{tag}")


def hosts(tb):
    return json.load(open(tb_dir(tb) / "hosts.json"))


def control_dir(tb):
    ctl = Path("/tmp/mmctl") / tb
    ctl.mkdir(parents=True, exist_ok=True)
    return ctl


def ssh(tb, ip, cmd, timeout=120, input=None, check=False, mux=True):
    """Runs `cmd` on `ip`, over the testbed's shared connection unless `mux` is false."""
    shared = (["-o", "ControlMaster=auto", "-o", f"ControlPath={control_dir(tb)}/%C", "-o", "ControlPersist=900"]
              if mux else ["-o", "ControlMaster=no", "-o", "ControlPath=none"])
    args = ["ssh", "-i", key(tb), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
            *shared, f"ubuntu@{ip}", cmd]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, input=input)
    except subprocess.TimeoutExpired:
        if check:
            raise Infra(f"ssh {ip} timed out: {cmd[:60]}")
        return subprocess.CompletedProcess(args, 255, b"", b"timeout")
    if check and r.returncode != 0:
        raise Infra(f"ssh {ip} exit {r.returncode}: {r.stderr.decode()[-300:]}")
    return r


def ssh_retry(tb, ip, cmd, timeout=120, tries=3):
    """Runs an idempotent `cmd` on `ip`, retrying on fresh connections when ssh itself fails (exit 255),
    so one wedged shared connection costs one timeout rather than the result."""
    r = ssh(tb, ip, cmd, timeout=timeout)
    for _ in range(tries - 1):
        if r.returncode != 255:
            break
        r = ssh(tb, ip, cmd, timeout=timeout, mux=False)
    return r


# Bytes per second a copy must sustain before it is abandoned and retried on a fresh connection.
FETCH_MIN_BPS = 250_000


def fetch(tb, ip, cmd, tries=3):
    """Writes the output of `cmd` on `ip` to a remote file, then copies that file back whole.

    Producing the output never depends on the connection, and a copy that stalls is retried on a
    fresh connection with a deadline sized to the file. Returns `(data, ok)`; `ok` holds only for a
    copy whose length matches the remote file.
    """
    tmp = f"/tmp/mmfetch.{os.urandom(6).hex()}"
    r = ssh_retry(tb, ip, f"({cmd}) > {tmp}; stat -c %s {tmp}", timeout=600, tries=tries)
    try:
        size = int(r.stdout.decode().split()[-1])
    except (IndexError, ValueError):
        return b"", False
    deadline = 60 + size / FETCH_MIN_BPS
    for i in range(tries):
        c = ssh(tb, ip, f"cat {tmp}", timeout=deadline, mux=i == 0)
        if c.returncode == 0 and len(c.stdout) == size:
            ssh(tb, ip, f"rm -f {tmp}", timeout=30)
            return c.stdout, True
    return b"", False


def reset_connections(tb):
    """Closes the testbed's shared ssh connections, so a stale or slow one never outlives a run."""
    ip = hosts(tb)

    def go(n):
        subprocess.run(["ssh", "-o", f"ControlPath={control_dir(tb)}/%C", "-O", "exit", f"ubuntu@{ip[n][0]}"],
                       capture_output=True, timeout=15)
    par(go, list(ip))


def par(fn, names, workers=50):
    with cf.ThreadPoolExecutor(min(workers, max(1, len(names)))) as ex:
        return dict(zip(names, ex.map(fn, names)))


def validators(tb):
    return sorted((n for n in hosts(tb) if n != "monitoring"), key=int)


# ---------------------------------------------------------------- run specification

def parse_run(run_id):
    # Scenarios may contain dots (loss0.1), so split the testbed and mode from the left, the rate from the right.
    tb, mode, rest = run_id.split(".", 2)
    scen, rate = rest.rsplit(".", 1)
    assert rate in RATES and mode in MODES and tb in TESTBEDS, run_id
    return dict(id=run_id, tb=tb, mode=mode, scen=scen, rate=rate)


def scenario(tb, scen):
    t = TESTBEDS[tb]
    s = dict(kind=scen, crashed=[], loss=0.0, censors=[], victims=[], extension_bound=None)
    if scen == "crash1":
        s["crashed"] = t["crash1"]
    elif scen == "crash9":
        s["crashed"] = t["crash9"]
    elif scen == "loss0.1":
        s["loss"] = 0.001
    elif scen.startswith("censor"):
        n, e = re.fullmatch(r"censor(\d+)-e(\d+)", scen).groups()
        s["censors"] = t["crash1"] if n == "1" else t["crash9"]
        s["victims"] = t["victims"]
        s["extension_bound"] = int(e)
    else:
        assert scen == "healthy", scen
    return s


def seed_for(run_id, attempt):
    return int.from_bytes(hashlib.sha256(f"{run_id}/attempt-{attempt}".encode()).digest()[:8], "big") >> 1


def node_config(tb, name, run, sc, seed, schedule):
    cfg = yaml.safe_load(open(tb_dir(tb) / "deploy" / f"node-{name}.yaml"))
    cfg.pop("benchmark", None)
    m = MODES[run["mode"]]
    cfg["pipeline_depth"] = m["pipeline_depth"]
    cfg["extension_bound"] = m["extension_bound"] if sc["extension_bound"] is None else sc["extension_bound"]
    if m["pipeline_window"] is None:
        cfg.pop("pipeline_window", None)
    else:
        cfg["pipeline_window"] = m["pipeline_window"]
    cfg["proposal_policy"] = "endorsed"
    cfg["trace_sampling"] = 0.0
    cfg["benchmark"] = {"committee_seed": seed, "schedule": schedule,
                        "faults": {"loss": sc["loss"], "censors": sc["censors"], "victims": sc["victims"]}}
    return cfg


# ---------------------------------------------------------------- node operations

PREP = r"""set -u
sudo systemctl stop binary >/dev/null 2>&1
for i in $(seq 90); do systemctl is-active --quiet binary || break; sleep 1; done
if systemctl is-active --quiet binary; then echo "ACTIVE yes"; else echo "ACTIVE no"; fi
WIPE
rm -f /tmp/mmfetch.*
echo "SHA $(sha256sum /home/ubuntu/bins/MODE 2>/dev/null | cut -c1-64)"
echo "DISK $(df -BG --output=avail /home/ubuntu | tail -1 | tr -dc 0-9)"
echo "CLOCK $(chronyc -n tracking 2>/dev/null | awk '/^System time/ {print $4, $6}')"
echo "LEAP $(chronyc -n tracking 2>/dev/null | awk -F': ' '/^Leap status/ {print $2}')"
"""


def clock_ms(line):
    # "System time : 0.000012345 seconds fast of NTP time"
    parts = line.split()
    if len(parts) != 2:
        return None
    try:
        v = float(parts[0]) * 1000
    except ValueError:
        return None
    return v if parts[1] == "fast" else -v


def preflight(tb, mode, attempt_dir=None, wipe=True):
    """Stops every binary, wipes data and logs (unless wipe is false), and checks binaries, disk and
    clocks on every node."""
    want = json.load(open(AR / "provenance" / "binaries.json"))[mode]["sha256"]
    names = validators(tb)
    ip = hosts(tb)

    def go(n):
        script = PREP.replace("MODE", mode).replace(
            "WIPE", "sudo rm -rf /home/ubuntu/data; sudo rm -f /var/log/binary.log" if wipe else "")
        r = ssh(tb, ip[n][0], script, timeout=180)
        out = dict(re.findall(r"^(ACTIVE|SHA|DISK|CLOCK|LEAP) ?(.*)$", r.stdout.decode(), re.M))
        out["rc"] = r.returncode
        return out
    res = par(go, names)
    problems, clocks = [], {}
    for n, o in res.items():
        if o["rc"] != 0 or "SHA" not in o:
            problems.append(f"{n}: unreachable ({o['rc']})")
            continue
        if o.get("ACTIVE") != "no":
            problems.append(f"{n}: binary still active")
        if o.get("SHA") != want:
            problems.append(f"{n}: {mode} sha {o.get('SHA', '')[:12]} != {want[:12]}")
        if int(o.get("DISK") or 0) < 100:
            problems.append(f"{n}: disk {o.get('DISK')} GB free")
        c = clock_ms(o.get("CLOCK", ""))
        clocks[n] = c
        if c is None or abs(c) > CLOCK_BOUND_MS:
            problems.append(f"{n}: clock offset {c} ms")
        if o.get("LEAP", "").strip() != "Normal":
            problems.append(f"{n}: chrony leap status {o.get('LEAP')}")
    free = shutil.disk_usage(AR).free / 2**30
    if free < MIN_LOCAL_FREE_GB:
        problems.append(f"local disk: {free:.0f} GB free")
    if attempt_dir:
        json.dump({"preflight": clocks}, open(attempt_dir / "clocks.json", "w"), indent=1)
    return problems, clocks


def configure(tb, run, sc, seed, schedule, attempt_dir):
    """Installs the run's binary and config on every node; crashed nodes get them too but never start."""
    m = MODES[run["mode"]]
    ip = hosts(tb)
    cfgdir = attempt_dir / "configs"
    cfgdir.mkdir(exist_ok=True)

    def go(n):
        cfg = node_config(tb, n, run, sc, seed, schedule)
        text = yaml.safe_dump(cfg, sort_keys=False)
        (cfgdir / f"node-{n}.yaml").write_text(text)
        cmd = (f"set -e; cp /home/ubuntu/bins/{m['binary']} /home/ubuntu/binary; chmod +x /home/ubuntu/binary; "
               "cat > /home/ubuntu/config.conf; sha256sum /home/ubuntu/binary | cut -c1-64")
        r = ssh(tb, ip[n][0], cmd, input=text.encode(), timeout=120)
        return r.returncode, r.stdout.decode().strip()
    res = par(go, validators(tb))
    want = json.load(open(AR / "provenance" / "binaries.json"))[m["binary"]]["sha256"]
    bad = [n for n, (rc, sha) in res.items() if rc != 0 or sha != want]
    if bad:
        raise Infra(f"configure failed on {bad[:5]}")


def start(tb, live):
    ip = hosts(tb)
    res = par(lambda n: ssh(tb, ip[n][0], "sudo systemctl start binary && sleep 1 && systemctl is-active binary",
                            timeout=60).stdout.decode().strip(), live)
    bad = [n for n, s in res.items() if s != "active"]
    if bad:
        raise Infra(f"start failed on {bad[:5]}")


def stop(tb, names=None):
    ip = hosts(tb)
    names = names or validators(tb)
    par(lambda n: ssh(tb, ip[n][0], "sudo systemctl stop binary; systemctl is-active binary || true", timeout=120),
        names)


SCRAPE = r"""curl -s -m 5 localhost:9090/metrics | grep -E '^(FAMILIES)' ; echo "__ACTIVE $(systemctl is-active binary)"
echo "__MEM $(awk '/^MemTotal/ {t=$2} /^MemAvailable/ {a=$2} END {printf "%.4f", 1-a/t}' /proc/meminfo)"
echo "__ERRORS $(grep -c '"level":"ERROR"' /var/log/binary.log 2>/dev/null)"
echo "__TCP $(awk '$1 == "Tcp:" && $2 ~ /^[0-9]+$/ {print $12, $13}' /proc/net/snmp)"
"""


def scrape(tb, live):
    """One scrape of the gate metrics from every live node: {node: {series: value}}."""
    fams = "|".join(sorted(set(M.values())))
    ip = hosts(tb)
    cmd = SCRAPE.replace("FAMILIES", fams)

    def go(n):
        r = ssh(tb, ip[n][0], cmd, timeout=8)
        if r.returncode != 0:
            # A shared connection can stall; one fresh connection decides.
            r = ssh(tb, ip[n][0], cmd, timeout=9, mux=False)
        if r.returncode != 0:
            return None
        vals = {}
        for line in r.stdout.decode().splitlines():
            if line.startswith("__"):
                k, _, v = line.partition(" ")
                vals[k] = v.strip()
                continue
            name, _, v = line.rpartition(" ")
            try:
                vals[name] = float(v)
            except ValueError:
                pass
        return vals
    t = time.time()
    return t, par(go, live)


# ---------------------------------------------------------------- gate

def fam(vals, family, suffix=""):
    """Sum of every series of a metric family (across label sets)."""
    pre = family + suffix
    return sum(v for k, v in vals.items() if isinstance(v, float) and (k == pre or k.startswith(pre + "{")))


def buckets(vals, family):
    out = {}
    for k, v in vals.items():
        if k.startswith(family + "_bucket{") and isinstance(v, float):
            le = re.search(r'le="([^"]+)"', k).group(1)
            le = math.inf if le == "+Inf" else float(le)
            out[le] = out.get(le, 0.0) + v
    return out


def quantile(bk, q):
    """Prometheus-style quantile over cumulative buckets {le: count}."""
    items = sorted(bk.items())
    if not items or items[-1][1] <= 0:
        return None
    total = items[-1][1]
    rank = q * total
    prev_le, prev_c = 0.0, 0.0
    for le, c in items:
        if c >= rank:
            if le == math.inf:
                return prev_le
            if c == prev_c:
                return le
            return prev_le + (le - prev_le) * (rank - prev_c) / (c - prev_c)
        prev_le, prev_c = le, c
    return items[-1][0]


def window(prev, cur, live, blocks_per_s=None):
    """Aggregates one window between two scrapes; blocks_per_s is each producer's scheduled rate, once
    the schedule has started."""
    (t0, a), (t1, b) = prev, cur
    dt = t1 - t0
    w = dict(t=t1, dt=dt, missing=[], inactive=[], mem_high=[], errors_new=[], lagging=[], idle_producers=[],
             retransmitting={})
    placed, qb, pb, rb = 0.0, {}, {}, {}
    unplaced, views, nulls, rates = 0.0, {}, 0.0, []
    for n in live:
        x, y = a.get(n), b.get(n)
        if not y:
            w["missing"].append(n)
            continue
        if y.get("__ACTIVE") != "active":
            w["inactive"].append(n)
        try:
            if float(y.get("__MEM", "0")) > GATE_MEM:
                w["mem_high"].append(n)
        except ValueError:
            pass
        if x and y.get("__ERRORS", "0") != x.get("__ERRORS", "0"):
            w["errors_new"].append(n)
        try:
            (out0, re0), (out1, re1) = (map(int, x["__TCP"].split()), map(int, y["__TCP"].split())) if x else ((0, 0), (0, 0))
            if out1 > out0 and (re1 - re0) / (out1 - out0) > GATE_RETRANS:
                w["retransmitting"][n] = round((re1 - re0) / (out1 - out0), 4)
        except (KeyError, ValueError):
            pass
        unplaced += fam(y, M["unplaced"])
        views[n] = fam(y, M["view"])
        if not x:
            continue
        placed += fam(y, M["placed"], "_count") - fam(x, M["placed"], "_count")
        nulls += fam(y, M["nullified"]) - fam(x, M["nullified"])
        for name, acc in ((M["queue"], qb), (M["placed"], pb), (M["round"], rb)):
            bx, by = buckets(x, name), buckets(y, name)
            for le, c in by.items():
                acc[le] = acc.get(le, 0.0) + c - bx.get(le, 0.0)
        if views[n] <= fam(x, M["view"]):
            w.setdefault("stalled_views", []).append(n)
        if blocks_per_s:
            built = fam(y, M["started"]) - fam(x, M["started"])
            if built <= 0:
                w["idle_producers"].append(n)
            if built < GATE_PRODUCTION * blocks_per_s * dt:
                w["lagging"].append(n)
        rates.append((views[n] - fam(x, M["view"])) / dt if dt > 0 else 0.0)
    w["placed_tps"] = placed * TX_PER_BLOCK / dt if dt > 0 else 0.0
    w["placement_p50_s"] = quantile(pb, 0.5)
    w["placement_p99_s"] = quantile(pb, 0.99)
    w["queue_p99_s"] = quantile(qb, 0.99)
    w["round_p50_s"] = quantile(rb, 0.5)
    w["unplaced"] = unplaced
    w["nullifications"] = nulls
    w["view_spread"] = (max(views.values()) - min(views.values())) if views else None
    w["view_rate"] = sorted(rates)[len(rates) // 2] if rates else None
    w.setdefault("stalled_views", [])
    return w


def gate(ws, offered_tps, live, producers):
    """Checks the last three windows; returns (passed, failed checks, diagnosis)."""
    if len(ws) < 3:
        return False, ["too few windows"], "infra"
    w = ws[-3:]
    fails = []
    host_bad = set()
    lagging = set()
    for x in w:
        host_bad |= set(x["missing"]) | set(x["inactive"]) | set(x["mem_high"]) | set(x["errors_new"])
        host_bad |= set(x["stalled_views"])
        lagging |= set(x.get("lagging", []))
    if lagging:
        fails.append(f"production below {GATE_PRODUCTION:.0%} of schedule: {len(lagging)} producers "
                     f"{sorted(lagging, key=int)[:8]}")
        # A few lagging producers are node faults; most of them lagging is the system at its limit.
        if len(lagging) <= 9:
            host_bad |= lagging
    if host_bad:
        fails.append(f"hosts: {sorted(host_bad, key=int)[:8]}")
    # Placement arrives in bursts as views finalize, so throughput is judged over the 30 s, with no window
    # below GATE_TPS_WINDOW of the offered rate.
    tps_ok = (sum(x["placed_tps"] * x["dt"] for x in w) / sum(x["dt"] for x in w) >= GATE_TPS * offered_tps
              and all(x["placed_tps"] >= GATE_TPS_WINDOW * offered_tps for x in w))
    if not tps_ok:
        fails.append("throughput: " + ", ".join(f"{x['placed_tps'] / 1000:.0f}k" for x in w))
    growth_slack = 2 * producers
    backlog_growing = w[2]["unplaced"] > w[0]["unplaced"] * 1.10 + growth_slack and w[2]["unplaced"] > w[1]["unplaced"]
    queue_bad = any(x["queue_p99_s"] is not None and x["queue_p99_s"] >= GATE_QUEUE_P99_S for x in w)
    if backlog_growing or queue_bad:
        fails.append("backlog: unplaced " + ", ".join(f"{x['unplaced']:.0f}" for x in w) +
                     "; queue p99 " + ", ".join("-" if x["queue_p99_s"] is None else f"{x['queue_p99_s']:.2f}" for x in w))
    p50 = [x["placement_p50_s"] for x in w]
    p99 = [x["placement_p99_s"] for x in w]
    if None in p50 or None in p99:
        fails.append("latency: no placements")
    else:
        med = sorted(p50)[1]
        if any(abs(v - med) > GATE_P50_BAND * med for v in p50):
            fails.append("latency p50: " + ", ".join(f"{v * 1000:.0f}" for v in p50))
        if p99[1] > p99[0] * (1 + GATE_P99_RISE) and p99[2] > p99[1] * (1 + GATE_P99_RISE):
            fails.append("latency p99 rising: " + ", ".join(f"{v * 1000:.0f}" for v in p99))
    # Scrapes of different regions land up to about a second apart, so allow two seconds of views.
    rate = sorted(x.get("view_rate") or 0.0 for x in w)[1]
    bound = max(GATE_VIEW_SPREAD, GATE_VIEW_SPREAD_S * rate)
    spread = [x["view_spread"] for x in w if x["view_spread"] is not None]
    if spread and min(spread) > bound:
        fails.append("view spread: " + ", ".join(f"{v:.0f}" for v in spread))
    n = [x["nullifications"] for x in w]
    if n[0] < n[1] < n[2] and n[2] >= 2 * n[0] + 3:
        fails.append("nullifications rising: " + ", ".join(f"{v:.0f}" for v in n))
    if not fails:
        return True, [], None
    if host_bad and len(host_bad) <= 9:
        diag = "infra"
    elif not tps_ok and backlog_growing and not host_bad:
        diag = "saturated"
    elif host_bad:
        diag = "infra"
    else:
        diag = "unstable"
    return False, fails, diag


# ---------------------------------------------------------------- drain and collection

DRAIN_CHECK = r"""
import json, sys
c0, c1 = int(sys.argv[1]), int(sys.argv[2])
starts, placed, ordered = set(), set(), set()
sets = {"start": starts, "placement": placed, "ordered": ordered}
with open("/var/log/binary.log", errors="replace") as f:
    for line in f:
        if '"benchmark_event"' not in line:
            continue
        try:
            x = json.loads(line)["fields"]
        except Exception:
            continue
        s = sets.get(x.get("benchmark_event"))
        if s is None:
            continue
        t = x.get("started_at_us")
        if t is None or not (c0 <= t < c1):
            continue
        s.add((x["chain"], x["height"], x["digest"]))
print(len(starts), len(starts - placed), len(starts - ordered))
"""


def drain_check(tb, producers, c0_us, c1_us):
    ip = hosts(tb)

    def go(n):
        r = ssh(tb, ip[n][0], f"python3 - {c0_us} {c1_us}", input=DRAIN_CHECK.encode(), timeout=60)
        try:
            return tuple(int(v) for v in r.stdout.decode().split())
        except ValueError:
            return None
    return par(go, producers)


def collect(tb, live, crashed, attempt_dir):
    ip = hosts(tb)
    for d in ("events", "warnings", "status"):
        (attempt_dir / d).mkdir(exist_ok=True)

    def go(n):
        out = {}
        data, ok = fetch(tb, ip[n][0], "grep -F '\"benchmark_event\"' /var/log/binary.log | gzip -c")
        (attempt_dir / "events" / f"{n}.jsonl.gz").write_bytes(data)
        out["events_bytes"] = len(data)
        out["events_rc"] = 0 if ok else 255
        data, _ = fetch(tb, ip[n][0], "grep -E '\"level\":\"(WARN|ERROR)\"' /var/log/binary.log | head -n 20000 | gzip -c")
        (attempt_dir / "warnings" / f"{n}.jsonl.gz").write_bytes(data)
        r = ssh_retry(tb, ip[n][0], "grep -c '' /var/log/binary.log; grep -c '\"level\":\"ERROR\"' /var/log/binary.log; "
                      "grep -c '\"level\":\"WARN\"' /var/log/binary.log", timeout=300)
        out["log_lines"] = r.stdout.decode().split()
        return out
    return par(go, live, workers=25)


def keep_logs(tb, attempt_dir, t0_ms, cohort0, cohort1, late_nodes=2):
    """Fetches the full log of every producer that placed a cohort block without naming it, and of
    the producers with the latest-named placements, before the next preflight wipes the logs."""
    w0, w1 = (t0_ms + cohort0 * 1000) * 1000, (t0_ms + cohort1 * 1000) * 1000
    unnamed, late = set(), {}
    for f in (attempt_dir / "events").glob("*.jsonl.gz"):
        n = f.name.split(".")[0]
        placed, ordered = {}, {}
        with gzip.open(f, "rt", errors="replace") as fh:
            for line in fh:
                if '"placement"' not in line and '"ordered"' not in line:
                    continue
                try:
                    x = json.loads(line)["fields"]
                except Exception:  # noqa: BLE001
                    continue
                e = x.get("benchmark_event")
                if e in ("placement", "ordered") and w0 <= x.get("started_at_us", -1) < w1:
                    (placed if e == "placement" else ordered)[(x["chain"], x["height"])] = x["timestamp_us"]
        for k, t in ordered.items():
            if k not in placed:
                unnamed.add(n)
            elif placed[k] > t:
                late[n] = max(late.get(n, 0), placed[k] - t)
    chosen = sorted(unnamed, key=int) + [n for n, _ in sorted(late.items(), key=lambda x: -x[1])
                                         if n not in unnamed][:late_nodes]
    if not chosen:
        return {}
    (attempt_dir / "logs").mkdir(exist_ok=True)
    ip = hosts(tb)

    def go(n):
        data, _ = fetch(tb, ip[n][0], "gzip -c /var/log/binary.log")
        if data:
            (attempt_dir / "logs" / f"{n}.log.gz").write_bytes(data)
        return len(data)
    sizes = par(go, chosen, workers=8)
    return {"unnamed": sorted(unnamed, key=int), "late_ms": {n: late[n] / 1000 for n in late}, "fetched": sizes}


def window_suspects(windows):
    """Nodes any of the last three windows flagged."""
    out = set()
    for x in windows[-3:]:
        for key in ("missing", "inactive", "mem_high", "errors_new", "stalled_views", "lagging", "idle_producers",
                    "retransmitting"):
            out |= set(x.get(key, []))
    return out


def warned_nodes(attempt_dir):
    """Nodes whose collected warnings include a staging failure or an error."""
    out = set()
    for f in (attempt_dir / "warnings").glob("*.jsonl.gz"):
        with gzip.open(f, "rt", errors="replace") as fh:
            for line in fh:
                if "cannot stage" in line or '"level":"ERROR"' in line:
                    out.add(f.name.split(".")[0])
                    break
    return out


def save_logs(tb, attempt_dir, nodes):
    """Fetches the full log of each suspect node (at most MAX_EVIDENCE_LOGS) before anything wipes it."""
    chosen = sorted(nodes, key=int)[:MAX_EVIDENCE_LOGS]
    (attempt_dir / "logs").mkdir(exist_ok=True)
    ip = hosts(tb)

    def go(n):
        data, _ = fetch(tb, ip[n][0], "gzip -c /var/log/binary.log")
        if data:
            (attempt_dir / "logs" / f"{n}.log.gz").write_bytes(data)
        return len(data)
    return {"nodes": chosen, "bytes": par(go, chosen, workers=8)}


def final_metrics(tb, live, attempt_dir):
    ip = hosts(tb)
    (attempt_dir / "status").mkdir(exist_ok=True)

    def go(n):
        r = ssh(tb, ip[n][0], "curl -s -m 10 localhost:9090/metrics | gzip -c", timeout=60)
        (attempt_dir / "status" / f"{n}.prom.gz").write_bytes(r.stdout)
        return len(r.stdout)
    return par(go, live)


PROM_EXPRS = {
    "placement_p50": 'histogram_quantile(0.5, sum by (le) (rate(application_proposal_placement_latency_bucket[30s])))',
    "placement_p99": 'histogram_quantile(0.99, sum by (le) (rate(application_proposal_placement_latency_bucket[30s])))',
    "finalization_p50": 'histogram_quantile(0.5, sum by (le) (rate(application_proposal_finalization_latency_bucket[30s])))',
    "view_p50": 'histogram_quantile(0.5, sum by (le) (rate(engine_voter_round_latency_bucket[30s])))',
    "placed_tps": f'sum(rate(application_proposal_placement_latency_count[30s])) * {TX_PER_BLOCK}',
    "cpu_cores": 'sum by (instance) (rate(node_cpu_seconds_total{mode!="idle"}[30s]))',
    "net_tx_bytes": 'sum by (instance) (rate(node_network_transmit_bytes_total{device!="lo"}[30s]))',
    "net_rx_bytes": 'sum by (instance) (rate(node_network_receive_bytes_total{device!="lo"}[30s]))',
    "mem_used": '1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes',
    "disk_write_bytes": 'sum by (instance) (rate(node_disk_written_bytes_total[30s]))',
    "disk_writes": 'sum by (instance) (rate(node_disk_writes_completed_total[30s]))',
    "process_rss": 'process_resident_memory_bytes',
    "voter_busy": 'rate(engine_voter_busy_micros_total[30s]) / 1e6',
    "disk_flushes": 'sum by (instance) (rate(node_disk_flush_requests_total[30s]))',
    "nullifications": 'sum(rate(engine_voter_nullifications_total[30s]))',
    "view_timeouts": 'sum(rate(engine_voter_view_timeouts_total[30s]))',
    "engine_transmitted_bytes": 'sum without (instance, job) (rate(engine_voter_transmitted_bytes_total[30s]))',
    "engine_retransmitted_bytes": 'sum without (instance, job) (rate(engine_voter_retransmitted_bytes_total[30s]))',
    "outbound_bandwidth": 'sum(rate(runtime_outbound_bandwidth_total[30s]))',
    "inbound_bandwidth": 'sum(rate(runtime_inbound_bandwidth_total[30s]))',
    "messages_sent": 'sum by (message) (rate(network_spawner_messages_sent_total[30s]))',
}


def prometheus(tb, t0, t1, attempt_dir):
    mon = hosts(tb)["monitoring"][0]
    out = {"start": t0, "end": t1, "step": 5, "series": {}}
    for name, expr in PROM_EXPRS.items():
        u = (f"http://{mon}:9090/api/v1/query_range?" +
             urllib.parse.urlencode({"query": expr, "start": t0, "end": t1, "step": 5}))
        try:
            out["series"][name] = json.load(urllib.request.urlopen(u, timeout=120))["data"]["result"]
        except Exception as e:  # noqa: BLE001
            out["series"][name] = {"error": str(e)}
    with gzip.open(attempt_dir / "prometheus.json.gz", "wt") as f:
        json.dump(out, f)


# ---------------------------------------------------------------- one attempt

def attempt(tb, run_id, n, canary=False):
    """Runs one attempt and returns (verdict, details)."""
    run = parse_run(run_id)
    sc = scenario(tb, run["scen"])
    live = [x for x in validators(tb) if int(x) not in sc["crashed"]]
    crashed = [x for x in validators(tb) if int(x) in sc["crashed"]]
    offered = RATES[run["rate"]]
    per_producer = int(round(offered * TX_BYTES / len(live)))
    seed = seed_for(run_id, n)
    d = RUNS / run_id / f"attempt-{n}"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    meta = dict(run_id=run_id, attempt=n, testbed=tb, mode=run["mode"], scenario=sc, rate=run["rate"],
                offered_tps=offered, per_producer_bytes_per_second=per_producer, live=[int(x) for x in live],
                seed=seed, binary=MODES[run["mode"]]["binary"], canary=canary,
                commit=json.load(open(AR / "provenance" / "source.json"))["commit"],
                cluster_tag=config(tb)["tag"],
                tools_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in (Path(__file__).resolve(), AR / "tools" / "analyze.py")},
                constants=dict(lead_s=LEAD_S, warmup_s=WARMUP_S,
                extension_s=EXTENSION_S, max_extensions=MAX_EXTENSIONS, cohort_s=COHORT_S,
                drain_max_s=DRAIN_MAX_S, load_s=LOAD_S, scrape_s=SCRAPE_S), started_at=time.time())
    phase = lambda p, secs=None, ext=0: S.update(lambda P: S_phase(P, tb, run_id, n, p, secs, ext))  # noqa: E731
    try:
        phase("preflight")
        reset_connections(tb)
        problems, clocks = preflight(tb, MODES[run["mode"]]["binary"], d)
        if problems:
            raise Infra("preflight: " + "; ".join(problems[:6]))
        phase("configure")
        t0_ms = now_ms() + (LEAD_S + 20) * 1000
        schedule = {"start_unix_ms": t0_ms, "phases": [{"duration_ms": LOAD_S * 1000, "bytes_per_second": per_producer}]}
        meta["schedule"] = schedule
        configure(tb, run, sc, seed, schedule, d)
        start(tb, live)
        run_log(d, f"started {len(live)} nodes; schedule starts {t0_ms}")
        phase("warm-up", WARMUP_S + 20)
        blocks_per_s = per_producer / BODY
        # Scrape every 10 s on the schedule's grid, from 30 s before the schedule start.
        scrapes, windows = [], []
        k = -3

        def tick(k):
            target = t0_ms / 1000 + k * SCRAPE_S
            delay = target - time.time()
            if delay > 0:
                time.sleep(delay)
            s = scrape(tb, live)
            scrapes.append((k, s))
            if len(scrapes) >= 2:
                w = window(scrapes[-2][1], s, live, blocks_per_s if k * SCRAPE_S > SCRAPE_S else None)
                w["k"] = k
                windows.append(w)
                # A node absent from three scrapes in a row is checked directly before the
                # attempt is abandoned: an unreachable scrape alone says nothing of the node.
                recent = windows[-3:]
                if len(recent) == 3:
                    suspects = set.intersection(*(set(x["missing"]) | set(x["inactive"]) for x in recent))
                    ip = hosts(tb)
                    down = [n for n in suspects
                            if ssh(tb, ip[n][0], "systemctl is-active binary", timeout=30, mux=False)
                            .stdout.decode().strip() != "active"]
                    if down:
                        raise Infra(f"live nodes down or unreachable: {sorted(down, key=int)[:8]}")
            return s
        gate_at = WARMUP_S
        gates, extensions, diag = [], 0, None
        while True:
            while k * SCRAPE_S < gate_at:
                k += 1
                tick(k)
            passed, fails, diag = gate(windows, offered, live, len(live))
            gates.append(dict(at_s=gate_at, passed=passed, fails=fails, diagnosis=diag,
                              windows=[{kk: vv for kk, vv in w.items() if kk != "t"} for w in windows[-3:]]))
            run_log(d, f"gate at {gate_at}s: {'pass' if passed else 'FAIL ' + '; '.join(fails)}")
            if passed:
                break
            if diag == "infra" and extensions >= 1:
                raise Infra("gate: " + "; ".join(fails))
            if extensions == MAX_EXTENSIONS:
                break
            extensions += 1
            gate_at += EXTENSION_S
            phase("extension", EXTENSION_S, extensions)
            S.update(lambda P: P["events"].append(dict(at=S.now(), tb=tb, level="warn",
                     text=f"{run_id}: gate failed ({'; '.join(fails)[:160]}), warm-up extended 60 s")))
        meta["gate"] = gates
        meta["extensions"] = extensions
        steady = gates[-1]["passed"]
        if canary and (not steady or extensions > 1):
            raise Paused(f"canary did not settle within one extension: {gates[-1]['fails']}")
        if not steady and diag == "infra":
            raise Infra("gate: " + "; ".join(gates[-1]["fails"]))
        cohort0 = gate_at + SCRAPE_S
        cohort1 = cohort0 + COHORT_S
        meta["cohort_s"] = [cohort0, cohort1]
        meta["unsteady_diagnosis"] = None if steady else diag
        phase("cohort", COHORT_S + SCRAPE_S)
        while k * SCRAPE_S < cohort1:
            k += 1
            tick(k)
            w = windows[-1]
            if k * SCRAPE_S > cohort0 and w["placed_tps"] == 0:
                raise Infra(f"stall: no placement anywhere in window ending {k * SCRAPE_S}s")
            if k * SCRAPE_S > cohort0 and w["idle_producers"]:
                raise Infra(f"producers built nothing in window ending {k * SCRAPE_S}s: "
                            f"{sorted(w['idle_producers'], key=int)[:8]}")
        phase("drain", DRAIN_MAX_S)
        c0_us, c1_us = (t0_ms + cohort0 * 1000) * 1000, (t0_ms + cohort1 * 1000) * 1000
        drained, checks = False, []
        while k * SCRAPE_S < cohort1 + DRAIN_MAX_S:
            k += 1
            tick(k)
            if k * SCRAPE_S >= cohort1 + max(DRAIN_MIN_S, 20) and (k * SCRAPE_S - cohort1) % 20 == 0:
                res = drain_check(tb, live, c0_us, c1_us)
                checks.append(dict(at_s=k * SCRAPE_S, result={n_: r for n_, r in res.items()}))
                # Delivery implies placement, and the engine may place blocks without naming them.
                if all(r is not None and r[2] == 0 for r in res.values()):
                    drained = True
                    break
        meta["drain"] = dict(drained=drained, ended_at_s=k * SCRAPE_S, checks=checks)
        phase("collect")
        final_metrics(tb, live, d)
        stop(tb, live)
        meta["ended_at"] = time.time()
        with gzip.open(d / "scrapes.json.gz", "wt") as f:
            json.dump({"windows": [{kk: vv for kk, vv in w.items()} for w in windows]}, f)
        coll = collect(tb, live, crashed, d)
        meta["collection"] = coll
        meta["full_logs"] = keep_logs(tb, d, t0_ms, cohort0, cohort1)
        problems, clocks_after = preflight(tb, MODES[run["mode"]]["binary"], wipe=False)
        c = json.load(open(d / "clocks.json"))
        c["after"] = clocks_after
        json.dump(c, open(d / "clocks.json", "w"), indent=1)
        meta["post_check"] = problems
        prometheus(tb, t0_ms / 1000 - 30, meta["ended_at"] + 15, d)
        json.dump(meta, open(d / "run.json", "w"), indent=1)
        phase("record")
        r = subprocess.run([sys.executable, str(AR / "tools" / "analyze.py"), str(d)], capture_output=True, text=True)
        (d / "analysis.log").write_text(r.stdout + r.stderr)
        if r.returncode != 0:
            raise Infra(f"analysis failed: {r.stderr[-300:]}")
        result = json.load(open(d / "result.json"))
        suspects = set(result["checks"]["accounting"]["value"].get("outliers", []))
        suspects |= warned_nodes(d)
        if result["verdict"] != "accepted":
            suspects |= window_suspects(windows)
        if suspects:
            meta["evidence_logs"] = save_logs(tb, d, suspects)
            json.dump(meta, open(d / "run.json", "w"), indent=1)
        if result["verdict"] == "infra":
            failed = [k for k, v in result["checks"].items() if not v["pass"]]
            raise Infra(f"acceptance: {result['reason']}")
        return result["verdict"], result
    except (Infra, Paused) as e:
        meta["error"] = str(e)
        meta["ended_at"] = time.time()
        if locals().get("windows"):
            with gzip.open(d / "scrapes.json.gz", "wt") as fh:
                json.dump({"windows": locals()["windows"]}, fh)
        try:
            stop(tb, live)
        except Exception:  # noqa: BLE001
            pass
        try:
            suspects = window_suspects(locals().get("windows", []))
            if suspects and "evidence_logs" not in meta:
                meta["evidence_logs"] = save_logs(tb, d, suspects)
        except Exception as x:  # noqa: BLE001
            meta["evidence_logs"] = {"error": str(x)}
        json.dump(meta, open(d / "run.json", "w"), indent=1)
        raise
    except Exception as e:  # noqa: BLE001
        meta["error"] = "unexpected: " + "".join(traceback.format_exception(type(e), e, e.__traceback__))[-2000:]
        meta["ended_at"] = time.time()
        json.dump(meta, open(d / "run.json", "w"), indent=1)
        try:
            stop(tb, live)
        except Exception:  # noqa: BLE001
            pass
        raise Infra(f"unexpected error: {e}")


def S_phase(P, tb, run_id, n, p, secs, ext):
    cur = P["testbeds"][tb].get("current") or {}
    started = cur.get("run_started_at") if cur.get("run_id") == run_id and cur.get("attempt") == n else S.now()
    P["testbeds"][tb]["current"] = dict(run_id=run_id, attempt=n, phase=p, phase_started_at=S.now(),
                                        phase_seconds=secs, extensions=ext, run_started_at=started)
    P["testbeds"][tb]["state"] = "running"
    r = P["runs"][run_id]
    r["status"] = "running"
    r["attempts"] = max(r.get("attempts", 0), n)


# ---------------------------------------------------------------- the queue

def queue(tb):
    return [r["id"] for r in S.runs() if r["tb"] == tb]


def set_run(run_id, status, **fields):
    def f(P):
        r = P["runs"][run_id]
        r["status"] = status
        r["finished_at" if status not in ("pending", "running", "retry") else "queued_at"] = S.now()
        for k, v in fields.items():
            if v is not None:
                r[k] = v
    S.update(f)


def event(tb, level, text):
    S.update(lambda P: P["events"].append(dict(at=S.now(), tb=tb, level=level, text=text)))


def network_failed(tb, rate):
    """Records a network failure at `rate`, holding the rate once failures run NETWORK_HOLD_AFTER deep."""
    out = {}

    def f(P):
        h = P["testbeds"][tb].setdefault("network", {}).setdefault(rate, {"streak": 0, "total": 0, "until": 0})
        h["streak"] += 1
        h["total"] += 1
        if h["streak"] >= NETWORK_HOLD_AFTER:
            h["until"] = time.time() + NETWORK_HOLD_S
        out.update(h)
    S.update(f)
    return out


def network_carried(tb, rate):
    """Clears the hold on `rate` once a run at it gets past the network checks."""
    def f(P):
        h = P["testbeds"][tb].get("network", {}).get(rate)
        if h:
            h["streak"], h["until"] = 0, 0
    S.update(f)


def run_queue(tb, only=None):
    log(tb, "driver starting")
    S.update(lambda P: P.__setitem__("state", "running"))
    streak = 0      # consecutive runs ending unstable or with an infrastructure retry
    while True:
        P = S.load()
        if P["testbeds"][tb]["state"] == "paused":
            log(tb, "testbed is paused; exiting")
            return
        if (tb_dir(tb) / "STOP").exists():
            (tb_dir(tb) / "STOP").unlink()
            log(tb, "STOP file found; exiting between runs")
            S.update(lambda P: P["testbeds"][tb].__setitem__("current", None))
            return
        ids = queue(tb) if not only else only
        pending = [i for i in ids if P["runs"][i]["status"] in ("pending", "running")]
        retries = [i for i in ids if P["runs"][i]["status"] == "retry"]
        if not pending and not retries:
            break
        holds = P["testbeds"][tb].get("network", {})
        held = lambda i: holds.get(parse_run(i)["rate"], {}).get("until", 0) > time.time()
        ready = [i for i in pending if not held(i)] + [i for i in retries if not held(i)]
        if not ready:
            # Every run left waits on a sick network: sleep until the first hold ends.
            wake = min(holds[parse_run(i)["rate"]]["until"] for i in pending + retries)
            S.update(lambda P: P["testbeds"][tb].__setitem__("current", None))
            time.sleep(max(1.0, min(60.0, wake - time.time())))
            continue
        run_id = ready[0]
        rate = parse_run(run_id)["rate"]
        rec = P["runs"][run_id]
        done_attempts = rec.get("attempts", 0)
        n = done_attempts + 1
        canary = run_id == ids[0]
        is_rerun = rec["status"] == "retry"
        log(tb, f"{run_id} attempt {n}{' (canary)' if canary else ''}{' (re-run)' if is_rerun else ''}")
        try:
            verdict, result = attempt(tb, run_id, n, canary=canary)
        except Paused as e:
            log(tb, f"PAUSED: {e}")
            set_run(run_id, "pending", attempts=n, reason=f"paused: {e}")
            pause(tb, str(e))
            return
        except Network as e:
            net_n = rec.get("network_failures", 0) + 1
            log(tb, f"network failure {net_n}: {e}")
            hold = network_failed(tb, rate)
            set_run(run_id, "pending", attempts=n, network_failures=net_n, reason=f"network: {str(e)[:160]}")
            if hold["total"] >= NETWORK_MAX_FAILURES:
                pause(tb, f"{hold['total']} attempts at {rate} lost to a sick network; last: {e}")
                return
            if hold["streak"] >= NETWORK_HOLD_AFTER:
                event(tb, "warn", f"{run_id} attempt {n}: {str(e)[:200]}; every {rate} run waits "
                      f"{NETWORK_HOLD_S // 60} min after {hold['streak']} network failures in a row at {rate}")
                continue
            event(tb, "warn", f"{run_id} attempt {n}: {str(e)[:200]}; retrying in {NETWORK_BACKOFF_S} s")
            time.sleep(NETWORK_BACKOFF_S)
            continue
        except Infra as e:
            log(tb, f"infrastructure failure: {e}")
            event(tb, "warn", f"{run_id} attempt {n}: infrastructure: {str(e)[:200]}")
            streak += 1
            infra_n = rec.get("infra_failures", 0) + 1
            if infra_n >= 2 or streak >= 2:
                set_run(run_id, "pending", attempts=n, infra_failures=infra_n, reason=f"infra: {str(e)[:200]}")
                pause(tb, f"two infrastructure failures in a row; last: {e}")
                return
            set_run(run_id, "pending", attempts=n, infra_failures=infra_n, reason=f"retrying after infra: {str(e)[:200]}")
            continue
        network_carried(tb, rate)
        fields = dict(attempts=n, placement_p50_ms=result.get("placement_p50_ms"),
                      placement_p99_ms=result.get("placement_p99_ms"), achieved_tps=result.get("achieved_tps"),
                      reason=result.get("reason"), infra_failures=0)
        if verdict == "unstable":
            streak += 1
            if not is_rerun:
                set_run(run_id, "retry", **fields)
                event(tb, "warn", f"{run_id}: unstable ({result.get('reason')}); re-run queued at the end")
            else:
                set_run(run_id, "unstable", **fields)
                event(tb, "error", f"{run_id}: unstable again on re-run; both attempts kept")
            if streak >= 2:
                pause(tb, f"two unstable or infrastructure-retried runs in a row (last {run_id})")
                return
            continue
        streak = 0
        set_run(run_id, verdict, **fields)
        event(tb, "info" if verdict == "accepted" else "warn",
              f"{run_id}: {verdict}" + (f" · p50 {result['placement_p50_ms']:.0f} ms, p99 {result['placement_p99_ms']:.0f} ms"
                                        if result.get("placement_p50_ms") is not None else "")
              + (f" · {result.get('reason')}" if verdict != "accepted" and result.get("reason") else "")
              + (f" · retransmitting above {GATE_RETRANS:.0%} through the cohort: "
                 + ", ".join(f"{n} {v:.0%}" for n, v in sorted(sick.items(), key=lambda kv: int(kv[0])))
                 if (sick := (result.get("network") or {}).get("sustained")) else ""))
        if verdict == "saturated":
            run = parse_run(run_id)
            order = list(RATES)
            for other in ids:
                o = parse_run(other)
                if (o["mode"], o["scen"]) == (run["mode"], run["scen"]) and order.index(o["rate"]) > order.index(run["rate"]):
                    if S.load()["runs"][other]["status"] == "pending":
                        set_run(other, "skipped", reason=f"{run['rate']} saturated in this sweep")
        if verdict == "failed":
            event(tb, "error", f"{run_id}: failed acceptance: {result.get('reason')}")
    if only:
        S.update(lambda P: (P["testbeds"][tb].__setitem__("state", "ready"), P["testbeds"][tb].__setitem__("current", None)))
        log(tb, f"finished the requested runs: {only}")
        return
    S.update(lambda P: (P["testbeds"][tb].__setitem__("state", "done"), P["testbeds"][tb].__setitem__("current", None)))
    log(tb, "queue complete")
    P = S.load()
    if all(P["testbeds"][t]["state"] == "done" for t in TESTBEDS):
        S.update(lambda P: P.__setitem__("state", "done"))


def pause(tb, why):
    event(tb, "error", f"testbed paused: {why}")

    def f(P):
        P["testbeds"][tb]["state"] = "paused"
        P["testbeds"][tb]["current"] = None
        P["state"] = "paused"
        P["note"] = f"{tb} paused: {why[:200]}"
    S.update(f)


# ---------------------------------------------------------------- setup

def setup(tb, presigned):
    """Stages the three binaries on every node from presigned URLs and verifies them."""
    b = json.load(open(AR / "provenance" / "binaries.json"))
    urls = json.load(open(presigned))
    ip = hosts(tb)

    def go(n):
        cmds = ["set -e", "mkdir -p /home/ubuntu/bins"]
        for mode in BINARIES:
            cmds.append(f"curl -sSf --retry 5 -o /home/ubuntu/bins/{mode} '{urls[mode]}'")
            cmds.append(f"chmod +x /home/ubuntu/bins/{mode}")
        cmds.append("sha256sum /home/ubuntu/bins/* ")
        cmds.append("which chronyc python3 curl gzip >/dev/null && echo TOOLS_OK")
        r = ssh(tb, ip[n][0], "; ".join(cmds), timeout=600)
        got = dict((p.split("/")[-1], s) for s, p in re.findall(r"^([0-9a-f]{64})\s+(\S+)$", r.stdout.decode(), re.M))
        ok = all(got.get(m) == b[m]["sha256"] for m in BINARIES) and "TOOLS_OK" in r.stdout.decode()
        return ok, r.stderr.decode()[-200:]
    res = par(go, validators(tb))
    bad = {n: e for n, (ok, e) in res.items() if not ok}
    print(json.dumps({"staged": len(res) - len(bad), "bad": bad}, indent=1))
    return not bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["setup", "run", "stop", "check"])
    ap.add_argument("tb", choices=list(TESTBEDS))
    ap.add_argument("--presigned")
    ap.add_argument("--only", nargs="*", help="run only these run IDs, in order")
    a = ap.parse_args()
    if a.cmd == "setup":
        sys.exit(0 if setup(a.tb, a.presigned) else 1)
    elif a.cmd == "stop":
        stop(a.tb)
    elif a.cmd == "check":
        problems, clocks = preflight(a.tb, "base")
        print(json.dumps({"problems": problems, "clocks_ms": clocks}, indent=1))
    else:
        run_queue(a.tb, a.only)


if __name__ == "__main__":
    main()
