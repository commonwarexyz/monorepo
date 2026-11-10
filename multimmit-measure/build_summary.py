#!/usr/bin/env python3
"""Builds summary.json.zst and manifest.json from runs/ and the published dataset.

summary.json.zst holds one record per attempt (schema 2), plus the published BlueBottle and Raptr
records copied unchanged with source "published". manifest.json lists every run, every
attempt and its status, and every archived file with its sha256. Re-running this script on the same
runs/ reproduces both files byte for byte.
"""
import gzip, hashlib, json, subprocess, sys
from pathlib import Path

AR = Path(__file__).resolve().parent.parent
PUBLISHED = AR / "provenance" / "published.json"
sys.path.insert(0, str(AR / "status"))
import status as S  # noqa: E402


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cohort_mean(prom, name, w0, w1, reduce_sum=True):
    series = prom.get("series", {}).get(name)
    if not isinstance(series, list) or not series:
        return None
    total, n = 0.0, 0
    stamps = sorted({float(t) for s in series for t, _ in s["values"] if w0 <= float(t) < w1})
    for t in stamps:
        vals = [float(v) for s in series for tt, v in s["values"] if float(tt) == t and v not in ("NaN", "+Inf")]
        if vals:
            total += sum(vals) if reduce_sum else sum(vals) / len(vals)
            n += 1
    return total / n if n else None


def main():
    records, manifest = [], {"runs": {}, "files": {}}
    P = S.load()
    for run in S.runs():
        rid = run["id"]
        rdir = AR / "runs" / rid
        entry = {"status": P["runs"][rid]["status"], "attempts": []}
        for a in sorted(rdir.glob("attempt-*"), key=lambda p: int(p.name.split("-")[1])) if rdir.exists() else []:
            meta = json.load(open(a / "run.json")) if (a / "run.json").exists() else {}
            res = a / "result.json"
            item = {"attempt": int(a.name.split("-")[1]), "error": meta.get("error")}
            if res.exists():
                r = json.load(open(res))
                item["verdict"] = r["verdict"]
                prom_p = a / "prometheus.json.gz"
                if prom_p.exists() and prom_p.stat().st_size > 0:
                    prom = json.load(gzip.open(prom_p, "rt"))
                    w0, w1 = (x / 1e6 for x in r["cohort_utc_us"])
                    r["traffic_MB_per_s"] = {
                        "host_network_tx": (lambda v: v and v / 1e6)(cohort_mean(prom, "net_tx_bytes", w0, w1)),
                        "host_network_rx": (lambda v: v and v / 1e6)(cohort_mean(prom, "net_rx_bytes", w0, w1)),
                        "runtime_outbound": (lambda v: v and v / 1e6)(cohort_mean(prom, "outbound_bandwidth", w0, w1)),
                        "engine_transmitted": (lambda v: v and v / 1e6)(cohort_mean(prom, "engine_transmitted_bytes", w0, w1)),
                        "engine_retransmitted": (lambda v: v and v / 1e6)(cohort_mean(prom, "engine_retransmitted_bytes", w0, w1)),
                    }
                    r["resources"] = {
                        "cpu_cores_mean_per_validator": cohort_mean(prom, "cpu_cores", w0, w1, reduce_sum=False),
                        "disk_flushes_per_s_per_validator": cohort_mean(prom, "disk_flushes", w0, w1, reduce_sum=False),
                        "mem_used_mean": cohort_mean(prom, "mem_used", w0, w1, reduce_sum=False),
                    }
                r["source"] = "this-archive"
                r["protocol"] = "Multimmit"
                r["topology"] = r["testbed"]
                records.append(r)
            entry["attempts"].append(item)
            for f in sorted(a.rglob("*")):
                if f.is_file():
                    manifest["files"][str(f.relative_to(AR))] = sha(f)
        manifest["runs"][rid] = entry
    if PUBLISHED.exists():
        for x in json.load(open(PUBLISHED)):
            if x["protocol"] != "Multimmit":
                records.append({**x, "source": "published", "latency_milestone": "placement"})
    for f in sorted((AR / "provenance").rglob("*")) + sorted((AR / "tools").glob("*.py")):
        if f.is_file():
            manifest["files"][str(f.relative_to(AR))] = sha(f)
    raw = json.dumps({"schema": 2, "records": records}, sort_keys=True, indent=None).encode()
    (AR / "summary.json").write_bytes(raw)
    subprocess.run(["zstd", "-q", "-f", "-19", "--no-progress", str(AR / "summary.json"), "-o", str(AR / "summary.json.zst")],
                   check=True)
    (AR / "summary.json").unlink()
    manifest["files"]["summary.json.zst"] = sha(AR / "summary.json.zst")
    json.dump(manifest, open(AR / "manifest.json", "w"), indent=1, sort_keys=True)
    print(json.dumps({"records": len(records), "files": len(manifest["files"])}))


if __name__ == "__main__":
    main()
