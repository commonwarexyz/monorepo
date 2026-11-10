#!/usr/bin/env python3
"""Analyzes one attempt directory into result.json: cohort latencies, acceptance checks and a verdict.

Placement of a block is the earlier of its placement event and its ordered delivery. The engine names
placed blocks only when it holds every history opening since the last one it placed; otherwise it places
them silently, or names them once the missing opening arrives. Ordered delivery implies a fixed position,
so delivery bounds placement from above and this measure stays conservative. Each record counts the
blocks placed without a name and the blocks named after delivery.

Latency is measured per block from its scheduled submission (started_at_us), so every transaction in a
block shares its block's latency and block-weighted statistics equal transaction-weighted ones.
The cohort is every block whose scheduled submission falls in [cohort start, cohort end).
"""
import bisect, gzip, json, math, re, statistics, sys
from collections import defaultdict
from pathlib import Path

TX_PER_BLOCK = 512
BODY = 262144
CLOCK_BOUND_MS = 2.0
BIN_S = 10


def with_last(it):
    """Yields each item of `it` with whether it is the last one."""
    it = iter(it)
    prev = next(it, None)
    if prev is None:
        return
    for x in it:
        yield prev, False
        prev = x
    yield prev, True


def pct(xs, p):
    xs = sorted(xs)
    i = (len(xs) - 1) * p
    lo = int(i)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


def stats(xs):
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "mean": round(statistics.fmean(xs), 2), "min": round(min(xs), 2),
            **{f"p{int(p * 100)}": round(pct(xs, p), 2) for p in (0.25, 0.5, 0.75, 0.9, 0.95, 0.99)},
            "max": round(max(xs), 2)}


def prom_value(text, family):
    total, seen = 0.0, False
    for line in text.splitlines():
        if line.startswith(family + " ") or line.startswith(family + "{"):
            try:
                total += float(line.rsplit(" ", 1)[1])
                seen = True
            except ValueError:
                pass
    return total if seen else None


# A victim block is censored when, had every leader been honest, it would have been placed in a censor's
# view. That view is read off the other chains: the median view in which their blocks submitted within
# CENSOR_MATCH_US of the victim block's submission were first finalized. Leaders rotate round-robin, so
# participant view mod n leads each view.
CENSOR_MATCH_US = 25_000


def censored_views(meta, cohort, starts, final_view, placed, first_class, victims):
    """Placement of the victim blocks the censors' views would have placed, against the other chains'
    blocks first finalized in those same views."""
    censors = set(meta["scenario"]["censors"])
    n = len(meta["live"]) + len(meta["scenario"]["crashed"])
    others = sorted((starts[k], final_view[k]) for k in starts if k[0] not in victims and k in final_view)
    times = [t for t, _ in others]

    def honest_view(t):
        a = bisect.bisect_left(times, t - CENSOR_MATCH_US)
        b = bisect.bisect_right(times, t + CENSOR_MATCH_US)
        return statistics.median_low([v for _, v in others[a:b]]) if b > a else None

    victim, other = [], []
    by_extension = 0
    for k in cohort:
        if k not in placed:
            continue
        if k[0] in victims:
            v = honest_view(starts[k])
            if v is not None and v % n in censors:
                victim.append((placed[k] - starts[k]) / 1000)
                by_extension += str(first_class.get(k, "")).startswith("extension")
        elif k in final_view and final_view[k] % n in censors:
            other.append((placed[k] - starts[k]) / 1000)
    return {"victim_placement": stats(victim), "other_placement": stats(other), "victim_blocks": len(victim),
            "victim_first_finalized_by_extension": by_extension,
            "victim_extension_share": round(by_extension / len(victim), 4) if victim else None,
            "match_window_ms": CENSOR_MATCH_US / 1000}


def main(d):
    d = Path(d)
    meta = json.load(open(d / "run.json"))
    t0_us = meta["schedule"]["start_unix_ms"] * 1000
    c0, c1 = meta["cohort_s"]
    w0, w1 = t0_us + c0 * 1_000_000, t0_us + c1 * 1_000_000
    live = [str(n) for n in meta["live"]]
    victims = set(meta["scenario"]["victims"])
    per_producer = meta["per_producer_bytes_per_second"]

    starts, signed = {}, {}
    final_view = {}
    ev = defaultdict(dict)
    first_class = {}
    covers = defaultdict(list)
    counts = defaultdict(int)
    unparsed = 0
    cut_tails = 0
    nodes_with_events = 0
    starts_by_producer = defaultdict(int)
    for n in live:
        f = d / "events" / f"{n}.jsonl.gz"
        if not f.exists() or f.stat().st_size < 30:
            continue
        nodes_with_events += 1
        with gzip.open(f, "rt", errors="replace") as fh:
            for line, last in with_last(fh):
                try:
                    x = json.loads(line)["fields"]
                except Exception:
                    # Stopping a node can cut its final log line short; any other bad line counts.
                    if last:
                        cut_tails += 1
                    else:
                        unparsed += 1
                    continue
                e = x.get("benchmark_event")
                if not e:
                    continue
                counts[e] += 1
                if e == "certificate_covers":
                    covers[(x["chain"], x["height"])].append(x["timestamp_us"])
                    continue
                k = (x["chain"], x["height"], x["digest"])
                if e == "start":
                    starts[k] = x["started_at_us"]
                    if w0 <= x["started_at_us"] < w1:
                        starts_by_producer[n] += 1
                elif e in ("signed", "certified", "receipt", "first_finalization", "placement", "ordered"):
                    if k not in ev[e]:
                        ev[e][k] = x["timestamp_us"]
                        if e == "first_finalization":
                            first_class[k] = x.get("reason")
                            if x.get("view") is not None:
                                final_view[k] = x["view"]
    cohort = [k for k, s in starts.items() if w0 <= s < w1]
    # Placement: the earlier of the named placement and ordered delivery (see the module docs).
    named = ev["placement"]
    unnamed = [k for k in cohort if k not in named and k in ev["ordered"]]
    late = [k for k in cohort if k in named and k in ev["ordered"] and named[k] > ev["ordered"][k]]
    late_ms = sorted((named[k] - ev["ordered"][k]) / 1000 for k in late)
    placement_accounting = {"named": sum(1 for k in cohort if k in named), "unnamed_delivered": len(unnamed),
                            "named_after_delivery": len(late),
                            "named_after_delivery_ms": stats(late_ms),
                            "unnamed_blocks": [list(k) for k in unnamed[:50]]}
    ev["placement"] = {k: min(t for t in (named.get(k), ev["ordered"].get(k)) if t is not None)
                       for k in set(named) | set(ev["ordered"])}
    lat = {}
    for e, name in (("placement", "placement"), ("first_finalization", "finalization"), ("ordered", "delivery"),
                    ("certified", "certification_producer"), ("receipt", "receipt"), ("signed", "signing")):
        vals = [(ev[e][k] - starts[k]) / 1000 for k in cohort if k in ev[e]]
        lat[name] = {**stats(vals), "missing": len(cohort) - len(vals)}
    for e, name in (("placement", "placement"), ("first_finalization", "finalization"), ("ordered", "delivery")):
        vals = [(ev[e][k] - ev["signed"][k]) / 1000 for k in cohort if k in ev[e] and k in ev["signed"]]
        lat[name + "_from_signing"] = stats(vals)
    # Certification at every validator, sampled every eighth height of every chain.
    by_height = {(k[0], k[1]): s for k, s in starts.items()}
    cov = {"first": [], "median": [], "last": []}
    seen_all = 0
    sampled = 0
    for (chain, height), times in covers.items():
        s = by_height.get((chain, height))
        if s is None or not (w0 <= s < w1):
            continue
        sampled += 1
        times = sorted(times)
        seen_all += len(times) >= len(live)
        cov["first"].append((times[0] - s) / 1000)
        cov["median"].append((pct(times, 0.5) - s) / 1000)
        cov["last"].append((times[-1] - s) / 1000)
    lat["certification_first_validator"] = stats(cov["first"])
    lat["certification_median_validator"] = stats(cov["median"])
    lat["certification_last_validator"] = stats(cov["last"])
    # Per 10 s series by scheduled submission.
    series = defaultdict(list)
    for k in cohort:
        if k in ev["placement"]:
            series[(starts[k] - w0) // (BIN_S * 1_000_000)].append((ev["placement"][k] - starts[k]) / 1000)
    series = [{"t_s": c0 + (b + 0.5) * BIN_S, "n": len(v), "p50": round(pct(v, 0.5), 1), "p99": round(pct(v, 0.99), 1)}
              for b, v in sorted(series.items())]
    classes = defaultdict(int)
    for k in cohort:
        if k in first_class:
            classes[first_class[k]] += 1
    censorship = None
    if victims:
        def sub(pred):
            return stats([(ev["placement"][k] - starts[k]) / 1000 for k in cohort if pred(k) and k in ev["placement"]])
        vic = [k for k in cohort if k[0] in victims]
        ext = sum(1 for k in vic if str(first_class.get(k, "")).startswith("extension"))
        censorship = {"victim_placement": sub(lambda k: k[0] in victims),
                      "other_placement": sub(lambda k: k[0] not in victims),
                      "victim_finalization": stats([(ev["first_finalization"][k] - starts[k]) / 1000 for k in vic
                                                    if k in ev["first_finalization"]]),
                      "victim_blocks": len(vic), "victim_first_finalized_by_extension": ext,
                      "victim_extension_share": round(ext / len(vic), 4) if vic else None,
                      "censored_views": censored_views(meta, cohort, starts, final_view, ev["placement"], first_class, victims)}

    # Scrape windows over the cohort.
    with gzip.open(d / "scrapes.json.gz", "rt") as fh:
        windows = json.load(fh)["windows"]
    cw = [w for w in windows if c0 < w["k"] * 10 <= c1]
    views = [w for w in cw]
    final_dropped, final_rx = 0.0, None
    loss_nodes = 0
    for n in live:
        f = d / "status" / f"{n}.prom.gz"
        if f.exists() and f.stat().st_size > 100:
            text = gzip.open(f, "rt").read()
            v = prom_value(text, "network_injected_loss_dropped_total")
            if v is not None:
                final_dropped += v
                loss_nodes += 1

    # Acceptance checks.
    cohort_seconds = c1 - c0
    expected_per_producer = per_producer * cohort_seconds / BODY
    offered = meta["offered_tps"]
    placed_in_cohort = sum(1 for k in cohort if k in ev["placement"])
    achieved = placed_in_cohort * TX_PER_BLOCK / cohort_seconds
    clocks = json.load(open(d / "clocks.json"))
    clock_vals = [v for part in ("preflight", "after") for v in clocks.get(part, {}).values()]
    status_ok = sum(1 for n in live if (d / "status" / f"{n}.prom.gz").exists() and (d / "status" / f"{n}.prom.gz").stat().st_size > 100)
    checks = {
        "steady": {"pass": bool(meta["gate"][-1]["passed"]), "value": f"{meta['extensions']} extensions"},
        "cohort_complete": {"pass": len(cohort) > 0 and lat["delivery"]["missing"] == 0 and lat["placement"]["missing"] == 0,
                            "value": f"{len(cohort)} blocks; undelivered {lat['delivery']['missing']}; "
                                     f"placed unnamed {len(unnamed)}, named after delivery {len(late)}"},
        "throughput": {"pass": achieved >= 0.95 * offered, "value": round(achieved)},
        "liveness": {"pass": nodes_with_events == len(live) and all(not w["missing"] and not w["inactive"] for w in cw),
                     "value": f"{nodes_with_events}/{len(live)} nodes with events"},
        "backlog": {"pass": bool(cw) and all(w["queue_p99_s"] is None or w["queue_p99_s"] < 1.0 for w in cw[-3:]),
                    "value": [w["queue_p99_s"] for w in cw[-3:]]},
        "accounting": {"pass": all(abs(starts_by_producer[n] - expected_per_producer) <= 1.5 for n in live),
                       "value": {"expected": round(expected_per_producer, 2),
                                 "min": min((starts_by_producer[n] for n in live), default=0),
                                 "max": max((starts_by_producer[n] for n in live), default=0),
                                 "outliers": [n for n in live if abs(starts_by_producer[n] - expected_per_producer) > 1.5]}},
        "clocks": {"pass": bool(clock_vals) and all(v is not None and abs(v) <= CLOCK_BOUND_MS for v in clock_vals),
                   "value": round(max((abs(v) for v in clock_vals if v is not None), default=-1), 3)},
        "telemetry": {"pass": nodes_with_events == len(live) and status_ok == len(live) and unparsed == 0,
                      "value": f"events {nodes_with_events}, metrics {status_ok}, unparsed lines {unparsed}, "
                               f"final lines cut by stop {cut_tails}"},
    }
    # TCP retransmission share per node over the cohort windows, reported as a network condition.
    sick_windows, retrans = {}, {}
    for w in cw:
        for n, share in w.get("retransmitting", {}).items():
            sick_windows[n] = sick_windows.get(n, 0) + 1
            retrans[n] = max(retrans.get(n, 0.0), share)
    sick = {n: retrans[n] for n, count in sick_windows.items() if 2 * count >= max(1, len(cw))}
    network = {"sustained": sick, "max": retrans}
    if meta["scenario"]["loss"] > 0:
        checks["loss_injected"] = {"pass": loss_nodes == len(live) and final_dropped > 0, "value": final_dropped}
    failed = [k for k, v in checks.items() if not v["pass"]]
    if not checks["steady"]["pass"]:
        verdict = "saturated" if meta.get("unsteady_diagnosis") == "saturated" else "unstable"
        reason = "; ".join(meta["gate"][-1]["fails"])[:300]
    elif set(failed) & {"clocks", "telemetry", "liveness"}:
        verdict = "infra"
        reason = "; ".join(f"{k}: {checks[k]['value']}" for k in failed)
    elif failed:
        verdict = "failed"
        reason = "; ".join(f"{k}: {checks[k]['value']}" for k in failed)
    else:
        verdict = "accepted"
        reason = None
    round_p50 = [w["round_p50_s"] for w in cw if w.get("round_p50_s") is not None]
    nulls = [w["nullifications"] for w in cw]
    out = {
        "schema": 2, "run_id": meta["run_id"], "attempt": meta["attempt"], "testbed": meta["testbed"],
        "mode": meta["mode"], "scenario": meta["scenario"], "rate": meta["rate"], "offered_tps": offered,
        "fsync": meta["mode"] == "base-fsync", "seed": meta["seed"], "commit": meta["commit"],
        "binary": meta["binary"], "cluster_tag": meta["cluster_tag"],
        "cohort_utc_us": [w0, w1], "verdict": verdict, "reason": reason, "checks": checks, "network": network,
        "achieved_tps": round(achieved),
        "placement_p50_ms": lat["placement"].get("p50"), "placement_p99_ms": lat["placement"].get("p99"),
        "latency_ms": lat, "placement_events": placement_accounting, "series": series, "first_finality_classes": dict(classes),
        "censorship": censorship, "views": {"round_p50_ms_windows": [round(v * 1000, 1) for v in round_p50],
                                            "nullifications_per_window": nulls},
        "loss": {"dropped_messages": final_dropped} if meta["scenario"]["loss"] > 0 else None,
        "gate": meta["gate"], "extensions": meta["extensions"], "drain": meta["drain"],
        "event_counts": dict(counts), "cohort_blocks": len(cohort),
        "sampled_heights": sampled, "sampled_heights_seen_by_all": seen_all,
    }
    json.dump(out, open(d / "result.json", "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("run_id", "verdict", "reason", "achieved_tps", "placement_p50_ms",
                                          "placement_p99_ms", "cohort_blocks")}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
