#!/usr/bin/env python3
"""Run fresh-process allocation comparisons; sample RSS while each phase is paused."""

import argparse
import datetime
import hashlib
import itertools
import json
import os
import pathlib
import re
import signal
import statistics
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--items", type=int, default=3_906_250)
    parser.add_argument("--p", type=int, choices=[2, 3], default=2)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--cache-bytes", type=int, default=1_048_576)
    parser.add_argument("--policies", nargs="+", choices=["slabs", "exact", "reuse"],
                        default=["slabs", "exact", "reuse"])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = args.output / "results.jsonl"
    if results.exists():
        parser.error(f"results already exist: {results}")
    binaries = {
        name: (args.binaries / f"index_scale_{name}").resolve()
        for name in args.policies
    }
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    env = dict(os.environ, INDEX_MEMORY_CHECKPOINTS="1", INDEX_BUFFER_CACHE_STATS="1",
               INDEX_BUFFER_CACHE_BYTES=str(args.cache_bytes))
    records = []
    choices = list(itertools.product(["u64", "packed"], binaries))
    for repetition in range(args.repetitions):
        order = choices[repetition:] + choices[:repetition]
        if repetition % 2:
            order.reverse()
        for value, policy in order:
            name = f"{repetition + 1}-{policy}-{value}"
            print(f"START {name} items={args.items}", flush=True)
            record = dict(run=name, policy=policy, value=value, items=args.items, p=args.p,
                          cache_bytes=args.cache_bytes, sha256=hashes[policy],
                          started=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          mimalloc_env={k: v for k, v in env.items() if k.startswith("MIMALLOC_")},
                          load_start=os.getloadavg(), rss={}, timings={})
            started = time.monotonic()
            timing_args = ["-l"] if sys.platform == "darwin" else ["-v"]
            stderr_path = args.output / f"{name}.stderr"
            with stderr_path.open("w") as stderr, (args.output / f"{name}.stdout").open("w") as stdout:
                process = subprocess.Popen(
                    ["/usr/bin/time", *timing_args, str(binaries[policy]), str(args.items),
                     f"relocate_{value}_{args.p}"], env=env, text=True,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                    start_new_session=True,
                )
                try:
                    for line in process.stdout:
                        stdout.write(line)
                        stdout.flush()
                        if line.startswith("index_scale: "):
                            assert f"allocation={policy}" in line, line
                            assert "allocator=mimalloc" in line, line
                        timing = re.search(r"::(\w+)/items=\d+ p=\d+ value_bytes=\d+ ns/op=([\d.]+)", line)
                        if timing:
                            record["timings"][timing[1]] = float(timing[2])
                        checkpoint = re.match(r"memory_checkpoint: phase=(\w+) pid=(\d+) keys=(\d+)", line)
                        if checkpoint:
                            phase, pid, keys = checkpoint.groups()
                            rss = int(subprocess.check_output(["ps", "-o", "rss=", "-p", pid], text=True)) * 1024
                            record["rss"][phase] = dict(bytes=rss, keys=int(keys),
                                bytes_per_key=rss / int(keys) if int(keys) else None)
                            process.stdin.write("\n")
                            process.stdin.flush()
                            print(f"  {name} {phase}: rss={rss} keys={keys}", flush=True)
                    code = process.wait()
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
            errors = stderr_path.read_text()
            assert code == 0 and len(record["timings"]) == 10, errors
            if sys.platform == "darwin":
                peak = re.search(r"(\d+)\s+maximum resident set size", errors)
                peak_bytes = int(peak[1])
            else:
                peak = re.search(r"Maximum resident set size \(kbytes\):\s+(\d+)", errors)
                peak_bytes = int(peak[1]) * 1024
            cache = re.search(r"buffer_cache: hits=(\d+) misses=(\d+) evicted=(\d+) peak_bytes=(\d+) cached_bytes=(\d+) budget=(\d+)", errors)
            if policy == "reuse":
                assert cache, errors
                record["cache"] = dict(zip(["hits", "misses", "evicted", "peak_bytes", "cached_bytes", "budget"], map(int, cache.groups())))
                assert record["cache"]["peak_bytes"] <= args.cache_bytes
            record.update(peak_rss_bytes=peak_bytes, wall_seconds=time.monotonic() - started,
                          load_end=os.getloadavg())
            records.append(record)
            with results.open("a") as output:
                output.write(json.dumps(record) + "\n")
            print(f"DONE {name}: {record['timings']}", flush=True)

    summary = []
    for value, policy in choices:
        group = [record for record in records if record["policy"] == policy and record["value"] == value]
        row = dict(policy=policy, value=value, items=args.items, p=args.p,
                   timings={phase: statistics.median(r["timings"][phase] for r in group)
                            for phase in group[0]["timings"]},
                   rss_bytes_per_key={phase: statistics.median(r["rss"][phase]["bytes_per_key"] for r in group)
                                      for phase in group[0]["rss"] if phase != "empty"},
                   peak_rss_bytes=statistics.median(r["peak_rss_bytes"] for r in group))
        if policy == "reuse":
            row["cache_hit_fraction"] = statistics.median(
                r["cache"]["hits"] / (r["cache"]["hits"] + r["cache"]["misses"]) for r in group)
        summary.append(row)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
