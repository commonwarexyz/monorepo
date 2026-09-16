#!/usr/bin/env python3
"""Run and archive the explicit Bajillion publication matrix."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[4]
RESULTS_PREFIX = "clearing/src/bajillion/benches/results/"
GIB = 1024**3

DEFAULT_PROFILES = (
    (1_000_000, 1_000, 512, 1),
    (1_000_000, 10_000, 512, 1),
    (1_000_000, 100_000, 512, 1),
    (1_000_000, 1_000_000, 512, 1),
)
DEFAULT_ACTIVITY = (
    (0, 1_000), (0, 10_000), (0, 100_000), (0, 1_000_000),
)
DEFAULT_PAYOUT = (
    (0, 0), (0, 1), (0, 1_024), (0, 500_000), (0, 1_000_000),
    (1_024, 1), (65_536, 1), (1_000_000, 1),
)
DEFAULT_ACK = (
    (1_000_000, 1_000, 512, 1, 0, 0),
    (1_000_000, 10_000, 512, 1, 0, 0),
    (1_000_000, 100_000, 512, 1, 0, 0),
    (1_000_000, 1_000_000, 512, 1, 0, 0),
)


def parse_tuple(value: str, width: int, label: str) -> tuple[int, ...]:
    try:
        result = tuple(int(part) for part in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{label} must contain integers") from error
    if len(result) != width or any(number < 0 for number in result):
        raise argparse.ArgumentTypeError(
            f"{label} requires {width} comma-separated nonnegative integers"
        )
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def capture(*command: str) -> bytes:
    return subprocess.check_output(command, cwd=ROOT)


def optional_capture(*command: str) -> str | None:
    try:
        return capture(*command).decode(errors="replace")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def filesystem(path: Path) -> dict[str, str]:
    resolved = path.resolve()
    candidates = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        detail = after.split()
        mount = Path(fields[4].replace("\\040", " "))
        try:
            resolved.relative_to(mount)
        except ValueError:
            continue
        candidates.append((len(mount.parts), mount, fields[5], detail[0], detail[1]))
    if not candidates:
        raise RuntimeError(f"cannot resolve filesystem for {resolved}")
    _, mount, options, kind, device = max(candidates)
    if kind in {"tmpfs", "ramfs", "overlay"}:
        raise RuntimeError(f"benchmark storage must be a real filesystem, got {kind}")
    return {"mount": str(mount), "options": options, "type": kind, "device": device}


def source_files(root: Path = ROOT) -> list[Path]:
    encoded = subprocess.check_output(
        ("git", "ls-files", "-co", "--exclude-standard", "-z"), cwd=root
    )
    paths = []
    for raw in encoded.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        if relative.as_posix().startswith(RESULTS_PREFIX):
            continue
        path = root / relative
        if path.is_file():
            paths.append(relative)
    return sorted(set(paths), key=lambda path: path.as_posix())


def source_fingerprint(paths: list[Path], root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        with (root / relative).open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        digest.update(b"\0")
    return digest.hexdigest()


def snapshot_source(output: Path, paths: list[Path]) -> dict[str, object]:
    patch = capture(
        "git", "diff", "--binary", "HEAD", "--", ".", f":(exclude){RESULTS_PREFIX}"
    )
    patch_path = output / "source.patch.gz"
    with patch_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
            stream.write(patch)
    lock = ROOT / "Cargo.lock"
    shutil.copy2(lock, output / "Cargo.lock")
    tracked = set(
        Path(os.fsdecode(raw))
        for raw in capture("git", "ls-files", "-z").split(b"\0")
        if raw
    )
    untracked = [path for path in paths if path not in tracked]
    archive = output / "untracked-source.tar.gz"
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for relative in untracked:
                    source = ROOT / relative
                    info = tar.gettarinfo(str(source), arcname=relative.as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    with source.open("rb") as stream:
                        tar.addfile(info, stream)
    return {
        "base_revision": capture("git", "rev-parse", "HEAD").decode().strip(),
        "source_sha256": source_fingerprint(paths),
        "source_file_count": len(paths),
        "patch_sha256": sha256(patch_path),
        "untracked_archive_sha256": sha256(archive),
        "lockfile_sha256": sha256(output / "Cargo.lock"),
        "results_excluded": RESULTS_PREFIX,
    }


def reconstruct_source(output: Path, source: dict[str, object], paths: list[Path],
                       destination: Path) -> None:
    subprocess.check_call(
        ("git", "clone", "--quiet", "--no-local", str(ROOT), str(destination))
    )
    subprocess.check_call(
        ("git", "checkout", "--quiet", "--detach", str(source["base_revision"])),
        cwd=destination,
    )
    with gzip.open(output / "source.patch.gz", "rb") as stream:
        subprocess.run(
            ("git", "apply", "--binary", "-"), cwd=destination,
            input=stream.read(), check=True,
        )
    with tarfile.open(output / "untracked-source.tar.gz", "r:gz") as archive:
        archive.extractall(destination, filter="data")
    shutil.copy2(output / "Cargo.lock", destination / "Cargo.lock")
    reconstructed = source_files(destination)
    if reconstructed != paths:
        raise RuntimeError("reconstructed source file inventory differs from snapshot")
    if source_fingerprint(paths, destination) != source["source_sha256"]:
        raise RuntimeError("reconstructed source fingerprint differs from snapshot")


def read_proc(pid: int) -> dict[str, object] | None:
    root = Path("/proc") / str(pid)
    try:
        stat = (root / "stat").read_text().rsplit(")", 1)[1].split()
        status = (root / "status").read_text().splitlines()
        io = (root / "io").read_text().splitlines()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None

    def field(lines: list[str], name: str) -> int | None:
        for line in lines:
            if line.startswith(name):
                try:
                    return int(line[len(name):].split()[0])
                except (IndexError, ValueError):
                    return None
        return None

    threads = {}
    try:
        for task in (root / "task").iterdir():
            fields = (task / "stat").read_text().rsplit(")", 1)[1].split()
            threads[task.name] = int(fields[11]) + int(fields[12])
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return {
        "monotonic_ns": time.monotonic_ns(),
        "user_ticks": int(stat[11]),
        "system_ticks": int(stat[12]),
        "rss_kib": field(status, "VmRSS:"),
        "hwm_kib": field(status, "VmHWM:"),
        "read_bytes": field(io, "read_bytes:"),
        "write_bytes": field(io, "write_bytes:"),
        "thread_ticks": threads,
    }


def process_group_sample(pid: int) -> dict[str, object] | None:
    snapshots = []
    descendants = {pid}
    changed = True
    while changed:
        changed = False
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) in descendants:
                continue
            try:
                fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                parent = int(fields[1])
            except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
                continue
            if parent in descendants:
                descendants.add(int(entry.name))
                changed = True
    for child in sorted(descendants):
        sample = read_proc(child)
        if sample is not None:
            snapshots.append(sample)
    if not snapshots:
        return None
    return {
        "monotonic_ns": time.monotonic_ns(),
        "processes": len(snapshots),
        "user_ticks": sum(int(sample["user_ticks"]) for sample in snapshots),
        "system_ticks": sum(int(sample["system_ticks"]) for sample in snapshots),
        "rss_kib": sum(int(sample["rss_kib"] or 0) for sample in snapshots),
        "hwm_kib": sum(int(sample["hwm_kib"] or 0) for sample in snapshots),
        "read_bytes": sum(int(sample["read_bytes"] or 0) for sample in snapshots),
        "write_bytes": sum(int(sample["write_bytes"] or 0) for sample in snapshots),
        "thread_ticks": {
            f"{index}:{thread}": ticks
            for index, sample in enumerate(snapshots)
            for thread, ticks in sample["thread_ticks"].items()
        },
    }


def monitor(pid: int, destination: Path, stop: threading.Event) -> None:
    with destination.open("w") as stream:
        while not stop.wait(1):
            sample = process_group_sample(pid)
            if sample is None:
                return
            stream.write(json.dumps(sample, sort_keys=True) + "\n")
            stream.flush()


def binary_from_build_log(path: Path, target_name: str) -> Path:
    candidates = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        executable = record.get("executable")
        target = record.get("target", {})
        if executable and target.get("name") == target_name:
            candidates.append(Path(executable))
    if len(candidates) != 1 or not candidates[0].is_file():
        raise RuntimeError(f"expected one executable for {target_name}, got {candidates}")
    return candidates[0]


def validate_ack(path: Path, case: tuple[int, ...], samples: int, warmup: int,
                 workers: int, runtime_workers: int) -> None:
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    metadata = [record for record in records if record.get("record") == "ack_metadata"]
    observed = [record for record in records if record.get("record") == "ack_sample"]
    if len(metadata) != 1 or len(observed) != samples + warmup:
        raise RuntimeError("ACK output has the wrong metadata/sample inventory")
    meta = metadata[0]
    n, a, b, k, w, h = case
    expected = {"n": n, "a": a, "b": b, "k": k, "w": w, "h": h}
    if any(meta.get(key) != value for key, value in expected.items()):
        raise RuntimeError("ACK metadata dimensions differ from the requested case")
    required = {
        "samples": samples,
        "warmup": warmup,
        "benchmark_limits": True,
        "native_strategy": "rayon_adaptive",
        "native_worker_pools": 1,
        "workers": workers,
        "runtime_workers": runtime_workers,
        "public_store_concurrency": 3,
        "private_control_after_public_commit": True,
        "native_logical_page_bytes": 4084,
        "native_physical_page_bytes": 4096,
        "native_cache_pages": 262144,
        "native_cache_budget_bytes": 1073741824,
        "native_cache_instances": 1,
        "native_state_activity_write_buffer_bytes": 268435456,
        "native_payout_write_buffer_bytes": 8388608,
        "native_replay_buffer_bytes": 8388608,
        "native_private_write_replay_buffer_bytes": 8388608,
        "native_log_operations_per_section": 33554432,
        "native_log_merkle_nodes_per_blob": 67108864,
        "native_state_operations_per_blob": 33554432,
        "native_state_merkle_nodes_per_blob": 67108864,
    }
    if any(meta.get(key) != value for key, value in required.items()):
        raise RuntimeError("ACK metadata contract mismatch")
    row_count = meta.get("row_count")
    activity_append_operations = meta.get("activity_append_operations")
    if (
        not isinstance(row_count, int)
        or row_count <= 0
        or activity_append_operations != row_count + a * k
        or not isinstance(meta.get("activity_append_bytes"), int)
        or meta["activity_append_bytes"] < activity_append_operations
    ):
        raise RuntimeError("ACK activity-Append inventory is inconsistent")
    if (
        meta.get("payout_output_operations") != w
        or not isinstance(meta.get("payout_output_bytes"), int)
        or (w == 0 and meta["payout_output_bytes"] != 0)
        or (w > 0 and meta["payout_output_bytes"] < w)
    ):
        raise RuntimeError("ACK payout-output inventory is inconsistent")
    withdrawal_output_bytes = meta.get("withdrawal_output_bytes")
    if (w == 0 and withdrawal_output_bytes != 0) or (
        w > 0 and (not isinstance(withdrawal_output_bytes, int) or withdrawal_output_bytes <= 0)
    ):
        raise RuntimeError("ACK signed-pipeline withdrawal output size is inconsistent with W")
    heads = set()
    manifests = set()
    for index, sample in enumerate(observed):
        if sample.get("sample") != index or sample.get("warmup") != (index < warmup):
            raise RuntimeError("ACK sample order/warmup marker mismatch")
        if not isinstance(sample.get("ns"), int) or sample["ns"] <= 0:
            raise RuntimeError("ACK sample duration must be positive integer nanoseconds")
        if sample.get("reopen_verified") is not True:
            raise RuntimeError("ACK sample lacks raw reopen verification")
        if any(sample.get(key, 0) <= 0 for key in
               ("state_operations", "activity_operations", "payout_operations")):
            raise RuntimeError("ACK sample lacks advancing public operation counts")
        heads.add(sample.get("public_head_sha256"))
        manifests.add(sample.get("private_manifest_sha256"))
        if w == n and (sample.get("live_accounts_after") != 0 or sample.get("deletions") != n):
            raise RuntimeError("full-exit ACK did not delete all live accounts")
    if None in heads or None in manifests or len(heads) != 1 or len(manifests) != 1:
        raise RuntimeError("fixed-parent ACK samples changed public/private commitments")


def mean_per_iteration(times: list[float], iterations: list[float]) -> float:
    if not times or len(times) != len(iterations):
        raise RuntimeError("Criterion times/iterations length mismatch")
    if any(value <= 0 for value in times) or any(value <= 0 for value in iterations):
        raise RuntimeError("Criterion times/iterations must be positive")
    return statistics.fmean(
        elapsed / count for elapsed, count in zip(times, iterations, strict=True)
    )


def validate_raw_samples(
    path: Path,
    expected_kind: str,
    expected_samples: int,
    expected_boundary: str,
    expected_dimensions: dict[str, int] | None = None,
    expected_names: set[str] | None = None,
) -> dict[str, list[dict[str, object]]]:
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    metadata = [record for record in records if record.get("record") == "raw_metadata"]
    observed = [record for record in records if record.get("record") == "raw_sample"]
    if not metadata or len(metadata) + len(observed) != len(records):
        raise RuntimeError("raw output contains unknown records or no metadata")
    by_name = {}
    for meta in metadata:
        name = meta.get("name")
        if not isinstance(name, str) or not name or name in by_name:
            raise RuntimeError("raw metadata names must be unique nonempty strings")
        if (
            meta.get("kind") != expected_kind
            or meta.get("boundary") != expected_boundary
            or type(meta.get("samples")) is not int
            or meta.get("samples") != expected_samples
            or type(meta.get("iterations_per_sample")) is not int
            or meta["iterations_per_sample"] <= 0
        ):
            raise RuntimeError(f"raw metadata contract mismatch for {name}")
        if expected_dimensions and any(
            type(meta.get(key)) is not type(value) or meta.get(key) != value
            for key, value in expected_dimensions.items()
        ):
            raise RuntimeError(f"raw metadata dimensions differ for {name}")
        if expected_kind == "prepare" and not (
            meta["iterations_per_sample"] == 1
            and type(meta.get("expected_bytes")) is int
            and meta["expected_bytes"] > 0
        ):
            raise RuntimeError(f"raw prepare encoding contract mismatch for {name}")
        if expected_kind == "activity_verify" and not (
            meta["iterations_per_sample"] == 1_000
            and meta.get("fixture") == "standalone_rows_without_payment_entries"
            and type(meta.get("lookup_bytes")) is int
            and meta["lookup_bytes"] > 0
            and type(meta.get("head_bytes")) is int
            and meta["head_bytes"] > 0
            and isinstance(meta.get("expected_present"), bool)
        ):
            raise RuntimeError(f"raw activity encoding contract mismatch for {name}")
        samples = [record for record in observed if record.get("name") == name]
        if len(samples) != expected_samples:
            raise RuntimeError(f"raw sample count mismatch for {name}")
        for index, sample in enumerate(samples):
            if (
                sample.get("kind") != expected_kind
                or type(sample.get("sample")) is not int
                or sample.get("sample") != index
                or type(sample.get("iterations")) is not int
                or sample.get("iterations") != meta["iterations_per_sample"]
                or type(sample.get("total_ns")) is not int
                or sample["total_ns"] <= 0
                or sample.get("verified") is not True
            ):
                raise RuntimeError(f"raw sample contract mismatch for {name} sample {index}")
        by_name[name] = samples
    if any(record.get("name") not in by_name for record in observed):
        raise RuntimeError("raw sample lacks matching metadata")
    if expected_names is not None and set(by_name) != expected_names:
        raise RuntimeError(
            "raw benchmark inventory mismatch: "
            f"missing={sorted(expected_names - set(by_name))} "
            f"unexpected={sorted(set(by_name) - expected_names)}"
        )
    return by_name


def activity_raw_names(history: int, rows: int) -> set[str]:
    operations = history + rows + 2 + (1 if history > 0 else 0)
    key = f"H={history} R={rows} operations={operations} floor=0"
    if rows == 0:
        cases = ("absence_empty",)
    elif rows == 1:
        cases = ("presence", "absence_left", "absence_right")
    else:
        cases = ("presence", "absence_left", "absence_adjacent", "absence_right")
    return {
        f"bajillion::native_proofs::activity_verify/{case}/{key}"
        for case in cases
    }


def aggregate_checks(output: Path, ack_cases: tuple[tuple[int, ...], ...]) -> dict[str, str]:
    """Archive emitted check records and normalize every encoded byte field."""
    records = []
    rows = []
    token = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?P<value>\S+)")
    directories = sorted(
        path for path in output.iterdir()
        if path.is_dir() and any(marker in path.name for marker in
                                 ("-check", "-sizes-", "-challenge-", "-ack-N"))
    )
    for directory in directories:
        rows_before = len(rows)
        stdout = directory / "stdout.log"
        if not stdout.is_file():
            raise RuntimeError(f"missing check log: {stdout}")
        for line in stdout.read_text(errors="replace").splitlines():
            try:
                structured = json.loads(line)
            except json.JSONDecodeError:
                structured = None
            if isinstance(structured, dict) and structured.get("record") == "ack_metadata":
                records.append({"command": directory.name, "line": line})
                dimensions = {
                    key: value for key, value in structured.items()
                    if key in {"n", "a", "b", "k", "w", "h", "backend", "boundary",
                               "native_strategy", "workers", "native_worker_pools",
                               "runtime_workers", "public_store_concurrency"}
                }
                for key, value in structured.items():
                    if key.endswith("_bytes") and isinstance(value, int):
                        rows.append({
                            "command": directory.name,
                            "scope": "durable_ack metadata",
                            "metric": key.removesuffix("_bytes"),
                            "bytes": value,
                            "dimensions_json": json.dumps(
                                dimensions, sort_keys=True, separators=(",", ":")
                            ),
                        })
                continue
            fields = [(match.group("key"), match.group("value"))
                      for match in token.finditer(line)]
            byte_fields = [(key, value) for key, value in fields if key.endswith("_bytes")]
            if not byte_fields:
                continue
            record = {"command": directory.name, "line": line}
            records.append(record)
            dimensions = {key: value for key, value in fields if not key.endswith("_bytes")}
            prefix = line[:token.search(line).start()].strip().rstrip(" /") if token.search(line) else line
            for key, value in byte_fields:
                try:
                    encoded_bytes = int(value.rstrip(","))
                except ValueError as error:
                    raise RuntimeError(f"non-integer byte result in {line!r}") from error
                rows.append({
                    "command": directory.name,
                    "scope": prefix,
                    "metric": key.removesuffix("_bytes"),
                    "bytes": encoded_bytes,
                    "dimensions_json": json.dumps(dimensions, sort_keys=True,
                                                   separators=(",", ":")),
                })
        if len(rows) == rows_before:
            raise RuntimeError(f"check log contains no encoded-byte results: {stdout}")
    if not rows:
        raise RuntimeError("no encoded-byte check records found")
    expected_package_sizes = {
        "root_bundle": 184,
        "descriptor": 192,
        "header_certificate": 101,
        "header_roots_withdrawal_total_certificate": 293,
    }
    for metric, expected in expected_package_sizes.items():
        observed = {
            row["bytes"] for row in rows
            if row["scope"] == "clearing sizes:" and row["metric"] == metric
        }
        if observed != {expected}:
            raise RuntimeError(
                f"canonical {metric} size mismatch: got {sorted(observed)}, "
                f"expected {[expected]}"
            )
    compact_outputs = {
        row["bytes"] for row in rows
        if row["scope"] == "clearing withdrawal claim:" and row["metric"] == "output"
    }
    signed_outputs = {
        row["bytes"] for row in rows
        if row["scope"] == "durable_ack metadata"
        and row["metric"] == "withdrawal_output" and row["bytes"] > 0
    }
    if len(compact_outputs) > 1:
        raise RuntimeError("compact withdrawal fixtures disagree on output-frame size")
    if any(case[4] > 0 for case in ack_cases):
        if len(signed_outputs) != 1:
            raise RuntimeError("expected one nonempty signed-pipeline output-frame size")
        if compact_outputs == signed_outputs:
            raise RuntimeError("compact and signed-pipeline output fixtures unexpectedly match")
    elif signed_outputs:
        raise RuntimeError("check inventory unexpectedly contains a signed withdrawal output")
    bytes_path = output / "bytes.csv"
    with bytes_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=(
            "command", "scope", "metric", "bytes", "dimensions_json"
        ))
        writer.writeheader()
        writer.writerows(rows)
    checks_path = output / "raw-checks.jsonl.gz"
    with checks_path.open("wb") as raw_stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_stream, mtime=0) as stream:
            for record in records:
                stream.write((json.dumps(record, sort_keys=True) + "\n").encode())
    return {
        "bytes.csv": sha256(bytes_path),
        "raw-checks.jsonl.gz": sha256(checks_path),
    }


def aggregate(output: Path, proof_samples: int, raw_samples: int, ack_samples: int,
              ack_cases: tuple[tuple[int, ...], ...],
              expected_criterion: set[str], expected_raw: set[str]) -> dict[str, str]:
    timing_rows = []
    raw = []
    names = set()
    observed_ack_cases = []
    criterion_roots = [output / "criterion"]
    criterion_roots.extend(sorted((output / "criterion-cases").glob("*")))
    for criterion in criterion_roots:
        if not criterion.is_dir():
            continue
        for estimate_path in sorted(criterion.glob("**/new/estimates.json")):
            directory = estimate_path.parent
            benchmark_path = directory / "benchmark.json"
            sample_path = directory / "sample.json"
            if not benchmark_path.is_file() or not sample_path.is_file():
                raise RuntimeError(f"incomplete Criterion record: {directory}")
            benchmark = json.loads(benchmark_path.read_text())
            estimates = json.loads(estimate_path.read_text())
            sample = json.loads(sample_path.read_text())
            name = benchmark["full_id"]
            if name in names:
                raise RuntimeError(f"duplicate benchmark ID: {name}")
            names.add(name)
            if len(sample["times"]) != proof_samples:
                raise RuntimeError(
                    f"{name} has {len(sample['times'])} samples, expected {proof_samples}"
                )
            timing_rows.append({
                "kind": "criterion",
                "name": name,
                "mean_ns": mean_per_iteration(sample["times"], sample["iters"]),
                "samples": len(sample["times"]),
            })
            raw.append({
                "kind": "criterion",
                "benchmark": benchmark,
                "estimates": estimates,
                "sample": sample,
            })
        for report in sorted(criterion.glob("**/report"), reverse=True):
            if report.is_dir():
                shutil.rmtree(report)
    observed_raw = set()
    boundaries = {
        "prepare": "detached_inputs_to_prepared_dealing_return",
        "activity_verify": "decoded_lookup_to_resolve_result",
    }
    for stdout in sorted(output.glob("*-raw/stdout.log")):
        records = [json.loads(line) for line in stdout.read_text().splitlines() if line.strip()]
        kinds = {record.get("kind") for record in records}
        if len(kinds) != 1 or next(iter(kinds)) not in boundaries:
            raise RuntimeError(f"raw output has unknown or mixed kinds: {stdout}")
        kind = next(iter(kinds))
        samples = validate_raw_samples(stdout, kind, raw_samples, boundaries[kind])
        metadata = {
            record["name"]: record
            for record in records
            if record.get("record") == "raw_metadata"
        }
        for name, values in samples.items():
            if name in names:
                raise RuntimeError(f"duplicate benchmark ID: {name}")
            names.add(name)
            observed_raw.add(name)
            timing_rows.append({
                "kind": f"raw_{kind}",
                "name": name,
                "mean_ns": statistics.fmean(
                    record["total_ns"] / record["iterations"] for record in values
                ),
                "samples": len(values),
            })
            raw.append({
                "kind": f"raw_{kind}",
                "metadata": metadata[name],
                "samples": values,
            })
    for stdout in sorted(output.glob("*-ack-*-timed/stdout.log")):
        records = [json.loads(line) for line in stdout.read_text().splitlines() if line.strip()]
        metadata = next(record for record in records if record.get("record") == "ack_metadata")
        observed_ack_cases.append(tuple(metadata[key] for key in ("n", "a", "b", "k", "w", "h")))
        samples = [record for record in records
                   if record.get("record") == "ack_sample" and not record["warmup"]]
        name = metadata["name"]
        if name in names:
            raise RuntimeError(f"duplicate benchmark ID: {name}")
        names.add(name)
        if len(samples) != ack_samples:
            raise RuntimeError(
                f"{name} has {len(samples)} samples, expected {ack_samples}"
            )
        values = [record["ns"] for record in samples]
        timing_rows.append({
            "kind": "durable_ack",
            "name": name,
            "mean_ns": statistics.fmean(values),
            "samples": len(values),
        })
        raw.append({"kind": "durable_ack", "records": records})
    timings = output / "timings.csv"
    if expected_criterion and not any(row["kind"] == "criterion" for row in timing_rows):
        raise RuntimeError("no Criterion timing records found")
    if not any(row["kind"] == "durable_ack" for row in timing_rows):
        raise RuntimeError("no durable ACK timing records found")
    if sorted(observed_ack_cases) != sorted(ack_cases):
        raise RuntimeError(
            f"durable ACK inventory mismatch: got {observed_ack_cases}, expected {ack_cases}"
        )
    observed_criterion = {row["name"] for row in timing_rows if row["kind"] == "criterion"}
    if observed_criterion != expected_criterion:
        raise RuntimeError(
            "Criterion inventory mismatch: "
            f"missing={sorted(expected_criterion - observed_criterion)} "
            f"unexpected={sorted(observed_criterion - expected_criterion)}"
        )
    if observed_raw != expected_raw:
        raise RuntimeError(
            "raw sample inventory mismatch: "
            f"missing={sorted(expected_raw - observed_raw)} "
            f"unexpected={sorted(observed_raw - expected_raw)}"
        )
    with timings.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=(
            "kind", "name", "mean_ns", "samples"
        ))
        writer.writeheader()
        writer.writerows(sorted(timing_rows, key=lambda row: (row["kind"], row["name"])))
    samples_path = output / "samples.jsonl.gz"
    with samples_path.open("wb") as raw_stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_stream, mtime=0) as stream:
            for record in raw:
                stream.write((json.dumps(record, sort_keys=True) + "\n").encode())
    return {
        "timings.csv": sha256(timings),
        "samples.jsonl.gz": sha256(samples_path),
    }


def validate_criterion_case(
    criterion: Path, expected_titles: set[str], samples: int
) -> set[str]:
    observed = {}
    for estimate_path in sorted(criterion.glob("**/new/estimates.json")):
        directory = estimate_path.parent
        benchmark_path = directory / "benchmark.json"
        sample_path = directory / "sample.json"
        if not benchmark_path.is_file() or not sample_path.is_file():
            raise RuntimeError(f"incomplete Criterion record: {directory}")
        benchmark = json.loads(benchmark_path.read_text())
        json.loads(estimate_path.read_text())
        sample = json.loads(sample_path.read_text())
        name = benchmark["full_id"]
        if name in observed:
            raise RuntimeError(f"duplicate Criterion record: {name}")
        observed[name] = (
            benchmark["title"], len(sample["times"]), len(sample["iters"])
        )
    matched = set()
    missing = []
    for title in expected_titles:
        candidates = [name for name, record in observed.items() if record[0] == title]
        if len(candidates) != 1:
            missing.append(title)
        else:
            matched.add(candidates[0])
    if missing:
        raise RuntimeError(f"missing or ambiguous Criterion records: {sorted(missing)}")
    unexpected = set(observed) - matched
    if unexpected:
        raise RuntimeError(f"unexpected Criterion records: {sorted(unexpected)}")
    wrong = {
        name: {"times": observed[name][1], "iters": observed[name][2]}
        for name in matched
        if observed[name][1] != samples or observed[name][2] != samples
    }
    if wrong:
        raise RuntimeError(f"Criterion sample count mismatch: {wrong}, expected {samples}")
    return matched


def cargo_home_config() -> dict[str, str]:
    root = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    return {
        name: sha256(root / name)
        for name in ("config.toml", "config")
        if (root / name).is_file()
    }


class Runner:
    def __init__(self, args: argparse.Namespace, output: Path, source: dict[str, object],
                 paths: list[Path], root: Path) -> None:
        self.args = args
        self.output = output
        self.source = source
        self.paths = paths
        self.root = root
        self.commands: list[dict[str, object]] = []
        self.outputs: dict[str, str] = {}
        self.binaries: dict[str, Path] = {}
        self.expected_criterion: set[str] = set()
        self.expected_raw: set[str] = set()
        self.manifest_path = output / "manifest.json"

    def save(self) -> None:
        manifest = {
            "schema": 1,
            "started_utc": self.args.started_utc,
            "source": self.source,
            "cpu_tick_hz": os.sysconf("SC_CLK_TCK"),
            "host": {
                "uname": optional_capture("uname", "-a"),
                "os_release": Path("/etc/os-release").read_text() if Path("/etc/os-release").is_file() else None,
                "cpu": optional_capture("lscpu"),
                "memory": optional_capture("free", "-b"),
                "block_devices": optional_capture("lsblk", "-J", "-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS"),
                "filesystem_details": optional_capture(
                    "findmnt", "-J", "-o", "SOURCE,FSTYPE,SIZE,USED,AVAIL,OPTIONS",
                    "-T", str(self.args.storage_directory),
                ),
                "storage_filesystem": filesystem(self.args.storage_directory),
                "rustc": optional_capture("rustc", "-Vv"),
                "cargo": optional_capture("cargo", "-V"),
                "cc": optional_capture("cc", "--version"),
                "linker": optional_capture("ld", "--version"),
            },
            "plan": vars(self.args.plan),
            "resource_contract": {
                "gates": ["rss", "free_disk", "elapsed_time"],
                "process_count": "telemetry_only",
            },
            "build_environment": {
                "rustup_toolchain": os.environ.get("RUSTUP_TOOLCHAIN"),
                "cargo_home_config": cargo_home_config(),
                "unset_overrides": [
                    "AR", "CC", "CXX", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                    "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET",
                    "CARGO_PROFILE_*", "CARGO_TARGET_*_LINKER",
                    "CARGO_TARGET_*_RUSTFLAGS",
                ],
            },
            "expected_criterion": sorted(self.expected_criterion),
            "expected_raw": sorted(self.expected_raw),
            "commands": self.commands,
            "outputs": self.outputs,
        }
        temporary = self.manifest_path.with_name(".manifest.json.tmp")
        temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        temporary.replace(self.manifest_path)

    def assert_source(self) -> None:
        if source_fingerprint(self.paths, self.root) != self.source["source_sha256"]:
            raise RuntimeError("source changed after publication snapshot")

    def run(self, name: str, command: list[str], env: dict[str, str] | None = None,
            validate=None, timeout_seconds: int | None = None) -> Path:
        self.assert_source()
        for path in {self.output, self.args.storage_directory}:
            if shutil.disk_usage(path).free < self.args.min_free_gib * GIB:
                raise RuntimeError(f"free disk is below the configured gate on {path}")
        directory = self.output / f"{len(self.commands):03d}-{name}"
        directory.mkdir()
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        telemetry = directory / "telemetry.jsonl"
        record = {
            "name": name,
            "command": [Path(command[0]).name, *command[1:]],
            "environment": env or {},
            "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        self.commands.append(record)
        self.save()
        process_env = os.environ.copy()
        for key in tuple(process_env):
            if key.startswith("COMMONWARE_CLEARING_"):
                del process_env[key]
        process_env.update(env or {})
        for key in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS",
            "CARGO_BUILD_TARGET", "CC", "CXX", "AR",
        ):
            process_env.pop(key, None)
        for key in tuple(process_env):
            if (
                key.startswith("CARGO_PROFILE_")
                or key.startswith("CARGO_TARGET_") and (
                    key.endswith("_LINKER") or key.endswith("_RUSTFLAGS")
                )
            ):
                del process_env[key]
        process_env.setdefault("CRITERION_HOME", str(self.output / "criterion"))
        process_env["CARGO_TERM_COLOR"] = "never"
        process_env["TERM"] = "dumb"
        if self.args.target_directory is not None:
            process_env["CARGO_TARGET_DIR"] = str(self.args.target_directory)
        started = time.monotonic()
        timeout_seconds = timeout_seconds or self.args.timeout_seconds
        record["timeout_seconds"] = timeout_seconds
        self.save()
        with stdout.open("wb") as out, stderr.open("wb") as err:
            process = subprocess.Popen(
                command, cwd=self.root, env=process_env, stdout=out, stderr=err,
                start_new_session=True,
            )
            stop = threading.Event()
            thread = threading.Thread(target=monitor, args=(process.pid, telemetry, stop))
            thread.start()
            reason = None
            while process.poll() is None:
                if time.monotonic() - started > timeout_seconds:
                    reason = "timeout"
                sample = process_group_sample(process.pid)
                if sample and sample.get("rss_kib") and sample["rss_kib"] > self.args.rss_gib * GIB // 1024:
                    reason = "rss_limit"
                for path in {self.output, self.args.storage_directory}:
                    if shutil.disk_usage(path).free < self.args.min_free_gib * GIB:
                        reason = "disk_limit"
                if reason:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                    break
                time.sleep(1)
            stop.set()
            thread.join()
        record.update(
            exit_code=process.returncode,
            elapsed_seconds=time.monotonic() - started,
            termination_reason=reason,
            stdout_sha256=sha256(stdout),
            stderr_sha256=sha256(stderr),
            telemetry_sha256=sha256(telemetry),
        )
        self.save()
        if reason or process.returncode:
            raise RuntimeError(f"{name} failed: reason={reason} exit={process.returncode}")
        self.assert_source()
        if validate:
            try:
                validate(stdout)
            except Exception as error:
                record["validation_error"] = str(error)
                self.save()
                raise
            record["validated"] = True
            self.save()
        return stdout

    def build(self) -> None:
        builds = (
            ("clearing", "bajillion", [
                "cargo", "bench", "--locked", "-p", "commonware-clearing", "--features",
                "bench", "--bench", "bajillion", "--no-run", "--message-format=json",
            ]),
            ("ack", "durable_ack", [
                "cargo", "bench", "--locked", "-p", "commonware-terminal", "--bench",
                "durable_ack", "--features", "bench", "--no-run", "--message-format=json",
            ]),
        )
        for key, target, command in builds:
            log = self.run(f"build-{key}", command)
            binary = binary_from_build_log(log, target)
            self.binaries[key] = binary
            self.commands[-1]["binary_name"] = binary.name
            self.commands[-1]["binary_sha256"] = sha256(binary)
            self.save()

    def clearing(self, selector: str, name: str, profile=None, history=0, rows=0,
                 payouts=0, timed=False) -> None:
        env = {
            "COMMONWARE_CLEARING_BENCH": selector,
            "COMMONWARE_CLEARING_ACCOUNTS": str(profile[0] if profile else self.args.accounts),
            "COMMONWARE_CLEARING_HISTORY": str(history),
            "COMMONWARE_CLEARING_ROWS": str(rows),
            "COMMONWARE_CLEARING_PAYOUTS": str(payouts),
        }
        if profile:
            env["COMMONWARE_CLEARING_PROFILE"] = (
                f"N={profile[0]} A={profile[1]} B={profile[2]} K={profile[3]}"
            )
        command = [str(self.binaries["clearing"])]
        if timed:
            criterion = self.output / "criterion-cases" / name
            if criterion.exists():
                raise RuntimeError(f"Criterion case path already exists: {criterion}")
            env["CRITERION_HOME"] = str(criterion)
            inventory = self.run(
                name + "-inventory", command + ["--bench", "--list", "--noplot"], env
            )
            ids = {
                line.removesuffix(": benchmark")
                for line in inventory.read_text(errors="replace").splitlines()
                if line.endswith(": benchmark")
            }
            if not ids:
                raise RuntimeError(f"{name} listed no Criterion benchmarks")
            command += ["--bench", "--sample-size", str(self.args.proof_samples), "--warm-up-time",
                        str(self.args.criterion_warmup), "--measurement-time",
                        str(self.args.criterion_measurement), "--noplot"]
        else:
            command += ["--test"]
            self.run(name, command, env)
            return
        observed = set()
        self.run(
            name, command, env,
            validate=lambda _: observed.update(validate_criterion_case(
                criterion, ids, self.args.proof_samples,
            )),
            timeout_seconds=self.args.timing_timeout_seconds,
        )
        duplicates = self.expected_criterion & observed
        if duplicates:
            raise RuntimeError(f"duplicate planned Criterion IDs: {sorted(duplicates)}")
        self.expected_criterion.update(observed)
        self.save()

    def clearing_raw(self, selector: str, name: str, kind: str, boundary: str,
                     profile=None, history=0, rows=0) -> None:
        env = {
            "COMMONWARE_CLEARING_BENCH": selector,
            "COMMONWARE_CLEARING_ACCOUNTS": str(profile[0] if profile else self.args.accounts),
            "COMMONWARE_CLEARING_HISTORY": str(history),
            "COMMONWARE_CLEARING_ROWS": str(rows),
            "COMMONWARE_CLEARING_PAYOUTS": "0",
            "COMMONWARE_CLEARING_SAMPLES": str(self.args.raw_samples),
        }
        if profile:
            env["COMMONWARE_CLEARING_PROFILE"] = (
                f"N={profile[0]} A={profile[1]} B={profile[2]} K={profile[3]}"
            )
        expected_dimensions = (
            {"n": profile[0], "a": profile[1], "b": profile[2], "k": profile[3]}
            if profile else {"n": self.args.accounts, "h": history, "r": rows}
        )
        if profile:
            expected_names = {
                "bajillion::prepare/"
                f"N={profile[0]} A={profile[1]} B={profile[2]} K={profile[3]} "
                f"E={profile[1] * profile[3]}"
            }
        else:
            expected_names = activity_raw_names(history, rows)
        observed = set()
        self.run(
            name + "-raw", [str(self.binaries["clearing"]), "--test"], env,
            validate=lambda path: observed.update(validate_raw_samples(
                path, kind, self.args.raw_samples, boundary, expected_dimensions, expected_names,
            )),
            timeout_seconds=self.args.timing_timeout_seconds,
        )
        duplicates = self.expected_raw & observed
        if duplicates:
            raise RuntimeError(f"duplicate planned raw benchmark IDs: {sorted(duplicates)}")
        self.expected_raw.update(expected_names)
        self.save()

    def ack(self, case: tuple[int, ...], readiness: bool, trace: bool = False) -> None:
        n, a, b, k, w, h = case
        samples = 1 if readiness else self.args.ack_samples
        warmup = 0 if readiness else self.args.ack_warmup
        command = [
            str(self.binaries["ack"]), "--storage-directory", str(self.args.storage_directory),
            "--accounts", str(n), "--senders", str(a), "--recipients", str(b),
            "--out-degree", str(k), "--withdrawals", str(w), "--history", str(h),
            "--samples", str(samples), "--warmup", str(warmup), "--runtime-workers",
            str(self.args.runtime_workers), "--workers", str(self.args.workers),
            "--benchmark-limits",
        ]
        label = f"ack-N{n}-A{a}-B{b}-K{k}-W{w}-H{h}-{'check' if readiness else 'timed'}"
        trace_path = None
        if trace:
            trace_path = self.output / f"{len(self.commands):03d}-{label}" / "fsync.trace"
            command = [
                "strace", "-f", "-qq", "-e", "trace=fsync,fdatasync", "-o",
                str(trace_path), *command,
            ]
        self.run(
            label, command,
            validate=lambda path: validate_ack(
                path, case, samples, warmup, self.args.workers, self.args.runtime_workers,
            ),
            timeout_seconds=(
                self.args.timeout_seconds if readiness
                else self.args.timing_timeout_seconds
            ),
        )
        if trace_path is not None:
            calls = len(re.findall(r"\b(?:fsync|fdatasync)\(", trace_path.read_text()))
            if calls == 0:
                raise RuntimeError("untimed ACK trace contains no fsync/fdatasync calls")
            self.commands[-1]["fsync_calls"] = calls
            self.commands[-1]["fsync_trace_sha256"] = sha256(trace_path)
            self.save()


def make_plan(args: argparse.Namespace) -> argparse.Namespace:
    profiles = tuple(args.profile or DEFAULT_PROFILES)
    activity = tuple(args.activity_case or DEFAULT_ACTIVITY)
    payout = tuple(args.payout_case or DEFAULT_PAYOUT)
    ack = tuple(args.ack_case or DEFAULT_ACK)
    if args.mode in ("timings", "all") and len(profiles) < 3:
        raise SystemExit("timings require three profiles for the claim and adjudication cases")
    for n, a, b, k in profiles:
        if n <= 0 or a > n or not 0 < b <= n or not 0 < k <= b:
            raise SystemExit(f"invalid profile: {(n, a, b, k)}")
    for n, a, b, k, w, _ in ack:
        if n <= 0 or a > n or w > n or not 0 < b <= n or not 0 < k <= b:
            raise SystemExit(f"invalid ACK case: {(n, a, b, k, w)}")
    for history, payouts in payout:
        if payouts > args.accounts:
            raise SystemExit(
                f"payout case {(history, payouts)} exceeds --accounts={args.accounts}"
            )
    positive = {
        "proof samples": args.proof_samples,
        "raw samples": args.raw_samples,
        "ACK samples": args.ack_samples,
        "Criterion warmup": args.criterion_warmup,
        "Criterion measurement": args.criterion_measurement,
        "runtime workers": args.runtime_workers,
        "native workers": args.workers,
        "RSS GiB": args.rss_gib,
        "minimum free GiB": args.min_free_gib,
        "timeout seconds": args.timeout_seconds,
        "timing timeout seconds": args.timing_timeout_seconds,
        "accounts": args.accounts,
        "storage size GiB": args.storage_size_gib,
        "storage IOPS": args.storage_iops,
        "storage throughput MiB/s": args.storage_throughput_mib,
    }
    for label, value in positive.items():
        if value <= 0:
            raise SystemExit(f"{label} must be positive")
    if args.ack_warmup < 0:
        raise SystemExit("ACK warmup must be nonnegative")
    if args.raw_samples > 100:
        raise SystemExit("raw samples must not exceed 100")
    return argparse.Namespace(
        profiles=profiles,
        activity=activity,
        payout=payout,
        ack=ack,
        settings={
            "proof_samples": args.proof_samples,
            "raw_samples": args.raw_samples,
            "accounts": args.accounts,
            "instance_type": args.instance_type,
            "storage_medium": args.storage_medium,
            "storage_size_gib": args.storage_size_gib,
            "storage_iops": args.storage_iops,
            "storage_throughput_mib_per_second": args.storage_throughput_mib,
            "ack_samples": args.ack_samples,
            "ack_warmup": args.ack_warmup,
            "criterion_warmup_seconds": args.criterion_warmup,
            "criterion_measurement_seconds": args.criterion_measurement,
            "runtime_workers": args.runtime_workers,
            "workers": args.workers,
            "rss_gib": args.rss_gib,
            "minimum_free_gib": args.min_free_gib,
            "timeout_seconds": args.timeout_seconds,
            "timing_timeout_seconds": args.timing_timeout_seconds,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "checks", "timings", "scaling", "all"))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--storage-directory", type=Path)
    parser.add_argument("--target-directory", type=Path)
    parser.add_argument("--profile", action="append", type=lambda value: parse_tuple(value, 4, "profile"))
    parser.add_argument("--accounts", type=int, default=1_000_000)
    parser.add_argument("--activity-case", action="append", type=lambda value: parse_tuple(value, 2, "activity case"))
    parser.add_argument("--payout-case", action="append", type=lambda value: parse_tuple(value, 2, "payout case"))
    parser.add_argument("--ack-case", action="append", type=lambda value: parse_tuple(value, 6, "ACK case"))
    parser.add_argument("--proof-samples", type=int, default=20)
    parser.add_argument("--raw-samples", type=int, default=3)
    parser.add_argument("--ack-samples", type=int, default=3)
    parser.add_argument("--ack-warmup", type=int, default=0)
    parser.add_argument("--criterion-warmup", type=float, default=0.25)
    parser.add_argument("--criterion-measurement", type=float, default=1.0)
    parser.add_argument("--runtime-workers", type=int, default=2)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--rss-gib", type=int, default=24)
    parser.add_argument("--min-free-gib", type=int, default=20)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--timing-timeout-seconds", type=int, default=10_800)
    parser.add_argument("--instance-type", default="c8a.4xlarge")
    parser.add_argument("--storage-medium", default="gp3")
    parser.add_argument("--storage-size-gib", type=int, default=160)
    parser.add_argument("--storage-iops", type=int, default=6_000)
    parser.add_argument("--storage-throughput-mib", type=int, default=250)
    args = parser.parse_args()
    if args.output is not None:
        args.output = args.output.resolve()
    if args.storage_directory is not None:
        args.storage_directory = args.storage_directory.resolve()
    if args.target_directory is not None:
        args.target_directory = args.target_directory.resolve()
    args.plan = make_plan(args)
    rendered = json.dumps(vars(args.plan), indent=2)
    if args.mode == "plan":
        print(rendered)
        return 0
    if args.output is None or args.storage_directory is None:
        parser.error("checks/timings/all require --output and --storage-directory")
    if not args.execute:
        parser.error("checks/timings/all require --execute")
    if args.output.exists():
        parser.error("--output must not already exist")
    try:
        args.output.resolve().relative_to(ROOT)
    except ValueError:
        pass
    else:
        relative_output = args.output.resolve().relative_to(ROOT).as_posix()
        if not relative_output.startswith(RESULTS_PREFIX):
            parser.error("an in-repository --output must be under the excluded results directory")
    args.storage_directory.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True)
    args.started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    paths = source_files()
    source = snapshot_source(args.output, paths)
    temporary = tempfile.TemporaryDirectory(prefix="bajillion-publication-source-")
    execution_root = Path(temporary.name) / "repo"
    reconstruct_source(args.output, source, paths, execution_root)
    source["execution"] = "reconstructed immutable private snapshot"
    runner = Runner(args, args.output, source, paths, execution_root)
    runner.save()
    runner.build()
    if args.mode == "scaling":
        for case in reversed(args.plan.ack):
            runner.ack(case, readiness=False)
        for history, rows in args.plan.activity:
            runner.clearing(
                "native-activity-sizes", f"activity-H{history}-R{rows}-check",
                history=history, rows=rows, payouts=0,
            )
        for profile in args.plan.profiles:
            runner.clearing(
                "challenge-sizes", "challenge-" + "-".join(map(str, profile)),
                profile=profile,
            )
        for history, rows in args.plan.activity:
            runner.clearing_raw(
                "native-activity-proof-samples", f"activity-H{history}-R{rows}-timed",
                "activity_verify", "decoded_lookup_to_resolve_result",
                history=history, rows=rows,
            )
        for profile in args.plan.profiles:
            runner.clearing_raw(
                "prepare-samples", "prepare-" + "-".join(map(str, profile)),
                "prepare", "detached_inputs_to_prepared_dealing_return", profile=profile,
            )
    if args.mode in ("checks", "all"):
        for profile in args.plan.profiles:
            runner.clearing("sizes", "sizes-" + "-".join(map(str, profile)), profile=profile)
        for history, rows in args.plan.activity:
            runner.clearing("native-activity-sizes", f"activity-H{history}-R{rows}-check",
                            history=history, rows=rows, payouts=0)
        for history, payouts in args.plan.payout:
            runner.clearing("native-payout-sizes", f"payout-H{history}-W{payouts}-check",
                            history=history, rows=0, payouts=payouts)
        for profile in args.plan.profiles:
            runner.clearing("challenge-sizes", "challenge-" + "-".join(map(str, profile)),
                            profile=profile)
        for index, case in enumerate(args.plan.ack):
            runner.ack(case, readiness=True, trace=index == 0)
    if args.mode in ("timings", "all"):
        for history, rows in args.plan.activity:
            runner.clearing_raw(
                "native-activity-proof-samples", f"activity-H{history}-R{rows}-timed",
                "activity_verify", "decoded_lookup_to_resolve_result",
                history=history, rows=rows,
            )
        for history, payouts in args.plan.payout:
            runner.clearing("native-payout-proofs", f"payout-H{history}-W{payouts}-timed",
                            history=history, rows=0, payouts=payouts, timed=True)
        for profile in args.plan.profiles:
            runner.clearing_raw(
                "prepare-samples", "prepare-" + "-".join(map(str, profile)),
                "prepare", "detached_inputs_to_prepared_dealing_return", profile=profile,
            )
        runner.clearing("verify-claim", "verify-claim-current-N1000000", 
                        profile=args.plan.profiles[1], timed=True)
        for profile in (args.plan.profiles[0], args.plan.profiles[2]):
            runner.clearing("adjudicate", "adjudicate-" + "-".join(map(str, profile)),
                            profile=profile, timed=True)
        for case in args.plan.ack:
            runner.ack(case, readiness=False)
        for selector in ("sign-vote", "verify-certificate"):
            runner.clearing(selector, selector + "-n100", profile=args.plan.profiles[1], timed=True)
    if args.mode in ("checks", "scaling", "all"):
        runner.outputs.update(aggregate_checks(args.output, args.plan.ack))
    if args.mode in ("timings", "scaling", "all"):
        runner.outputs.update(aggregate(
            args.output, args.proof_samples, args.raw_samples, args.ack_samples,
            args.plan.ack, runner.expected_criterion, runner.expected_raw,
        ))
    runner.commands.append({"finished_utc": dt.datetime.now(dt.timezone.utc).isoformat()})
    runner.save()
    temporary.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
