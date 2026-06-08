#!/usr/bin/env python3
"""Run configured Gungraun benchmarks and maintain benchmark artifacts.

The script has two modes:

* ``generate`` runs the configured benchmarks and writes ``current.toml``. This
  is the baseline artifact uploaded from ``main``.
* ``check`` runs the same benchmarks, compares them with a required baseline,
  writes comparison artifacts, and renders ``comment.md`` for pull requests.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

REPORT_METRICS = ["Ir", "L1hits", "LLhits", "RamHits", "TotalRW", "EstimatedCycles"]
DEFAULT_GATE_METRIC = "EstimatedCycles"
DEFAULT_GATE_DIRECTION = "down"
DEFAULT_GATE_THRESHOLD = 10.0
RAW_OUTPUT = "gungraun-output.jsonl"
COMMENT_MARKER = "<!-- commonware-benchmark-tracking-results -->"


@dataclass(frozen=True)
class Gate:
    metric: str
    direction: str
    threshold_percent: float

    @classmethod
    def default(cls) -> Self:
        return cls(
            metric=DEFAULT_GATE_METRIC,
            direction=DEFAULT_GATE_DIRECTION,
            threshold_percent=DEFAULT_GATE_THRESHOLD,
        )

    @property
    def description(self) -> str:
        movement = "decrease" if self.direction == "down" else "increase"
        return f"{self.metric} should {movement}; tolerance {self.threshold_percent:.2f}%"

    def failed(self, delta: float) -> bool:
        if self.direction == "down":
            return delta > self.threshold_percent
        return delta < -self.threshold_percent

    def to_toml(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "direction": self.direction,
            "threshold_percent": self.threshold_percent,
        }


@dataclass(frozen=True)
class Benchmark:
    package: str
    target: str
    name: str
    filter: str
    baseline_suite: str
    cargo_flags: list[str]
    gates: list[Gate]

    @property
    def key(self) -> tuple[str, str]:
        return (self.baseline_suite, self.name)


@dataclass(frozen=True)
class Result:
    benchmark: Benchmark
    metrics: dict[str, int]
    commit: str = ""
    run_id: str = ""
    ref: str = ""

    @classmethod
    def from_toml(cls, item: dict[str, Any]) -> Self:
        benchmark = Benchmark(
            package=required_str(item, "package"),
            target=required_str(item, "target"),
            name=required_str(item, "name"),
            filter=required_str(item, "filter"),
            baseline_suite=required_str(item, "baseline_suite"),
            cargo_flags=required_str_list(item.get("cargo_flags", []), "cargo_flags"),
            gates=parse_gates(item.get("gates"), [Gate.default()], "gates"),
        )
        metrics = read_metrics(item)
        return cls(
            benchmark=benchmark,
            metrics=metrics,
            commit=optional_str(item, "commit"),
            run_id=optional_str(item, "run_id"),
            ref=optional_str(item, "ref"),
        )

    def to_toml(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "package": self.benchmark.package,
            "target": self.benchmark.target,
            "name": self.benchmark.name,
            "filter": self.benchmark.filter,
            "baseline_suite": self.benchmark.baseline_suite,
            "cargo_flags": self.benchmark.cargo_flags,
            "gates": [gate.to_toml() for gate in self.benchmark.gates],
            "metrics": self.metrics,
        }
        if self.commit:
            values["commit"] = self.commit
        if self.run_id:
            values["run_id"] = self.run_id
        if self.ref:
            values["ref"] = self.ref
        return values


@dataclass(frozen=True)
class Comparison:
    current: Result
    baseline: Result | None
    deltas: dict[str, float]

    @property
    def gate_failures(self) -> list[Gate]:
        if self.baseline is None:
            return []
        return [
            gate
            for gate in self.current.benchmark.gates
            if gate.failed(self.deltas[gate.metric])
        ]

    @property
    def regressed(self) -> bool:
        return bool(self.gate_failures)

    def to_toml(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            **self.current.to_toml(),
            "metric_deltas": self.deltas,
            "failed_gates": [gate.to_toml() for gate in self.gate_failures],
        }
        if self.baseline is not None:
            values["baseline_metrics"] = self.baseline.metrics
            values["regressed"] = self.regressed
        return values


def parse_args() -> argparse.Namespace:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", required=True, type=Path)
    common.add_argument("--output-dir", required=True, type=Path)

    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="mode", required=True)

    check = subcommands.add_parser("check", parents=[common])
    check.add_argument("--baseline", required=True, type=Path)

    subcommands.add_parser("generate", parents=[common])
    return parser.parse_args()


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        value = tomllib.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"`{path}` must contain a TOML table")
    return value


def required_str(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"`{key}` must be a non-empty string")
    return value


def optional_str(item: dict[str, Any], key: str) -> str:
    value = item.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"`{key}` must be a string")
    return value


def required_str_list(value: Any, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"`{key}` must be a string array")
    return value


def required_float(value: Any, key: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"`{key}` must be a number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as err:
        raise ValueError(f"`{key}` must be a number") from err
    if parsed < 0:
        raise ValueError(f"`{key}` must be non-negative")
    return parsed


def parse_gates(value: Any, inherited: list[Gate], field: str) -> list[Gate]:
    if value is None:
        return inherited
    if not isinstance(value, list) or not value:
        raise ValueError(f"`{field}` must be a non-empty gate array")

    gates = []
    for index, gate in enumerate(value):
        if not isinstance(gate, dict):
            raise ValueError(f"`{field}[{index}]` must be a table")
        metric = required_str(gate, "metric")
        direction = required_str(gate, "direction")
        if direction not in {"down", "up"}:
            raise ValueError(f"`{field}[{index}].direction` must be `down` or `up`")
        threshold = required_float(gate.get("threshold_percent"), "threshold_percent")
        gates.append(Gate(metric=metric, direction=direction, threshold_percent=threshold))
    return gates


def metrics_for(benchmarks: list[Benchmark]) -> list[str]:
    metrics = list(REPORT_METRICS)
    for benchmark in benchmarks:
        for gate in benchmark.gates:
            if gate.metric not in metrics:
                metrics.append(gate.metric)
    return metrics


def read_metrics(item: dict[str, Any]) -> dict[str, int]:
    metrics = item.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError(f"benchmark `{item.get('name', '')}` is missing metrics")
    parsed = {}
    expected = list(REPORT_METRICS)
    for gate in parse_gates(item.get("gates"), [Gate.default()], "gates"):
        if gate.metric not in expected:
            expected.append(gate.metric)
    for metric in expected:
        value = parse_metric_value(metrics.get(metric))
        if value is None:
            raise ValueError(f"benchmark `{item.get('name', '')}` is missing `{metric}`")
        parsed[metric] = value
    return parsed


def validate_config(config: dict[str, Any]) -> list[Benchmark]:
    packages = config.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("config must contain a non-empty `packages` array")

    config_gates = parse_gates(config.get("gates"), [Gate.default()], "gates")
    benchmarks = []
    seen = set()

    for package_index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise ValueError(f"`packages[{package_index}]` must be a table")

        package_name = required_str(package, "name")
        baseline_suite = package.get("baseline_suite", package_name)
        if not isinstance(baseline_suite, str) or not baseline_suite:
            raise ValueError(f"`packages[{package_index}].baseline_suite` must be a string")
        cargo_flags = required_str_list(
            package.get("cargo_flags", []), f"packages[{package_index}].cargo_flags"
        )
        package_gates = parse_gates(
            package.get("gates"),
            config_gates,
            f"packages[{package_index}].gates",
        )

        target_tables = package.get("benchmarks")
        if not isinstance(target_tables, list) or not target_tables:
            raise ValueError(f"`packages[{package_index}].benchmarks` must be non-empty")

        for target_index, target_table in enumerate(target_tables):
            if not isinstance(target_table, dict):
                raise ValueError(
                    f"`packages[{package_index}].benchmarks[{target_index}]` must be a table"
                )
            target = required_str(
                target_table, "name"
            )
            target_gates = parse_gates(
                target_table.get("gates"),
                package_gates,
                f"packages[{package_index}].benchmarks[{target_index}].gates",
            )
            variants = target_table.get("variants")
            if not isinstance(variants, list) or not variants:
                raise ValueError(
                    f"`packages[{package_index}].benchmarks[{target_index}].variants` "
                    "must be non-empty"
                )

            for variant_index, variant in enumerate(variants):
                if not isinstance(variant, dict):
                    raise ValueError(
                        f"`packages[{package_index}].benchmarks[{target_index}]"
                        f".variants[{variant_index}]` must be a table"
                    )
                name = required_str(variant, "name")
                filter_pattern = required_str(variant, "filter")
                gates = parse_gates(
                    variant.get("gates"),
                    target_gates,
                    f"packages[{package_index}].benchmarks[{target_index}]"
                    f".variants[{variant_index}].gates",
                )
                benchmark = Benchmark(
                    package=package_name,
                    target=target,
                    name=name,
                    filter=filter_pattern,
                    baseline_suite=baseline_suite,
                    cargo_flags=cargo_flags,
                    gates=gates,
                )
                if benchmark.key in seen:
                    raise ValueError(f"duplicate benchmark `{benchmark.name}`")
                seen.add(benchmark.key)
                benchmarks.append(benchmark)

    return benchmarks


def run_benchmarks(benchmarks: list[Benchmark], output_dir: Path) -> list[Result]:
    raw_output = output_dir / RAW_OUTPUT
    raw_output.write_text("", encoding="utf-8")
    metrics = metrics_for(benchmarks)

    results = []
    for benchmark in benchmarks:
        output = run_one_benchmark(benchmark, raw_output, metrics)
        summaries = parse_json_objects(output, benchmark.name)
        matches = [summary for summary in summaries if matches_filter(summary, benchmark.filter)]
        if len(matches) != 1:
            raise ValueError(
                f"expected one Gungraun result for `{benchmark.name}`, got {len(matches)}"
            )
        results.append(
            Result(
                benchmark=benchmark,
                metrics=extract_metrics(matches[0], metrics),
                commit=os.environ.get("GITHUB_SHA", ""),
                run_id=os.environ.get("GITHUB_RUN_ID", ""),
                ref=os.environ.get("GITHUB_REF_NAME", ""),
            )
        )
    return results


def run_one_benchmark(benchmark: Benchmark, raw_output: Path, metrics: list[str]) -> str:
    cmd = (
        ["cargo", "bench"]
        + benchmark.cargo_flags
        + ["-p", benchmark.package, "--bench", benchmark.target, "--"]
        + [
            benchmark.filter,
            "--output-format=json",
            f"--callgrind-metrics={','.join(metrics)}",
        ]
    )
    print("$ " + shlex.join(cmd), flush=True)

    lines = []
    with raw_output.open("a", encoding="utf-8") as f:
        f.write("$ " + shlex.join(cmd) + "\n")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=os.environ.copy(),
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            f.write(line)
            lines.append(line)
        if proc.wait() != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)
    return "".join(lines)


def parse_json_objects(text: str, source: str) -> list[dict[str, Any]]:
    objects = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid JSON in {source}:{line_number}: {err}") from err
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object in {source}:{line_number}")
        objects.append(value)
    return objects


def matches_filter(summary: dict[str, Any], pattern: str) -> bool:
    module_path = summary.get("module_path")
    bench_id = summary.get("id")
    candidates = []
    if isinstance(module_path, str):
        candidates.append(module_path)
    if isinstance(module_path, str) and isinstance(bench_id, str):
        candidates.append(f"{module_path}::{bench_id}")
    if isinstance(bench_id, str):
        candidates.append(bench_id)
    return any(fnmatch.fnmatchcase(candidate, pattern) for candidate in candidates)


def extract_metrics(summary: dict[str, Any], selected_metrics: list[str]) -> dict[str, int]:
    callgrind = callgrind_summary(summary)
    metrics = {}
    for metric in selected_metrics:
        value = current_metric_value(callgrind.get(metric))
        if value is None:
            raise ValueError(f"Gungraun result is missing `{metric}`")
        metrics[metric] = value
    return metrics


def callgrind_summary(summary: dict[str, Any]) -> dict[str, Any]:
    profiles = summary.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("Gungraun result is missing `profiles`")
    for profile in profiles:
        if not isinstance(profile, dict) or profile.get("tool") != "Callgrind":
            continue
        summaries = profile.get("summaries")
        if not isinstance(summaries, dict):
            continue
        total = summaries.get("total")
        if not isinstance(total, dict):
            continue
        total_summary = total.get("summary")
        if not isinstance(total_summary, dict):
            continue
        callgrind = total_summary.get("Callgrind")
        if isinstance(callgrind, dict):
            return callgrind
    raise ValueError("Gungraun result is missing total Callgrind metrics")


def current_metric_value(summary: Any) -> int | None:
    if not isinstance(summary, dict):
        return None
    metrics = summary.get("metrics")
    if not isinstance(metrics, dict):
        return None
    value = parse_metric_value(metrics.get("Left"))
    if value is not None:
        return value
    both = metrics.get("Both")
    if isinstance(both, list) and both:
        return parse_metric_value(both[0])
    return None


def parse_metric_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        return parse_metric_value(value.get("Int"))
    return None


def load_baseline(path: Path) -> dict[tuple[str, str], Result]:
    if not path.exists():
        raise ValueError(f"baseline `{path}` does not exist")
    values = read_toml(path).get("benchmarks")
    if not isinstance(values, list):
        raise ValueError(f"baseline `{path}` must contain a `benchmarks` array")
    baseline = {}
    for item in values:
        if not isinstance(item, dict):
            raise ValueError(f"baseline `{path}` contains a non-table benchmark")
        result = Result.from_toml(item)
        baseline[result.benchmark.key] = result
    return baseline


def compare(current: list[Result], baseline: dict[tuple[str, str], Result]) -> list[Comparison]:
    comparisons = []
    for result in current:
        previous = baseline.get(result.benchmark.key)
        if previous is None:
            comparisons.append(Comparison(current=result, baseline=None, deltas={}))
            continue
        deltas = {}
        for metric in metrics_for([result.benchmark]):
            if metric not in result.metrics:
                raise ValueError(f"current result `{result.benchmark.name}` is missing `{metric}`")
            if metric not in previous.metrics:
                raise ValueError(f"baseline `{result.benchmark.name}` is missing `{metric}`")
            if previous.metrics[metric] == 0:
                raise ValueError(f"baseline `{result.benchmark.name}` has zero `{metric}`")
            deltas[metric] = percent_delta(result.metrics[metric], previous.metrics[metric])
        comparisons.append(Comparison(current=result, baseline=previous, deltas=deltas))
    return comparisons


def percent_delta(current: int, baseline: int) -> float:
    return ((current - baseline) / baseline) * 100


def write_outputs(
    output_dir: Path,
    current: list[Result],
    comparisons: list[Comparison] | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_toml_array(output_dir / "current.toml", "benchmarks", [r.to_toml() for r in current])

    summary: dict[str, Any] = {
        "benchmark_count": len(current),
        "metrics": metrics_for([result.benchmark for result in current]),
    }
    if comparisons is not None:
        write_toml_array(
            output_dir / "comparison.toml",
            "comparisons",
            [c.to_toml() for c in comparisons],
        )
        summary["regression_count"] = sum(1 for c in comparisons if c.regressed)
        (output_dir / "comment.md").write_text(render_report(comparisons), encoding="utf-8")

    write_toml_table(output_dir / "summary.toml", summary)


def render_report(comparisons: list[Comparison]) -> str:
    regressions = sum(1 for item in comparisons if item.regressed)
    warnings = report_warnings(comparisons)
    lines = [
        COMMENT_MARKER,
        "## Benchmark results",
        "",
        f"Regressions: `{regressions}`.",
    ]
    if warnings:
        lines.append("")
        render_warnings(lines, warnings)
    for item in comparisons:
        lines.extend(["", f"<details><summary>{summary_line(item)}</summary>", ""])
        render_metadata(lines, item.current.benchmark)
        render_metrics(lines, item)
        lines.extend(["", "</details>"])

    commits = sorted(
        {
            item.baseline.commit[:12]
            for item in comparisons
            if item.baseline is not None and item.baseline.commit
        }
    )
    if commits:
        lines.extend(["", f"Baseline commit(s): `{', '.join(commits)}`"])
    lines.append("")
    return "\n".join(lines)


def report_warnings(comparisons: list[Comparison]) -> list[str]:
    warnings = []
    for item in comparisons:
        if item.baseline is None:
            warnings.append(f"Missing baseline for `{item.current.benchmark.name}`.")
    return warnings


def render_warnings(lines: list[str], warnings: list[str]) -> None:
    lines.append("> [!WARN]")
    for warning in warnings:
        lines.append(f"> {warning}")


def summary_line(item: Comparison) -> str:
    name = f"`{escape_summary(item.current.benchmark.name)}`"
    if item.baseline is None:
        return f"⚠️ {name} (baseline missing)"

    status = "❌" if item.regressed else "✅"
    gates = item.current.benchmark.gates
    if len(gates) == 1:
        gate = gates[0]
        current = format_count(item.current.metrics[gate.metric])
        delta = format_delta(item.deltas[gate.metric])
        gate_summary = (
            f"{gate.metric}: {current}, delta: {delta}, "
            f"{gate.description}"
        )
    else:
        gate_summary = f"{len(item.gate_failures)}/{len(gates)} gates failed"
    return f"{status} {name} ({gate_summary})"


def render_metadata(lines: list[str], benchmark: Benchmark) -> None:
    rows = [
        ("Package", benchmark.package),
        ("Benchmark target", benchmark.target),
        ("Variant", benchmark.name),
        ("Filter", benchmark.filter),
        ("Baseline suite", benchmark.baseline_suite),
        ("Gates", "; ".join(gate.description for gate in benchmark.gates)),
    ]
    if benchmark.cargo_flags:
        rows.append(("Cargo flags", " ".join(benchmark.cargo_flags)))

    lines.extend(["| Field | Value |", "|---|---|"])
    for key, value in rows:
        lines.append(f"| {key} | `{escape_cell(value)}` |")


def render_metrics(lines: list[str], item: Comparison) -> None:
    if item.baseline is None:
        render_current_metrics(lines, item.current)
        return

    lines.extend(["", "| Metric | Baseline | Current | Delta | Gate |", "|---|---:|---:|---:|---|"])
    for metric in metrics_for([item.current.benchmark]):
        gate = gate_text(item.current.benchmark, metric)
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{metric}`",
                    format_count(item.baseline.metrics[metric]),
                    format_count(item.current.metrics[metric]),
                    format_delta(item.deltas[metric]),
                    gate,
                ]
            )
            + " |"
        )


def render_current_metrics(lines: list[str], item: Result) -> None:
    lines.extend(["", "| Metric | Current | Gate |", "|---|---:|---|"])
    for metric in metrics_for([item.benchmark]):
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{metric}`",
                    format_count(item.metrics[metric]),
                    gate_text(item.benchmark, metric),
                ]
            )
            + " |"
        )


def gate_text(benchmark: Benchmark, metric: str) -> str:
    gates = [gate for gate in benchmark.gates if gate.metric == metric]
    return "<br>".join(gate.description for gate in gates)


def format_count(value: int) -> str:
    return f"{value:,}"


def format_delta(value: float) -> str:
    return f"{value:+.2f}%"


def escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def escape_summary(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )


def write_toml_table(path: Path, values: dict[str, Any]) -> None:
    path.write_text("\n".join(f"{k} = {toml_value(v)}" for k, v in values.items()) + "\n")


def write_toml_array(path: Path, name: str, values: list[dict[str, Any]]) -> None:
    lines = []
    for value in values:
        if lines:
            lines.append("")
        lines.append(f"[[{name}]]")
        append_toml(lines, value, name)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_toml(lines: list[str], values: dict[str, Any], prefix: str) -> None:
    nested = []
    nested_arrays = []
    for key, value in values.items():
        if isinstance(value, dict):
            nested.append((key, value))
        elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
            nested_arrays.append((key, value))
        else:
            lines.append(f"{key} = {toml_value(value)}")
    for key, value in nested:
        lines.extend(["", f"[{prefix}.{key}]"])
        append_toml(lines, value, f"{prefix}.{key}")
    for key, items in nested_arrays:
        for item in items:
            lines.extend(["", f"[[{prefix}.{key}]]"])
            append_toml(lines, item, f"{prefix}.{key}")


def toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    raise TypeError(f"unsupported TOML value: {value!r}")


def main() -> int:
    args = parse_args()
    benchmarks = validate_config(read_toml(args.config))
    current = run_benchmarks(benchmarks, args.output_dir)

    if args.mode == "generate":
        write_outputs(args.output_dir, current)
        print(f"benchmark_count: {len(current)}")
        return 0

    baseline = load_baseline(args.baseline)
    comparisons = compare(current, baseline)
    write_outputs(args.output_dir, current, comparisons)
    regressions = sum(1 for item in comparisons if item.regressed)
    print(f"benchmark_count: {len(current)}")
    print(f"regression_count: {regressions}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
