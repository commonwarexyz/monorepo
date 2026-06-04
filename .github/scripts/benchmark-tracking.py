#!/usr/bin/env python3
"""Run Gungraun benchmarks and compare them with a main-branch artifact."""

import argparse
import fnmatch
import json
import os
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

SELECTED_METRICS = [
    "Ir",
    "L1hits",
    "LLhits",
    "RamHits",
    "TotalRW",
    "EstimatedCycles",
]
GATE_METRIC = "EstimatedCycles"
RAW_OUTPUT = "gungraun-output.jsonl"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Path to benchmark tracking config TOML")
    parser.add_argument("--output-dir", required=True, help="Directory for result artifacts")
    parser.add_argument(
        "--baseline",
        help="Path to a previous Gungraun benchmark-tracking current.toml artifact from main",
    )
    parser.add_argument(
        "--no-compare",
        action="store_true",
        help="Only write current benchmark results without comparing to a baseline",
    )
    parser.add_argument(
        "--skip-run",
        action="store_true",
        help=f"Only process an existing {RAW_OUTPUT} file in the output directory",
    )
    return parser.parse_args()


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def string_array(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"`{field}` must be a string array")
    return value


def threshold(value: Any, field: str) -> float:
    threshold_percent = float(value)
    if threshold_percent < 0:
        raise ValueError(f"`{field}` must be non-negative")
    return threshold_percent


def reject_criterion_args(value: dict[str, Any], prefix: str) -> None:
    if "criterion_args" in value:
        raise ValueError(f"`{prefix}.criterion_args` is not supported for Gungraun tracking")


def validate_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    packages = config.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("config must contain a non-empty `packages` array")

    default_threshold = threshold(
        config.get("default_threshold_percent", 10.0), "default_threshold_percent"
    )
    validated = []
    seen = set()
    for package_idx, package in enumerate(packages):
        prefix = f"packages[{package_idx}]"
        if not isinstance(package, dict):
            raise ValueError(f"`{prefix}` must be an object")
        reject_criterion_args(package, prefix)

        package_name = package.get("name")
        if not isinstance(package_name, str) or not package_name:
            raise ValueError(f"`{prefix}.name` must be a non-empty string")
        baseline_suite = package.get("baseline_suite", package_name)
        if not isinstance(baseline_suite, str) or not baseline_suite:
            raise ValueError(f"`{prefix}.baseline_suite` must be a non-empty string")
        cargo_flags = string_array(package.get("cargo_flags", []), f"{prefix}.cargo_flags")
        package_threshold = threshold(
            package.get("threshold_percent", default_threshold), f"{prefix}.threshold_percent"
        )
        benchmarks = package.get("benchmarks")
        if not isinstance(benchmarks, list) or not benchmarks:
            raise ValueError(f"`{prefix}.benchmarks` must be a non-empty array")

        for benchmark_idx, benchmark in enumerate(benchmarks):
            bench_prefix = f"{prefix}.benchmarks[{benchmark_idx}]"
            if not isinstance(benchmark, dict):
                raise ValueError(f"`{bench_prefix}` must be an object")
            reject_criterion_args(benchmark, bench_prefix)

            bench_name = benchmark.get("name")
            if not isinstance(bench_name, str) or not bench_name:
                raise ValueError(f"`{bench_prefix}.name` must be a non-empty string")
            benchmark_threshold = threshold(
                benchmark.get("threshold_percent", package_threshold),
                f"{bench_prefix}.threshold_percent",
            )
            variants = benchmark.get("variants")
            if not isinstance(variants, list) or not variants:
                raise ValueError(f"`{bench_prefix}.variants` must be a non-empty array")

            for variant_idx, variant in enumerate(variants):
                variant_prefix = f"{bench_prefix}.variants[{variant_idx}]"
                if isinstance(variant, str):
                    raise ValueError(f"`{variant_prefix}` must be a Gungraun variant object")
                if not isinstance(variant, dict):
                    raise ValueError(f"`{variant_prefix}` must be an object")
                reject_criterion_args(variant, variant_prefix)

                variant_name = variant.get("name")
                if not isinstance(variant_name, str) or not variant_name:
                    raise ValueError(f"`{variant_prefix}.name` must be a non-empty string")
                variant_filter = variant.get("filter")
                if not isinstance(variant_filter, str) or not variant_filter:
                    raise ValueError(f"`{variant_prefix}.filter` must be a non-empty string")
                variant_threshold = threshold(
                    variant.get("threshold_percent", benchmark_threshold),
                    f"{variant_prefix}.threshold_percent",
                )

                key = (baseline_suite, package_name, bench_name, variant_name)
                if key in seen:
                    raise ValueError(f"duplicate benchmark variant `{variant_name}`")
                seen.add(key)
                validated.append(
                    {
                        "package": package_name,
                        "bench": bench_name,
                        "name": variant_name,
                        "filter": variant_filter,
                        "baseline_suite": baseline_suite,
                        "cargo_flags": cargo_flags,
                        "threshold_percent": variant_threshold,
                    }
                )
    return validated


def run_streamed(cmd: list[str], output: Path, env: dict[str, str]) -> str:
    print("$ " + shlex.join(cmd), flush=True)
    stdout_lines = []
    with output.open("a", encoding="utf-8") as f:
        f.write("$ " + shlex.join(cmd) + "\n")
        f.flush()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            f.write(line)
            stdout_lines.append(line)
        code = proc.wait()
        if code != 0:
            raise subprocess.CalledProcessError(code, cmd)
    return "".join(stdout_lines)


def parse_json_objects(text: str, source: str) -> list[dict[str, Any]]:
    objects = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid JSON in {source}:{line_number}: {err}") from err
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object in {source}:{line_number}")
        objects.append(value)
    return objects


def parse_metric_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        return parse_metric_value(value.get("Int"))
    return None


def current_metric_value(metric_summary: Any) -> int | None:
    if not isinstance(metric_summary, dict):
        return None

    metrics = metric_summary.get("metrics")
    if not isinstance(metrics, dict):
        return None

    value = parse_metric_value(metrics.get("Left"))
    if value is not None:
        return value

    both = metrics.get("Both")
    if isinstance(both, list) and both:
        return parse_metric_value(both[0])
    return None


def callgrind_summary(summary: dict[str, Any]) -> dict[str, Any]:
    profiles = summary.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("Gungraun JSON object is missing `profiles`")

    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        if profile.get("tool") != "Callgrind":
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
    raise ValueError("Gungraun JSON object is missing total Callgrind metrics")


def extract_metrics(summary: dict[str, Any]) -> dict[str, int]:
    callgrind = callgrind_summary(summary)
    metrics = {}
    for metric in SELECTED_METRICS:
        value = current_metric_value(callgrind.get(metric))
        if value is None:
            raise ValueError(f"Gungraun JSON object is missing `{metric}`")
        metrics[metric] = value
    return metrics


def benchmark_paths(summary: dict[str, Any]) -> list[str]:
    module_path = summary.get("module_path")
    bench_id = summary.get("id")

    paths = []
    if isinstance(module_path, str):
        paths.append(module_path)
    if isinstance(module_path, str) and isinstance(bench_id, str):
        paths.append(f"{module_path}::{bench_id}")
    if isinstance(bench_id, str):
        paths.append(bench_id)
    return paths


def matches_filter(summary: dict[str, Any], pattern: str) -> bool:
    for candidate in benchmark_paths(summary):
        if fnmatch.fnmatchcase(candidate, pattern):
            return True
    return False


def result_from_summary(bench: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    metrics = extract_metrics(summary)
    return {
        **bench,
        "metrics": metrics,
        "value": metrics[GATE_METRIC],
        "value_metric": GATE_METRIC,
    }


def run_benchmarks(benchmarks: list[dict[str, Any]], output_dir: Path) -> list[dict[str, Any]]:
    raw_output = output_dir / RAW_OUTPUT
    raw_output.write_text("", encoding="utf-8")
    env = os.environ.copy()

    results = []
    metrics = ",".join(SELECTED_METRICS)
    for bench in benchmarks:
        cmd = (
            ["cargo", "bench"]
            + bench["cargo_flags"]
            + ["-p", bench["package"], "--bench", bench["bench"], "--"]
            + [bench["filter"], "--output-format=json", f"--callgrind-metrics={metrics}"]
        )
        stdout = run_streamed(cmd, raw_output, env)
        summaries = parse_json_objects(stdout, bench["filter"])
        if len(summaries) != 1:
            raise RuntimeError(
                f"expected exactly one Gungraun JSON result for `{bench['name']}`, "
                f"got {len(summaries)}"
            )
        results.append(result_from_summary(bench, summaries[0]))
    return results


def load_skip_run_results(benchmarks: list[dict[str, Any]], output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / RAW_OUTPUT
    summaries = parse_json_objects(path.read_text(encoding="utf-8"), str(path))
    results = []
    for bench in benchmarks:
        matches = [summary for summary in summaries if matches_filter(summary, bench["filter"])]
        if len(matches) != 1:
            raise RuntimeError(
                f"expected exactly one Gungraun JSON result for `{bench['name']}`, "
                f"got {len(matches)}"
            )
        results.append(result_from_summary(bench, matches[0]))
    return results


def load_baseline(path: str | None) -> list[dict[str, Any]] | None:
    if path is None:
        return None
    baseline_path = Path(path)
    if not baseline_path.exists():
        return None
    baseline = read_toml(baseline_path).get("benchmarks")
    if not isinstance(baseline, list):
        raise ValueError(f"baseline `{path}` must contain a `benchmarks` array")
    return baseline


def find_baseline(
    data: list[dict[str, Any]] | None, baseline_suite: str, name: str
) -> dict[str, Any] | None:
    if data is None:
        return None
    for bench in data:
        if bench.get("baseline_suite") == baseline_suite and bench.get("name") == name:
            return bench
    return None


def baseline_metrics(bench: dict[str, Any]) -> dict[str, int]:
    metrics = bench.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError(f"baseline `{bench.get('name', '')}` is missing Gungraun metrics")
    parsed = {}
    for metric in SELECTED_METRICS:
        value = parse_metric_value(metrics.get(metric))
        if value is None:
            raise ValueError(f"baseline `{bench.get('name', '')}` is missing `{metric}`")
        parsed[metric] = value
    return parsed


def compare_results(
    current: list[dict[str, Any]], baseline_data: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    comparisons = []
    for result in current:
        baseline = find_baseline(baseline_data, result["baseline_suite"], result["name"])
        if baseline is None:
            comparisons.append(
                {
                    **result,
                    "baseline": None,
                    "baseline_metrics": None,
                    "metric_deltas": None,
                    "delta_percent": None,
                    "regressed": False,
                    "status": "missing baseline",
                }
            )
            continue

        base_metrics = baseline_metrics(baseline)
        gate_baseline = base_metrics[GATE_METRIC]
        if gate_baseline == 0:
            raise ValueError(f"baseline `{result['name']}` has zero `{GATE_METRIC}`")
        delta_percent = ((result["value"] - gate_baseline) / gate_baseline) * 100
        regressed = delta_percent > result["threshold_percent"]
        metric_deltas = {}
        for metric in SELECTED_METRICS:
            base = base_metrics[metric]
            current_value = result["metrics"][metric]
            metric_deltas[metric] = None if base == 0 else ((current_value - base) / base) * 100

        comparisons.append(
            {
                **result,
                "baseline": baseline,
                "baseline_metrics": base_metrics,
                "metric_deltas": metric_deltas,
                "delta_percent": delta_percent,
                "regressed": regressed,
                "status": "regressed" if regressed else "ok",
            }
        )
    return comparisons


def format_count(value: int | None) -> str:
    if value is None:
        return "-"
    return f"{value:,}"


def format_delta(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:+.2f}%"


def escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def toml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return toml_quote(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    raise TypeError(f"unsupported TOML value: {value!r}")


def write_toml_table(path: Path, values: dict[str, Any]) -> None:
    lines = []
    for key, value in values.items():
        if value is None:
            continue
        lines.append(f"{key} = {toml_value(value)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_toml_values(lines: list[str], values: dict[str, Any], prefix: str) -> None:
    nested = []
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, dict):
            nested.append((key, value))
        else:
            lines.append(f"{key} = {toml_value(value)}")
    for key, value in nested:
        lines.extend(["", f"[{prefix}.{key}]"])
        append_toml_values(lines, value, f"{prefix}.{key}")


def write_toml_array(path: Path, name: str, values: list[dict[str, Any]]) -> None:
    lines = []
    for value in values:
        if lines:
            lines.append("")
        lines.append(f"[[{name}]]")
        append_toml_values(lines, value, name)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def status_text(item: dict[str, Any]) -> str:
    if item["status"] == "regressed":
        return "FAIL"
    if item["status"] == "missing baseline":
        return "WARN missing baseline"
    return "PASS"


def render_markdown(comparisons: list[dict[str, Any]], current: list[dict[str, Any]]) -> str:
    regression_count = sum(1 for item in comparisons if item["regressed"])
    missing_count = sum(1 for item in comparisons if item["baseline"] is None)
    lines = [
        "<!-- commonware-benchmark-tracking-results -->",
        "## Benchmark results",
        "",
    ]
    if comparisons:
        lines.append(
            f"Gate: `{GATE_METRIC}` only. "
            f"Regressions: `{regression_count}`. Missing baselines: `{missing_count}`."
        )
    else:
        lines.append(f"Recorded current Gungraun metrics. Gate metric: `{GATE_METRIC}`.")

    if comparisons:
        lines.extend(
            [
                "",
                "| Benchmark | Metric | Baseline | Current | Delta | Threshold | Status |",
                "|---|---|---:|---:|---:|---:|---|",
            ]
        )
        for item in comparisons:
            for metric in SELECTED_METRICS:
                baseline = None
                if item["baseline_metrics"] is not None:
                    baseline = item["baseline_metrics"][metric]
                threshold = f"{item['threshold_percent']:.2f}%" if metric == GATE_METRIC else "-"
                status = status_text(item) if metric == GATE_METRIC else "-"
                delta = None if item["metric_deltas"] is None else item["metric_deltas"][metric]
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            f"`{escape_cell(item['name'])}`",
                            f"`{metric}`",
                            format_count(baseline),
                            format_count(item["metrics"][metric]),
                            format_delta(delta),
                            threshold,
                            status,
                        ]
                    )
                    + " |"
                )
    else:
        lines.extend(
            [
                "",
                "| Benchmark | Metric | Current |",
                "|---|---|---:|",
            ]
        )
        for item in current:
            for metric in SELECTED_METRICS:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            f"`{escape_cell(item['name'])}`",
                            f"`{metric}`",
                            format_count(item["metrics"][metric]),
                        ]
                    )
                    + " |"
                )

    commits = sorted(
        {
            item["baseline"].get("commit", "")[:12]
            for item in comparisons
            if item["baseline"] and item["baseline"].get("commit")
        }
    )
    if commits:
        lines.extend(["", f"Baseline commit(s): `{', '.join(commits)}`"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    config_path = Path(args.config)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    config = read_toml(config_path)
    benchmarks = validate_config(config)

    if args.skip_run:
        current = load_skip_run_results(benchmarks, output_dir)
    else:
        current = run_benchmarks(benchmarks, output_dir)

    commit = os.environ.get("GITHUB_SHA")
    run_id = os.environ.get("GITHUB_RUN_ID")
    ref = os.environ.get("GITHUB_REF_NAME")
    for result in current:
        if commit:
            result["commit"] = commit
        if run_id:
            result["run_id"] = run_id
        if ref:
            result["ref"] = ref

    if args.no_compare:
        comparisons = []
    else:
        baseline_data = load_baseline(args.baseline)
        comparisons = compare_results(current, baseline_data)

    regression_count = sum(1 for item in comparisons if item["regressed"])
    missing_count = sum(1 for item in comparisons if item["baseline"] is None)
    summary = {
        "benchmark_count": len(current),
        "regression_count": regression_count,
        "missing_baseline_count": missing_count,
        "gate_metric": GATE_METRIC,
        "metrics": SELECTED_METRICS,
    }

    write_toml_array(output_dir / "current.toml", "benchmarks", current)
    write_toml_array(output_dir / "comparison.toml", "comparisons", comparisons)
    write_toml_table(output_dir / "summary.toml", summary)
    (output_dir / "comment.md").write_text(
        render_markdown(comparisons, current), encoding="utf-8"
    )

    for key, value in summary.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
