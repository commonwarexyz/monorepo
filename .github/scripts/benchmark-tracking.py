#!/usr/bin/env python3
"""Run exact Criterion benchmarks and compare them with a main-branch artifact."""

import argparse
import os
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

BENCHER_RE = re.compile(
    r"^test (.+?) \.\.\. bench:\s+([\d,]+)\s+(\S+)(?:\s+\(\+/-\s+([\d,]+)\))?"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Path to benchmark tracking config TOML")
    parser.add_argument("--output-dir", required=True, help="Directory for result artifacts")
    parser.add_argument(
        "--baseline",
        help="Path to a previous benchmark-tracking current.toml artifact from main",
    )
    parser.add_argument(
        "--no-compare",
        action="store_true",
        help="Only write current benchmark results without comparing to a baseline",
    )
    parser.add_argument(
        "--skip-run",
        action="store_true",
        help="Only process an existing bencher output file in the output directory",
    )
    return parser.parse_args()


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def string_array(value: Any, field: str) -> list[str]:
    if isinstance(value, str):
        value = shlex.split(value)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"`{field}` must be a string array or shell string")
    return value


def threshold(value: Any, field: str) -> float:
    threshold_percent = float(value)
    if threshold_percent < 0:
        raise ValueError(f"`{field}` must be non-negative")
    return threshold_percent


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
        package_name = package.get("name")
        if not isinstance(package_name, str) or not package_name:
            raise ValueError(f"`{prefix}.name` must be a non-empty string")
        baseline_suite = package.get("baseline_suite", package_name)
        if not isinstance(baseline_suite, str) or not baseline_suite:
            raise ValueError(f"`{prefix}.baseline_suite` must be a non-empty string")
        cargo_flags = string_array(package.get("cargo_flags", []), f"{prefix}.cargo_flags")
        package_criterion_args = string_array(
            package.get("criterion_args", []), f"{prefix}.criterion_args"
        )
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
            bench_name = benchmark.get("name")
            if not isinstance(bench_name, str) or not bench_name:
                raise ValueError(f"`{bench_prefix}.name` must be a non-empty string")
            criterion_args = string_array(
                benchmark.get("criterion_args", package_criterion_args),
                f"{bench_prefix}.criterion_args",
            )
            benchmark_threshold = threshold(
                benchmark.get("threshold_percent", package_threshold),
                f"{bench_prefix}.threshold_percent",
            )
            variants = benchmark.get("variants")
            if not isinstance(variants, list) or not variants:
                raise ValueError(f"`{bench_prefix}.variants` must be a non-empty array")

            for variant_idx, variant in enumerate(variants):
                variant_prefix = f"{bench_prefix}.variants[{variant_idx}]"
                variant_criterion_args = criterion_args
                variant_threshold = benchmark_threshold
                if isinstance(variant, str):
                    variant_name = variant
                elif isinstance(variant, dict):
                    variant_name = variant.get("name")
                    if not isinstance(variant_name, str) or not variant_name:
                        raise ValueError(f"`{variant_prefix}.name` must be a non-empty string")
                    variant_criterion_args = string_array(
                        variant.get("criterion_args", criterion_args),
                        f"{variant_prefix}.criterion_args",
                    )
                    variant_threshold = threshold(
                        variant.get("threshold_percent", benchmark_threshold),
                        f"{variant_prefix}.threshold_percent",
                    )
                else:
                    raise ValueError(f"`{variant_prefix}` must be a string or object")
                key = (baseline_suite, package_name, bench_name, variant_name)
                if key in seen:
                    raise ValueError(f"duplicate benchmark variant `{variant_name}`")
                seen.add(key)
                validated.append(
                    {
                        "package": package_name,
                        "bench": bench_name,
                        "name": variant_name,
                        "baseline_suite": baseline_suite,
                        "cargo_flags": cargo_flags,
                        "criterion_args": variant_criterion_args,
                        "threshold_percent": variant_threshold,
                    }
                )
    return validated


def run_streamed(cmd: list[str], output: Path, env: dict[str, str]) -> None:
    print("$ " + shlex.join(cmd), flush=True)
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
        code = proc.wait()
        if code != 0:
            raise subprocess.CalledProcessError(code, cmd)


def parse_bencher_output(text: str) -> list[dict[str, Any]]:
    results = []
    for line in text.splitlines():
        match = BENCHER_RE.match(line.strip())
        if not match:
            continue
        name, value, unit, error = match.groups()
        results.append(
            {
                "name": name,
                "value": int(value.replace(",", "")),
                "range": f"+/- {error}" if error else "",
                "unit": unit,
            }
        )
    return results


def run_benchmarks(benchmarks: list[dict[str, Any]], output_dir: Path) -> list[dict[str, Any]]:
    raw_output = output_dir / "bencher-output.txt"
    raw_output.write_text("", encoding="utf-8")
    env = os.environ.copy()

    results = []
    for bench in benchmarks:
        cmd = (
            ["cargo", "bench"]
            + bench["cargo_flags"]
            + ["-p", bench["package"], "--bench", bench["bench"], "--"]
            + ["--output-format", "bencher", "--exact"]
            + bench["criterion_args"]
            + [bench["name"]]
        )
        before = raw_output.read_text(encoding="utf-8")
        run_streamed(cmd, raw_output, env)
        after = raw_output.read_text(encoding="utf-8")
        parsed = parse_bencher_output(after[len(before) :])
        if len(parsed) != 1:
            names = ", ".join(result["name"] for result in parsed) or "none"
            raise RuntimeError(
                f"expected exactly one result for `{bench['name']}`, got {len(parsed)}: {names}"
            )
        if parsed[0]["name"] != bench["name"]:
            raise RuntimeError(
                f"criterion did not run the exact benchmark requested: "
                f"requested `{bench['name']}`, got `{parsed[0]['name']}`"
            )
        results.append({**bench, **parsed[0]})
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


def format_value(value: int | None, unit: str) -> str:
    if value is None:
        return "-"
    if unit != "ns/iter":
        return f"{value:,} {unit}"
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.3f} s"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.3f} ms"
    if value >= 1_000:
        return f"{value / 1_000:.3f} us"
    return f"{value:,} ns"


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
                    "delta_percent": None,
                    "regressed": False,
                    "status": "missing baseline",
                }
            )
            continue

        delta_percent = ((result["value"] - baseline["value"]) / baseline["value"]) * 100
        regressed = delta_percent > result["threshold_percent"]
        comparisons.append(
            {
                **result,
                "baseline": baseline,
                "delta_percent": delta_percent,
                "regressed": regressed,
                "status": "regressed" if regressed else "ok",
            }
        )
    return comparisons


def render_markdown(comparisons: list[dict[str, Any]]) -> str:
    regression_count = sum(1 for item in comparisons if item["regressed"])
    missing_count = sum(1 for item in comparisons if item["baseline"] is None)
    lines = [
        "<!-- commonware-benchmark-tracking-results -->",
        "## Benchmark results",
        "",
    ]
    if regression_count:
        lines.append(
            f"> [!CAUTION]\n>\n> {regression_count} benchmark(s) exceeded the regression threshold."
        )
    else:
        lines.append(
            "> [!TIP]\n>\n> ✅ **PASSED**: No benchmark exceeded the regression threshold."
        )
    if missing_count:
        lines.extend(
            [
                "",
                f"> [!WARNING]\n>\n> {missing_count} benchmark(s) had no uploaded main-branch baseline.",
            ]
        )
    lines.extend(
        [
            "",
            "<details>",
            "<summary>Benchmark comparison table</summary>",
            "",
            "| Benchmark | Baseline (main) | Current | Delta | Threshold | Status |",
            "|---|---:|---:|---:|---:|---|",
        ]
    )
    for item in comparisons:
        baseline = item["baseline"]
        base_value = baseline["value"] if baseline else None
        base_unit = baseline.get("unit", item["unit"]) if baseline else item["unit"]
        if item["delta_percent"] is None:
            delta = "-"
        else:
            delta = f"{item['delta_percent']:+.2f}%"
        if item["status"] == "regressed":
            status = "❌ FAIL regression"
        elif item["status"] == "missing baseline":
            status = "⚠️ WARN missing baseline"
        else:
            status = "✅ PASS"
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{escape_cell(item['name'])}`",
                    format_value(base_value, base_unit),
                    format_value(item["value"], item["unit"]),
                    delta,
                    f"{item['threshold_percent']:.2f}%",
                    status,
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
    lines.extend(["", "</details>"])
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
        current = parse_bencher_output(
            (output_dir / "bencher-output.txt").read_text(encoding="utf-8")
        )
        by_name = {bench["name"]: bench for bench in benchmarks}
        current = [{**by_name[result["name"]], **result} for result in current]
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
    }

    write_toml_array(output_dir / "current.toml", "benchmarks", current)
    write_toml_array(output_dir / "comparison.toml", "comparisons", comparisons)
    write_toml_table(output_dir / "summary.toml", summary)
    (output_dir / "comment.md").write_text(render_markdown(comparisons), encoding="utf-8")

    for key, value in summary.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
