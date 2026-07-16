use crate::{
    config::{Benchmark, Gate},
    results::{display_metrics, Comparison},
};
use std::collections::BTreeSet;

const COMMENT_MARKER: &str = "<!-- commonware-benchmark-tracking-results -->";

pub(super) fn render_report(comparisons: &[Comparison]) -> String {
    let regressions = comparisons.iter().filter(|item| item.regressed()).count();
    let warnings = report_warnings(comparisons);
    let mut lines = vec![
        COMMENT_MARKER.to_string(),
        "## Benchmark results".to_string(),
        String::new(),
        format!("Regressions: `{regressions}`."),
    ];
    if !warnings.is_empty() {
        lines.extend([String::new(), "> [!WARNING]".to_string(), ">".to_string()]);
        lines.extend(warnings.into_iter().map(|warning| format!("> {warning}")));
    }

    for item in comparisons {
        lines.extend([
            String::new(),
            format!("<details><summary>{}</summary>", summary_line(item)),
            String::new(),
        ]);
        render_metadata(&mut lines, &item.current.benchmark);
        render_metrics(&mut lines, item);
        lines.extend([String::new(), "</details>".to_string()]);
    }

    let commits = comparisons
        .iter()
        .filter_map(|item| item.baseline.as_ref())
        .filter(|baseline| !baseline.commit.is_empty())
        .map(|baseline| baseline.commit.chars().take(12).collect::<String>())
        .collect::<BTreeSet<_>>();
    if !commits.is_empty() {
        lines.extend([
            String::new(),
            format!(
                "Baseline commit(s): `{}`",
                commits.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ]);
    }
    lines.push(String::new());
    lines.join("\n")
}

fn report_warnings(comparisons: &[Comparison]) -> Vec<String> {
    let mut warnings = Vec::new();
    for item in comparisons {
        let Some(baseline) = &item.baseline else {
            warnings.push(format!(
                "Missing baseline for `{}`.",
                item.current.benchmark.name
            ));
            continue;
        };
        for gate in &item.current.benchmark.gates {
            if !baseline.metrics.contains_key(&gate.label()) {
                warnings.push(format!(
                    "Baseline for `{}` is missing `{}`; that gate was not evaluated.",
                    item.current.benchmark.name,
                    gate.label()
                ));
            }
        }
    }
    warnings
}

fn summary_line(item: &Comparison) -> String {
    let name = format!("`{}`", escape_summary(&item.current.benchmark.name));
    if item.baseline.is_none() {
        return format!("⚠️ {name} (baseline missing)");
    }

    let status = if item.regressed() { "❌" } else { "✅" };
    let gates = &item.current.benchmark.gates;
    let gate_summary = if gates.len() == 1 {
        let gate = &gates[0];
        let current = format_count(item.current.metrics[&gate.label()]);
        let delta = item
            .deltas
            .get(&gate.label())
            .map_or_else(|| "n/a".to_string(), |delta| format_delta(*delta));
        format!(
            "{}: {current}, delta: {delta}, {}",
            gate.label(),
            gate.description()
        )
    } else {
        let failed = item.gate_failures().len();
        format!("{}/{} gates passed", gates.len() - failed, gates.len())
    };
    format!("{status} {name} ({gate_summary})")
}

fn render_metadata(lines: &mut Vec<String>, benchmark: &Benchmark) {
    let mut rows = vec![
        ("Package", benchmark.package.clone()),
        ("Benchmark target", benchmark.target.clone()),
        ("Variant", benchmark.name.clone()),
        ("Filter", benchmark.filter.clone()),
        ("Baseline suite", benchmark.baseline_suite.clone()),
        (
            "Gates",
            benchmark
                .gates
                .iter()
                .map(Gate::description)
                .collect::<Vec<_>>()
                .join("; "),
        ),
    ];
    if !benchmark.cargo_flags.is_empty() {
        rows.push(("Cargo flags", benchmark.cargo_flags.join(" ")));
    }

    lines.extend(["| Field | Value |".to_string(), "|---|---|".to_string()]);
    for (key, value) in rows {
        lines.push(format!("| {key} | `{}` |", escape_cell(&value)));
    }
}

fn render_metrics(lines: &mut Vec<String>, item: &Comparison) {
    if let Some(baseline) = &item.baseline {
        lines.extend([
            String::new(),
            "| Metric | Baseline | Current | Delta | Gate |".to_string(),
            "|---|---:|---:|---:|---|".to_string(),
        ]);
        for metric in display_metrics(&item.current, Some(baseline)) {
            let baseline_value = baseline
                .metrics
                .get(&metric)
                .map_or_else(|| "n/a".to_string(), |value| format_count(*value));
            let current_value = item
                .current
                .metrics
                .get(&metric)
                .map_or_else(|| "n/a".to_string(), |value| format_count(*value));
            let delta = item
                .deltas
                .get(&metric)
                .map_or_else(|| "n/a".to_string(), |value| format_delta(*value));
            lines.push(format!(
                "| `{metric}` | {baseline_value} | {current_value} | {delta} | {} |",
                gate_text(&item.current.benchmark, &metric)
            ));
        }
        return;
    }

    lines.extend([
        String::new(),
        "| Metric | Current | Gate |".to_string(),
        "|---|---:|---|".to_string(),
    ]);
    for metric in display_metrics(&item.current, None) {
        let Some(value) = item.current.metrics.get(&metric) else {
            continue;
        };
        lines.push(format!(
            "| `{metric}` | {} | {} |",
            format_count(*value),
            gate_text(&item.current.benchmark, &metric)
        ));
    }
}

fn gate_text(benchmark: &Benchmark, metric: &str) -> String {
    let gates = benchmark
        .gates
        .iter()
        .filter(|gate| gate.label() == metric)
        .map(Gate::description)
        .collect::<Vec<_>>()
        .join("<br>");
    if gates.is_empty() {
        return "-".to_string();
    }
    gates
}

fn format_count(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (index, ch) in text.chars().rev().enumerate() {
        if index != 0 && index % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

fn format_delta(value: f64) -> String {
    format!("{value:+.2}%")
}

fn escape_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

fn escape_summary(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
}
