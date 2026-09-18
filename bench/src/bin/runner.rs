use crate::{
    config::{Benchmark, callgrind_labels},
    results::BenchResult,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Command, Stdio},
};

const RAW_OUTPUT: &str = "gungraun-output.jsonl";
const CUSTOM_OUTPUT: &str = "commonware-bench-metrics.jsonl";
const BENCHMARK_TRACKING_CFG: &str = "--cfg benchmark_tracking";

pub(crate) fn run_benchmarks(
    benchmarks: &[Benchmark],
    output_dir: &Path,
) -> Result<Vec<BenchResult>> {
    fs::create_dir_all(output_dir)?;
    let raw_output = output_dir.join(RAW_OUTPUT);
    let custom_output = env::current_dir()?.join(output_dir).join(CUSTOM_OUTPUT);
    fs::File::create(&raw_output)?;
    fs::File::create(&custom_output)?;
    let callgrind_metrics = callgrind_labels(benchmarks);

    let mut results = Vec::new();
    for benchmark in benchmarks {
        let output = run_one_benchmark(benchmark, &raw_output, &custom_output, &callgrind_metrics)?;
        let stdout_lines = parse_lines(&output.stdout, &benchmark.name)?;
        let custom_lines = parse_lines(&output.custom, &benchmark.name)?;
        let summaries = stdout_lines
            .iter()
            .filter_map(OutputLine::summary)
            .filter(|summary| summary.matches(&benchmark.filter))
            .collect::<Vec<_>>();
        if summaries.len() != 1 {
            bail!(
                "expected one Gungraun result for `{}`, got {}",
                benchmark.name,
                summaries.len()
            );
        }

        let mut metrics = summaries[0].callgrind_metrics(&callgrind_metrics)?;
        for (name, value) in custom_metrics(&custom_lines, &benchmark.name)? {
            if metrics.insert(name.clone(), value).is_some() {
                bail!(
                    "benchmark `{}` emitted duplicate metric `{name}`",
                    benchmark.name
                );
            }
        }
        results.push(BenchResult {
            benchmark: benchmark.clone(),
            metrics,
            commit: env::var("GITHUB_SHA").unwrap_or_default(),
            run_id: env::var("GITHUB_RUN_ID").unwrap_or_default(),
            ref_name: env::var("GITHUB_REF_NAME").unwrap_or_default(),
        });
    }
    Ok(results)
}

fn run_one_benchmark(
    benchmark: &Benchmark,
    raw_output: &Path,
    custom_output: &Path,
    callgrind_metrics: &[String],
) -> Result<BenchmarkOutput> {
    let mut cmd = vec!["cargo".to_string(), "bench".to_string()];
    cmd.extend(benchmark.cargo_flags.clone());
    cmd.extend([
        "-p".to_string(),
        benchmark.package.clone(),
        "--bench".to_string(),
        benchmark.target.clone(),
        "--".to_string(),
        benchmark.filter.clone(),
        "--output-format=json".to_string(),
        format!("--callgrind-metrics={}", callgrind_metrics.join(",")),
    ]);
    let command = shlex::try_join(cmd.iter().map(String::as_str)).context("quote command")?;
    println!("$ {command}");

    let mut raw = fs::OpenOptions::new().append(true).open(raw_output)?;
    writeln!(raw, "$ {command}")?;

    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .env(commonware_bench::METRICS_PATH_ENV, custom_output)
        .env("RUSTFLAGS", rustflags())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn `{command}`"))?;

    let stdout = child.stdout.take().context("missing stdout")?;
    let reader = BufReader::new(stdout);
    let mut lines = String::new();
    for line in reader.lines() {
        let line = line?;
        println!("{line}");
        writeln!(raw, "{line}")?;
        lines.push_str(&line);
        lines.push('\n');
    }

    let status = child.wait()?;
    if !status.success() {
        bail!("benchmark command failed with {status}: {command}");
    }
    let custom = fs::read_to_string(custom_output).with_context(|| {
        format!(
            "read custom benchmark metrics from {}",
            custom_output.to_string_lossy()
        )
    })?;
    Ok(BenchmarkOutput {
        stdout: lines,
        custom,
    })
}

fn rustflags() -> String {
    match env::var("RUSTFLAGS") {
        Ok(flags) if !flags.is_empty() => format!("{flags} {BENCHMARK_TRACKING_CFG}"),
        _ => BENCHMARK_TRACKING_CFG.to_string(),
    }
}

struct BenchmarkOutput {
    stdout: String,
    custom: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum OutputLine {
    Custom(CustomMetricLine),
    Summary(SummaryLine),
}

impl OutputLine {
    pub(crate) const fn summary(&self) -> Option<&SummaryLine> {
        match self {
            Self::Summary(summary) => Some(summary),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct CustomMetricLine {
    commonware_bench_metrics: bool,
    benchmark: String,
    metrics: BTreeMap<String, JsonValue>,
}

#[derive(Deserialize)]
pub(crate) struct SummaryLine {
    module_path: Option<String>,
    id: Option<String>,
    profiles: Option<Vec<JsonValue>>,
}

impl SummaryLine {
    pub(crate) fn matches(&self, pattern: &str) -> bool {
        let mut candidates = Vec::new();
        if let Some(module_path) = &self.module_path {
            candidates.push(module_path.clone());
        }
        if let (Some(module_path), Some(id)) = (&self.module_path, &self.id) {
            candidates.push(format!("{module_path}::{id}"));
        }
        if let Some(id) = &self.id {
            candidates.push(id.clone());
        }
        let Ok(pattern) = glob::Pattern::new(pattern) else {
            return false;
        };
        candidates
            .iter()
            .any(|candidate| pattern.matches(candidate))
    }

    pub(crate) fn callgrind_metrics(&self, selected: &[String]) -> Result<BTreeMap<String, u64>> {
        let callgrind = self.callgrind_summary()?;
        let mut metrics = BTreeMap::new();
        for metric in selected {
            let value = current_metric_value(callgrind.get(metric))
                .with_context(|| format!("Gungraun result is missing `{metric}`"))?;
            metrics.insert(metric.clone(), value);
        }
        Ok(metrics)
    }

    fn callgrind_summary(&self) -> Result<&serde_json::Map<String, JsonValue>> {
        let profiles = self
            .profiles
            .as_ref()
            .context("Gungraun result is missing `profiles`")?;
        for profile in profiles {
            if profile.get("tool").and_then(JsonValue::as_str) != Some("Callgrind") {
                continue;
            }
            if let Some(callgrind) = profile
                .get("summaries")
                .and_then(|value| value.get("total"))
                .and_then(|value| value.get("summary"))
                .and_then(|value| value.get("Callgrind"))
                .and_then(JsonValue::as_object)
            {
                return Ok(callgrind);
            }
        }
        bail!("Gungraun result is missing total Callgrind metrics");
    }
}

pub(crate) fn parse_lines(text: &str, source: &str) -> Result<Vec<OutputLine>> {
    let mut lines = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        lines.push(
            serde_json::from_str(line)
                .with_context(|| format!("invalid JSON in {source}:{}", line_number + 1))?,
        );
    }
    Ok(lines)
}

pub(crate) fn custom_metrics(
    lines: &[OutputLine],
    benchmark: &str,
) -> Result<BTreeMap<String, u64>> {
    let mut parsed = BTreeMap::new();
    for line in lines {
        let OutputLine::Custom(line) = line else {
            continue;
        };
        if !line.commonware_bench_metrics || line.benchmark != benchmark {
            continue;
        }
        for (name, value) in &line.metrics {
            if name.is_empty() {
                bail!("custom metric entry has an invalid metric name");
            }
            let value = parse_json_metric_value(value)
                .with_context(|| format!("custom metric `{name}` must be an integer"))?;
            parsed.insert(name.clone(), value);
        }
    }
    Ok(parsed)
}

fn current_metric_value(summary: Option<&JsonValue>) -> Option<u64> {
    let metrics = summary?.get("metrics")?.as_object()?;
    if let Some(value) = metrics.get("Left").and_then(parse_json_metric_value) {
        return Some(value);
    }
    metrics
        .get("Both")
        .and_then(JsonValue::as_array)
        .and_then(|both| both.first())
        .and_then(parse_json_metric_value)
}

fn parse_json_metric_value(value: &JsonValue) -> Option<u64> {
    if let Some(value) = value.as_u64() {
        return Some(value);
    }
    value.get("Int").and_then(JsonValue::as_u64)
}
