use crate::{
    config::{Benchmark, Gate, tracked_labels},
    render::render_report,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    path::Path,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BenchResult {
    #[serde(flatten)]
    pub(crate) benchmark: Benchmark,
    pub(crate) metrics: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) commit: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) run_id: String,
    #[serde(default, rename = "ref", skip_serializing_if = "String::is_empty")]
    pub(crate) ref_name: String,
}

impl BenchResult {
    fn validate(&self) -> Result<()> {
        for label in tracked_labels(std::slice::from_ref(&self.benchmark)) {
            if !self.metrics.contains_key(&label) {
                bail!("benchmark `{}` is missing `{label}`", self.benchmark.name);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Comparison {
    pub(crate) current: BenchResult,
    pub(crate) baseline: Option<BenchResult>,
    pub(crate) deltas: BTreeMap<String, f64>,
}

impl Comparison {
    pub(crate) fn gate_failures(&self) -> Vec<Gate> {
        if self.baseline.is_none() {
            return Vec::new();
        }
        self.current
            .benchmark
            .gates
            .iter()
            .filter(|gate| {
                self.deltas
                    .get(&gate.label())
                    .is_some_and(|delta| gate.failed(*delta))
            })
            .cloned()
            .collect()
    }

    pub(crate) fn regressed(&self) -> bool {
        !self.gate_failures().is_empty()
    }

    fn output(&self) -> ComparisonOutput {
        ComparisonOutput {
            current: self.current.clone(),
            metric_deltas: self
                .deltas
                .iter()
                .map(|(label, delta)| (label.clone(), MetricDeltaOutput::from(*delta)))
                .collect(),
            failed_gates: self.gate_failures(),
            baseline_metrics: self
                .baseline
                .as_ref()
                .map(|baseline| baseline.metrics.clone()),
            regressed: self.baseline.as_ref().map(|_| self.regressed()),
        }
    }
}

#[derive(Deserialize)]
struct BaselineFile {
    benchmarks: Vec<BenchResult>,
}

pub(crate) fn load_baseline(path: Option<&Path>) -> Result<HashMap<(String, String), BenchResult>> {
    let Some(path) = path else {
        return Ok(HashMap::new());
    };
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let input = fs::read_to_string(path)?;
    let parsed: BaselineFile = toml::from_str(&input).with_context(|| {
        format!(
            "baseline `{}` must contain a `benchmarks` array",
            path.display()
        )
    })?;
    let mut baseline = HashMap::new();
    for result in parsed.benchmarks {
        result.validate()?;
        baseline.insert(result.benchmark.key(), result);
    }
    Ok(baseline)
}

pub(crate) fn compare(
    current: &[BenchResult],
    baseline: &HashMap<(String, String), BenchResult>,
) -> Result<Vec<Comparison>> {
    let mut comparisons = Vec::new();
    for result in current {
        for gate in &result.benchmark.gates {
            if !result.metrics.contains_key(&gate.label()) {
                bail!(
                    "current result `{}` is missing `{}`",
                    result.benchmark.name,
                    gate.label()
                );
            }
        }

        let Some(previous) = baseline.get(&result.benchmark.key()).cloned() else {
            comparisons.push(Comparison {
                current: result.clone(),
                baseline: None,
                deltas: BTreeMap::new(),
            });
            continue;
        };

        let mut deltas = BTreeMap::new();
        for metric in display_metrics(result, Some(&previous)) {
            let (Some(current), Some(baseline)) =
                (result.metrics.get(&metric), previous.metrics.get(&metric))
            else {
                continue;
            };
            deltas.insert(metric, percent_delta(*current, *baseline));
        }
        comparisons.push(Comparison {
            current: result.clone(),
            baseline: Some(previous),
            deltas,
        });
    }
    Ok(comparisons)
}

pub(crate) fn display_metrics(
    current: &BenchResult,
    baseline: Option<&BenchResult>,
) -> Vec<String> {
    let mut metrics = tracked_labels(std::slice::from_ref(&current.benchmark));
    let mut seen = metrics.iter().cloned().collect::<HashSet<_>>();
    for result in [Some(current), baseline].into_iter().flatten() {
        for metric in result.metrics.keys() {
            if seen.insert(metric.clone()) {
                metrics.push(metric.clone());
            }
        }
    }
    metrics
}

fn percent_delta(current: u64, baseline: u64) -> f64 {
    if baseline == 0 {
        if current == 0 {
            return 0.0;
        }
        return f64::INFINITY;
    }

    ((current as f64 - baseline as f64) / baseline as f64) * 100.0
}

#[derive(Serialize)]
struct CurrentFile<'a> {
    benchmarks: &'a [BenchResult],
}

#[derive(Serialize)]
struct SummaryFile {
    benchmark_count: usize,
    metrics: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regression_count: Option<usize>,
}

#[derive(Serialize)]
struct ComparisonFile {
    comparisons: Vec<ComparisonOutput>,
}

#[derive(Serialize)]
struct ComparisonOutput {
    #[serde(flatten)]
    current: BenchResult,
    metric_deltas: BTreeMap<String, MetricDeltaOutput>,
    failed_gates: Vec<Gate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_metrics: Option<BTreeMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regressed: Option<bool>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum MetricDeltaOutput {
    Finite(f64),
    NonFinite(&'static str),
}

impl From<f64> for MetricDeltaOutput {
    fn from(delta: f64) -> Self {
        if delta.is_finite() {
            return Self::Finite(delta);
        }
        if delta.is_nan() {
            return Self::NonFinite("nan");
        }
        if delta.is_sign_positive() {
            return Self::NonFinite("inf");
        }
        Self::NonFinite("-inf")
    }
}

pub(crate) fn write_outputs(
    output_dir: &Path,
    current: &[BenchResult],
    comparisons: Option<&[Comparison]>,
) -> Result<()> {
    for result in current {
        result.validate()?;
    }

    fs::create_dir_all(output_dir)?;
    fs::write(
        output_dir.join("current.toml"),
        toml::to_string(&CurrentFile {
            benchmarks: current,
        })?,
    )?;

    let mut summary = SummaryFile {
        benchmark_count: current.len(),
        metrics: tracked_labels(
            &current
                .iter()
                .map(|result| result.benchmark.clone())
                .collect::<Vec<_>>(),
        ),
        regression_count: None,
    };
    if let Some(comparisons) = comparisons {
        let comparison_file = ComparisonFile {
            comparisons: comparisons.iter().map(Comparison::output).collect(),
        };
        fs::write(
            output_dir.join("comparison.toml"),
            toml::to_string(&comparison_file)?,
        )?;
        summary.regression_count = Some(comparisons.iter().filter(|item| item.regressed()).count());
        fs::write(output_dir.join("comment.md"), render_report(comparisons))?;
    }
    fs::write(output_dir.join("summary.toml"), toml::to_string(&summary)?)?;
    Ok(())
}
