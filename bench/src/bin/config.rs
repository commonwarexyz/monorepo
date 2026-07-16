use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::HashSet;

pub(crate) const CALLGRIND_METRICS: &[&str] = &[
    "Ir",
    "L1hits",
    "LLhits",
    "RamHits",
    "TotalRW",
    "EstimatedCycles",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Direction {
    Down,
    Up,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gate {
    #[serde(deserialize_with = "non_empty_string")]
    pub(crate) metric: String,
    pub(crate) direction: Direction,
    #[serde(deserialize_with = "non_negative_f64")]
    pub(crate) threshold_percent: f64,
}

impl Gate {
    fn default() -> Self {
        Self {
            metric: "EstimatedCycles".to_string(),
            direction: Direction::Down,
            threshold_percent: 10.0,
        }
    }

    pub(crate) fn label(&self) -> String {
        self.metric.clone()
    }

    pub(crate) fn description(&self) -> String {
        let movement = match self.direction {
            Direction::Down => "decrease",
            Direction::Up => "increase",
        };
        format!(
            "{} should {movement}; tolerance {:.2}%",
            self.metric, self.threshold_percent
        )
    }

    pub(crate) fn failed(&self, delta: f64) -> bool {
        match self.direction {
            Direction::Down => delta > self.threshold_percent,
            Direction::Up => delta < -self.threshold_percent,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Benchmark {
    #[serde(deserialize_with = "non_empty_string")]
    pub(crate) package: String,
    #[serde(deserialize_with = "non_empty_string")]
    pub(crate) target: String,
    #[serde(deserialize_with = "non_empty_string")]
    pub(crate) name: String,
    #[serde(deserialize_with = "non_empty_string")]
    pub(crate) filter: String,
    #[serde(deserialize_with = "non_empty_string")]
    pub(crate) baseline_suite: String,
    #[serde(default)]
    pub(crate) cargo_flags: Vec<String>,
    #[serde(deserialize_with = "non_empty_vec")]
    pub(crate) gates: Vec<Gate>,
}

impl Benchmark {
    pub(crate) fn key(&self) -> (String, String) {
        (self.baseline_suite.clone(), self.name.clone())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default, deserialize_with = "optional_non_empty_vec")]
    gates: Option<Vec<Gate>>,
    #[serde(deserialize_with = "non_empty_vec")]
    packages: Vec<PackageConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageConfig {
    #[serde(deserialize_with = "non_empty_string")]
    name: String,
    #[serde(default, deserialize_with = "optional_non_empty_string")]
    baseline_suite: Option<String>,
    #[serde(default)]
    cargo_flags: Vec<String>,
    #[serde(default, deserialize_with = "optional_non_empty_vec")]
    gates: Option<Vec<Gate>>,
    #[serde(deserialize_with = "non_empty_vec")]
    benchmarks: Vec<TargetConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    #[serde(deserialize_with = "non_empty_string")]
    name: String,
    #[serde(default, deserialize_with = "optional_non_empty_vec")]
    gates: Option<Vec<Gate>>,
    #[serde(deserialize_with = "non_empty_vec")]
    variants: Vec<VariantConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantConfig {
    #[serde(deserialize_with = "non_empty_string")]
    name: String,
    #[serde(deserialize_with = "non_empty_string")]
    filter: String,
    #[serde(default, deserialize_with = "optional_non_empty_vec")]
    gates: Option<Vec<Gate>>,
}

pub(crate) fn load_config(input: &str) -> Result<Vec<Benchmark>> {
    let config: Config = toml::from_str(input)?;
    let config_gates = inherit_gates(config.gates, &[Gate::default()]);
    let mut benchmarks = Vec::new();
    let mut seen = HashSet::new();
    for package in config.packages {
        let baseline_suite = package
            .baseline_suite
            .clone()
            .unwrap_or_else(|| package.name.clone());
        let package_gates = inherit_gates(package.gates, &config_gates);
        for target in package.benchmarks {
            let target_gates = inherit_gates(target.gates, &package_gates);
            for variant in target.variants {
                let benchmark = Benchmark {
                    package: package.name.clone(),
                    target: target.name.clone(),
                    name: variant.name,
                    filter: variant.filter,
                    baseline_suite: baseline_suite.clone(),
                    cargo_flags: package.cargo_flags.clone(),
                    gates: inherit_gates(variant.gates, &target_gates),
                };
                if !seen.insert(benchmark.key()) {
                    bail!("duplicate benchmark `{}`", benchmark.name);
                }
                benchmarks.push(benchmark);
            }
        }
    }
    Ok(benchmarks)
}

fn inherit_gates(gates: Option<Vec<Gate>>, inherited: &[Gate]) -> Vec<Gate> {
    let Some(gates) = gates else {
        return inherited.to_vec();
    };
    gates
}

fn validate_non_empty(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("must be a non-empty string".to_string());
    }
    Ok(())
}

fn non_empty_string<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_non_empty(&value).map_err(de::Error::custom)?;
    Ok(value)
}

fn optional_non_empty_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    validate_non_empty(&value).map_err(de::Error::custom)?;
    Ok(Some(value))
}

fn non_empty_vec<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(de::Error::custom("must be a non-empty array"));
    }
    Ok(values)
}

fn optional_non_empty_vec<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let Some(values) = Option::<Vec<T>>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if values.is_empty() {
        return Err(de::Error::custom("must be a non-empty array"));
    }
    Ok(Some(values))
}

fn non_negative_f64<'de, D>(deserializer: D) -> std::result::Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = f64::deserialize(deserializer)?;
    if value < 0.0 {
        return Err(de::Error::custom("must be non-negative"));
    }
    Ok(value)
}

pub(crate) fn tracked_labels(benchmarks: &[Benchmark]) -> Vec<String> {
    let mut labels = CALLGRIND_METRICS
        .iter()
        .map(|metric| metric.to_string())
        .collect::<Vec<_>>();
    let mut seen = labels.iter().cloned().collect::<HashSet<_>>();
    for benchmark in benchmarks {
        for gate in &benchmark.gates {
            let label = gate.label();
            if seen.insert(label.clone()) {
                labels.push(label);
            }
        }
    }
    labels
}

pub(crate) fn callgrind_labels(benchmarks: &[Benchmark]) -> Vec<String> {
    let _ = benchmarks;
    CALLGRIND_METRICS
        .iter()
        .map(|metric| metric.to_string())
        .collect()
}
