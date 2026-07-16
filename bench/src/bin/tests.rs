use super::{
    config::{
        callgrind_labels, load_config, tracked_labels, Benchmark, Direction, Gate,
        CALLGRIND_METRICS,
    },
    render::render_report,
    results::{compare, load_baseline, write_outputs, BenchResult},
    runner::{custom_metrics, parse_lines, OutputLine},
};
use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::PathBuf,
};

const FIXTURE: &str = r#"{"module_path":"qmdb_gungraun::qmdb_merkleize::bench_merkleize","id":"any_unordered_fixed_mmr","profiles":[{"tool":"Callgrind","summaries":{"total":{"summary":{"Callgrind":{"Ir":{"metrics":{"Both":[{"Int":1000000},{"Int":900000}]}},"L1hits":{"metrics":{"Both":[{"Int":850000},{"Int":800000}]}},"LLhits":{"metrics":{"Both":[{"Int":120000},{"Int":110000}]}},"RamHits":{"metrics":{"Both":[{"Int":30000},{"Int":25000}]}},"TotalRW":{"metrics":{"Both":[{"Int":300000},{"Int":280000}]}},"EstimatedCycles":{"metrics":{"Both":[{"Int":1450000},{"Int":1300000}]}}}}}}}]}
{"module_path":"qmdb_gungraun::qmdb_merkleize::bench_merkleize","id":"current_ordered_fixed_mmb_chunk_256","profiles":[{"tool":"Callgrind","summaries":{"total":{"summary":{"Callgrind":{"Ir":{"metrics":{"Left":{"Int":2000000}}},"L1hits":{"metrics":{"Left":{"Int":1600000}}},"LLhits":{"metrics":{"Left":{"Int":300000}}},"RamHits":{"metrics":{"Left":{"Int":100000}}},"TotalRW":{"metrics":{"Left":{"Int":650000}}},"EstimatedCycles":{"metrics":{"Left":{"Int":2550000}}}}}}}}]}"#;
const CUSTOM_FIXTURE: &str = r#"{"commonware_bench_metrics":true,"benchmark":"qmdb::merkleize/v=any::unordered::fixed::mmr k=10000 ch=false s=true cc=true","metrics":{"blob_reads":12}}
{"commonware_bench_metrics":true,"benchmark":"qmdb::merkleize/v=current::ordered::fixed::mmb chunk=256 k=10000 ch=false s=true cc=true","metrics":{"blob_reads":24}}"#;
const CONFIG: &str = include_str!("../../../.github/benchmark-tracking.toml");

fn test_benchmarks() -> Vec<Benchmark> {
    load_config(CONFIG).unwrap()
}

fn test_lines() -> Vec<OutputLine> {
    parse_lines(FIXTURE, "fixture").unwrap()
}

fn custom_lines() -> Vec<OutputLine> {
    parse_lines(CUSTOM_FIXTURE, "custom fixture").unwrap()
}

fn result_for(benchmark: Benchmark, metrics: Option<BTreeMap<String, u64>>) -> BenchResult {
    let metrics = metrics.unwrap_or_else(|| {
        let lines = test_lines();
        let mut metrics = lines
            .iter()
            .filter_map(OutputLine::summary)
            .find(|item| item.matches(&benchmark.filter))
            .unwrap()
            .callgrind_metrics(&callgrind_labels(std::slice::from_ref(&benchmark)))
            .unwrap();
        metrics.extend(custom_metrics(&custom_lines(), &benchmark.name).unwrap());
        metrics
    });
    BenchResult {
        benchmark,
        metrics,
        commit: String::new(),
        run_id: String::new(),
        ref_name: String::new(),
    }
}

#[test]
fn parses_and_filters_gungraun_output() {
    let lines = test_lines();
    let summaries = lines
        .iter()
        .filter_map(OutputLine::summary)
        .collect::<Vec<_>>();
    assert_eq!(summaries.len(), 2);
    assert!(summaries[0].matches("*::bench_merkleize::any_unordered_fixed_mmr"));
    assert!(!summaries[0].matches("*::missing"));
}

#[test]
fn extracts_selected_callgrind_metrics() {
    let lines = test_lines();
    let summaries = lines
        .iter()
        .filter_map(OutputLine::summary)
        .collect::<Vec<_>>();
    let metrics = summaries[0]
        .callgrind_metrics(&callgrind_metrics())
        .unwrap();
    assert_eq!(metrics["Ir"], 1_000_000);
    assert_eq!(metrics["EstimatedCycles"], 1_450_000);

    let metrics = summaries[1]
        .callgrind_metrics(&callgrind_metrics())
        .unwrap();
    assert_eq!(metrics["Ir"], 2_000_000);
    assert_eq!(metrics["EstimatedCycles"], 2_550_000);
}

#[test]
fn reads_custom_metrics_from_jsonl_file() {
    let output_dir = unique_temp_dir();
    let custom_output = output_dir.join("custom.jsonl");
    let benchmark = test_benchmarks()[0].clone();
    fs::write(
        &custom_output,
        format!(
            "{{\"commonware_bench_metrics\":true,\"benchmark\":\"{}\",\"metrics\":{{\"blob_reads\":12}}}}\n",
            benchmark.name
        ),
    )
    .unwrap();

    let lines = fs::read_to_string(&custom_output).unwrap();

    let parsed = parse_lines(&lines, "custom metrics").unwrap();
    let metrics = custom_metrics(&parsed, &benchmark.name).unwrap();
    assert_eq!(metrics["blob_reads"], 12);
    fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn compares_and_renders_passing_result() {
    let current = result_for(test_benchmarks()[0].clone(), None);
    let baseline = HashMap::from([(current.benchmark.key(), current.clone())]);
    let comparisons = compare(&[current], &baseline).unwrap();
    let report = render_report(&comparisons);

    assert!(!comparisons[0].regressed());
    assert!(report.contains("Regressions: `0`."));
    assert!(report.contains("2/2 gates passed"));
    assert!(report.contains("`EstimatedCycles`"));
    assert!(report.contains("| `Ir` | 1,000,000 | 1,000,000 | +0.00% | - |"));
    assert!(!report.contains("Missing baseline"));
}

#[test]
fn missing_baseline_warns_without_regression() {
    let current = result_for(test_benchmarks()[0].clone(), None);
    let comparisons = compare(&[current], &HashMap::new()).unwrap();
    let report = render_report(&comparisons);

    assert!(!comparisons[0].regressed());
    assert!(report.contains("Missing baseline"));
    assert!(report.contains("| `EstimatedCycles` | 1,450,000 |"));
}

#[test]
fn estimated_cycles_regression_writes_summary() {
    let benchmark = test_benchmarks()[0].clone();
    let baseline_metrics = tracked_labels(std::slice::from_ref(&benchmark))
        .into_iter()
        .map(|metric| (metric, 1_000))
        .collect::<BTreeMap<_, _>>();
    let mut current_metrics = baseline_metrics.clone();
    current_metrics.insert("EstimatedCycles".to_string(), 1_111);
    let baseline = result_for(benchmark.clone(), Some(baseline_metrics));
    let current = result_for(benchmark.clone(), Some(current_metrics));

    let comparisons = compare(
        std::slice::from_ref(&current),
        &HashMap::from([(benchmark.key(), baseline)]),
    )
    .unwrap();
    assert!(comparisons[0].regressed());

    let output_dir = unique_temp_dir();
    write_outputs(&output_dir, &[current], Some(&comparisons)).unwrap();
    let summary = fs::read_to_string(output_dir.join("summary.toml")).unwrap();
    assert!(summary.contains("regression_count = 1"));
    fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn custom_metric_gate_regresses() {
    let benchmark = custom_metric_benchmark();
    let mut current_metrics = complete_metrics();
    current_metrics.insert("blob_reads".to_string(), 111);
    let current = result_for(benchmark.clone(), Some(current_metrics));
    let baseline = result_for(
        benchmark.clone(),
        Some(BTreeMap::from([("blob_reads".to_string(), 100)])),
    );

    let comparisons = compare(
        std::slice::from_ref(&current),
        &HashMap::from([(benchmark.key(), baseline)]),
    )
    .unwrap();
    let report = render_report(&comparisons);

    assert!(comparisons[0].regressed());
    assert!(report.contains("blob_reads"));
    assert!(report.contains("Regressions: `1`."));

    let output_dir = unique_temp_dir();
    write_outputs(&output_dir, &[current], Some(&comparisons)).unwrap();
    let current = fs::read_to_string(output_dir.join("current.toml")).unwrap();
    assert!(current.contains("blob_reads = 111"));
    fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn zero_baseline_metric_regresses_when_current_increases() {
    let benchmark = custom_metric_benchmark();
    let mut current_metrics = complete_metrics();
    current_metrics.insert("blob_reads".to_string(), 1);
    let current = result_for(benchmark.clone(), Some(current_metrics));
    let baseline = result_for(
        benchmark.clone(),
        Some(BTreeMap::from([("blob_reads".to_string(), 0)])),
    );

    let comparisons = compare(
        std::slice::from_ref(&current),
        &HashMap::from([(benchmark.key(), baseline)]),
    )
    .unwrap();
    let report = render_report(&comparisons);

    assert!(comparisons[0].deltas["blob_reads"].is_infinite());
    assert!(comparisons[0].regressed());
    assert!(report.contains("Regressions: `1`."));
    assert!(report.contains("| `blob_reads` | 0 | 1 | +inf% |"));

    let output_dir = unique_temp_dir();
    write_outputs(&output_dir, &[current], Some(&comparisons)).unwrap();
    let comparison = fs::read_to_string(output_dir.join("comparison.toml")).unwrap();
    let summary = fs::read_to_string(output_dir.join("summary.toml")).unwrap();
    let comment = fs::read_to_string(output_dir.join("comment.md")).unwrap();
    assert!(comparison.contains("blob_reads = \"inf\""));
    assert!(summary.contains("regression_count = 1"));
    assert!(comment.contains("Regressions: `1`."));
    fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn missing_custom_metric_baseline_warns_without_regression() {
    let benchmark = custom_metric_benchmark();
    let current = result_for(
        benchmark.clone(),
        Some(BTreeMap::from([("blob_reads".to_string(), 111)])),
    );
    let baseline = result_for(
        benchmark.clone(),
        Some(BTreeMap::from([("EstimatedCycles".to_string(), 100)])),
    );

    let comparisons = compare(&[current], &HashMap::from([(benchmark.key(), baseline)])).unwrap();
    let report = render_report(&comparisons);

    assert!(!comparisons[0].regressed());
    assert!(report.contains("that gate was not evaluated"));
    assert!(report.contains("| `blob_reads` | n/a | 111 | n/a |"));
}

#[test]
fn rejects_invalid_config_fields_while_deserializing() {
    let empty_gate = r#"
packages = [
  { name = "commonware-storage", benchmarks = [
    { name = "qmdb_gungraun", variants = [
      { name = "qmdb::merkleize/variant=empty", filter = "*", gates = [] }
    ] }
  ] }
]
"#;
    assert!(load_config(empty_gate)
        .unwrap_err()
        .to_string()
        .contains("must be a non-empty array"));

    let negative_threshold = r#"
[[packages]]
name = "commonware-storage"

[[packages.benchmarks]]
name = "qmdb_gungraun"

[[packages.benchmarks.variants]]
name = "qmdb::merkleize/variant=negative"
filter = "*"
gates = [{ metric = "EstimatedCycles", direction = "down", threshold_percent = -1 }]
"#;
    assert!(load_config(negative_threshold)
        .unwrap_err()
        .to_string()
        .contains("must be non-negative"));
}

#[test]
fn rejects_unknown_config_fields_while_deserializing() {
    for input in [
        r#"
extra = true

[[packages]]
name = "commonware-storage"

[[packages.benchmarks]]
name = "qmdb_gungraun"

[[packages.benchmarks.variants]]
name = "qmdb::merkleize/variant=extra"
filter = "*"
"#,
        r#"
[[packages]]
name = "commonware-storage"
extra = true

[[packages.benchmarks]]
name = "qmdb_gungraun"

[[packages.benchmarks.variants]]
name = "qmdb::merkleize/variant=extra"
filter = "*"
"#,
        r#"
[[packages]]
name = "commonware-storage"

[[packages.benchmarks]]
name = "qmdb_gungraun"
extra = true

[[packages.benchmarks.variants]]
name = "qmdb::merkleize/variant=extra"
filter = "*"
"#,
        r#"
[[packages]]
name = "commonware-storage"

[[packages.benchmarks]]
name = "qmdb_gungraun"

[[packages.benchmarks.variants]]
name = "qmdb::merkleize/variant=extra"
filter = "*"
extra = true
"#,
    ] {
        assert!(load_config(input)
            .unwrap_err()
            .to_string()
            .contains("unknown field"));
    }
}

#[test]
fn rejects_invalid_baseline_fields_while_deserializing() {
    let output_dir = unique_temp_dir();
    let baseline = output_dir.join("current.toml");
    fs::write(
        &baseline,
        r#"
[[benchmarks]]
package = ""
target = "qmdb_gungraun"
name = "qmdb::merkleize/variant=empty"
filter = "*"
baseline_suite = "commonware-storage"
gates = [{ metric = "EstimatedCycles", direction = "down", threshold_percent = 10 }]

[benchmarks.metrics]
Ir = 1
L1hits = 1
LLhits = 1
RamHits = 1
TotalRW = 1
EstimatedCycles = 1
"#,
    )
    .unwrap();

    let err = load_baseline(Some(&baseline)).unwrap_err();
    assert!(format!("{err:#}").contains("must be a non-empty string"));
    fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn written_current_file_can_be_loaded_as_baseline() {
    let current = result_for(test_benchmarks()[0].clone(), None);
    let output_dir = unique_temp_dir();
    write_outputs(&output_dir, std::slice::from_ref(&current), None).unwrap();

    let baseline = load_baseline(Some(&output_dir.join("current.toml"))).unwrap();
    let comparisons = compare(&[current], &baseline).unwrap();

    assert_eq!(comparisons[0].deltas["EstimatedCycles"], 0.0);
    fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn generate_rejects_missing_gate_metric() {
    let benchmark = custom_metric_benchmark();
    let current = result_for(benchmark, Some(complete_metrics()));
    let output_dir = unique_temp_dir();

    let err = write_outputs(&output_dir, &[current], None).unwrap_err();

    assert!(err.to_string().contains("missing `blob_reads`"));
    assert!(!output_dir.join("current.toml").exists());
    fs::remove_dir_all(output_dir).unwrap();
}

fn callgrind_metrics() -> Vec<String> {
    CALLGRIND_METRICS
        .iter()
        .map(|metric| metric.to_string())
        .collect()
}

fn complete_metrics() -> BTreeMap<String, u64> {
    callgrind_metrics()
        .into_iter()
        .map(|metric| (metric, 1))
        .collect()
}

fn custom_metric_benchmark() -> Benchmark {
    Benchmark {
        package: "commonware-storage".to_string(),
        target: "qmdb_gungraun".to_string(),
        name: "qmdb::merkleize/v=any::unordered::fixed::mmr k=10000 ch=false s=true cc=true"
            .to_string(),
        filter: "*::bench_merkleize::any_unordered_fixed_mmr".to_string(),
        baseline_suite: "commonware-storage".to_string(),
        cargo_flags: Vec::new(),
        gates: vec![Gate {
            metric: "blob_reads".to_string(),
            direction: Direction::Down,
            threshold_percent: 10.0,
        }],
    }
}

fn unique_temp_dir() -> PathBuf {
    let mut path = env::temp_dir();
    path.push(format!(
        "benchmark-tracker-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}
