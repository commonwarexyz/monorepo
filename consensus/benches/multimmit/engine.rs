//! Whole-engine performance profile.
//!
//! Criterion measures host wall time for fixed block and view work. The latency gate reads the
//! production engine's deterministic-time histograms, so those values are never presented as host
//! throughput. Capture a reproducible host baseline with:
//!
//! `cargo bench -p commonware-consensus --bench multimmit -- engine::production --save-baseline multimmit-engine-current`

use commonware_consensus::{
    multimmit::mocks::cluster::{Cluster, ClusterOptions},
    types::{View, ViewDelta},
};
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_runtime::{
    Metrics as _, Runner as _,
    deterministic::{Config as RuntimeConfig, Runner as DeterministicRunner},
};
use criterion::{Criterion, Throughput, criterion_group};
use std::{
    hint::black_box,
    sync::OnceLock,
    time::{Duration, Instant},
};

const NODES: usize = 6;
const BLOCKS_PER_CHAIN: u64 = 2;
const VIEW_ADVANCE: u64 = 18;
const VIEW_RETENTION: u64 = VIEW_ADVANCE * 2;
const NETWORK_LATENCY: Duration = Duration::from_millis(15);
const NETWORK_JITTER: Duration = Duration::from_millis(5);
const STORAGE_SYNC_INTERVAL: Duration = Duration::from_millis(20);
const PRODUCTION_INTERVAL: Duration = Duration::from_millis(50);
const RUNTIME_SEED: u64 = 0x5eed_cafe;
const PROFILE_SEED: u64 = 0xface_feed;

// The reproducible current baseline is 50ms for all four tails. One additional histogram bucket
// leaves deterministic scheduling headroom while still making a two-bucket regression fail.
const COMPLETION_P95_LIMIT: Duration = Duration::from_millis(100);
const COMPLETION_P99_LIMIT: Duration = Duration::from_millis(100);
const RELEASE_P95_LIMIT: Duration = Duration::from_millis(100);
const RELEASE_P99_LIMIT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
struct ProfileReport {
    blocks: u64,
    views: u64,
    workload_views: u64,
    completion_samples: u64,
    completion_p95: Duration,
    completion_p99: Duration,
    release_samples: u64,
    release_p95: Duration,
    release_p99: Duration,
}

#[derive(Clone, Copy, Debug)]
struct ProfileRun {
    report: ProfileReport,
    block_elapsed: Duration,
    view_elapsed: Duration,
}

fn parameters(storage_delay: bool) -> String {
    let sync_ms = if storage_delay {
        STORAGE_SYNC_INTERVAL.as_millis()
    } else {
        0
    };
    format!("n={NODES} bpc={BLOCKS_PER_CHAIN} view_target={VIEW_ADVANCE} sync_ms={sync_ms}",)
}

fn run_profile(storage_delay: bool) -> ProfileRun {
    let runtime = DeterministicRunner::new(
        RuntimeConfig::default()
            .with_seed(RUNTIME_SEED)
            .with_timeout(Some(Duration::from_secs(60))),
    );

    runtime.start(|context| async move {
        let nodes = (0..NODES).collect::<Vec<_>>();
        let chains = (0..NODES as u32).collect::<Vec<_>>();
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: NODES as u32,
                seed: PROFILE_SEED,
                extras: 0,
                leaders: None,
                quota: None,
                latency: Some(NETWORK_LATENCY),
                jitter: Some(NETWORK_JITTER),
                production: Some(PRODUCTION_INTERVAL),
                view_retention: Some(ViewDelta::new(VIEW_RETENTION)),
            },
        )
        .await;
        if storage_delay {
            cluster.set_storage_sync_interval(STORAGE_SYNC_INTERVAL);
        }
        cluster.start_all().await;

        let workload_initial_views = collect_views(&cluster, &nodes).await;
        let mut block_elapsed = Duration::ZERO;
        for target in 1..=BLOCKS_PER_CHAIN {
            let started = Instant::now();
            cluster.produce_once();
            block_elapsed += started.elapsed();
            block_elapsed += cluster.measure_wait_produced(&nodes, target, 600).await;
        }
        let started = Instant::now();
        cluster.stop_producing();
        block_elapsed += started.elapsed();
        block_elapsed += cluster
            .measure_wait_finalized(&nodes, &chains, BLOCKS_PER_CHAIN, 1_200)
            .await;

        let view_initial_views = collect_views(&cluster, &nodes).await;
        let target_view = view_initial_views
            .iter()
            .copied()
            .max()
            .expect("the profile has engines")
            + VIEW_ADVANCE;
        let (view_elapsed, final_views) = cluster
            .measure_wait_view(&nodes, View::new(target_view), 12_000)
            .await;

        let views = view_initial_views
            .iter()
            .zip(&final_views)
            .map(|(initial, final_view)| final_view - initial)
            .min()
            .expect("the profile has engines");
        let workload_views = workload_initial_views
            .iter()
            .zip(final_views)
            .map(|(initial, final_view)| final_view - initial)
            .min()
            .expect("the profile has engines");
        let inspection = cluster.inspect(0).await.expect("engine remains live");
        let blocks = inspection
            .chain_progress()
            .iter()
            .map(|progress| progress.finalized().get())
            .sum();
        let metrics = context.encode();
        let (completion_p95, completion_samples) =
            histogram_percentile(&metrics, "ready_to_sign_latency", 95);
        let (completion_p99, _) = histogram_percentile(&metrics, "ready_to_sign_latency", 99);
        let (release_p95, release_samples) =
            histogram_percentile(&metrics, "sign_ready_to_wire_latency", 95);
        let (release_p99, _) = histogram_percentile(&metrics, "sign_ready_to_wire_latency", 99);

        ProfileRun {
            report: ProfileReport {
                blocks,
                views,
                workload_views,
                completion_samples,
                completion_p95,
                completion_p99,
                release_samples,
                release_p95,
                release_p99,
            },
            block_elapsed,
            view_elapsed,
        }
    })
}

async fn collect_views(cluster: &Cluster<MinPk>, nodes: &[usize]) -> Vec<u64> {
    let mut views = Vec::with_capacity(nodes.len());
    for &node in nodes {
        let inspection = cluster.inspect(node).await.expect("engine remains live");
        views.push(inspection.view().get());
    }
    views
}

fn histogram_percentile(metrics: &str, suffix: &str, percentile: u64) -> (Duration, u64) {
    let bucket_suffix = format!("{suffix}_bucket");
    let mut buckets = Vec::<(f64, u64)>::new();

    for line in metrics.lines() {
        let Some((sample, value)) = line.split_once(' ') else {
            continue;
        };
        let name = sample.split_once('{').map_or(sample, |(name, _)| name);
        if !name.ends_with(&bucket_suffix) {
            continue;
        }
        let Some(bound) = label_value(sample, "le") else {
            continue;
        };
        let bound = match bound {
            "+Inf" => f64::INFINITY,
            bound => bound.parse().expect("histogram bound is numeric"),
        };
        let count = value.parse().expect("histogram count is an integer");
        if let Some((_, total)) = buckets.iter_mut().find(|(existing, _)| *existing == bound) {
            *total += count;
        } else {
            buckets.push((bound, count));
        }
    }

    buckets.sort_by(|(left, _), (right, _)| left.total_cmp(right));
    let samples = buckets
        .last()
        .map(|(_, count)| *count)
        .expect("production engine exported the latency histogram");
    assert!(samples > 0, "latency histogram contains samples");
    let rank = samples.saturating_mul(percentile).div_ceil(100);
    let bound = buckets
        .into_iter()
        .find_map(|(bound, count)| (count >= rank).then_some(bound))
        .expect("histogram contains the requested percentile");
    assert!(
        bound.is_finite(),
        "latency percentile exceeded the largest bucket"
    );
    (Duration::from_secs_f64(bound), samples)
}

fn label_value<'a>(sample: &'a str, label: &str) -> Option<&'a str> {
    let needle = format!("{label}=\"");
    let value = sample.split_once(&needle)?.1;
    value.split_once('"').map(|(value, _)| value)
}

fn check_report(report: ProfileReport) {
    assert_eq!(report.blocks, NODES as u64 * BLOCKS_PER_CHAIN);
    assert!(report.views >= VIEW_ADVANCE);
    assert!(report.workload_views >= VIEW_ADVANCE);
    assert!(report.completion_samples >= 100);
    assert!(report.release_samples >= 100);
    assert!(report.completion_p95 <= COMPLETION_P95_LIMIT);
    assert!(report.completion_p99 <= COMPLETION_P99_LIMIT);
    assert!(report.release_p95 <= RELEASE_P95_LIMIT);
    assert!(report.release_p99 <= RELEASE_P99_LIMIT);

    static REPRODUCIBLE_BASELINE: OnceLock<ProfileReport> = OnceLock::new();
    if REPRODUCIBLE_BASELINE.set(report).is_ok() {
        eprintln!("multimmit deterministic latency baseline: {report:?}");
    }
}

fn bench_production_block_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::production_block_throughput", module_path!()));
    group.throughput(Throughput::Elements(NODES as u64 * BLOCKS_PER_CHAIN));
    group.bench_function(parameters(false), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let run = run_profile(false);
                elapsed += run.block_elapsed;
                check_report(run.report);
                black_box(run.report.blocks);
            }
            elapsed
        });
    });
    group.finish();
}

fn bench_production_view_throughput(c: &mut Criterion) {
    let calibration = run_profile(false);
    check_report(calibration.report);
    let completed_views = calibration.report.views;

    let mut group = c.benchmark_group(format!("{}::production_view_throughput", module_path!()));
    group.throughput(Throughput::Elements(completed_views));
    group.bench_function(parameters(false), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let run = run_profile(false);
                elapsed += run.view_elapsed;
                check_report(run.report);
                assert_eq!(run.report.views, completed_views);
                black_box(run.report.views);
            }
            elapsed
        });
    });
    group.finish();
}

fn bench_production_latency_gate(c: &mut Criterion) {
    c.bench_function(
        &format!(
            "{}::production_latency_gate/{}",
            module_path!(),
            parameters(true)
        ),
        |b| {
            b.iter(|| {
                let run = run_profile(true);
                check_report(run.report);
                black_box(run.report)
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_production_block_throughput,
        bench_production_view_throughput,
        bench_production_latency_gate
}
