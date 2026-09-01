//! The whole-engine performance profile: a six-node cluster produces fixed block and view work.
//!
//! The benchmark target times its block and view regions on the host. The latency gate test reads
//! the production engine's deterministic-time histograms from the same run, which are never host
//! measurements.

use crate::{
    multimmit::mocks::cluster::{Cluster, ClusterOptions},
    types::{View, ViewDelta},
};
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_runtime::{
    Metrics as _, Runner as _,
    deterministic::{Config as RuntimeConfig, Runner as DeterministicRunner},
    telemetry::metrics::histogram_percentile,
};
use std::time::{Duration, Instant};

/// Engines in the profile's committee.
pub const ENGINE_NODES: usize = 6;
/// Blocks each producer chain finalizes during the block region.
pub const ENGINE_BLOCKS_PER_CHAIN: u64 = 2;
/// Views every engine advances during the view region.
pub const ENGINE_VIEW_ADVANCE: u64 = 18;
const VIEW_RETENTION: u64 = ENGINE_VIEW_ADVANCE * 2;
const NETWORK_LATENCY: Duration = Duration::from_millis(15);
const NETWORK_JITTER: Duration = Duration::from_millis(5);
const STORAGE_SYNC_INTERVAL: Duration = Duration::from_millis(20);
const PRODUCTION_INTERVAL: Duration = Duration::from_millis(50);
const RUNTIME_SEED: u64 = 0x5eed_cafe;
const PROFILE_SEED: u64 = 0xface_feed;

/// Deterministic outcomes of one profile run.
#[derive(Clone, Copy, Debug)]
pub struct EngineReport {
    /// Blocks finalized across every producer chain.
    pub blocks: u64,
    /// Views the slowest engine advanced during the view region.
    pub views: u64,
    /// Views the slowest engine advanced across the whole workload.
    pub workload_views: u64,
    /// Local block builds the latency histogram recorded.
    pub build_samples: u64,
    /// The 95th percentile build latency, in deterministic time.
    pub build_p95: Duration,
    /// The 99th percentile build latency, in deterministic time.
    pub build_p99: Duration,
    /// DA votes the latency histogram recorded.
    pub da_vote_samples: u64,
    /// The 95th percentile DA-vote latency, in deterministic time.
    pub da_vote_p95: Duration,
    /// The 99th percentile DA-vote latency, in deterministic time.
    pub da_vote_p99: Duration,
}

/// One profile run: its deterministic report and the host time of its measured regions.
#[derive(Clone, Copy, Debug)]
pub struct EngineRun {
    /// The run's deterministic outcomes.
    pub report: EngineReport,
    /// Host time spent producing and finalizing the fixed blocks.
    pub block_elapsed: Duration,
    /// Host time spent advancing the fixed views.
    pub view_elapsed: Duration,
}

/// Returns the profile's parameters as a `key=value` benchmark label suffix.
pub fn engine_parameters(storage_delay: bool) -> String {
    let sync_ms = if storage_delay {
        STORAGE_SYNC_INTERVAL.as_millis()
    } else {
        0
    };
    format!(
        "n={ENGINE_NODES} bpc={ENGINE_BLOCKS_PER_CHAIN} view_target={ENGINE_VIEW_ADVANCE} sync_ms={sync_ms}"
    )
}

/// Runs the profile once, adding a storage sync interval when `storage_delay` is set.
///
/// # Panics
///
/// Panics if the cluster misses a progress deadline or does not export its latency histograms.
pub fn run_engine_profile(storage_delay: bool) -> EngineRun {
    let runtime = DeterministicRunner::new(
        RuntimeConfig::default()
            .with_seed(RUNTIME_SEED)
            .with_timeout(Some(Duration::from_secs(60))),
    );

    runtime.start(|context| async move {
        let nodes = (0..ENGINE_NODES).collect::<Vec<_>>();
        let chains = (0..ENGINE_NODES as u32).collect::<Vec<_>>();
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                latency: NETWORK_LATENCY,
                jitter: NETWORK_JITTER,
                production: PRODUCTION_INTERVAL,
                view_retention: ViewDelta::new(VIEW_RETENTION),
                ..ClusterOptions::new(PROFILE_SEED, ENGINE_NODES as u32)
            },
        )
        .await;
        if storage_delay {
            cluster.set_storage_sync_interval(STORAGE_SYNC_INTERVAL);
        }
        cluster.start_all().await;

        let workload_initial_views = collect_views(&cluster, &nodes).await;
        let mut block_elapsed = Duration::ZERO;
        for target in 1..=ENGINE_BLOCKS_PER_CHAIN {
            let started = Instant::now();
            cluster.produce_once();
            cluster
                .wait_produced(&nodes, target, Duration::from_secs(60))
                .await;
            block_elapsed += started.elapsed();
        }
        let started = Instant::now();
        cluster.stop_producing();
        cluster
            .wait_finalized(
                &nodes,
                &chains,
                ENGINE_BLOCKS_PER_CHAIN,
                Duration::from_secs(120),
            )
            .await;
        block_elapsed += started.elapsed();

        let view_initial_views = collect_views(&cluster, &nodes).await;
        let target_view = view_initial_views
            .iter()
            .copied()
            .max()
            .expect("the profile has engines")
            + ENGINE_VIEW_ADVANCE;
        let started = Instant::now();
        cluster
            .wait_view(&nodes, View::new(target_view), Duration::from_secs(120))
            .await;
        let view_elapsed = started.elapsed();
        let final_views = collect_views(&cluster, &nodes).await;

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
        let (build_p95, build_samples) = latency_percentile(&metrics, "build_latency", 95);
        let (build_p99, _) = latency_percentile(&metrics, "build_latency", 99);
        let (da_vote_p95, da_vote_samples) = latency_percentile(&metrics, "da_vote_latency", 95);
        let (da_vote_p99, _) = latency_percentile(&metrics, "da_vote_latency", 99);

        EngineRun {
            report: EngineReport {
                blocks,
                views,
                workload_views,
                build_samples,
                build_p95,
                build_p99,
                da_vote_samples,
                da_vote_p95,
                da_vote_p99,
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

/// Returns the `percentile` latency bound of histogram `name` and its sample count.
fn latency_percentile(metrics: &str, name: &str, percentile: u64) -> (Duration, u64) {
    let (bound, samples) = histogram_percentile(metrics, name, percentile)
        .expect("production engine exported the latency histogram with samples");
    assert!(
        bound.is_finite(),
        "latency percentile exceeded the largest bucket"
    );
    (Duration::from_secs_f64(bound), samples)
}
