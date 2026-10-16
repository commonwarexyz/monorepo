//! Wide-area scale runs: a committee spread over AWS regions on a measured latency matrix.
//!
//! These runs are long and print measurements rather than assert tight bounds, so they are
//! ignored by default. Run them with:
//!
//! ```text
//! cargo test --release -p commonware-consensus --lib multimmit::tests::wan -- --ignored --nocapture
//! ```

use super::{assert_agreement, runner};
use crate::{
    Reporter,
    multimmit::{
        DeclarationRule, ViewEnd,
        mocks::cluster::{Cluster, ClusterOptions, LaunchSpec},
        types::{Activity, BlockRef, Window},
    },
};
use commonware_actor::Feedback;
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_p2p::simulated::Link;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{probability, sync::Mutex};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// AWS regions, in the order of [`RTT_MILLIS`].
const REGIONS: [&str; 13] = [
    "us-east-1",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-south-1",
    "ap-northeast-1",
    "ap-northeast-2",
];

/// Typical round-trip times between the regions, in milliseconds. Links carry half.
const RTT_MILLIS: [[u64; 13]; 13] = [
    [0, 67, 15, 68, 76, 80, 90, 110, 215, 200, 185, 145, 175],
    [67, 0, 60, 125, 135, 140, 145, 160, 165, 140, 220, 100, 125],
    [15, 60, 0, 70, 80, 85, 95, 105, 220, 200, 195, 145, 175],
    [68, 125, 70, 0, 12, 18, 25, 40, 175, 255, 120, 205, 230],
    [76, 135, 80, 12, 0, 9, 15, 32, 170, 265, 112, 210, 240],
    [80, 140, 85, 18, 9, 0, 10, 30, 160, 280, 105, 220, 245],
    [90, 145, 95, 25, 15, 10, 0, 22, 155, 245, 110, 225, 230],
    [110, 160, 105, 40, 32, 30, 22, 0, 175, 275, 135, 240, 255],
    [215, 165, 220, 175, 170, 160, 155, 175, 0, 92, 60, 70, 75],
    [200, 140, 200, 255, 265, 280, 245, 275, 92, 0, 150, 105, 130],
    [185, 220, 195, 120, 112, 105, 110, 135, 60, 150, 0, 130, 125],
    [145, 100, 145, 205, 210, 220, 225, 240, 70, 105, 130, 0, 33],
    [175, 125, 175, 230, 240, 245, 230, 255, 75, 130, 125, 33, 0],
];

/// One-way latency between two nodes in the same region.
const INTRA_REGION: Duration = Duration::from_millis(1);

/// How often the run samples every node.
const SAMPLE: Duration = Duration::from_millis(20);

/// Inspects `node`, retrying while the voter's best-effort query queue drops the request.
async fn inspect(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    node: usize,
) -> crate::multimmit::Inspection<Digest> {
    for _ in 0..1_000 {
        if let Some(inspection) = cluster.inspect(node).await {
            return inspection;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    let mut failures = Vec::new();
    for index in cluster.all_nodes() {
        if let Some(failure) = cluster.stop_failed(index).await {
            failures.push(format!("node {index}: {failure}"));
        }
    }
    panic!(
        "engine {node} stopped answering inspections; marshal failures:\n{}",
        failures.join("\n")
    );
}

/// The link between two regions: half the round trip, with jitter of a twentieth of it, and a
/// quarter millisecond within a region.
fn link(from: usize, to: usize) -> Link {
    let (latency, jitter) = if from == to {
        (INTRA_REGION, Duration::from_micros(250))
    } else {
        let one_way = Duration::from_micros(RTT_MILLIS[from][to] * 500);
        (one_way, one_way / 20)
    };
    Link {
        latency,
        jitter,
        success_rate: probability!(1.0),
    }
}

/// One scale scenario.
struct Scenario {
    /// Region of every node, in committee order.
    regions: Vec<usize>,
    /// The window cap `N`; the flow bound is `2N`.
    cap: u32,
    /// Application time to build one block.
    build: Duration,
    /// Views every node must pass after warm-up.
    views: u64,
    /// Views to pass before measuring.
    warmup: u64,
    /// Simulated-time budget for the measured part.
    budget: Duration,
}

/// Production and finality instants of every block, and the observer's final height per chain.
#[derive(Default)]
struct Probe {
    signed: HashMap<(u32, u64), SystemTime>,
    finalized: HashMap<(u32, u64), SystemTime>,
    finals: Vec<u64>,
}

impl Probe {
    fn finalize(&mut self, tips: &[BlockRef<Digest>], now: SystemTime) {
        if self.finals.len() < tips.len() {
            self.finals.resize(tips.len(), 0);
        }
        for tip in tips {
            let chain = tip.chain().get();
            let height = tip.height().get();
            let last = &mut self.finals[chain as usize];
            for h in *last + 1..=height {
                self.finalized.insert((chain, h), now);
            }
            *last = (*last).max(height);
        }
    }
}

/// Records every producer's signing instants and the observer's finality instants.
#[derive(Clone)]
struct ProbeReporter {
    observer: bool,
    clock: Arc<deterministic::Context>,
    probe: Arc<Mutex<Probe>>,
}

impl Reporter for ProbeReporter {
    type Activity = Activity<MinPk, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let now = self.clock.current();
        let mut probe = self.probe.lock();
        match activity {
            Activity::TransactionProposed { block, .. } => {
                probe
                    .signed
                    .entry((block.chain().get(), block.height().get()))
                    .or_insert(now);
            }
            Activity::ViewSweep { finals, .. } if self.observer => probe.finalize(&finals, now),
            Activity::ViewResolved { tips, .. } if self.observer => probe.finalize(&tips, now),
            _ => {}
        }
        Feedback::Ok
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// Percentage of `samples` equal to `value`.
fn share(samples: &[f64], value: f64) -> f64 {
    let hits = samples.iter().filter(|sample| **sample == value).count();
    100.0 * hits as f64 / samples.len().max(1) as f64
}

/// Mean, median, 90th percentile, and maximum of `samples`.
fn summary(mut samples: Vec<f64>) -> String {
    if samples.is_empty() {
        return "no samples".into();
    }
    samples.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    format!(
        "mean {mean:.1} median {:.1} p90 {:.1} max {:.1} (n={})",
        at(0.5),
        at(0.9),
        at(1.0),
        samples.len()
    )
}

/// Returns every value of the metrics named `*suffix` (without labels) in `encoded`.
fn metric(encoded: &str, suffix: &str) -> Vec<f64> {
    encoded
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (name, value) = line.rsplit_once(' ')?;
            let name = name.split('{').next()?;
            name.ends_with(suffix).then(|| value.parse().ok())?
        })
        .collect()
}

/// The view a node was in at `time`, from its sampled entries.
fn view_at(entries: &[(u64, SystemTime)], time: SystemTime) -> u64 {
    let index = entries.partition_point(|(_, entered)| *entered <= time);
    entries[index.saturating_sub(1)].0
}

/// Runs `scenario` and prints its measurements.
fn run(seed: u64, scenario: Scenario) {
    let n = u32::try_from(scenario.regions.len()).unwrap();
    let seconds = (scenario.budget.as_secs() + 120).max(300);
    runner(seconds).start(|context| async move {
        let options = ClusterOptions {
            window: Window::new(scenario.cap).unwrap(),
            ..ClusterOptions::new(seed, n)
        };
        let mut cluster: Cluster<MinPk> = Cluster::new(&context, options).await;
        let all = cluster.all_nodes();
        for &from in &all {
            for &to in &all {
                if from != to {
                    let link = link(scenario.regions[from], scenario.regions[to]);
                    cluster.set_link(from, to, link).await;
                }
            }
        }
        let fixture = cluster.fixture();
        let codec = fixture.config.codec_config();
        let probe = Arc::new(Mutex::new(Probe::default()));
        let clock = Arc::new(context.child("probe"));
        for &node in &all {
            let reporter = ProbeReporter {
                observer: node == 0,
                clock: Arc::clone(&clock),
                probe: Arc::clone(&probe),
            };
            cluster
                .launch(LaunchSpec::new(node).reporter(reporter))
                .await;
            cluster.app(node).delay_builds(scenario.build);
        }
        cluster.await_ready(&all).await;
        cluster.produce();

        let mut entries = vec![Vec::new(); all.len()];
        let mut deliveries = Vec::new();
        let (mut cache, mut outbox, mut jobs, mut pending, mut waiting, mut parked) =
            (0, 0, 0, 0, 0, 0);
        let launched = context.current();
        let wall = std::time::Instant::now();
        let mut reported = 0;
        let mut measured = None;
        loop {
            context.sleep(SAMPLE).await;
            let now = context.current();
            let mut lowest = u64::MAX;
            for &node in &all {
                let inspection = inspect(&context, &mut cluster, node).await;
                let view = inspection.view().get();
                if entries[node].last().is_none_or(|(last, _)| *last != view) {
                    entries[node].push((view, now));
                }
                lowest = lowest.min(view);
                if measured.is_some() {
                    cache = cache.max(inspection.cached_artifacts());
                    outbox = outbox.max(inspection.outbox_len());
                    jobs = jobs.max(inspection.verification_jobs_len());
                    pending = pending.max(inspection.pending_artifacts());
                    waiting = waiting.max(inspection.waiting_artifacts());
                    parked = parked.max(inspection.parked_updates());
                }
            }
            if lowest >= reported + 5 {
                reported = lowest;
                println!(
                    "progress: every node at view {lowest}, {:.1} s simulated, {:.0} s wall",
                    now.duration_since(launched).unwrap().as_secs_f64(),
                    wall.elapsed().as_secs_f64()
                );
            }
            deliveries.push((now, cluster.deliveries(0).last().map_or(0, |i| i.get())));
            match measured {
                None if lowest >= scenario.warmup => {
                    let mut baseline = Vec::new();
                    for &node in &all {
                        let inspection = inspect(&context, &mut cluster, node).await;
                        baseline.push((
                            inspection.view_ends(),
                            inspection.declarations(),
                            inspection.view().get(),
                        ));
                    }
                    let finals = inspect(&context, &mut cluster, 0)
                        .await
                        .chain_progress()
                        .iter()
                        .map(|chain| chain.finalized().get())
                        .collect::<Vec<_>>();
                    println!(
                        "warm-up: every node at view {} after {:.1} s",
                        lowest,
                        now.duration_since(launched).unwrap().as_secs_f64()
                    );
                    measured = Some((now, baseline, finals));
                }
                Some((start, ref baseline, _))
                    if lowest >= baseline.iter().map(|b| b.2).max().unwrap() + scenario.views
                        || now.duration_since(start).unwrap() >= scenario.budget =>
                {
                    break;
                }
                _ => {}
            }
            assert!(
                now.duration_since(launched).unwrap() < scenario.budget * 2,
                "warm-up did not finish: views {:?}",
                entries
                    .iter()
                    .map(|e| e.last().map(|v| v.0))
                    .collect::<Vec<_>>()
            );
        }
        let (start, baseline, start_finals) = measured.unwrap();
        let end = context.current();
        let elapsed = end.duration_since(start).unwrap();

        // Liveness and view lengths.
        let mut gaps = Vec::new();
        let mut max_gap = (0.0, 0);
        let mut lengths = Vec::new();
        for &node in &all {
            for pair in entries[node].windows(2) {
                if pair[1].1 < start {
                    continue;
                }
                let gap = millis(pair[1].1.duration_since(pair[0].1).unwrap());
                gaps.push(gap);
                if gap > max_gap.0 {
                    max_gap = (gap, node);
                }
                if node == 0 {
                    lengths.push(gap / (pair[1].0 - pair[0].0) as f64);
                }
            }
        }
        let mut summary_rows = Vec::new();
        let (mut count, mut bound, mut declared, mut ends_millis, mut ends_total) = (0, 0, 0, 0, 0);
        let rules = [
            DeclarationRule::Stopped,
            DeclarationRule::Late,
            DeclarationRule::Bound,
            DeclarationRule::ViewChange,
            DeclarationRule::Split,
            DeclarationRule::Grace,
            DeclarationRule::SilentLeader,
        ];
        let mut by_rule = [0u64; 7];
        let (mut deltas, mut thetas, mut graces, mut views) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for &node in &all {
            let inspection = inspect(&context, &mut cluster, node).await;
            let (ends_before, declarations_before, view_before) = &baseline[node];
            let ends = inspection.view_ends();
            count += ends.get(ViewEnd::Count) - ends_before.get(ViewEnd::Count);
            bound += ends.get(ViewEnd::Bound) - ends_before.get(ViewEnd::Bound);
            declared += ends.get(ViewEnd::Declared) - ends_before.get(ViewEnd::Declared);
            ends_total += ends.total() - ends_before.total();
            ends_millis += ends.total_millis() - ends_before.total_millis();
            let declarations = inspection.declarations();
            for (slot, rule) in by_rule.iter_mut().zip(rules) {
                *slot += declarations.get(rule) - declarations_before.get(rule);
            }
            deltas.push(inspection.delay_millis() as f64);
            thetas.push(inspection.production_millis() as f64);
            graces.push(inspection.grace_millis() as f64);
            views.push((inspection.view().get() - view_before) as f64);
            if node < 3 || node == all.len() - 1 {
                summary_rows.push(format!(
                    "  node {node} ({}): view {} ends {:?} delta {} ms theta {} ms grace {} ms",
                    REGIONS[scenario.regions[node]],
                    inspection.view(),
                    ends,
                    inspection.delay_millis(),
                    inspection.production_millis(),
                    inspection.grace_millis(),
                ));
            }
        }

        // Throughput at the observer.
        let observer = inspect(&context, &mut cluster, 0).await;
        let finalized = observer
            .chain_progress()
            .iter()
            .zip(&start_finals)
            .map(|(chain, start)| (chain.finalized().get() - start) as f64)
            .collect::<Vec<_>>();
        let observed_views = observer.view().get() - baseline[0].2;

        // Production to finality (observer) and to ordered delivery (observer's marshal).
        let (finality_millis, finality_views, ordered_millis) = {
            let probe = probe.lock();
            let mut finality_millis = Vec::new();
            let mut finality_views = Vec::new();
            for (block, finalized) in &probe.finalized {
                let Some(signed) = probe.signed.get(block) else {
                    continue;
                };
                if *signed < start || *finalized > end {
                    continue;
                }
                finality_millis.push(millis(finalized.duration_since(*signed).unwrap()));
                finality_views.push(
                    (view_at(&entries[0], *finalized) - view_at(&entries[0], *signed)) as f64,
                );
            }
            let mut ordered_millis = Vec::new();
            for (index, block) in cluster.deliveries(0).outputs() {
                let Some(signed) = probe
                    .signed
                    .get(&(block.chain().get(), block.height().get()))
                else {
                    continue;
                };
                let at = deliveries.partition_point(|(_, last)| *last < index.get());
                let Some((delivered, _)) = deliveries.get(at) else {
                    continue;
                };
                if *signed >= start {
                    ordered_millis.push(millis(delivered.duration_since(*signed).unwrap()));
                }
            }
            (finality_millis, finality_views, ordered_millis)
        };

        // Resource occupancy and certificate sizes from the engines' metrics.
        let encoded = context.encode();
        let max = |name: &str| metric(&encoded, name).into_iter().fold(0.0, f64::max);
        let sum = |name: &str| metric(&encoded, name).into_iter().sum::<f64>();
        let qc_bytes = sum("_vqc_bytes_sum") + sum("_lqc_bytes_sum");
        let qcs = sum("_vqc_bytes_count") + sum("_lqc_bytes_count");
        let vqcs = sum("_vqc_latency_count");
        let lqcs = sum("_lqc_latency_count");

        let total = ends_total.max(1) as f64;
        let chains = finalized.len() as f64;
        let seconds = elapsed.as_secs_f64();
        println!(
            "== n={n} f={} quorum={} N={} D={} build={:?} regions={}",
            codec.max_faults(),
            codec.view_quorum(),
            scenario.cap,
            codec.window().flow(),
            scenario.build,
            scenario
                .regions
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
        );
        println!(
            "measured {seconds:.1} s simulated; views passed per node: {}",
            summary(views)
        );
        println!(
            "view entry gaps (all nodes, ms): {}; longest at node {}",
            summary(gaps),
            max_gap.1
        );
        println!("observer view length (ms): {}", summary(lengths));
        println!(
            "entry->final vote (ms, all nodes): mean {:.1}",
            ends_millis as f64 / total
        );
        println!(
            "view ends: count {count} ({:.1}%) bound {bound} ({:.1}%) declared {declared} \
             ({:.1}%) of {ends_total}",
            100.0 * count as f64 / total,
            100.0 * bound as f64 / total,
            100.0 * declared as f64 / total,
        );
        println!(
            "declarations (chains, all nodes): {}",
            rules
                .iter()
                .zip(by_rule)
                .map(|(rule, count)| format!("{rule:?}={count}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!(
            "delta_hat (ms): {}\ntheta_hat (ms): {}\ngrace (ms): {}",
            summary(deltas),
            summary(thetas),
            summary(graces)
        );
        println!(
            "finalized per chain at observer: {:.1} blocks/s, {:.2} blocks/view (min chain \
             {:.0} blocks over {observed_views} views, total {:.0})",
            finalized.iter().sum::<f64>() / chains / seconds,
            finalized.iter().sum::<f64>() / chains / observed_views.max(1) as f64,
            finalized.iter().copied().fold(f64::MAX, f64::min),
            finalized.iter().sum::<f64>(),
        );
        println!(
            "signed->final at observer (ms): {}",
            summary(finality_millis)
        );
        println!(
            "signed->final at observer (views): {}",
            summary(finality_views.clone())
        );
        println!(
            "final in the signing view at observer: {:.1}% (one view later {:.1}%)",
            share(&finality_views, 0.0),
            share(&finality_views, 1.0),
        );
        println!(
            "signed->ordered at observer (ms): {}",
            summary(ordered_millis)
        );
        println!(
            "max over nodes: cached artifacts {cache} (capacity {}, remote {}, local {}), \
             pending {pending}, waiting {waiting}, parked {parked}, outbox {outbox}, \
             verification jobs {jobs} (capacity {})",
            max("_artifact_cache_capacity"),
            max("_remote_artifact_capacity"),
            max("_local_artifact_capacity"),
            max("_verification_job_capacity"),
        );
        println!(
            "certificates: {qcs:.0} aggregated ({vqcs:.0} V-QC, {lqcs:.0} L-QC), mean {:.0} bytes, \
             V-QC ceiling {} bytes",
            qc_bytes / qcs.max(1.0),
            codec.max_vqc_bytes(),
        );
        for row in summary_rows {
            println!("{row}");
        }

        let stream = assert_agreement(&cluster, &all).await;
        println!(
            "agreement: {} ordered outputs agree at every node",
            stream.len()
        );
    });
}

/// Assigns `sizes[r]` consecutive nodes to region `r`.
fn spread(sizes: &[usize]) -> Vec<usize> {
    sizes
        .iter()
        .enumerate()
        .flat_map(|(region, size)| std::iter::repeat_n(region, *size))
        .collect()
}

/// Fifty validators over thirteen AWS regions (eleven of four, two of three) with production
/// defaults: `N = 12`, `D = 6N`.
#[commonware_macros::test_traced("WARN")]
#[ignore = "long-running scale run; prints measurements"]
fn wan_n50_thirteen_regions() {
    let mut sizes = vec![4; 11];
    sizes.extend([3, 3]);
    run(
        5000,
        Scenario {
            regions: spread(&sizes),
            cap: 12,
            build: Duration::from_millis(3),
            views: 40,
            warmup: 5,
            budget: Duration::from_secs(30),
        },
    );
}

/// Six validators in six of the regions, for comparison with the fifty-node run.
#[test]
#[ignore = "long-running scale run; prints measurements"]
fn wan_n6_six_regions() {
    run(
        5001,
        Scenario {
            regions: vec![0, 1, 3, 6, 8, 11],
            cap: 12,
            build: Duration::from_millis(3),
            views: 100,
            warmup: 5,
            budget: Duration::from_secs(120),
        },
    );
}
