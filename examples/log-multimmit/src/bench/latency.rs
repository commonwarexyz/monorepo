//! Latency of locally produced blocks from input submission to finality and ordered delivery.

use commonware_consensus::{
    multimmit::{
        WAN_LATENCY,
        types::{BlockRef, ChainId},
    },
    types::{Height, View},
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, Histogram, HistogramExt as _, MetricsExt as _},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tracing::info;

/// Log target of benchmark events, kept stable for tooling that selects them by target.
const BENCHMARK_TARGET: &str = "commonware_log_multimmit::application::actor";

/// Buckets of the views a block waits from its header signature to its first finality. The
/// zero bucket counts blocks final in the view they were signed in.
const VIEWS_WAITED: [f64; 9] = [0.0, 1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 16.0, 32.0];

/// Exact identity of one producer block.
type Reference = BlockRef<Sha256Digest>;

/// The finality latency goal `2 * delta_hat + eta` for a block from its header signature.
///
/// The node refreshes it from engine inspections and the application reads it when one of its
/// blocks is signed. Clones share the value.
#[derive(Clone)]
pub struct FinalityGoal {
    /// The least time between two vote updates for one view (`eta`).
    vote_interval: Duration,
    /// The goal in milliseconds, or `u64::MAX` before the first refresh.
    millis: Arc<AtomicU64>,
}

impl FinalityGoal {
    /// Creates a goal for an engine whose vote interval is `vote_interval`, unknown until the
    /// first [`Self::refresh`].
    pub fn new(vote_interval: Duration) -> Self {
        Self {
            vote_interval,
            millis: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }

    /// Sets the goal from the engine's one-way delay estimate `delta_hat`, in milliseconds.
    pub fn refresh(&self, delay_millis: u64) {
        let eta = u64::try_from(self.vote_interval.as_millis()).unwrap_or(u64::MAX);
        let goal = delay_millis
            .saturating_mul(2)
            .saturating_add(eta)
            .min(u64::MAX - 1);
        self.millis.store(goal, Ordering::Relaxed);
    }

    /// Returns the current goal, if it was refreshed.
    pub fn get(&self) -> Option<Duration> {
        let millis = self.millis.load(Ordering::Relaxed);
        (millis != u64::MAX).then(|| Duration::from_millis(millis))
    }
}

/// Final positions consensus reported for one view.
///
/// Every block up to each listed position is in every correct log: the tips of a resolved view,
/// or the per-chain finals of the view being swept.
#[derive(Clone, Copy)]
pub struct Finality<'a> {
    /// Final chain positions, at most one per chain.
    pub blocks: &'a [Reference],
    /// The view the positions belong to.
    pub view: View,
}

/// What one block's first finality measured, for the producer's running totals.
pub struct FirstFinality {
    /// Views from the one the block's header was signed in, if this node saw it signed.
    pub views: Option<u64>,
    /// When the block's header was signed, if this node saw it signed.
    pub signed_at: Option<SystemTime>,
    /// Whether finality came within the goal captured at signing, if both are known.
    pub within_goal: Option<bool>,
}

/// One benchmark event for a tracked block.
#[derive(Clone, Copy)]
enum Sample {
    /// Tracking started when the block's input was submitted.
    Start,
    /// The block was dropped to stay within capacity.
    Evicted,
    /// The block was delivered in the total order.
    Ordered,
    /// Consensus finalized the block for the first time.
    FirstFinality { view: View },
}

impl Sample {
    const fn event(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Evicted => "eviction",
            Self::Ordered => "ordered",
            Self::FirstFinality { .. } => "first_finalization",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Start => "submitted",
            Self::Evicted => "capacity",
            Self::Ordered => "delivery",
            Self::FirstFinality { .. } => "consensus",
        }
    }
}

/// The header signature of a tracked block, as consensus reported it to this node.
#[derive(Clone, Copy)]
struct Signature {
    /// This node's view when the header was signed.
    view: View,
    at: SystemTime,
    /// The finality goal when the header was signed, if known.
    goal: Option<Duration>,
}

/// One tracked block awaiting finality and ordered delivery.
struct ProposalStart {
    block: Reference,
    started_at: SystemTime,
    input_ready_at: Option<SystemTime>,
    signature: Option<Signature>,
    finalized: bool,
    ordered: bool,
}

/// Tracks local blocks from input submission to consensus finality and to ordered delivery.
///
/// A block is final once a finalized leader's chain tip is the block or one of its
/// descendants. It is ordered once marshal delivers it in the total order, which can happen
/// before consensus reports finality. A block stays tracked until both are observed or it is
/// evicted to stay within capacity.
///
/// Coverage follows the exact parent links of this node's own blocks, including the empty ones
/// that are not tracked, so a finalized tip above an empty block still covers the batches below
/// it. A link is kept until finality passes its height and no unfinalized block below needs it.
pub struct ProposalLatency {
    started: VecDeque<ProposalStart>,
    /// Parent digest of each retained own block.
    lineage: BTreeMap<Reference, Sha256Digest>,
    capacity: usize,
    metrics: LatencyMetrics,
}

/// Latency metrics, and whether benchmark events are logged.
struct LatencyMetrics {
    benchmark: bool,
    finality: Histogram,
    ordering: Histogram,
    input_finality: Histogram,
    finality_views: Histogram,
    signed_finality: Histogram,
    signed_ordering: Histogram,
    goal_finalized: Counter,
    goal_met: Counter,
    dropped: Counter,
    finality_evicted: Counter,
    starts: Counter,
    outstanding: Gauge,
    nonfinalized: Gauge,
}

impl LatencyMetrics {
    fn new(context: &impl Metrics, benchmark: bool) -> Self {
        Self {
            benchmark,
            starts: context.counter(
                "proposal_started",
                "local input batches tracked for latency",
            ),
            outstanding: context.gauge(
                "proposal_outstanding",
                "starts awaiting ordering or removal",
            ),
            nonfinalized: context.gauge(
                "proposal_nonfinalized",
                "retained starts without observed finality",
            ),
            finality: context.histogram(
                "proposal_finalization_latency",
                "time from batch submission to first local consensus finality",
                WAN_LATENCY,
            ),
            ordering: context.histogram(
                "proposal_ordering_latency",
                "time from batch submission to delivery in the total order",
                WAN_LATENCY,
            ),
            input_finality: context.histogram(
                "input_finalization_latency",
                "time from scheduled batch submission to protocol finalization, including input queueing",
                WAN_LATENCY,
            ),
            finality_views: context.histogram(
                "proposal_finalization_views",
                "views from the one a local block's header was signed in to the one whose finality first covers it",
                VIEWS_WAITED,
            ),
            signed_finality: context.histogram(
                "proposal_signed_finalization_latency",
                "time from a local block's header signature to its first local consensus finality",
                WAN_LATENCY,
            ),
            signed_ordering: context.histogram(
                "proposal_signed_ordering_latency",
                "time from a local block's header signature to its delivery in the total order",
                WAN_LATENCY,
            ),
            goal_finalized: context.counter(
                "proposal_goal_finalized",
                "local blocks first final whose signing time and finality goal (2 * delta_hat + eta) are known",
            ),
            goal_met: context.counter(
                "proposal_goal_met",
                "local blocks first final within the finality goal (2 * delta_hat + eta) of their header signature",
            ),
            dropped: context.counter(
                "proposal_latency_dropped_total",
                "proposal starts evicted before ordered delivery (see proposal_finalization_latency_evicted for finality)",
            ),
            finality_evicted: context.counter(
                "proposal_finalization_latency_evicted",
                "proposal starts evicted before first finality (see proposal_latency_dropped_total for ordering)",
            ),
        }
    }

    fn sample(&self, start: &ProposalStart, sample: Sample, now: SystemTime) {
        if !self.benchmark {
            return;
        }
        let micros = |time: SystemTime| {
            u64::try_from(
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros(),
            )
            .unwrap_or(u64::MAX)
        };
        let elapsed = |time: SystemTime| {
            u64::try_from(now.duration_since(time).unwrap_or_default().as_micros())
                .unwrap_or(u64::MAX)
        };
        let view = match sample {
            Sample::FirstFinality { view } => Some(view.get()),
            Sample::Start | Sample::Evicted | Sample::Ordered => None,
        };
        info!(
            target: BENCHMARK_TARGET,
            benchmark_event = sample.event(),
            latency_start = "batch_submission",
            reason = sample.reason(),
            chain = start.block.chain().get(),
            height = start.block.height().get(),
            digest = %start.block.digest(),
            timestamp_us = micros(now),
            started_at_us = micros(start.started_at),
            input_ready_at_us = start.input_ready_at.map(micros),
            elapsed_us = elapsed(start.started_at),
            input_elapsed_us = start.input_ready_at.map(elapsed),
            finalized = start.finalized,
            signed_view = start.signature.map(|signature| signature.view.get()),
            signed_at_us = start.signature.map(|signature| micros(signature.at)),
            goal_us = start
                .signature
                .and_then(|signature| signature.goal)
                .map(|goal| u64::try_from(goal.as_micros()).unwrap_or(u64::MAX)),
            view,
            starts = self.starts.get(),
            drops = self.dropped.get(),
            finality_evictions = self.finality_evicted.get(),
            outstanding = self.outstanding.get(),
            nonfinalized = self.nonfinalized.get(),
            "proposal benchmark sample"
        );
    }
}

impl ProposalLatency {
    /// Registers the latency metrics and tracks up to `capacity` blocks and `capacity` parent
    /// links.
    ///
    /// With `benchmark` set, every event is also logged at INFO.
    pub fn new(context: &impl Metrics, capacity: NonZeroUsize, benchmark: bool) -> Self {
        Self {
            started: VecDeque::new(),
            lineage: BTreeMap::new(),
            capacity: capacity.get(),
            metrics: LatencyMetrics::new(context, benchmark),
        }
    }

    /// Starts tracking `block`, whose parent is `parent` and whose input was submitted at
    /// `started_at`.
    ///
    /// `input_ready_at` is the scheduled arrival of the block's input, when a workload paces
    /// production. Evicts the oldest tracked block when full.
    pub fn start(
        &mut self,
        block: Reference,
        parent: Sha256Digest,
        started_at: SystemTime,
        input_ready_at: Option<SystemTime>,
        now: SystemTime,
    ) {
        self.link(block, parent);
        if self.started.iter().any(|start| start.block == block) {
            return;
        }
        while self.started.len() >= self.capacity {
            let evicted = self
                .started
                .pop_front()
                .expect("proposal capacity is nonzero");
            let metrics = &self.metrics;
            if !evicted.finalized {
                metrics.finality_evicted.inc();
                metrics.nonfinalized.dec();
            }
            if !evicted.ordered {
                metrics.dropped.inc();
                metrics.outstanding.dec();
            }
            metrics.sample(&evicted, Sample::Evicted, now);
        }
        self.metrics.starts.inc();
        self.metrics.outstanding.inc();
        self.metrics.nonfinalized.inc();
        let start = ProposalStart {
            block,
            started_at,
            input_ready_at,
            signature: None,
            finalized: false,
            ordered: false,
        };
        self.metrics.sample(&start, Sample::Start, started_at);
        self.started.push_back(start);
    }

    /// Records that `block`'s header was signed at `at`, while this node was in `view` and the
    /// finality goal was `goal`.
    pub fn sign(&mut self, block: Reference, view: View, at: SystemTime, goal: Option<Duration>) {
        if let Some(start) = self.started.iter_mut().find(|start| start.block == block) {
            start.signature.get_or_insert(Signature { view, at, goal });
        }
    }

    /// Records that own block `block` extends `parent`, so finality above it reaches older
    /// tracked blocks. Blocks without input are linked but not tracked.
    ///
    /// Drops the lowest link when full.
    pub fn link(&mut self, block: Reference, parent: Sha256Digest) {
        if self.lineage.contains_key(&block) {
            return;
        }
        while self.lineage.len() >= self.capacity {
            self.lineage.pop_first();
        }
        self.lineage.insert(block, parent);
    }

    /// Returns the lowest height of an unfinalized tracked block on each chain.
    fn oldest_unfinalized(&self) -> BTreeMap<ChainId, Height> {
        let mut oldest = BTreeMap::<ChainId, Height>::new();
        for start in self.started.iter().filter(|start| !start.finalized) {
            oldest
                .entry(start.block.chain())
                .and_modify(|height| *height = (*height).min(start.block.height()))
                .or_insert(start.block.height());
        }
        oldest
    }

    /// Records first finality for every tracked block `finality` covers.
    ///
    /// Coverage extends from each finalized tip down to older tracked blocks through the linked
    /// parents. Returns what each newly final block measured.
    pub fn finalize(&mut self, finality: Finality<'_>, now: SystemTime) -> Vec<FirstFinality> {
        // Ordering removes only finalized starts. New submissions cannot be covered by
        // this fact until their bodies have been staged and proposed.
        let covered =
            Self::finalized_ancestry(finality.blocks, &self.oldest_unfinalized(), |block| {
                self.lineage.get(&block).copied()
            });
        let metrics = &self.metrics;
        let mut finalized = Vec::new();
        for start in self.started.iter_mut() {
            if start.finalized || !covered.contains(&start.block) {
                continue;
            }
            start.finalized = true;
            metrics.nonfinalized.dec();
            metrics.finality.observe_between(start.started_at, now);
            if let Some(input_ready_at) = start.input_ready_at {
                metrics.input_finality.observe_between(input_ready_at, now);
            }
            let mut first = FirstFinality {
                views: None,
                signed_at: None,
                within_goal: None,
            };
            if let Some(signature) = start.signature {
                // A node can sign a block before peers leave the previous view, so finality may
                // come from an earlier view than the signature; that counts as no wait.
                let waited = finality.view.get().saturating_sub(signature.view.get());
                metrics.finality_views.observe(waited as f64);
                metrics.signed_finality.observe_between(signature.at, now);
                first.views = Some(waited);
                first.signed_at = Some(signature.at);
                if let Some(goal) = signature.goal {
                    let met = now.duration_since(signature.at).unwrap_or_default() <= goal;
                    metrics.goal_finalized.inc();
                    if met {
                        metrics.goal_met.inc();
                    }
                    first.within_goal = Some(met);
                }
            }
            finalized.push(first);
            metrics.sample(
                start,
                Sample::FirstFinality {
                    view: finality.view,
                },
                now,
            );
        }
        self.started
            .retain(|start| !start.finalized || !start.ordered);
        self.prune(finality.blocks);
        finalized
    }

    /// Drops the links no later finality walk can reach: those at or below a chain's finalized
    /// `tips` and its oldest unfinalized tracked block.
    fn prune(&mut self, tips: &[Reference]) {
        let oldest = self.oldest_unfinalized();
        let mut floors = BTreeMap::<ChainId, Height>::new();
        for tip in tips {
            let floor = oldest
                .get(&tip.chain())
                .map_or(tip.height(), |oldest| (*oldest).min(tip.height()));
            floors
                .entry(tip.chain())
                .and_modify(|height| *height = (*height).max(floor))
                .or_insert(floor);
        }
        self.lineage.retain(|block, _| {
            floors
                .get(&block.chain())
                .is_none_or(|floor| block.height() > *floor)
        });
    }

    fn finalized_ancestry(
        blocks: &[Reference],
        oldest: &BTreeMap<ChainId, Height>,
        mut parent: impl FnMut(Reference) -> Option<Sha256Digest>,
    ) -> BTreeSet<Reference> {
        let mut finalized = BTreeSet::new();
        for tip in blocks {
            let Some(oldest) = oldest.get(&tip.chain()) else {
                continue;
            };
            let mut cursor = *tip;
            while cursor.height() >= *oldest {
                finalized.insert(cursor);
                if cursor.height() == *oldest {
                    break;
                }
                let parent_height = cursor.height().previous().expect("above pending height");
                let Some(digest) = parent(cursor) else {
                    break;
                };
                cursor = BlockRef::new(cursor.chain(), parent_height, digest);
            }
        }
        finalized
    }

    /// Records ordered delivery once, retaining the start until finality is also observed.
    ///
    /// Returns when a newly ordered block's header was signed, if this node saw it signed.
    pub fn order(&mut self, block: Reference, now: SystemTime) -> Option<SystemTime> {
        let index = self.started.iter().position(|start| start.block == block)?;
        let start = &mut self.started[index];
        if start.ordered {
            return None;
        }
        start.ordered = true;
        self.metrics.outstanding.dec();
        self.metrics.ordering.observe_between(start.started_at, now);
        let signed_at = start.signature.map(|signature| signature.at);
        if let Some(signed_at) = signed_at {
            self.metrics.signed_ordering.observe_between(signed_at, now);
        }
        self.metrics.sample(start, Sample::Ordered, now);
        if start.finalized {
            self.started.remove(index);
        }
        signed_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, sync::Mutex};
    use std::{sync::Arc, time::Duration};

    fn reference(chain: u32, height: u64) -> Reference {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes(), &height.to_be_bytes()]),
        )
    }

    /// The digest [`reference`] gives the block below `block` on its chain.
    fn parent(block: Reference) -> Sha256Digest {
        reference(block.chain().get(), block.height().get() - 1).digest()
    }

    /// Returns `count` linked blocks on chain 0 from height 1, in height order.
    fn chain(count: u64) -> Vec<Reference> {
        (1..=count).map(|height| reference(0, height)).collect()
    }

    fn finality(blocks: &[Reference]) -> Finality<'_> {
        Finality {
            blocks,
            view: View::new(1),
        }
    }

    #[test]
    fn benchmark_events_include_raw_microseconds_and_loss_accounting() {
        #[derive(Clone, Default)]
        struct Output(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        deterministic::Runner::default().start(|runtime| async move {
            let output = Output::default();
            let writer = output.clone();
            let subscriber = tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_writer(move || writer.clone())
                .finish();
            let started = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
            let now = started + Duration::from_secs(2);
            tracing::subscriber::with_default(subscriber, || {
                let quiet_context = runtime.child("quiet");
                let mut quiet = ProposalLatency::new(&quiet_context, NZUsize!(1), false);
                quiet.start(
                    reference(0, 1),
                    parent(reference(0, 1)),
                    started,
                    None,
                    started,
                );
                quiet.finalize(finality(&[reference(0, 1)]), now);
                quiet.order(reference(0, 1), now);
                assert!(output.0.lock().is_empty());

                let mut latency = ProposalLatency::new(&runtime, NZUsize!(1), true);
                latency.start(
                    reference(0, 2),
                    parent(reference(0, 2)),
                    started,
                    Some(started - Duration::from_secs(2)),
                    started,
                );
                latency.sign(
                    reference(0, 2),
                    View::new(3),
                    started + Duration::from_secs(1),
                    Some(Duration::from_millis(250)),
                );
                latency.finalize(
                    Finality {
                        view: View::new(4),
                        ..finality(&[reference(0, 2)])
                    },
                    now,
                );
                latency.order(reference(0, 2), now);
                latency.start(reference(0, 3), parent(reference(0, 3)), started, None, now);
                latency.start(reference(0, 4), parent(reference(0, 4)), started, None, now);
                latency.order(reference(0, 4), now);
            });
            let output = String::from_utf8(output.0.lock().clone()).unwrap();
            let events: Vec<serde_yaml::Value> = output
                .lines()
                .map(|line| serde_yaml::from_str(line).unwrap())
                .collect();
            assert_eq!(events.len(), 7);
            let first = &events[0]["fields"];
            assert_eq!(first["benchmark_event"].as_str(), Some("start"));
            assert_eq!(first["latency_start"].as_str(), Some("batch_submission"));
            assert_eq!(first["reason"].as_str(), Some("submitted"));
            assert_eq!(first["started_at_us"].as_u64(), Some(10_000_000));
            assert_eq!(first["input_ready_at_us"].as_u64(), Some(8_000_000));
            assert_eq!(first["elapsed_us"].as_u64(), Some(0));
            assert!(first["signed_at_us"].is_null());
            let finality = &events[1]["fields"];
            assert_eq!(
                finality["benchmark_event"].as_str(),
                Some("first_finalization")
            );
            assert_eq!(finality["elapsed_us"].as_u64(), Some(2_000_000));
            assert_eq!(finality["input_elapsed_us"].as_u64(), Some(4_000_000));
            assert_eq!(finality["reason"].as_str(), Some("consensus"));
            assert_eq!(finality["view"].as_u64(), Some(4));
            assert_eq!(finality["signed_view"].as_u64(), Some(3));
            assert_eq!(finality["signed_at_us"].as_u64(), Some(11_000_000));
            assert_eq!(finality["goal_us"].as_u64(), Some(250_000));
            assert_eq!(
                events[2]["fields"]["benchmark_event"].as_str(),
                Some("ordered")
            );
            assert_eq!(events[2]["fields"]["reason"].as_str(), Some("delivery"));
            assert_eq!(
                events[4]["fields"]["benchmark_event"].as_str(),
                Some("eviction")
            );
            assert_eq!(events[4]["fields"]["reason"].as_str(), Some("capacity"));
            let last = &events[6]["fields"];
            assert_eq!(last["benchmark_event"].as_str(), Some("ordered"));
            assert_eq!(last["starts"].as_u64(), Some(3));
            assert_eq!(last["drops"].as_u64(), Some(1));
            assert_eq!(last["outstanding"].as_u64(), Some(0));
            assert_eq!(last["nonfinalized"].as_u64(), Some(1));
        });
    }

    #[test]
    fn benchmark_first_finality_counts_exact_blocks_once() {
        deterministic::Runner::default().start(|runtime| async move {
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(8), true);
            let blocks = chain(4);
            let now = runtime.current();
            for block in &blocks {
                latency.start(*block, parent(*block), now, None, now);
            }
            let conflicting = BlockRef::new(
                ChainId::new(0),
                Height::new(2),
                Sha256::hash(&[b"conflict"]),
            );
            latency.start(conflicting, parent(conflicting), now, None, now);
            // A final position covers its tracked ancestry.
            latency.finalize(finality(&[blocks[1]]), now);
            assert_eq!(latency.metrics.nonfinalized.get(), 3);
            // A later position counts only newly covered blocks.
            for _ in 0..2 {
                latency.finalize(finality(&[blocks[3]]), now);
            }
            assert_eq!(latency.metrics.outstanding.get(), 5);
            assert_eq!(latency.metrics.nonfinalized.get(), 1);
            assert!(
                latency
                    .started
                    .iter()
                    .any(|start| start.block == conflicting && !start.finalized)
            );
            assert!(
                runtime
                    .encode()
                    .contains("proposal_finalization_latency_count 4\n")
            );
        });
    }

    #[test]
    fn benchmark_censored_starts_remain_visible_until_finality_or_eviction() {
        deterministic::Runner::default().start(|runtime| async move {
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(2), true);
            let now = runtime.current();
            latency.start(
                reference(0, 1),
                parent(reference(0, 1)),
                now,
                Some(now - Duration::from_secs(2)),
                now,
            );
            latency.start(
                reference(0, 1),
                parent(reference(0, 1)),
                now + Duration::from_secs(1),
                None,
                now,
            );
            assert_eq!(latency.started[0].started_at, now);
            latency.start(reference(0, 2), parent(reference(0, 2)), now, None, now);
            assert_eq!(latency.metrics.starts.get(), 2);
            assert_eq!(latency.metrics.outstanding.get(), 2);
            assert_eq!(latency.metrics.nonfinalized.get(), 2);
            latency.start(reference(0, 3), parent(reference(0, 3)), now, None, now);
            assert_eq!(latency.metrics.dropped.get(), 1);
            assert_eq!(latency.metrics.finality_evicted.get(), 1);
            assert_eq!(latency.metrics.outstanding.get(), 2);
            assert_eq!(latency.metrics.nonfinalized.get(), 2);
            latency.order(reference(0, 2), now);
            latency.order(reference(0, 2), now);
            assert_eq!(latency.metrics.outstanding.get(), 1);
            assert_eq!(latency.metrics.nonfinalized.get(), 2);
            latency.order(reference(0, 3), now);
            assert_eq!(latency.metrics.outstanding.get(), 0);
            assert_eq!(latency.metrics.nonfinalized.get(), 2);
            for height in 4..=5 {
                latency.start(
                    reference(0, height),
                    parent(reference(0, height)),
                    now,
                    None,
                    now,
                );
            }
            assert_eq!(latency.started.len(), 2);
            assert_eq!(latency.metrics.outstanding.get(), 2);
            assert_eq!(latency.metrics.nonfinalized.get(), 2);
            assert_eq!(latency.metrics.dropped.get(), 1);
            assert_eq!(latency.metrics.finality_evicted.get(), 3);
        });
    }

    #[test]
    fn proposal_latency_retention_is_bounded_without_finality() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), false);
            let now = context.current();
            for height in 1..=3 {
                latency.start(
                    reference(0, height),
                    parent(reference(0, height)),
                    now,
                    None,
                    now,
                );
            }
            let started = &latency.started;
            assert_eq!(started.len(), 2);
            assert_eq!(started.front().unwrap().block.height(), Height::new(2));
            assert_eq!(latency.metrics.dropped.get(), 1);
            assert_eq!(latency.metrics.finality_evicted.get(), 1);
        });
    }

    #[test]
    fn proposal_latency_distinguishes_finality_and_ordering_evictions() {
        deterministic::Runner::default().start(|runtime| async move {
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(1), false);
            let now = runtime.current();
            latency.start(reference(0, 1), parent(reference(0, 1)), now, None, now);
            latency.finalize(finality(&[reference(0, 1)]), now);
            latency.start(reference(0, 2), parent(reference(0, 2)), now, None, now);
            assert_eq!(latency.metrics.dropped.get(), 1);
            assert_eq!(latency.metrics.finality_evicted.get(), 0);

            latency.start(reference(0, 3), parent(reference(0, 3)), now, None, now);
            assert_eq!(latency.metrics.dropped.get(), 2);
            assert_eq!(latency.metrics.finality_evicted.get(), 1);

            latency.order(reference(0, 3), now);
            latency.start(reference(0, 4), parent(reference(0, 4)), now, None, now);
            latency.order(reference(0, 4), now);
            latency.start(reference(0, 5), parent(reference(0, 5)), now, None, now);
            assert_eq!(latency.metrics.dropped.get(), 2);
            assert_eq!(latency.metrics.finality_evicted.get(), 3);
        });
    }

    #[test]
    fn batch_finality_includes_queueing_and_records_finality_once() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), false);
            let block = |height| {
                BlockRef::new(
                    ChainId::new(0),
                    Height::new(height),
                    Sha256::hash(&[b"block"]),
                )
            };
            let now = context.current();
            let input = now - Duration::from_secs(1);
            latency.finalize(finality(&[block(1)]), now);
            latency.start(block(2), parent(block(2)), input, Some(input), now);
            latency.start(block(2), parent(block(2)), now, Some(input), now);
            assert_eq!(latency.started[0].started_at, input);
            for _ in 0..2 {
                latency.finalize(finality(&[block(2)]), now);
            }
            let encoded = context.encode();
            assert!(encoded.contains("input_finalization_latency_count 1\n"));
            assert!(encoded.contains("proposal_finalization_latency_count 1\n"));
            let sum = |name: &str| {
                encoded
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .unwrap()
                    .trim()
                    .parse::<f64>()
                    .unwrap()
            };
            assert!(sum("proposal_finalization_latency_sum ") >= 1.0);
            assert!(
                (sum("input_finalization_latency_sum ")
                    - sum("proposal_finalization_latency_sum "))
                .abs()
                    < 1e-9
            );
        });
    }

    #[test]
    fn proposal_latency_evicts_the_oldest_start_across_chains() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), false);
            let now = context.current();
            let old = reference(1, 1);
            let newer = reference(0, 1);
            let newest = reference(0, 2);
            for block in [old, newer, newest] {
                latency.start(block, parent(block), now, None, now);
            }

            let started = &latency.started;
            assert!(!started.iter().any(|start| start.block == old));
            assert!(started.iter().any(|start| start.block == newer));
            assert!(started.iter().any(|start| start.block == newest));
        });
    }

    #[test]
    fn proposal_latency_observes_skipped_ancestry_after_ordering() {
        deterministic::Runner::default().start(|runtime| async move {
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(4), true);
            let blocks = chain(3);
            let now = runtime.current();
            for block in &blocks {
                latency.start(*block, parent(*block), now, None, now);
            }
            let conflicting = BlockRef::new(
                ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"conflict"]),
            );
            latency.start(conflicting, parent(conflicting), now, None, now);
            // Marshal can deliver a block in order before consensus reports its finality.
            for block in &blocks[..2] {
                latency.order(*block, now);
                latency.order(*block, now);
            }
            assert_eq!(latency.metrics.outstanding.get(), 2);
            assert!(
                runtime
                    .encode()
                    .contains("proposal_finalization_latency_count 0\n")
            );
            for _ in 0..2 {
                latency.finalize(
                    Finality {
                        view: View::new(7),
                        ..finality(&[blocks[2]])
                    },
                    now,
                );
            }
            assert_eq!(latency.metrics.nonfinalized.get(), 1);
            assert_eq!(latency.metrics.outstanding.get(), 2);
            assert_eq!(latency.started.len(), 2);
            assert!(
                latency
                    .started
                    .iter()
                    .any(|start| start.block == conflicting && !start.finalized)
            );
            let metrics = runtime.encode();
            assert!(metrics.contains("proposal_finalization_latency_count 3\n"));
            assert!(metrics.contains("proposal_ordering_latency_count 2\n"));
        });
    }

    #[test]
    fn proposal_latency_bounds_ancestry_to_pending_heights() {
        let chain = ChainId::new(0);
        let reference = |chain, height| {
            BlockRef::new(
                chain,
                Height::new(height),
                Sha256::hash(&[&height.to_be_bytes()]),
            )
        };
        let tip = reference(chain, 100);
        let unrelated = reference(ChainId::new(1), 100);
        let oldest = BTreeMap::from([(chain, Height::new(98))]);
        let mut lookups = 0;
        let finalized = ProposalLatency::finalized_ancestry(&[tip, unrelated], &oldest, |cursor| {
            lookups += 1;
            Some(reference(cursor.chain(), cursor.height().get() - 1).digest())
        });
        assert_eq!(lookups, 2);
        assert_eq!(
            finalized,
            (98..=100).map(|height| reference(chain, height)).collect()
        );
        let finalized = ProposalLatency::finalized_ancestry(&[tip], &BTreeMap::new(), |_| {
            panic!("no pending proposal needs ancestry")
        });
        assert!(finalized.is_empty());
        let finalized =
            ProposalLatency::finalized_ancestry(&[reference(chain, 97)], &oldest, |_| {
                panic!("tip precedes every pending proposal")
            });
        assert!(finalized.is_empty());
        let finalized = ProposalLatency::finalized_ancestry(&[tip], &oldest, |_| None);
        assert_eq!(finalized, BTreeSet::from([tip]));
    }

    #[test]
    fn proposal_latency_requires_exact_finalized_ancestry() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), false);
            let now = context.current();
            let left = reference(0, 1);
            let right = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"right"]));
            latency.start(left, parent(left), now, None, now);

            latency.finalize(finality(&[right]), now);
            assert!(
                latency
                    .started
                    .iter()
                    .any(|start| start.block == left && !start.finalized)
            );

            latency.finalize(finality(&[left]), now);
            assert!(latency.started.iter().all(|start| start.finalized));
            latency.order(left, now);
            assert!(latency.started.is_empty());

            // A finalized tip covers the tracked blocks its recorded parents lead to.
            let blocks = chain(2);
            for block in &blocks {
                latency.start(*block, parent(*block), now, None, now);
            }
            latency.finalize(finality(&[blocks[1]]), now);
            assert!(latency.started.iter().all(|start| start.finalized));
            for block in &blocks {
                latency.order(*block, now);
            }
            assert!(latency.started.is_empty());
        });
    }

    #[test]
    fn proposal_latency_follows_only_exact_recorded_parents() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(4), false);
            let now = context.current();
            // The tip's parent sits at the tracked block's height but on a different fork.
            let blocks = chain(2);
            latency.start(blocks[0], parent(blocks[0]), now, None, now);
            latency.start(blocks[1], Sha256::hash(&[b"fork"]), now, None, now);
            latency.finalize(finality(&[blocks[1]]), now);
            assert!(
                latency
                    .started
                    .iter()
                    .any(|start| start.block == blocks[0] && !start.finalized)
            );
            assert!(
                latency
                    .started
                    .iter()
                    .any(|start| start.block == blocks[1] && start.finalized)
            );
        });
    }

    #[test]
    fn proposal_latency_orders_blocks_that_were_never_directly_finalized() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), false);
            let now = context.current();
            let block = reference(0, 1);
            latency.start(block, parent(block), now, None, now);
            latency.order(block, now);
            assert_eq!(latency.started.len(), 1);
            assert!(latency.started[0].ordered);
            latency.order(block, now);
            assert_eq!(latency.started.len(), 1);
            assert_eq!(latency.metrics.outstanding.get(), 0);
            assert_eq!(latency.metrics.nonfinalized.get(), 1);
        });
    }

    #[test]
    fn finality_at_an_empty_tip_covers_the_batch_below_it() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(4), false);
            let now = context.current();
            let blocks = chain(3);
            latency.start(blocks[0], parent(blocks[0]), now, None, now);
            for empty in &blocks[1..] {
                latency.link(*empty, parent(*empty));
            }
            latency.finalize(finality(&[blocks[2]]), now);
            assert_eq!(latency.metrics.nonfinalized.get(), 0);
            assert!(
                context
                    .encode()
                    .contains("proposal_finalization_latency_count 1\n")
            );
        });
    }

    #[test]
    fn finality_through_interleaved_empty_blocks_covers_every_batch() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(16), false);
            let now = context.current();
            let blocks = chain(12);
            for block in &blocks {
                if block.height().get() % 2 == 1 {
                    latency.start(*block, parent(*block), now, None, now);
                } else {
                    latency.link(*block, parent(*block));
                }
            }
            latency.finalize(finality(&[blocks[11]]), now);
            assert_eq!(latency.metrics.nonfinalized.get(), 0);
            assert!(
                context
                    .encode()
                    .contains("proposal_finalization_latency_count 6\n")
            );
        });
    }

    #[test]
    fn lineage_is_pruned_below_finality_and_bounded() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(4), false);
            let now = context.current();
            let blocks = chain(9);
            for empty in &blocks[..6] {
                latency.link(*empty, parent(*empty));
            }
            assert_eq!(
                latency.lineage.keys().copied().collect::<Vec<_>>(),
                blocks[2..6]
            );

            // Finality with nothing left to cover drops every link up to the final height.
            latency.start(blocks[6], parent(blocks[6]), now, None, now);
            latency.finalize(finality(&[blocks[6]]), now);
            assert!(latency.lineage.is_empty());

            // An unfinalized block keeps the links above it.
            for batch in &blocks[7..] {
                latency.start(*batch, parent(*batch), now, None, now);
            }
            latency.finalize(finality(&[blocks[7]]), now);
            assert_eq!(
                latency.lineage.keys().copied().collect::<Vec<_>>(),
                [blocks[8]]
            );
        });
    }

    #[test]
    fn signed_latency_and_goal_use_the_goal_captured_at_signing() {
        deterministic::Runner::default().start(|context| async move {
            let mut latency = ProposalLatency::new(&context, NZUsize!(4), false);
            let signed = context.current();
            let blocks = chain(3);
            for block in &blocks {
                latency.start(*block, parent(*block), signed, None, signed);
            }
            let goal = Some(Duration::from_secs(1));
            latency.sign(blocks[0], View::new(1), signed, goal);
            // Only the first signature report counts.
            latency.sign(blocks[0], View::new(2), signed, None);
            latency.sign(
                blocks[1],
                View::new(1),
                signed,
                Some(Duration::from_millis(500)),
            );
            latency.sign(blocks[2], View::new(1), signed, None);

            let now = signed + Duration::from_millis(800);
            let finalized = latency.finalize(finality(&[blocks[2]]), now);
            assert_eq!(
                finalized
                    .iter()
                    .map(|first| first.within_goal)
                    .collect::<Vec<_>>(),
                [Some(true), Some(false), None]
            );
            assert!(
                finalized
                    .iter()
                    .all(|first| first.signed_at == Some(signed))
            );
            assert_eq!(latency.metrics.goal_finalized.get(), 2);
            assert_eq!(latency.metrics.goal_met.get(), 1);

            assert_eq!(latency.order(blocks[0], now), Some(signed));
            assert_eq!(latency.order(blocks[0], now), None);
            let metrics = context.encode();
            assert!(metrics.contains("proposal_signed_finalization_latency_count 3\n"));
            assert!(metrics.contains("proposal_signed_ordering_latency_count 1\n"));
        });
    }

    #[test]
    fn finality_goal_is_unknown_until_refreshed_and_shared_by_clones() {
        let goal = FinalityGoal::new(Duration::from_millis(10));
        let shared = goal.clone();
        assert_eq!(goal.get(), None);
        shared.refresh(40);
        assert_eq!(goal.get(), Some(Duration::from_millis(90)));
        shared.refresh(u64::MAX);
        assert!(goal.get().is_some());
    }
}
