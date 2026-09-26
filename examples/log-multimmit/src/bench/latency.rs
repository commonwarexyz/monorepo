//! Latency of locally produced blocks from input submission to finality and ordered delivery.

use commonware_consensus::{
    multimmit::{
        FinalityFact, WAN_LATENCY,
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
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    num::NonZeroUsize,
    time::SystemTime,
};
use tracing::info;

/// Log target of benchmark events, kept stable for tooling that selects them by target.
const BENCHMARK_TARGET: &str = "commonware_log_multimmit::application::actor";

/// Exact identity of one producer block.
type Reference = BlockRef<Sha256Digest>;

/// The parts of a finality fact the tracker reads.
#[derive(Clone, Copy)]
pub struct Finality<'a> {
    /// Finalized chain tips, indexed by chain.
    pub blocks: &'a [Reference],
    /// Heights the finalized leader proposed, indexed by chain.
    pub proposed: &'a [Height],
    /// Votes supporting the fact.
    pub votes: usize,
    /// View of the finalized leader.
    pub view: View,
}

impl<'a> From<&'a FinalityFact<Sha256Digest>> for Finality<'a> {
    fn from(fact: &'a FinalityFact<Sha256Digest>) -> Self {
        Self {
            blocks: fact.blocks(),
            proposed: fact.proposed(),
            votes: fact.votes(),
            view: fact.round().view(),
        }
    }
}

/// How a block's first finality relates to its leader's proposal and to the quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// At or below the proposed height, with exactly a quorum of votes.
    ProposedEarly,
    /// At or below the proposed height, with more than a quorum of votes.
    ProposedLate,
    /// Above the proposed height (carried by vote extensions), with exactly a quorum of votes.
    ExtensionEarly,
    /// Above the proposed height, with more than a quorum of votes.
    ExtensionLate,
}

impl Class {
    /// Classifies first finality of a block at `height` by a leader that proposed up to
    /// `proposed` with `votes` votes, against a `quorum`.
    fn new(height: Height, proposed: Height, votes: usize, quorum: usize) -> Self {
        match (height > proposed, votes > quorum) {
            (false, false) => Self::ProposedEarly,
            (false, true) => Self::ProposedLate,
            (true, false) => Self::ExtensionEarly,
            (true, true) => Self::ExtensionLate,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ProposedEarly => "proposed_early",
            Self::ProposedLate => "proposed_late",
            Self::ExtensionEarly => "extension_early",
            Self::ExtensionLate => "extension_late",
        }
    }
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
    FirstFinality {
        class: Class,
        view: View,
        votes: usize,
    },
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
            Self::FirstFinality { class, .. } => class.label(),
        }
    }
}

/// One tracked block awaiting finality and ordered delivery.
struct ProposalStart {
    block: Reference,
    /// Digest of the block's parent, which extends finality coverage to older tracked blocks.
    parent: Sha256Digest,
    started_at: SystemTime,
    input_ready_at: Option<SystemTime>,
    finalized: bool,
    ordered: bool,
}

/// Tracks local blocks from input submission to consensus finality and to ordered delivery.
///
/// A block is final once a finalized leader's chain tip is the block or one of its
/// descendants. It is ordered once marshal delivers it in the total order, which can happen
/// before consensus reports finality. A block stays tracked until both are observed or it is
/// evicted to stay within capacity.
pub struct ProposalLatency {
    started: VecDeque<ProposalStart>,
    capacity: usize,
    metrics: LatencyMetrics,
}

/// Latency metrics, and the quorum that enables benchmark events.
struct LatencyMetrics {
    benchmark_quorum: Option<usize>,
    finality: Histogram,
    ordering: Histogram,
    input_finality: Histogram,
    dropped: Counter,
    finality_evicted: Counter,
    starts: Counter,
    outstanding: Gauge,
    nonfinalized: Gauge,
    proposed_early: Counter,
    proposed_late: Counter,
    extension_early: Counter,
    extension_late: Counter,
}

impl LatencyMetrics {
    fn new(context: &impl Metrics, benchmark: Option<NonZeroUsize>) -> Self {
        Self {
            benchmark_quorum: benchmark.map(NonZeroUsize::get),
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
            proposed_early: context.counter(
                "proposal_first_finality_proposed_early",
                "first finality at or below proposed height with quorum votes",
            ),
            proposed_late: context.counter(
                "proposal_first_finality_proposed_late",
                "first finality at or below proposed height with more than quorum votes",
            ),
            extension_early: context.counter(
                "proposal_first_finality_extension_early",
                "first finality above proposed height with quorum votes",
            ),
            extension_late: context.counter(
                "proposal_first_finality_extension_late",
                "first finality above proposed height with more than quorum votes",
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

    const fn class_counter(&self, class: Class) -> &Counter {
        match class {
            Class::ProposedEarly => &self.proposed_early,
            Class::ProposedLate => &self.proposed_late,
            Class::ExtensionEarly => &self.extension_early,
            Class::ExtensionLate => &self.extension_late,
        }
    }

    fn sample(&self, start: &ProposalStart, sample: Sample, now: SystemTime) {
        if self.benchmark_quorum.is_none() {
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
        let evidence = match sample {
            Sample::FirstFinality { view, votes, .. } => Some((view, votes)),
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
            view = evidence.map(|(view, _)| view.get()),
            votes = evidence.map(|(_, votes)| votes as u64),
            quorum = self.benchmark_quorum.map(|quorum| quorum as u64),
            starts = self.starts.get(),
            drops = self.dropped.get(),
            finality_evictions = self.finality_evicted.get(),
            proposed_early = self.proposed_early.get(),
            proposed_late = self.proposed_late.get(),
            extension_early = self.extension_early.get(),
            extension_late = self.extension_late.get(),
            outstanding = self.outstanding.get(),
            nonfinalized = self.nonfinalized.get(),
            "proposal benchmark sample"
        );
    }
}

impl ProposalLatency {
    /// Registers the latency metrics and tracks up to `capacity` blocks.
    ///
    /// With a `benchmark` quorum, every event is also logged at INFO and first finality is
    /// classified against that quorum.
    pub fn new(
        context: &impl Metrics,
        capacity: NonZeroUsize,
        benchmark: Option<NonZeroUsize>,
    ) -> Self {
        Self {
            started: VecDeque::new(),
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
            parent,
            started_at,
            input_ready_at,
            finalized: false,
            ordered: false,
        };
        self.metrics.sample(&start, Sample::Start, started_at);
        self.started.push_back(start);
    }

    /// Records first finality for every tracked block `finality` covers.
    ///
    /// Coverage extends from each finalized tip down to older tracked blocks through the parents
    /// recorded when tracking started.
    pub fn finalize(&mut self, finality: Finality<'_>, now: SystemTime) {
        // Ordering removes only finalized starts. New submissions cannot be covered by
        // this fact until their bodies have been staged and proposed.
        let mut oldest = BTreeMap::<ChainId, Height>::new();
        for start in self.started.iter().filter(|start| !start.finalized) {
            oldest
                .entry(start.block.chain())
                .and_modify(|height| *height = (*height).min(start.block.height()))
                .or_insert(start.block.height());
        }
        let parents = self
            .started
            .iter()
            .map(|start| (start.block, start.parent))
            .collect::<HashMap<_, _>>();
        let covered = Self::finalized_ancestry(finality.blocks, &oldest, |block| {
            parents.get(&block).copied()
        });
        let metrics = &self.metrics;
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
            if let Some(quorum) = metrics.benchmark_quorum {
                let class = Class::new(
                    start.block.height(),
                    finality.proposed[start.block.chain().get() as usize],
                    finality.votes,
                    quorum,
                );
                metrics.class_counter(class).inc();
                metrics.sample(
                    start,
                    Sample::FirstFinality {
                        class,
                        view: finality.view,
                        votes: finality.votes,
                    },
                    now,
                );
            }
        }
        self.started
            .retain(|start| !start.finalized || !start.ordered);
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
    pub fn order(&mut self, block: Reference, now: SystemTime) {
        let Some(index) = self.started.iter().position(|start| start.block == block) else {
            return;
        };
        let start = &mut self.started[index];
        if start.ordered {
            return;
        }
        start.ordered = true;
        self.metrics.outstanding.dec();
        self.metrics.ordering.observe_between(start.started_at, now);
        self.metrics.sample(start, Sample::Ordered, now);
        if start.finalized {
            self.started.remove(index);
        }
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

    fn finality<'a>(blocks: &'a [Reference], proposed: &'a [Height], votes: usize) -> Finality<'a> {
        Finality {
            blocks,
            proposed,
            votes,
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
                let mut quiet = ProposalLatency::new(&quiet_context, NZUsize!(1), None);
                quiet.start(
                    reference(0, 1),
                    parent(reference(0, 1)),
                    started,
                    None,
                    started,
                );
                quiet.finalize(finality(&[reference(0, 1)], &[Height::new(1)], 3), now);
                quiet.order(reference(0, 1), now);
                assert!(output.0.lock().is_empty());

                let mut latency = ProposalLatency::new(&runtime, NZUsize!(1), Some(NZUsize!(3)));
                latency.start(
                    reference(0, 2),
                    parent(reference(0, 2)),
                    started,
                    Some(started - Duration::from_secs(2)),
                    started,
                );
                latency.finalize(
                    Finality {
                        view: View::new(4),
                        ..finality(&[reference(0, 2)], &[Height::new(2)], 3)
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
            let finality = &events[1]["fields"];
            assert_eq!(
                finality["benchmark_event"].as_str(),
                Some("first_finalization")
            );
            assert_eq!(finality["elapsed_us"].as_u64(), Some(2_000_000));
            assert_eq!(finality["input_elapsed_us"].as_u64(), Some(4_000_000));
            assert_eq!(finality["reason"].as_str(), Some("proposed_early"));
            assert_eq!(finality["view"].as_u64(), Some(4));
            assert_eq!(finality["votes"].as_u64(), Some(3));
            assert_eq!(finality["quorum"].as_u64(), Some(3));
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
    fn benchmark_first_finality_classifies_exact_blocks_once() {
        deterministic::Runner::default().start(|runtime| async move {
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(8), Some(NZUsize!(3)));
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
            // Height one is proposed; height two is covered by the quorum's extension.
            latency.finalize(finality(&[blocks[1]], &[Height::new(1)], 3), now);
            assert_eq!(latency.metrics.proposed_early.get(), 1);
            assert_eq!(latency.metrics.extension_early.get(), 1);
            assert_eq!(latency.metrics.nonfinalized.get(), 3);
            // A larger fact counts only newly covered blocks, with the configured quorum.
            for _ in 0..2 {
                latency.finalize(finality(&[blocks[3]], &[Height::new(3)], 4), now);
            }
            assert_eq!(latency.metrics.proposed_early.get(), 1);
            assert_eq!(latency.metrics.extension_early.get(), 1);
            assert_eq!(latency.metrics.proposed_late.get(), 1);
            assert_eq!(latency.metrics.extension_late.get(), 1);
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
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(2), Some(NZUsize!(2)));
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
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), None);
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
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(1), None);
            let now = runtime.current();
            latency.start(reference(0, 1), parent(reference(0, 1)), now, None, now);
            latency.finalize(finality(&[reference(0, 1)], &[Height::new(100)], 3), now);
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
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), None);
            let block = |height| {
                BlockRef::new(
                    ChainId::new(0),
                    Height::new(height),
                    Sha256::hash(&[b"block"]),
                )
            };
            let now = context.current();
            let input = now - Duration::from_secs(1);
            latency.finalize(finality(&[block(1)], &[Height::new(100)], 3), now);
            latency.start(block(2), parent(block(2)), input, Some(input), now);
            latency.start(block(2), parent(block(2)), now, Some(input), now);
            assert_eq!(latency.started[0].started_at, input);
            for _ in 0..2 {
                latency.finalize(finality(&[block(2)], &[Height::new(100)], 3), now);
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
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), None);
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
            let mut latency = ProposalLatency::new(&runtime, NZUsize!(4), Some(NZUsize!(3)));
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
                        ..finality(&[blocks[2]], &[Height::new(2)], 3)
                    },
                    now,
                );
            }
            assert_eq!(latency.metrics.proposed_early.get(), 2);
            assert_eq!(latency.metrics.extension_early.get(), 1);
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
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), None);
            let now = context.current();
            let left = reference(0, 1);
            let right = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"right"]));
            latency.start(left, parent(left), now, None, now);

            latency.finalize(finality(&[right], &[Height::new(100)], 3), now);
            assert!(
                latency
                    .started
                    .iter()
                    .any(|start| start.block == left && !start.finalized)
            );

            latency.finalize(finality(&[left], &[Height::new(100)], 3), now);
            assert!(latency.started.iter().all(|start| start.finalized));
            latency.order(left, now);
            assert!(latency.started.is_empty());

            // A finalized tip covers the tracked blocks its recorded parents lead to.
            let blocks = chain(2);
            for block in &blocks {
                latency.start(*block, parent(*block), now, None, now);
            }
            latency.finalize(finality(&[blocks[1]], &[Height::new(100)], 3), now);
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
            let mut latency = ProposalLatency::new(&context, NZUsize!(4), None);
            let now = context.current();
            // The tip's parent sits at the tracked block's height but on a different fork.
            let blocks = chain(2);
            latency.start(blocks[0], parent(blocks[0]), now, None, now);
            latency.start(blocks[1], Sha256::hash(&[b"fork"]), now, None, now);
            latency.finalize(finality(&[blocks[1]], &[Height::new(100)], 3), now);
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
            let mut latency = ProposalLatency::new(&context, NZUsize!(2), None);
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
}
