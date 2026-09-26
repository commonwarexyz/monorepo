//! Voter observability: metrics, round spans, and the trace context that follows each input.
//!
//! [`Telemetry`] owns the metrics and the current view's root span. [`Correlation`] keeps the
//! trace context of every input the core has admitted but not yet consumed. The remaining modules
//! hold small pure trackers the voter samples as it runs.

mod activity;
mod arrivals;
mod correlation;
pub(crate) mod metrics;
mod stall;
mod vote_build;

use crate::{
    multimmit::{
        actors::voter::tasks::TaskReservations,
        machine::CoreState,
        types::{BlockRef, TransactionBlockHeader},
    },
    types::{Epoch, Round, View},
};
pub(crate) use activity::PeerActivity;
use arrivals::BlockArrivals;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::telemetry::{
    metrics::{GaugeExt as _, Histogram, HistogramExt as _},
    traces::TracedExt as _,
};
pub(crate) use correlation::Correlation;
use metrics::{Metrics, ViewProofKind, ViewProofSource};
use stall::ProducerStallMonitor;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use tracing::{Span, info_span};
use vote_build::VoteBuildTrace;

/// Span that owns this work and the root that records its terminal error.
#[derive(Clone)]
pub(crate) struct TraceContext {
    pub(crate) span: Span,
    pub(crate) root: Span,
    /// The source and kind of the view proof an input carries, for its admission metric.
    pub(crate) view_proof: Option<(ViewProofSource, ViewProofKind)>,
}

impl TraceContext {
    pub(crate) const fn new(span: Span, root: Span) -> Self {
        Self {
            span,
            root,
            view_proof: None,
        }
    }
}

/// Creates one view's root span.
pub(crate) fn round_span(epoch: Epoch, view: View) -> Span {
    info_span!(
        parent: None,
        "multimmit.voter.round",
        epoch = epoch.get().traced(),
        view = view.get().traced()
    )
}

/// Creates the one child span for a consumed view timer.
pub(crate) fn round_timeout_span(parent: &Span, round: Round) -> Span {
    info_span!(
        parent: parent,
        "multimmit.voter.round.timeout",
        reason = tracing::field::Empty,
        epoch = round.epoch().get().traced(),
        view = round.view().get().traced()
    )
}

/// The voter's metrics, the current view's root span, and the trackers it samples.
pub(crate) struct Telemetry<D: Digest> {
    pub(crate) metrics: Metrics,
    /// The span of this node's in-flight vote-body pass.
    pub(crate) vote_build: VoteBuildTrace,
    epoch: Epoch,
    round_view: View,
    round_span: Span,
    view_started_at: BTreeMap<View, SystemTime>,
    /// First network observation per transaction block, consumed by DA-vote signing.
    arrivals: BlockArrivals<D>,
    stall: ProducerStallMonitor,
}

impl<D: Digest> Telemetry<D> {
    /// Starts telemetry in `view`; `entered_at` is when the view began, unknown after recovery.
    pub(crate) fn new(
        metrics: Metrics,
        epoch: Epoch,
        view: View,
        entered_at: Option<SystemTime>,
    ) -> Self {
        Self {
            metrics,
            vote_build: VoteBuildTrace::default(),
            epoch,
            round_view: view,
            round_span: round_span(epoch, view),
            view_started_at: entered_at.map(|at| (view, at)).into_iter().collect(),
            arrivals: BlockArrivals::new(),
            stall: ProducerStallMonitor::default(),
        }
    }

    /// Returns the current view's root span.
    pub(crate) const fn round_span(&self) -> &Span {
        &self.round_span
    }

    /// Returns the view the root span belongs to.
    pub(crate) const fn round_view(&self) -> View {
        self.round_view
    }

    /// Moves the root span to `view`, recording how long the previous view lasted.
    pub(crate) fn refresh_round(&mut self, view: View, now: SystemTime) {
        if view == self.round_view {
            return;
        }
        // A view's latency is the wall time between entering and leaving it, measured at the
        // transition itself: durability acknowledgement lags application, so observing at the
        // barrier would measure the sync pipeline instead of the view.
        if let Some(started_at) = self.view_started_at.get(&self.round_view) {
            self.metrics.round_latency.observe_between(*started_at, now);
        }
        self.round_view = view;
        self.view_started_at.insert(view, now);
        self.round_span = round_span(self.epoch, view);
    }

    /// Observes the time since `view` began on `histogram`, if this replica saw it begin.
    pub(crate) fn observe_since_view_start(
        &self,
        view: View,
        histogram: &Histogram,
        now: SystemTime,
    ) {
        if let Some(started_at) = self.view_started_at.get(&view) {
            histogram.observe_between(*started_at, now);
        }
    }

    /// Exports the machine's progress gauges and returns its current view.
    pub(crate) fn update_progress<H: Hasher<Digest = D>, V: Variant>(
        &mut self,
        machine: &CoreState<H, V>,
        tasks: &TaskReservations,
        now: SystemTime,
    ) -> View {
        let metrics = &self.metrics;
        let progress = machine.machine().progress();
        let _ = metrics.current_view.try_set(progress.view.get());
        let _ = metrics.retired_view.try_set(progress.retired_view.get());
        let _ = metrics
            .finality_floor
            .try_set(progress.finality_floor.get());
        let _ = metrics
            .proposal_anchor_view
            .try_set(progress.proposal_anchor_view.get());
        let _ = metrics.produced_blocks.try_set(progress.produced_blocks);
        let _ = metrics
            .artifact_cache_occupancy
            .try_set(progress.artifact_cache_occupancy);
        let _ = metrics
            .artifact_cache_capacity
            .try_set(progress.artifact_cache_capacity);
        let _ = metrics
            .remote_artifact_capacity
            .try_set(progress.remote_artifact_capacity);
        let _ = metrics
            .local_artifact_capacity
            .try_set(progress.local_artifact_capacity);
        let _ = metrics
            .verification_jobs
            .try_set(progress.verification_jobs);
        let _ = metrics
            .verification_job_capacity
            .try_set(progress.verification_job_capacity);
        let _ = metrics.future_artifacts.try_set(progress.future_artifacts);
        let _ = metrics
            .view_timeout_cutoff_vote
            .try_set(usize::from(progress.timeout_cutoff_vote));
        let _ = metrics
            .view_timeout_cutoff_timeout
            .try_set(usize::from(progress.timeout_cutoff_timeout));
        let _ = metrics
            .build_active
            .try_set(usize::from(tasks.local_build_active()));
        let _ = metrics.custody_active.try_set(tasks.local_custody_active());
        if let Some(producer) = progress.producer {
            let _ = metrics
                .producer_pipeline_blocked
                .try_set(usize::from(producer.pipeline_blocked()));
            self.stall.observe(producer, now);
        }
        self.view_started_at
            .retain(|view, _| *view > progress.retired_view);
        progress.view
    }

    /// Exports per-chain finality plus aggregate floors for the remaining chain heights.
    ///
    /// The per-chain family scales with the validator count, so only the value that localizes a
    /// single stalled chain stays per chain. Certification, DA, and dissemination report their
    /// slowest chain instead.
    pub(crate) fn update_chains<H: Hasher<Digest = D>, V: Variant>(
        &self,
        machine: &CoreState<H, V>,
    ) {
        let metrics = &self.metrics;
        let progress = machine.machine().chain_progress();
        assert_eq!(metrics.chains.len(), progress.len());
        let mut certified_floor = u64::MAX;
        let mut da_voted_floor = u64::MAX;
        let mut known_floor = u64::MAX;
        let mut finalized_ceiling = 0;
        for (chain_metrics, chain) in metrics.chains.iter().zip(&progress) {
            let finalized = chain.finalized().get();
            let _ = chain_metrics.finalized.try_set(finalized);
            certified_floor = certified_floor.min(chain.certified().get());
            da_voted_floor = da_voted_floor.min(chain.da_voted().get());
            known_floor = known_floor.min(chain.known().get());
            finalized_ceiling = finalized_ceiling.max(finalized);
        }
        if progress.is_empty() {
            return;
        }
        let lagging = progress
            .iter()
            .filter(|chain| chain.finalized().get() < finalized_ceiling)
            .count();
        let _ = metrics
            .headers_after_seal
            .try_set(machine.machine().headers_after_seal());
        let _ = metrics
            .header_restarts
            .try_set(machine.machine().header_restarts());
        let _ = metrics.chain_certified_floor.try_set(certified_floor);
        let _ = metrics.chain_da_voted_floor.try_set(da_voted_floor);
        let _ = metrics.chain_known_floor.try_set(known_floor);
        let _ = metrics.lagging_chains.try_set(lagging);
    }

    /// Exports the retention profile behind the durable floors.
    pub(crate) fn update_retention<H: Hasher<Digest = D>, V: Variant>(
        &self,
        machine: &CoreState<H, V>,
        events_since_checkpoint: u64,
    ) {
        let metrics = &self.metrics;
        let _ = metrics
            .retained_events
            .try_set(events_since_checkpoint as usize);
        let _ = metrics
            .retained_artifacts
            .try_set(machine.machine().retained_artifact_references());
        let _ = metrics
            .nullification_suffix
            .try_set(machine.machine().nullification_suffix() as usize);
        let _ = metrics
            .staged_batches
            .try_set(machine.machine().staged_barriers());
    }

    /// Adds the time since `started` to the voter's busy-time counter.
    pub(crate) fn record_busy(&self, started: SystemTime, now: SystemTime) {
        let elapsed = now.duration_since(started).unwrap_or_default();
        self.metrics
            .busy_micros
            .inc_by(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
    }

    /// Records the first network arrival of a transaction block.
    pub(crate) fn record_arrival(&mut self, reference: BlockRef<D>, at: SystemTime) {
        self.arrivals.record(reference, at);
    }

    /// Records ingest-to-DA-vote latency for a block first observed on the network.
    ///
    /// Locally produced blocks never enter the arrival window and are skipped.
    pub(crate) fn observe_da_vote_latency<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
        now: SystemTime,
    ) {
        let Some(arrived_at) = self.arrivals.take(&header.block_ref::<H>()) else {
            return;
        };
        self.metrics
            .da_vote_latency
            .observe_between(arrived_at, now);
    }

    /// Warns once when the local producer has been blocked for at least `threshold`.
    pub(crate) fn report_stall(&mut self, now: SystemTime, threshold: Duration) {
        self.stall.report(now, threshold);
    }
}
