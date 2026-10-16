//! Voter observability: metrics, round spans, and the trace context that follows each input.
//!
//! [`Telemetry`] owns the metrics and the current view's root span. [`Correlation`] keeps the
//! trace context of every input the core has admitted but not yet consumed.

mod correlation;
pub(crate) mod metrics;

use crate::{
    multimmit::{actors::voter::tasks::TaskReservations, machine::CoreState},
    types::{Epoch, View},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::telemetry::{
    metrics::{GaugeExt as _, Histogram, HistogramExt as _},
    traces::TracedExt as _,
};
pub(crate) use correlation::Correlation;
use metrics::{Cumulative, Metrics, ViewProofKind, ViewProofSource};
use std::{collections::BTreeMap, time::SystemTime};
use tracing::{Span, info_span};

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

/// The voter's metrics and the current view's root span.
pub(crate) struct Telemetry {
    pub(crate) metrics: Metrics,
    epoch: Epoch,
    round_view: View,
    round_span: Span,
    view_started_at: BTreeMap<View, SystemTime>,
    /// The machine's cumulative counts already added to their counters.
    exported: Cumulative,
}

impl Telemetry {
    /// Starts telemetry in `view`; `entered_at` is when the view began, unknown after recovery.
    pub(crate) fn new(
        metrics: Metrics,
        epoch: Epoch,
        view: View,
        entered_at: Option<SystemTime>,
    ) -> Self {
        Self {
            metrics,
            epoch,
            round_view: view,
            round_span: round_span(epoch, view),
            view_started_at: entered_at.map(|at| (view, at)).into_iter().collect(),
            exported: Cumulative::default(),
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
        // A view's latency is the wall time between entering and leaving it, measured when the
        // machine applies the transition, independent of when the transition becomes durable.
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
    pub(crate) fn update_progress<H: Hasher, V: Variant>(
        &mut self,
        machine: &CoreState<H, V>,
        tasks: &TaskReservations,
    ) -> View {
        let metrics = &self.metrics;
        let progress = machine.machine().progress();
        let _ = metrics.current_view.try_set(progress.view.get());
        let _ = metrics.retired_view.try_set(progress.retired_view.get());
        let _ = metrics.last_resolved.try_set(progress.last_resolved.get());
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
            .build_active
            .try_set(usize::from(tasks.local_build_active()));
        let _ = metrics.custody_active.try_set(tasks.local_custody_active());
        if let Some(producer) = progress.producer {
            let _ = metrics.produced_blocks.try_set(producer.produced().get());
        }
        let _ = metrics.delay_estimate.try_set(progress.delay);
        let _ = metrics.production_estimate.try_set(progress.production);
        let _ = metrics.grace.try_set(progress.grace);
        let cumulative = Cumulative::from(&progress);
        metrics.record_cumulative(&self.exported, &cumulative);
        self.exported = cumulative;
        self.view_started_at
            .retain(|view, _| *view > progress.retired_view);
        progress.view
    }

    /// Exports per-chain finality plus aggregate floors for the remaining chain heights.
    ///
    /// The per-chain family scales with the validator count, so only the value that localizes a
    /// single stalled chain stays per chain. Acceptance and the height quorum report their slowest
    /// chain instead.
    pub(crate) fn update_chains<H: Hasher, V: Variant>(&self, machine: &CoreState<H, V>) {
        let metrics = &self.metrics;
        let progress = machine.machine().chain_progress();
        assert_eq!(metrics.chains.len(), progress.len());
        let mut accepted_floor = u64::MAX;
        let mut quorum_floor = u64::MAX;
        let mut finalized_ceiling = 0;
        for (chain_metrics, chain) in metrics.chains.iter().zip(&progress) {
            let finalized = chain.finalized().get();
            let _ = chain_metrics.finalized.try_set(finalized);
            accepted_floor = accepted_floor.min(chain.accepted().get());
            quorum_floor = quorum_floor.min(chain.quorum().get());
            finalized_ceiling = finalized_ceiling.max(finalized);
        }
        if progress.is_empty() {
            return;
        }
        let lagging = progress
            .iter()
            .filter(|chain| chain.finalized().get() < finalized_ceiling)
            .count();
        let _ = metrics.chain_accepted_floor.try_set(accepted_floor);
        let _ = metrics.chain_quorum_floor.try_set(quorum_floor);
        let _ = metrics.lagging_chains.try_set(lagging);
    }

    /// Exports the journal events recovery would replay.
    pub(crate) fn update_retention(&self, events_since_checkpoint: u64) {
        let _ = self
            .metrics
            .retained_events
            .try_set(events_since_checkpoint as usize);
    }

    /// Adds the time since `started` to the voter's busy-time counter.
    pub(crate) fn record_busy(&self, started: SystemTime, now: SystemTime) {
        let elapsed = now.duration_since(started).unwrap_or_default();
        self.metrics
            .busy_micros
            .inc_by(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
    }
}
