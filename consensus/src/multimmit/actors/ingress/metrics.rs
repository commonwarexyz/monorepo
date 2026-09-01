//! Metrics registered by the ingress actor.

use crate::multimmit::actors::metrics::{STAGE_LATENCY, Traffic, plane_counter};
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{Counter, CounterFamily, Histogram, MetricsExt as _},
};

/// Ingress actor metrics.
pub(super) struct Metrics {
    /// Frames that decoded for their plane, by plane.
    pub(crate) decoded: CounterFamily<Traffic>,
    /// Artifacts forwarded to the voter in observation cohorts.
    pub(crate) forwarded: Counter,
    /// Artifacts dropped because their lane reached its item or byte bound.
    pub(crate) dropped_lane: Counter,
    /// Artifacts dropped because their peer exceeded its share of the lane.
    pub(crate) dropped_peer: Counter,
    /// Data-availability votes dropped because the sending peer is not the claimed signer.
    pub(crate) dropped_misattributed: Counter,
    /// Observation cohorts the voter's queue rejected.
    pub(crate) dropped_voter_cohorts: Counter,
    /// Network receipt to voter hand-off of one artifact.
    ///
    /// The ingress queue on the round's critical path.
    pub(crate) ingress_dwell: Histogram,
}

impl Metrics {
    pub(crate) fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            decoded: plane_counter(
                context,
                "decoded",
                "decoded canonical ingress messages by network plane",
            ),
            forwarded: context.counter("forwarded", "artifacts forwarded in observation cohorts"),
            dropped_lane: context.counter("dropped_lane", "artifacts dropped by a full lane"),
            dropped_peer: context.counter(
                "dropped_peer",
                "artifacts dropped by a per-lane peer budget",
            ),
            dropped_misattributed: context.counter(
                "dropped_misattributed",
                "data-availability votes dropped because the sender is not the signer",
            ),
            dropped_voter_cohorts: context.counter(
                "dropped_voter_cohorts",
                "observation cohorts rejected by the voter mailbox",
            ),
            ingress_dwell: context.histogram(
                "ingress_dwell",
                "network receipt to voter hand-off of one artifact",
                STAGE_LATENCY,
            ),
        }
    }
}
