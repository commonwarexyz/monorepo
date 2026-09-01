//! Metrics exported by the persistence actor.

use crate::multimmit::actors::metrics::{COUNT_POW2_FROM_ONE, STAGE_LATENCY};
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, Histogram, MetricsExt as _, histogram},
};
use std::time::Duration;

/// Journal throughput, prefix depth, and durability latency.
#[derive(Clone)]
pub(super) struct Metrics {
    pub(super) appended_barriers: Counter,
    pub(super) appended_events: Counter,
    pub(super) appended_bytes: Counter,
    pub(super) start_syncs: Counter,
    pub(super) durable_barriers: Counter,
    pub(super) prefix_depth: Histogram,
    pub(super) barrier_latency: Histogram,
    pub(super) urgent_tail_latency: Histogram,
    pub(super) pending_barriers: Gauge,
    pub(super) pending_bytes: Gauge,
    pub(super) covered_barriers: Gauge,
    pub(super) uncovered_barriers: Gauge,
    pub(super) uncovered_bytes: Gauge,
    pub(super) sync_in_flight: Gauge,
    pub(super) max_prefix_depth: Gauge,
    pub(super) max_unsynced_bytes: Gauge,
    pub(super) max_unsynced_age_milliseconds: Gauge,
}

impl Metrics {
    pub(super) fn new<E: RuntimeMetrics>(context: &E) -> Self {
        Self {
            appended_barriers: context.counter(
                "appended_barriers",
                "barriers appended to the voter safety journal",
            ),
            appended_events: context.counter(
                "appended_events",
                "events appended to the voter safety journal",
            ),
            appended_bytes: context.counter(
                "appended_bytes",
                "canonical bytes appended to the voter safety journal",
            ),
            start_syncs: context.counter(
                "start_syncs",
                "prefix-covering safety journal syncs started",
            ),
            durable_barriers: context.counter(
                "durable_barriers",
                "barriers acknowledged from durable safety journal prefixes",
            ),
            prefix_depth: context.histogram(
                "prefix_depth",
                "barriers covered by one safety journal prefix sync",
                COUNT_POW2_FROM_ONE,
            ),
            barrier_latency: context.histogram(
                "barrier_latency",
                "time from safety journal append to durable acknowledgement",
                STAGE_LATENCY,
            ),
            // This measures local storage contention before signature publication, so it uses
            // the local latency range.
            urgent_tail_latency: context.histogram(
                "urgent_tail_latency",
                "time from urgent tail append to its prefix sync start",
                histogram::Buckets::LOCAL,
            ),
            pending_barriers: context.gauge(
                "pending_barriers",
                "appended barriers awaiting durable acknowledgement",
            ),
            pending_bytes: context.gauge(
                "pending_bytes",
                "canonical appended bytes awaiting durable acknowledgement",
            ),
            covered_barriers: context.gauge(
                "covered_barriers",
                "barriers covered by the in-flight prefix sync",
            ),
            uncovered_barriers: context.gauge(
                "uncovered_barriers",
                "appended barriers not covered by the in-flight prefix sync",
            ),
            uncovered_bytes: context.gauge(
                "uncovered_bytes",
                "canonical appended bytes not covered by the in-flight prefix sync",
            ),
            sync_in_flight: context.gauge(
                "sync_in_flight",
                "whether one prefix-covering safety journal sync is in flight",
            ),
            max_prefix_depth: context.gauge(
                "max_prefix_depth",
                "maximum barriers covered by one safety journal prefix sync",
            ),
            max_unsynced_bytes: context.gauge(
                "max_unsynced_bytes",
                "maximum canonical bytes captured from one unsynced prefix",
            ),
            max_unsynced_age_milliseconds: context.gauge(
                "max_unsynced_age_milliseconds",
                "maximum age in milliseconds of the oldest barrier when its prefix sync starts",
            ),
        }
    }

    pub(super) fn observe_prefix(&self, depth: usize, bytes: usize, age: Duration) {
        self.prefix_depth.observe(depth as f64);
        set_max(&self.max_prefix_depth, depth);
        set_max(&self.max_unsynced_bytes, bytes);
        set_max(
            &self.max_unsynced_age_milliseconds,
            usize::try_from(age.as_millis()).unwrap_or(usize::MAX),
        );
    }

    pub(super) fn update_depths(
        &self,
        pending_barriers: usize,
        pending_bytes: usize,
        covered_barriers: usize,
        covered_bytes: usize,
    ) {
        let _ = self.pending_barriers.try_set(pending_barriers);
        let _ = self.pending_bytes.try_set(pending_bytes);
        let _ = self.covered_barriers.try_set(covered_barriers);
        let _ = self
            .uncovered_barriers
            .try_set(pending_barriers.saturating_sub(covered_barriers));
        let _ = self
            .uncovered_bytes
            .try_set(pending_bytes.saturating_sub(covered_bytes));
    }
}

fn set_max(metric: &Gauge, value: usize) {
    let value = i64::try_from(value).unwrap_or(i64::MAX);
    if value > metric.get() {
        metric.set(value);
    }
}
