use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{
        Counter, CounterFamily, EncodeLabelValue, EncodeStruct, Gauge, Histogram, MetricsExt as _,
        raw,
    },
};
use std::{fmt, sync::Arc};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub(super) struct Lane {
    pub lane: usize,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(super) enum StopReason {
    Shutdown,
    Actor,
    Read,
    Write,
    Worker,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::Shutdown => "shutdown",
            Self::Actor => "actor",
            Self::Read => "read",
            Self::Write => "write",
            Self::Worker => "worker",
        };
        f.write_str(reason)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub(super) struct Stop {
    pub reason: StopReason,
}

#[derive(Clone)]
pub(super) struct Metrics {
    pub inflight_reads: Gauge,
    pub read_workers: Gauge,
    pub reads: Counter,
    pub read_failures: Counter,
    pub writes: Counter,
    pub write_failures: Counter,
    pub read_capacity_waits: Counter,
    pub read_worker_stops: Counter,
    pub stops: CounterFamily<Stop>,
    pub lane_batch_size: Histogram,
    /// Per-lane counter handles resolved at construction.
    ///
    /// Family lookups take a lock and hash the label set, so the hot path
    /// indexes this slice instead. The family is kept alive alongside the
    /// handles so the metric stays registered.
    lane_messages: Arc<[raw::Counter]>,
    _lane_messages_family: CounterFamily<Lane>,
}

impl Metrics {
    pub fn init(context: &impl RuntimeMetrics, lanes: usize) -> Self {
        let lane_messages_family: CounterFamily<Lane> =
            context.family("lane_messages", "Number of messages selected by lane");
        let lane_messages = (0..lanes)
            .map(|lane| lane_messages_family.get_or_create(&Lane { lane }).clone())
            .collect();
        Self {
            inflight_reads: context.gauge("inflight_reads", "Number of active read-only handlers"),
            read_workers: context.gauge("read_workers", "Number of provisioned read workers"),
            reads: context.counter("reads", "Number of read-only handlers completed"),
            read_failures: context.counter("read_failures", "Number of failed read-only handlers"),
            writes: context.counter("writes", "Number of read-write handlers completed"),
            write_failures: context
                .counter("write_failures", "Number of failed read-write handlers"),
            read_capacity_waits: context.counter(
                "read_capacity_waits",
                "Number of times the service waited for read capacity",
            ),
            read_worker_stops: context.counter(
                "read_worker_stops",
                "Number of read workers that stopped unexpectedly",
            ),
            lane_messages,
            stops: context.family("stops", "Number of service stops by reason"),
            lane_batch_size: context.histogram(
                "lane_batch_size",
                "Number of lane messages processed in one service-loop iteration",
                [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0],
            ),
            _lane_messages_family: lane_messages_family,
        }
    }

    pub fn set_read_workers(&self, workers: usize) {
        self.read_workers.set(workers as _);
    }

    pub fn set_inflight_reads(&self, reads: usize) {
        self.inflight_reads.set(reads as _);
    }

    pub fn record_lane_message(&self, lane: usize) {
        self.lane_messages[lane].inc();
    }

    pub fn record_stop(&self, reason: StopReason) {
        self.stops.get_or_create(&Stop { reason }).inc();
    }

    pub fn observe_lane_batch(&self, size: usize) {
        self.lane_batch_size.observe(size as f64);
    }
}
