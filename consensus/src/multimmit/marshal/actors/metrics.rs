//! Shared metric helpers, and the backfill, serve and synchronizer metrics.

use commonware_resolver::Outcome;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{
        Counter, CounterFamily, EncodeLabelSet, EncodeLabelValue, Gauge, GaugeExt as _,
        MetricsExt as _, histogram,
    },
};

/// Converts a count to a counter increment, saturating at `u64::MAX`.
pub(crate) fn saturating_u64(count: impl TryInto<u64>) -> u64 {
    count.try_into().unwrap_or(u64::MAX)
}

/// The protocol obligation that caused marshal to issue an exact network fetch.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum FetchReason {
    Finality,
    FinalizedBody,
    StateSync,
    Explicit,
    CertifiedSubscription,
    Certified,
}

impl FetchReason {
    const ALL: [Self; 6] = [
        Self::Finality,
        Self::FinalizedBody,
        Self::StateSync,
        Self::Explicit,
        Self::CertifiedSubscription,
        Self::Certified,
    ];
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct FetchLabel {
    reason: FetchReason,
}

/// Work retained by the ordered custody window.
pub(crate) struct Synchronizer {
    pub windows: Counter,
    pub planned_outputs: Counter,
    pub local_outputs: Counter,
    pub fetched_outputs: Counter,
    pub blocked_prefixes: Counter,
    pub final_sweeps: Counter,
    pub emission_halts: Counter,
    pub unsettled_chains: Counter,
    pub emitted_slots: Counter,
    lookup_pages: Gauge,
    fetches: Gauge,
    ready_outputs: Gauge,
}

impl Synchronizer {
    pub(crate) fn new(context: &impl Metrics) -> Self {
        Self {
            windows: context.counter("custody_windows", "Bounded ordered custody windows started"),
            planned_outputs: context.counter(
                "custody_planned_outputs",
                "Finalized outputs scheduled for custody resolution",
            ),
            local_outputs: context.counter(
                "custody_local_outputs",
                "Planned outputs resolved from durable local custody",
            ),
            fetched_outputs: context.counter(
                "custody_fetched_outputs",
                "Planned outputs resolved through exact peer fetches",
            ),
            blocked_prefixes: context.counter(
                "custody_blocked_prefixes",
                "Transitions to ready custody work beyond an unresolved prefix",
            ),
            final_sweeps: context.counter(
                "final_sweeps",
                "Emission sweeps started from finality facts at the finalized floor",
            ),
            emission_halts: context.counter(
                "emission_halts",
                "Final sweeps cut short by an unsettled chain, deferring later slots to a following view",
            ),
            unsettled_chains: context.counter(
                "unsettled_chains",
                "Chains reported unsettled by the finality facts behind final sweeps",
            ),
            emitted_slots: context.counter(
                "emitted_slots",
                "Ordered slots planned by final sweeps",
            ),
            lookup_pages: context.gauge(
                "custody_lookup_pages",
                "Local custody lookup pages currently in flight",
            ),
            fetches: context.gauge(
                "custody_fetches",
                "Exact finalized-body fetches currently in flight",
            ),
            ready_outputs: context.gauge(
                "custody_ready_outputs",
                "Resolved outputs waiting for ordered publication",
            ),
        }
    }

    pub(crate) fn pressure(&self, lookup_pages: usize, fetches: usize, ready_outputs: usize) {
        let _ = self.lookup_pages.try_set(lookup_pages);
        let _ = self.fetches.try_set(fetches);
        let _ = self.ready_outputs.try_set(ready_outputs);
    }
}

pub(crate) struct Backfill {
    pending: Gauge,
    requests: CounterFamily<FetchLabel>,
    pub local_rechecks: Counter,
    pub local_recheck_coalesced: Counter,
    pub local_misses: Counter,
    local_rechecks_active: Gauge,
    local_rechecks_queued: Gauge,
    staging_active: Gauge,
    staging_active_bytes: Gauge,
    staging_queued: Gauge,
    staging_queued_bytes: Gauge,
    pub staging_latency: histogram::Timed,
    range_requests: Counter,
    range_requested_blocks: Counter,
    range_received_blocks: Counter,
    range_short_responses: Counter,
    complete: Counter,
    ambiguous: Counter,
    invalid: Counter,
    ignored: Counter,
}

pub(crate) struct Serve {
    pub coalesced: Counter,
    pub misses: Counter,
    active: Gauge,
    queued: Gauge,
    pending: Gauge,
}

impl Serve {
    pub(crate) fn new(context: &impl Metrics) -> Self {
        Self {
            coalesced: context.counter(
                "coalesced_total",
                "Resolver serve callers sharing an exact-key lookup",
            ),
            misses: context.counter(
                "misses_total",
                "Resolver serve lookups completed without the requested artifact",
            ),
            active: context.gauge("active_keys", "Resolver keys being served concurrently"),
            queued: context.gauge("queued_keys", "Resolver keys waiting for serve capacity"),
            pending: context.gauge(
                "pending_callers",
                "Resolver serve callers awaiting a result",
            ),
        }
    }

    pub(crate) fn update(&self, active: usize, queued: usize, pending: usize) {
        let _ = self.active.try_set(active);
        let _ = self.queued.try_set(queued);
        let _ = self.pending.try_set(pending);
    }
}

impl Backfill {
    pub(crate) fn new(context: &impl Metrics) -> Self {
        let requests = context.family(
            "requests_started",
            "Exact network fetches started by protocol obligation",
        );
        for reason in FetchReason::ALL {
            let _ = requests.get_or_create(&FetchLabel { reason });
        }
        Self {
            pending: context.gauge(
                "pending_requests",
                "Exact resolver requests retained by marshal",
            ),
            requests,
            local_rechecks: context.counter(
                "local_rechecks",
                "Exact-key local artifact lookups started before peer fetch",
            ),
            local_recheck_coalesced: context.counter(
                "local_recheck_coalesced",
                "Resolver waiters sharing an exact-key local artifact lookup",
            ),
            local_misses: context.counter(
                "local_misses",
                "Exact-key local artifact lookups completed without the artifact",
            ),
            local_rechecks_active: context.gauge(
                "local_rechecks_active",
                "Distinct exact-key local artifact lookups in progress",
            ),
            local_rechecks_queued: context.gauge(
                "local_rechecks_queued",
                "Distinct exact-key local artifact lookups waiting for capacity",
            ),
            staging_active: context.gauge(
                "staging_active",
                "Validated producer-block batches submitted for catalog admission",
            ),
            staging_active_bytes: context.gauge(
                "staging_active_bytes",
                "Encoded producer-block bytes submitted for catalog admission",
            ),
            staging_queued: context.gauge(
                "staging_queued",
                "Validated producer-block batches waiting for staging capacity",
            ),
            staging_queued_bytes: context.gauge(
                "staging_queued_bytes",
                "Encoded producer-block bytes waiting for staging capacity",
            ),
            staging_latency: histogram::Timed::register(
                context,
                "staging_duration",
                "Time spent in active catalog staging through admission acceptance",
            ),
            range_requests: context.counter(
                "range_requests",
                "Finalized producer-block range fetches submitted to peers",
            ),
            range_requested_blocks: context.counter(
                "range_requested_blocks",
                "Producer blocks requested through finalized range fetches",
            ),
            range_received_blocks: context.counter(
                "range_received_blocks",
                "Producer blocks accepted from finalized range responses",
            ),
            range_short_responses: context.counter(
                "range_short_responses",
                "Valid finalized range responses shorter than their requested bound",
            ),
            complete: context.counter("complete_total", "Resolver deliveries accepted as complete"),
            ambiguous: context.counter(
                "ambiguous_total",
                "Valid resolver deliveries that did not satisfy every subscriber",
            ),
            invalid: context.counter("invalid_total", "Invalid resolver deliveries rejected"),
            ignored: context.counter(
                "ignored_total",
                "Resolver deliveries with no active current-generation subscriber",
            ),
        }
    }

    pub(crate) fn pending(&self, count: usize) {
        let _ = self.pending.try_set(count);
    }

    pub(crate) fn request(&self, reason: FetchReason) {
        self.requests.get_or_create(&FetchLabel { reason }).inc();
    }

    pub(crate) fn rechecks(&self, active: usize, queued: usize) {
        let _ = self.local_rechecks_active.try_set(active);
        let _ = self.local_rechecks_queued.try_set(queued);
    }

    pub(crate) fn staging(
        &self,
        active: usize,
        active_bytes: u64,
        queued: usize,
        queued_bytes: u64,
    ) {
        let _ = self.staging_active.try_set(active);
        let _ = self.staging_active_bytes.try_set(active_bytes);
        let _ = self.staging_queued.try_set(queued);
        let _ = self.staging_queued_bytes.try_set(queued_bytes);
    }

    pub(crate) fn range_requested(&self, blocks: usize) {
        self.range_requests.inc();
        self.range_requested_blocks
            .inc_by(u64::try_from(blocks).unwrap_or(u64::MAX));
    }

    pub(crate) fn range_received(&self, requested: usize, received: usize) {
        self.range_received_blocks
            .inc_by(u64::try_from(received).unwrap_or(u64::MAX));
        if received < requested {
            self.range_short_responses.inc();
        }
    }

    pub(crate) fn outcome(&self, outcome: Outcome) {
        match outcome {
            Outcome::Complete => self.complete.inc(),
            Outcome::Ambiguous => self.ambiguous.inc(),
            Outcome::Invalid => self.invalid.inc(),
            Outcome::Ignored => self.ignored.inc(),
        };
    }
}
