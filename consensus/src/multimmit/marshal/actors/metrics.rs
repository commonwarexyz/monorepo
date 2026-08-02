//! Low-cardinality actor metrics for marshal's durable and bounded state.

use crate::multimmit::marshal::{storage::pending::ColdOpen, types::OutputIndex};
use commonware_resolver::Outcome;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{
        Counter, CounterFamily, EncodeLabelSet, EncodeLabelValue, Gauge, GaugeExt as _,
        MetricsExt as _, histogram,
    },
};

/// The protocol obligation that caused marshal to issue an exact network fetch.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(in crate::multimmit::marshal) enum FetchReason {
    Finality,
    FinalizedBody,
    StateSync,
    Explicit,
    CertifiedSubscription,
}

impl FetchReason {
    const ALL: [Self; 5] = [
        Self::Finality,
        Self::FinalizedBody,
        Self::StateSync,
        Self::Explicit,
        Self::CertifiedSubscription,
    ];
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct FetchLabel {
    reason: FetchReason,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReaderSourceLabel {
    source: ColdOpen,
}

/// Cold body reader acquisitions by source.
#[derive(Clone)]
pub(in crate::multimmit::marshal) struct ReaderAcquisitions(CounterFamily<ReaderSourceLabel>);

impl ReaderAcquisitions {
    fn new(context: &impl Metrics) -> Self {
        let family = context.family(
            "reader_acquisitions",
            "Temporary-custody segments opened for body materialization, by source",
        );
        for source in [ColdOpen::Sealed, ColdOpen::Recovered] {
            let _ = family.get_or_create(&ReaderSourceLabel { source });
        }
        Self(family)
    }

    pub(in crate::multimmit::marshal) fn inc(&self, source: ColdOpen) {
        self.0.get_or_create(&ReaderSourceLabel { source }).inc();
    }
}

pub(in crate::multimmit::marshal) struct Catalog {
    pub admissions: Counter,
    pub admission_cut_scheduled_items: Counter,
    pub commits: Counter,
    pub committed_outputs: Counter,
    pub acknowledgements: Counter,
    pub floor_installations: Counter,
    pub body_cache_hits: Counter,
    pub custody_cache_hits: Counter,
    pub custody_storage_hits: Counter,
    pub custody_misses: Counter,
    pub block_cache_evictions: Counter,
    pub materialized_cache_evictions: Counter,
    pub materialized_bodies: Counter,
    pub materialized_body_bytes: Counter,
    pub materialization_groups: Counter,
    pub reader_acquisitions: ReaderAcquisitions,
    pub admission_durability: histogram::Timed,
    pub finalized_archive_durability: histogram::Timed,
    pub checkpoint_publication: histogram::Timed,
    committed_count: Gauge,
    acknowledged_count: Gauge,
    block_cache_items: Gauge,
    block_cache_bytes: Gauge,
    materialized_cache_items: Gauge,
    materialized_cache_bytes: Gauge,
    materialization_active_jobs: Gauge,
    materialization_active_bytes: Gauge,
    materialization_queued_groups: Gauge,
    materialization_waiting_requests: Gauge,
}

/// Work retained by the ordered custody window.
pub(in crate::multimmit::marshal) struct Synchronizer {
    pub windows: Counter,
    pub planned_outputs: Counter,
    pub local_outputs: Counter,
    pub fetched_outputs: Counter,
    pub blocked_prefixes: Counter,
    lookup_pages: Gauge,
    fetches: Gauge,
    ready_outputs: Gauge,
}

impl Synchronizer {
    pub(in crate::multimmit::marshal) fn new(context: &impl Metrics) -> Self {
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

    pub(in crate::multimmit::marshal) fn pressure(
        &self,
        lookup_pages: usize,
        fetches: usize,
        ready_outputs: usize,
    ) {
        let _ = self.lookup_pages.try_set(lookup_pages);
        let _ = self.fetches.try_set(fetches);
        let _ = self.ready_outputs.try_set(ready_outputs);
    }
}

impl Catalog {
    pub(in crate::multimmit::marshal) fn new(context: &impl Metrics) -> Self {
        Self {
            admissions: context.counter(
                "admissions_total",
                "Temporary artifacts admitted to marshal storage",
            ),
            admission_cut_scheduled_items: context.counter(
                "admission_cut_scheduled_items",
                "Admission items scheduled while assembling durability cuts",
            ),
            commits: context.counter(
                "commits_total",
                "Checkpoint-last finalized batches committed",
            ),
            committed_outputs: context.counter(
                "committed_outputs_total",
                "Dense finalized outputs durably committed",
            ),
            acknowledgements: context.counter(
                "acknowledgements_total",
                "Application acknowledgements durably committed",
            ),
            floor_installations: context.counter(
                "floor_installations_total",
                "Verified state-sync floors durably installed",
            ),
            body_cache_hits: context.counter(
                "body_cache_hits",
                "Requested producer bodies served from the catalog cache",
            ),
            custody_cache_hits: context.counter(
                "custody_cache_hits",
                "Finalized custody references served from the live block cache",
            ),
            custody_storage_hits: context.counter(
                "custody_storage_hits",
                "Finalized custody references resolved from local storage",
            ),
            custody_misses: context.counter(
                "custody_misses",
                "Finalized custody references absent from live and durable local custody",
            ),
            block_cache_evictions: context.counter(
                "block_cache_evictions",
                "Live admitted blocks evicted from the catalog cache",
            ),
            materialized_cache_evictions: context.counter(
                "materialized_cache_evictions",
                "Historically materialized blocks evicted from the catalog cache",
            ),
            materialized_bodies: context.counter(
                "materialized_bodies",
                "Requested producer bodies decoded from temporary custody",
            ),
            materialized_body_bytes: context.counter(
                "materialized_body_bytes",
                "Encoded producer body bytes decoded from temporary custody",
            ),
            materialization_groups: context.counter(
                "materialization_groups",
                "Temporary-custody read groups submitted for materialization",
            ),
            reader_acquisitions: ReaderAcquisitions::new(context),
            admission_durability: histogram::Timed::register(
                context,
                "admission_durability_duration",
                "Duration of one coalesced temporary-storage durability cut",
            ),
            finalized_archive_durability: histogram::Timed::register(
                context,
                "finalized_archive_durability_duration",
                "Duration of one finalized archive durability cut",
            ),
            checkpoint_publication: histogram::Timed::register(
                context,
                "checkpoint_publication_duration",
                "Duration of one checkpoint-last publication sync",
            ),
            committed_count: context.gauge(
                "committed_output_count",
                "Number of dense outputs through the durable commit high-water",
            ),
            acknowledged_count: context.gauge(
                "acknowledged_output_count",
                "Number of dense outputs through the durable acknowledgement cursor",
            ),
            block_cache_items: context.gauge(
                "block_cache_items",
                "Live admitted blocks retained by the catalog cache",
            ),
            block_cache_bytes: context.gauge(
                "block_cache_bytes",
                "Encoded bytes retained by the catalog live block cache",
            ),
            materialized_cache_items: context.gauge(
                "materialized_cache_items",
                "Historically materialized blocks retained by the catalog cache",
            ),
            materialized_cache_bytes: context.gauge(
                "materialized_cache_bytes",
                "Encoded bytes retained by the catalog materialized block cache",
            ),
            materialization_active_jobs: context.gauge(
                "materialization_active_jobs",
                "Temporary-custody reader acquisitions and body reads currently executing",
            ),
            materialization_active_bytes: context.gauge(
                "materialization_active_bytes",
                "Encoded bytes charged to executing temporary-custody body reads",
            ),
            materialization_queued_groups: context.gauge(
                "materialization_queued_groups",
                "Temporary-custody body read groups waiting for capacity",
            ),
            materialization_waiting_requests: context.gauge(
                "materialization_waiting_requests",
                "Body requests waiting for capacity or an identical in-flight read",
            ),
        }
    }

    pub(in crate::multimmit::marshal) fn progress(
        &self,
        committed: Option<OutputIndex>,
        acknowledged: Option<OutputIndex>,
    ) {
        let _ = self.committed_count.try_set(count(committed));
        let _ = self.acknowledged_count.try_set(count(acknowledged));
    }

    pub(in crate::multimmit::marshal) fn caches(
        &self,
        live_items: usize,
        live_bytes: usize,
        materialized_items: usize,
        materialized_bytes: usize,
    ) {
        let _ = self
            .block_cache_items
            .try_set(u64::try_from(live_items).unwrap_or(u64::MAX));
        let _ = self
            .block_cache_bytes
            .try_set(u64::try_from(live_bytes).unwrap_or(u64::MAX));
        let _ = self
            .materialized_cache_items
            .try_set(u64::try_from(materialized_items).unwrap_or(u64::MAX));
        let _ = self
            .materialized_cache_bytes
            .try_set(u64::try_from(materialized_bytes).unwrap_or(u64::MAX));
    }

    pub(in crate::multimmit::marshal) fn materialization(
        &self,
        active_jobs: usize,
        active_bytes: u64,
        queued_groups: usize,
        waiting_requests: usize,
    ) {
        let _ = self
            .materialization_active_jobs
            .try_set(u64::try_from(active_jobs).unwrap_or(u64::MAX));
        let _ = self.materialization_active_bytes.try_set(active_bytes);
        let _ = self
            .materialization_queued_groups
            .try_set(u64::try_from(queued_groups).unwrap_or(u64::MAX));
        let _ = self
            .materialization_waiting_requests
            .try_set(u64::try_from(waiting_requests).unwrap_or(u64::MAX));
    }
}

fn count(index: Option<OutputIndex>) -> u64 {
    index.map_or(0, |index| index.get().saturating_add(1))
}

pub(in crate::multimmit::marshal) struct Resolver {
    pending: Gauge,
    requests: CounterFamily<FetchLabel>,
    pub local_rechecks: Counter,
    pub local_recheck_coalesced: Counter,
    pub local_misses: Counter,
    local_rechecks_active: Gauge,
    local_rechecks_queued: Gauge,
    complete: Counter,
    ambiguous: Counter,
    invalid: Counter,
    ignored: Counter,
}

pub(in crate::multimmit::marshal) struct Producer {
    pub coalesced: Counter,
    pub misses: Counter,
    active: Gauge,
    queued: Gauge,
    pending: Gauge,
}

impl Producer {
    pub(in crate::multimmit::marshal) fn new(context: &impl Metrics) -> Self {
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
            pending: context.gauge("pending_callers", "Resolver serve callers awaiting a result"),
        }
    }

    pub(in crate::multimmit::marshal) fn update(
        &self,
        active: usize,
        queued: usize,
        pending: usize,
    ) {
        let _ = self.active.try_set(active);
        let _ = self.queued.try_set(queued);
        let _ = self.pending.try_set(pending);
    }
}

impl Resolver {
    pub(in crate::multimmit::marshal) fn new(context: &impl Metrics) -> Self {
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

    pub(in crate::multimmit::marshal) fn pending(&self, count: usize) {
        let _ = self.pending.try_set(count);
    }

    pub(in crate::multimmit::marshal) fn request(&self, reason: FetchReason) {
        self.requests.get_or_create(&FetchLabel { reason }).inc();
    }

    pub(in crate::multimmit::marshal) fn rechecks(&self, active: usize, queued: usize) {
        let _ = self.local_rechecks_active.try_set(active);
        let _ = self.local_rechecks_queued.try_set(queued);
    }

    pub(in crate::multimmit::marshal) fn outcome(&self, outcome: Outcome) {
        match outcome {
            Outcome::Complete => self.complete.inc(),
            Outcome::Ambiguous => self.ambiguous.inc(),
            Outcome::Invalid => self.invalid.inc(),
            Outcome::Ignored => self.ignored.inc(),
        };
    }
}

pub(in crate::multimmit::marshal) struct Router {
    jobs: Gauge,
    subscriptions: Gauge,
    subscription_callers: Gauge,
}

impl Router {
    pub(in crate::multimmit::marshal) fn new(context: &impl Metrics) -> Self {
        Self {
            jobs: context.gauge("pending_jobs", "Concurrent marshal router jobs"),
            subscriptions: context.gauge(
                "block_subscriptions",
                "Distinct producer blocks with a live subscription",
            ),
            subscription_callers: context.gauge(
                "block_subscription_callers",
                "Callers waiting for a producer-block subscription",
            ),
        }
    }

    pub(in crate::multimmit::marshal) fn update(
        &self,
        jobs: usize,
        subscriptions: usize,
        callers: usize,
    ) {
        let _ = self.jobs.try_set(jobs);
        let _ = self.subscriptions.try_set(subscriptions);
        let _ = self.subscription_callers.try_set(callers);
    }
}

pub(in crate::multimmit::marshal) struct Delivery {
    pub attempts: Counter,
    pub hot_outputs: Counter,
    pub stored_outputs: Counter,
    in_flight: Gauge,
}

pub(in crate::multimmit::marshal) struct Promoter {
    batches: Counter,
    outputs: Counter,
    bytes: Counter,
    hot_bodies: Counter,
    fallback_bodies: Counter,
    promoted_count: Gauge,
}

impl Promoter {
    pub(in crate::multimmit::marshal) fn new(context: &impl Metrics) -> Self {
        Self {
            batches: context.counter(
                "batches_total",
                "Immutable finalized-body batches made durable",
            ),
            outputs: context.counter(
                "outputs_total",
                "Finalized block bodies made durable in immutable storage",
            ),
            bytes: context.counter(
                "bytes_total",
                "Encoded finalized block bytes made durable in immutable storage",
            ),
            hot_bodies: context.counter(
                "hot_bodies_total",
                "Immutable promotions satisfied by post-commit memory",
            ),
            fallback_bodies: context.counter(
                "fallback_bodies_total",
                "Immutable promotions not satisfied by the post-commit handoff",
            ),
            promoted_count: context.gauge(
                "promoted_output_count",
                "Number of dense outputs through the immutable promotion cursor",
            ),
        }
    }

    pub(in crate::multimmit::marshal) fn progress(&self, through: Option<OutputIndex>) {
        let _ = self.promoted_count.try_set(count(through));
    }

    pub(in crate::multimmit::marshal) fn batch(&self, outputs: usize, bytes: u64, hot: usize) {
        self.batches.inc();
        self.outputs
            .inc_by(u64::try_from(outputs).unwrap_or(u64::MAX));
        self.bytes.inc_by(bytes);
        self.hot_bodies
            .inc_by(u64::try_from(hot).unwrap_or(u64::MAX));
        self.fallback_bodies
            .inc_by(u64::try_from(outputs.saturating_sub(hot)).unwrap_or(u64::MAX));
    }
}

impl Delivery {
    pub(in crate::multimmit::marshal) fn new(context: &impl Metrics) -> Self {
        Self {
            attempts: context.counter(
                "attempts_total",
                "Application delivery attempts, including crash redeliveries",
            ),
            hot_outputs: context.counter(
                "hot_outputs",
                "Outputs delivered from post-commit memory without a storage read",
            ),
            stored_outputs: context.counter(
                "stored_outputs",
                "Outputs materialized from storage for application delivery",
            ),
            in_flight: context.gauge(
                "in_flight",
                "Application updates awaiting an Exact acknowledgement",
            ),
        }
    }

    pub(in crate::multimmit::marshal) fn in_flight(&self, count: usize) {
        let _ = self
            .in_flight
            .try_set(u64::try_from(count).unwrap_or(u64::MAX));
    }
}
