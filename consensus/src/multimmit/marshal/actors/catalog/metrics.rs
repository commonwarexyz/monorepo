//! Catalog metrics.

use crate::multimmit::marshal::{actors::metrics::saturating_u64, types::OutputIndex};
use commonware_runtime::{
    Clock, Metrics as RuntimeMetrics,
    telemetry::metrics::{
        Counter, CounterFamily, EncodeLabelSet, EncodeLabelValueTrait, Gauge, GaugeExt as _,
        Histogram, HistogramExt as _, LabelValueEncoder, MetricsExt as _, histogram,
    },
};
use std::{
    fmt::{self, Write as _},
    time::{Duration, SystemTime},
};

/// Buckets for catalog intake stalls, in seconds.
///
/// Intake waits span sub-millisecond mailbox handoffs through multi-second head-of-line
/// blocking behind barrier commands, so the range is wider than [`histogram::Buckets::LOCAL`].
const STALL: [f64; 14] = [
    0.0005, 0.001, 0.003, 0.01, 0.03, 0.06, 0.1, 0.15, 0.2, 0.3, 0.5, 1.0, 2.0, 5.0,
];

/// What started a catalog owner turn.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum Source {
    /// A command or independent read.
    Command,
    /// A background completion.
    Completion,
    /// Waiting for the next event.
    Wait,
    /// Work the catalog starts on its own.
    Internal,
}

impl Source {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Completion => "completion",
            Self::Wait => "wait",
            Self::Internal => "internal",
        }
    }
}

impl EncodeLabelValueTrait for Source {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> Result<(), fmt::Error> {
        encoder.write_str(self.as_str())
    }
}

/// The operation of a catalog owner turn: a request kind or a fixed internal event.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum Operation {
    Admit,
    Lqc,
    FinalLqc,
    LatestLqc,
    History,
    HistorySegment,
    WaitForCustody,
    Bodies,
    BodyCandidate,
    HeaderSegments,
    OutputRefs,
    Commit,
    Install,
    Prune,
    Promoted,
    Checkpoint,
    Progress,
    /// A finished admission cut.
    Admission,
    /// A commit's finalized archives became durable.
    CommitArchives,
    /// Delivery's durable cursor moved.
    DeliveryCursor,
    /// A body read finished.
    Materialization,
    /// Full pending segments finished retiring.
    Retire,
    /// Starting the waiting admission cut.
    AdmissionStart,
    /// Waiting with no parked command.
    Event,
}

impl Operation {
    /// Returns the stable label of the operation, also recorded on spans.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Lqc => "lqc",
            Self::FinalLqc => "final_lqc",
            Self::LatestLqc => "latest_lqc",
            Self::History => "history",
            Self::HistorySegment => "history_segment",
            Self::WaitForCustody => "wait_for_custody",
            Self::Bodies => "bodies",
            Self::BodyCandidate => "body_candidate_by_digest",
            Self::HeaderSegments => "header_segments",
            Self::OutputRefs => "output_refs",
            Self::Commit => "commit",
            Self::Install => "install",
            Self::Prune => "prune",
            Self::Promoted => "promoted",
            Self::Checkpoint => "checkpoint",
            Self::Progress => "progress",
            Self::Admission => "admission",
            Self::CommitArchives => "commit_archives",
            Self::DeliveryCursor => "delivery_cursor",
            Self::Materialization => "materialization",
            Self::Retire => "retire",
            Self::AdmissionStart => "admission_start",
            Self::Event => "event",
        }
    }
}

impl EncodeLabelValueTrait for Operation {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> Result<(), fmt::Error> {
        encoder.write_str(self.as_str())
    }
}

/// What made a waiting admission cut ripe.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum CutTrigger {
    /// A caller waits for durability.
    Reply,
    /// The cut holds more admissions than an eager cut.
    Items,
    /// The catalog had nothing else to do.
    Eager,
}

impl EncodeLabelValueTrait for CutTrigger {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> Result<(), fmt::Error> {
        encoder.write_str(match self {
            Self::Reply => "reply",
            Self::Items => "items",
            Self::Eager => "eager",
        })
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CutTriggerLabel {
    trigger: CutTrigger,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct WorkLabel {
    source: Source,
    operation: Operation,
}

/// The start of one catalog owner turn, recorded by [`Metrics::finish`].
#[must_use = "a work timer records nothing until finished"]
pub(super) struct WorkTimer {
    label: WorkLabel,
    started: SystemTime,
}

/// Catalog progress, caches and owner-turn accounting.
pub(super) struct Metrics {
    admissions: Counter,
    admission_cut_scheduled_items: Counter,
    commits: Counter,
    committed_outputs: Counter,
    floor_installations: Counter,
    body_cache_hits: Counter,
    custody_cache_hits: Counter,
    custody_storage_hits: Counter,
    custody_misses: Counter,
    block_cache_evictions: Counter,
    materialized_cache_evictions: Counter,
    materialized_bodies: Counter,
    materialized_body_bytes: Counter,
    materialization_groups: Counter,
    reader_acquisitions: Counter,
    admission_durability: histogram::Timed,
    finalized_archive_durability: histogram::Timed,
    checkpoint_publication: histogram::Timed,
    /// Time an admission command waits between mailbox enqueue and catalog intake.
    admission_command_dwell: Histogram,
    work_nanoseconds: CounterFamily<WorkLabel>,
    work_calls: CounterFamily<WorkLabel>,
    cut_triggers: CounterFamily<CutTriggerLabel>,
    committed_count: Gauge,
    block_cache_items: Gauge,
    block_cache_bytes: Gauge,
    materialized_cache_items: Gauge,
    materialized_cache_bytes: Gauge,
    materialization_active_jobs: Gauge,
    materialization_active_bytes: Gauge,
    materialization_queued_groups: Gauge,
    materialization_waiting_requests: Gauge,
}

impl Metrics {
    pub(super) fn new(context: &impl RuntimeMetrics) -> Self {
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
            reader_acquisitions: context.counter(
                "reader_acquisitions",
                "Temporary-custody segments opened for body materialization",
            ),
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
            admission_command_dwell: context.histogram(
                "admission_command_dwell_duration",
                "Time an admission command waits between mailbox enqueue and catalog intake",
                STALL,
            ),
            work_nanoseconds: context.family(
                "work_nanoseconds",
                "Catalog owner wall time by fixed source and operation, including inline waits but excluding independent background work",
            ),
            work_calls: context.family(
                "work_calls",
                "Catalog owner turns by fixed source and operation",
            ),
            cut_triggers: context.family(
                "admission_cut_triggers",
                "Admission cuts started, by what made the pending cut ripe",
            ),
            committed_count: context.gauge(
                "committed_output_count",
                "Number of dense outputs through the durable commit high-water",
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

    /// Publishes the durable commit high-water.
    pub(super) fn progress(&self, committed: Option<OutputIndex>) {
        let _ = self.committed_count.try_set(OutputIndex::count(committed));
    }

    /// Starts timing one owner turn, including its inline waits.
    pub(super) fn time(
        &self,
        source: Source,
        operation: Operation,
        clock: &impl Clock,
    ) -> WorkTimer {
        WorkTimer {
            label: WorkLabel { source, operation },
            started: clock.current(),
        }
    }

    /// Records the turn `timer` started and returns its duration.
    pub(super) fn finish(&self, timer: WorkTimer, clock: &impl Clock) -> Duration {
        let elapsed = clock
            .current()
            .duration_since(timer.started)
            .unwrap_or_default();
        self.work_nanoseconds
            .get_or_create(&timer.label)
            .inc_by(saturating_u64(elapsed.as_nanos()));
        self.work_calls.get_or_create(&timer.label).inc();
        elapsed
    }

    /// Records an admission command's wait between enqueue and intake.
    pub(super) fn admission_dwell(&self, enqueued: SystemTime, clock: &impl Clock) {
        self.admission_command_dwell
            .observe_between(enqueued, clock.current());
    }

    /// Counts admissions buffered into pending storage.
    pub(super) fn admitted(&self, admissions: usize) {
        self.admissions.inc_by(saturating_u64(admissions));
    }

    /// Counts the admissions of a starting cut and what made it ripe.
    pub(super) fn cut_started(&self, trigger: CutTrigger, items: usize) {
        self.cut_triggers
            .get_or_create(&CutTriggerLabel { trigger })
            .inc();
        self.admission_cut_scheduled_items
            .inc_by(saturating_u64(items));
    }

    /// Starts timing one admission cut's durability.
    pub(super) fn admission_durability_timer(&self, clock: &impl Clock) -> histogram::Timer {
        self.admission_durability.timer(clock)
    }

    /// Starts timing one commit's finalized-archive durability.
    pub(super) fn archive_durability_timer(&self, clock: &impl Clock) -> histogram::Timer {
        self.finalized_archive_durability.timer(clock)
    }

    /// Starts timing one checkpoint publication.
    pub(super) fn publication_timer(&self, clock: &impl Clock) -> histogram::Timer {
        self.checkpoint_publication.timer(clock)
    }

    /// Counts one published commit and its outputs.
    pub(super) fn committed(&self, outputs: usize) {
        self.commits.inc();
        self.committed_outputs.inc_by(saturating_u64(outputs));
    }

    /// Counts one installed floor.
    pub(super) fn floor_installed(&self) {
        self.floor_installations.inc();
    }

    /// Counts where one custody request's references resolved.
    pub(super) fn custody_lookup(&self, cache_hits: u64, storage_hits: u64, misses: u64) {
        self.custody_cache_hits.inc_by(cache_hits);
        self.custody_storage_hits.inc_by(storage_hits);
        self.custody_misses.inc_by(misses);
    }

    /// Counts bodies served from the caches.
    pub(super) fn body_cache_hits(&self, hits: u64) {
        self.body_cache_hits.inc_by(hits);
    }

    /// Counts bodies evicted from the live cache.
    pub(super) fn live_evicted(&self, evictions: u64) {
        self.block_cache_evictions.inc_by(evictions);
    }

    /// Counts bodies evicted from the materialized cache.
    pub(super) fn materialized_evicted(&self, evictions: u64) {
        self.materialized_cache_evictions.inc_by(evictions);
    }

    /// Counts read groups submitted for materialization.
    pub(super) fn materialization_groups(&self, groups: usize) {
        self.materialization_groups.inc_by(saturating_u64(groups));
    }

    /// Counts bodies decoded from pending custody.
    pub(super) fn materialized(&self, bodies: usize) {
        self.materialized_bodies.inc_by(saturating_u64(bodies));
    }

    /// Returns the counter of pending segments opened for body reads.
    pub(super) fn reader_acquisitions(&self) -> Counter {
        self.reader_acquisitions.clone()
    }

    /// Returns the counter of encoded bytes read back from pending custody.
    pub(super) fn materialized_body_bytes(&self) -> Counter {
        self.materialized_body_bytes.clone()
    }

    /// Publishes the size of both body caches.
    pub(super) fn caches(
        &self,
        live_items: usize,
        live_bytes: usize,
        materialized_items: usize,
        materialized_bytes: usize,
    ) {
        let _ = self.block_cache_items.try_set(live_items);
        let _ = self.block_cache_bytes.try_set(live_bytes);
        let _ = self.materialized_cache_items.try_set(materialized_items);
        let _ = self.materialized_cache_bytes.try_set(materialized_bytes);
    }

    /// Publishes body-read pressure.
    pub(super) fn materialization(
        &self,
        active_jobs: usize,
        active_bytes: u64,
        queued_groups: usize,
        waiting_requests: usize,
    ) {
        let _ = self.materialization_active_jobs.try_set(active_jobs);
        let _ = self.materialization_active_bytes.try_set(active_bytes);
        let _ = self.materialization_queued_groups.try_set(queued_groups);
        let _ = self
            .materialization_waiting_requests
            .try_set(waiting_requests);
    }
}
