//! Metrics for state sync progress.

use commonware_runtime::{telemetry::metrics::status::GaugeExt, Metrics as MetricsTrait};
use commonware_storage::qmdb::sync::SyncProgress;
use commonware_utils::channel::mpsc;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
};
use std::future::Future;

/// Label identifying a database by its index in the set.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(super) struct DbLabel {
    pub db: String,
}

impl DbLabel {
    pub fn new(idx: usize) -> Self {
        Self {
            db: idx.to_string(),
        }
    }
}

/// Per-database sync progress gauges.
#[derive(Clone)]
pub(super) struct SyncMetrics {
    /// Current journal size (operations applied) per database.
    pub journal_size: Family<DbLabel, Gauge>,
    /// Target range end (operations needed) per database.
    pub target_end: Family<DbLabel, Gauge>,
    /// Block height whose targets each database is syncing towards.
    pub target_height: Family<DbLabel, Gauge>,
}

impl SyncMetrics {
    /// Register sync metrics on the provided context.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let journal_size = Family::<DbLabel, Gauge>::default();
        context.register(
            "sync_journal_size",
            "Current journal size (operations applied) per database",
            journal_size.clone(),
        );

        let target_end = Family::<DbLabel, Gauge>::default();
        context.register(
            "sync_target_end",
            "Target range end (operations needed) per database",
            target_end.clone(),
        );

        let target_height = Family::<DbLabel, Gauge>::default();
        context.register(
            "sync_target_height",
            "Block height whose targets each database is syncing towards",
            target_height.clone(),
        );

        Self {
            journal_size,
            target_end,
            target_height,
        }
    }

    /// Update progress gauges from an engine snapshot.
    pub fn record_progress(&self, idx: usize, progress: &SyncProgress) {
        let label = DbLabel::new(idx);
        let _ = self
            .journal_size
            .get_or_create(&label)
            .try_set(progress.journal_size);
        let _ = self
            .target_end
            .get_or_create(&label)
            .try_set(progress.target_end);
    }

    /// Update the target block height for a database.
    pub fn record_target_height(&self, idx: usize, height: u64) {
        let label = DbLabel::new(idx);
        let _ = self.target_height.get_or_create(&label).try_set(height);
    }
}

/// Create a progress channel and return (sender, drain_future).
///
/// The drain future reads progress snapshots and updates the gauges.
/// It completes when the sender is dropped (sync finished).
pub(super) fn progress_channel(
    metrics: SyncMetrics,
    idx: usize,
) -> (mpsc::Sender<SyncProgress>, impl Future<Output = ()>) {
    let (tx, mut rx) = mpsc::channel(1);
    let drain = async move {
        while let Some(progress) = rx.recv().await {
            metrics.record_progress(idx, &progress);
        }
    };
    (tx, drain)
}
