use commonware_consensus::{marshal::Start, simplex::types::Finalization};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_runtime::{Clock, Metrics, Storage};

/// Startup plan that determines whether one-time peer state sync may still run.
///
/// Construction is two-phase so the caller can avoid fetching a finalized
/// floor from peers when state sync has already completed:
///
/// 1. [`SyncPlan::init`] reads the durable state-sync flag.
/// 2. If [`SyncPlan::may_state_sync`] returns `true`, the caller fetches a
///    finalized floor and attaches it via [`SyncPlan::with_floor`]. Otherwise
///    the caller skips floor selection entirely.
///
/// Once the durable flag has been set, this node never performs peer state
/// sync again. Future startups must recover by aligning databases with
/// marshal's processed height instead.
pub struct SyncPlan<F> {
    partition_prefix: String,
    state_sync_complete: bool,
    floor: Option<F>,
}

impl<F> SyncPlan<F> {
    /// Load the durable state-sync completion flag for this partition prefix.
    ///
    /// # Panics
    ///
    /// Panics if the metadata store cannot be opened. A node that cannot
    /// determine whether state sync already completed cannot safely choose a
    /// startup path.
    pub async fn init<E>(context: &E, partition_prefix: impl AsRef<str>) -> Self
    where
        E: Clock + Metrics + Storage,
    {
        let state_sync_complete = super::sync_complete(context, partition_prefix.as_ref()).await;
        Self {
            partition_prefix: partition_prefix.as_ref().into(),
            state_sync_complete,
            floor: None,
        }
    }

    /// Returns whether state sync can still run on this node.
    ///
    /// When `false`, the caller should skip floor selection: any floor passed
    /// to [`SyncPlan::with_floor`] would be ignored. The node has already
    /// completed its one-time startup sync, so future boots must recover from
    /// marshal's processed height instead of running peer state sync again.
    ///
    /// When `true`, the caller can optionally attach a finalized floor via
    /// [`SyncPlan::with_floor`]. If a floor is not attached, the node will
    /// attempt to sync from genesis via marshal.
    pub const fn may_state_sync(&self) -> bool {
        !self.state_sync_complete
    }

    /// Returns the partition prefix to use for state sync metadata storage.
    pub const fn partition_prefix(&self) -> &str {
        self.partition_prefix.as_str()
    }

    /// Returns a reference to the finalized floor attached to this plan, if any.
    pub const fn floor(&self) -> Option<&F> {
        self.floor.as_ref()
    }

    /// Attach a finalized floor to state sync from.
    ///
    /// Has no effect if state sync has already completed.
    #[must_use]
    pub fn with_floor(mut self, floor: F) -> Self {
        if self.may_state_sync() {
            self.floor = Some(floor);
        }
        self
    }
}

impl<S, C> SyncPlan<Finalization<S, C>>
where
    S: Scheme,
    C: Digest,
{
    /// Returns marshal's startup anchor for this plan.
    ///
    /// If a finalized floor was attached, marshal starts from that floor.
    /// Otherwise marshal starts from genesis and relies on its own durable
    /// progress to override that anchor when available.
    pub fn marshal_start<B>(&self, genesis: B) -> Start<S, C, B> {
        self.floor
            .clone()
            .map_or_else(|| Start::Genesis(genesis), Start::Floor)
    }
}
