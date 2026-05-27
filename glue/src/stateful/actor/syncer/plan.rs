use super::StartupSyncState;
use commonware_consensus::{
    marshal::{core::Variant, Start},
    simplex::types::Finalization,
    types::Height,
};
use commonware_cryptography::certificate::Scheme;
use commonware_runtime::{Clock, Metrics, Storage};

/// Startup plan that determines whether one-time peer state sync may still run.
///
/// Construction is two-phase so the caller can avoid fetching a finalized
/// floor from peers when startup sync has already completed:
///
/// 1. [`SyncPlan::init`] reads the durable startup-sync state.
/// 2. If [`SyncPlan::may_state_sync`] returns `true`, the caller fetches a
///    finalized floor and attaches it via [`SyncPlan::with_floor`]. Otherwise
///    the caller skips floor selection entirely.
///
/// Once startup sync completes, this node never performs peer state sync
/// again. Future startups must recover from the later of that synced height
/// and marshal's processed height instead.
pub struct SyncPlan<S, V>
where
    S: Scheme,
    V: Variant,
{
    partition_prefix: String,
    startup_sync_state: Option<StartupSyncState<V::Commitment>>,
    floor: Option<Finalization<S, V::Commitment>>,
}

impl<S, V> SyncPlan<S, V>
where
    S: Scheme,
    V: Variant,
{
    /// Load the durable startup-sync state for this partition prefix.
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
        let startup_sync_state =
            super::startup_sync_state::<E, V::Commitment>(context, partition_prefix.as_ref()).await;
        Self {
            partition_prefix: partition_prefix.as_ref().into(),
            startup_sync_state,
            floor: None,
        }
    }

    /// Returns whether state sync can still run on this node.
    ///
    /// When `false`, the caller should skip floor selection: any floor passed
    /// to [`SyncPlan::with_floor`] would be ignored. The node already has a
    /// durable completed startup-sync height, so future boots must recover from that
    /// height or marshal's processed height instead of running peer state sync again.
    ///
    /// When `true`, the caller can optionally attach a finalized floor via
    /// [`SyncPlan::with_floor`]. If a floor is not attached, the node will
    /// attempt to sync from genesis via marshal unless it is resuming an
    /// interrupted startup sync.
    pub const fn may_state_sync(&self) -> bool {
        !matches!(self.startup_sync_state, Some(StartupSyncState::Complete(_)))
    }

    /// Returns the durable completed startup-sync height, if one has been stored.
    pub fn sync_height(&self) -> Option<Height> {
        self.startup_sync_state
            .as_ref()
            .map(StartupSyncState::sync_height)
            .unwrap_or_default()
    }

    /// Returns the partition prefix to use for state sync metadata storage.
    pub const fn partition_prefix(&self) -> &str {
        self.partition_prefix.as_str()
    }

    /// Returns a reference to the finalized floor attached to this plan, if any.
    pub const fn floor(&self) -> Option<&Finalization<S, V::Commitment>> {
        self.floor.as_ref()
    }

    /// Attach a finalized floor to state sync from.
    ///
    /// Has no effect if state sync has already completed.
    #[must_use]
    pub fn with_floor(mut self, floor: Finalization<S, V::Commitment>) -> Self {
        if !self.may_state_sync() {
            return self;
        }

        self.floor = Some(floor);
        self
    }

    /// Returns marshal's startup anchor for this plan.
    ///
    /// If a finalized floor was attached, marshal starts from that floor.
    /// Otherwise marshal starts from genesis and relies on its own durable
    /// progress to override that anchor when available.
    pub fn marshal_start<B>(&self, genesis: B) -> Start<S, V::Commitment, B> {
        self.floor
            .clone()
            .map_or_else(|| Start::Genesis(genesis), Start::Floor)
    }

    /// Returns whether restart is blocked on selecting a new startup-sync floor.
    pub(crate) const fn requires_state_sync_floor(&self) -> bool {
        matches!(
            self.startup_sync_state,
            Some(StartupSyncState::InProgress(_))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SyncPlan;
    use crate::stateful::{
        actor::syncer::{set_sync_complete, set_sync_in_progress, FloorMarker},
        tests::mocks::{TestScheme, TestVariant},
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
    use commonware_runtime::{deterministic, Runner as _};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn stored_sync_height_disables_state_sync() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "stored_sync_height";

            let plan = SyncPlan::<TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(plan.may_state_sync());
            assert_eq!(plan.sync_height(), None);

            set_sync_complete::<_, Sha256Digest>(&context, partition_prefix, Height::new(7)).await;

            let plan = SyncPlan::<TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(!plan.may_state_sync());
            assert_eq!(plan.sync_height(), Some(Height::new(7)));
            assert!(plan.floor().is_none());
        });
    }

    #[test]
    fn in_progress_sync_requires_compatible_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "in_progress_sync_requires_compatible_floor";
            let stored = FloorMarker::new(Height::new(7), Sha256::fill(7));
            set_sync_in_progress(&context, partition_prefix, stored.clone()).await;

            let plan = SyncPlan::<TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(plan.may_state_sync());
            assert!(plan.requires_state_sync_floor());
            set_sync_in_progress(&context, partition_prefix, stored).await;
            set_sync_in_progress(
                &context,
                partition_prefix,
                FloorMarker::new(Height::new(9), Sha256::fill(9)),
            )
            .await;
        });
    }

    #[test]
    fn in_progress_sync_panics_for_backward_or_conflicting_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "in_progress_sync_panics_for_backward_or_conflicting_floor";
            let stored = FloorMarker::new(Height::new(7), Sha256::fill(7));
            set_sync_in_progress(&context, partition_prefix, stored.clone()).await;

            let backward = catch_unwind(AssertUnwindSafe(|| {
                stored.ensure_not_behind(&FloorMarker::new(Height::new(6), Sha256::fill(6)))
            }));
            assert!(backward.is_err());

            let conflicting = catch_unwind(AssertUnwindSafe(|| {
                stored.ensure_not_behind(&FloorMarker::new(Height::new(7), Sha256::fill(8)))
            }));
            assert!(conflicting.is_err());
        });
    }
}
