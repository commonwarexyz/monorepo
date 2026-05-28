use super::StateSyncMetadata;
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
/// floor from peers when state sync has already completed:
///
/// 1. [`SyncPlan::init`] reads the durable state sync state.
/// 2. If [`SyncPlan::may_state_sync`] returns `true`, the caller fetches a
///    finalized floor and attaches it via [`SyncPlan::with_floor`]. Otherwise
///    the caller skips floor selection entirely.
///
/// The plan owns the opened metadata store and is later consumed by
/// [`Stateful`](crate::stateful::Stateful), so startup does not reopen the same
/// metadata partition from multiple places.
///
/// Once state sync completes, this node never performs peer state sync
/// again. Future startups must recover from the later of that synced height
/// and marshal's processed height instead.
pub struct SyncPlan<E, S, V>
where
    E: Clock + Metrics + Storage,
    S: Scheme,
    V: Variant,
{
    sync_metadata: StateSyncMetadata<E, V::Commitment>,
    floor: Option<Finalization<S, V::Commitment>>,
}

impl<E, S, V> SyncPlan<E, S, V>
where
    E: Clock + Metrics + Storage,
    S: Scheme,
    V: Variant,
{
    /// Load the durable state sync metadata for this partition prefix.
    ///
    /// # Panics
    ///
    /// Panics if the metadata store cannot be opened. A node that cannot
    /// determine whether state sync already completed cannot safely choose a
    /// startup path.
    pub async fn init(context: &E, partition_prefix: impl AsRef<str>) -> Self {
        let sync_metadata =
            StateSyncMetadata::<E, V::Commitment>::init(context, partition_prefix).await;
        Self {
            sync_metadata,
            floor: None,
        }
    }

    /// Returns whether state sync can still run on this node.
    ///
    /// When `false`, the caller should skip floor selection: any floor passed
    /// to [`SyncPlan::with_floor`] would be ignored. The node already has a
    /// durable completed state sync height, so future boots must recover from that
    /// height or marshal's processed height instead of running peer state sync again.
    ///
    /// When `true`, the caller can optionally attach a finalized floor via
    /// [`SyncPlan::with_floor`]. If a floor is not attached, the node will
    /// attempt to sync from genesis via marshal unless it is resuming an
    /// interrupted state sync.
    pub fn may_state_sync(&self) -> bool {
        self.sync_metadata.sync_height().is_none()
    }

    /// Returns the durable completed state sync height, if one has been stored.
    pub fn sync_height(&self) -> Option<Height> {
        self.sync_metadata.sync_height()
    }

    /// Returns the partition prefix to use for state sync metadata storage.
    pub const fn partition_prefix(&self) -> &str {
        self.sync_metadata.partition_prefix()
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

    /// Returns whether startup must attach a new state sync floor.
    ///
    /// This is `true` after a previous process crashed while state sync was
    /// in progress. In that case [`Self::may_state_sync`] is also `true`, but
    /// starting from marshal/genesis is not allowed because partially synced
    /// database state must be reopened through the state-sync path.
    pub fn requires_state_sync_floor(&self) -> bool {
        self.sync_metadata.in_progress()
    }

    /// Consumes this plan and returns its durable state-sync metadata handle.
    pub(crate) fn into_sync_metadata(self) -> StateSyncMetadata<E, V::Commitment> {
        self.sync_metadata
    }
}

#[cfg(test)]
mod tests {
    use super::SyncPlan;
    use crate::stateful::{
        actor::syncer::{FloorMarker, StateSyncMetadata},
        tests::mocks::{TestScheme, TestVariant},
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    #[test]
    fn stored_sync_height_disables_state_sync() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "stored_sync_height";

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(plan.may_state_sync());
            assert_eq!(plan.sync_height(), None);
            drop(plan);

            let mut metadata =
                StateSyncMetadata::<_, Sha256Digest>::init(&context, partition_prefix).await;
            metadata.set_complete(Height::new(7)).await;
            drop(metadata);

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(!plan.may_state_sync());
            assert_eq!(plan.sync_height(), Some(Height::new(7)));
            assert!(plan.floor().is_none());
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync cannot be marked in-progress")]
    fn completed_sync_cannot_be_marked_in_progress() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "completed_sync_cannot_be_marked_in_progress";
            let mut metadata =
                StateSyncMetadata::<_, Sha256Digest>::init(&context, partition_prefix).await;
            metadata.set_complete(Height::new(7)).await;
            metadata
                .begin_sync(FloorMarker::new(Height::new(8), Sha256::fill(8)))
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync height cannot move backward")]
    fn complete_height_cannot_move_backward() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "complete_height_cannot_move_backward";
            let mut metadata =
                StateSyncMetadata::<_, Sha256Digest>::init(&context, partition_prefix).await;
            metadata.set_complete(Height::new(7)).await;
            metadata.set_complete(Height::new(6)).await;
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync height cannot be behind the in-progress floor")]
    fn complete_height_cannot_be_behind_in_progress_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "complete_height_cannot_be_behind_in_progress_floor";
            let mut metadata =
                StateSyncMetadata::<_, Sha256Digest>::init(&context, partition_prefix).await;
            metadata
                .begin_sync(FloorMarker::new(Height::new(7), Sha256::fill(7)))
                .await;
            metadata.set_complete(Height::new(6)).await;
        });
    }

    #[test]
    fn in_progress_sync_requires_compatible_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "in_progress_sync_requires_compatible_floor";
            let stored = FloorMarker::new(Height::new(7), Sha256::fill(7));
            let mut metadata =
                StateSyncMetadata::<_, Sha256Digest>::init(&context, partition_prefix).await;
            metadata.begin_sync(stored.clone()).await;
            drop(metadata);

            let mut plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(plan.may_state_sync());
            assert!(plan.requires_state_sync_floor());
            plan.sync_metadata.begin_sync(stored).await;
            plan.sync_metadata
                .begin_sync(FloorMarker::new(Height::new(9), Sha256::fill(9)))
                .await;
        });
    }

    #[test]
    #[should_panic(
        expected = "selected state sync floor cannot move behind the persisted in-progress floor"
    )]
    fn in_progress_sync_panics_for_backward_floor() {
        let stored = FloorMarker::new(Height::new(7), Sha256::fill(7));
        stored.ensure_not_behind(&FloorMarker::new(Height::new(6), Sha256::fill(6)));
    }

    #[test]
    #[should_panic(expected = "selected state sync floor conflicts with the persisted in-progress floor")]
    fn in_progress_sync_panics_for_conflicting_floor() {
        let stored = FloorMarker::new(Height::new(7), Sha256::fill(7));
        stored.ensure_not_behind(&FloorMarker::new(Height::new(7), Sha256::fill(8)));
    }
}
