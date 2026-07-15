use super::StateSyncMetadata;
use commonware_consensus::{
    marshal::{core::Variant, Start},
    simplex::types::Finalization,
    types::Height,
};
use commonware_cryptography::certificate::Scheme;
use commonware_storage::Context;
use tracing::warn;

/// Startup plan that determines whether one-time peer state sync may still run.
///
/// Construction is two-phase so the caller can avoid fetching a finalized
/// floor from peers when state sync has already completed:
///
/// 1. [`SyncPlan::init`] reads the durable state sync state.
/// 2. If [`SyncPlan::may_state_sync`] returns `true`, the caller may fetch a
///    finalized floor and attach it via [`SyncPlan::with_floor`]. An interrupted
///    sync already has a persisted floor, while a fresh sync needs one from the
///    caller. Otherwise the caller skips floor selection entirely.
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
    E: Context,
    S: Scheme,
    V: Variant,
{
    sync_metadata: StateSyncMetadata<E, S, V::Commitment>,
    floor: Option<Finalization<S, V::Commitment>>,
}

impl<E, S, V> SyncPlan<E, S, V>
where
    E: Context,
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
            StateSyncMetadata::<E, S, V::Commitment>::init(context, partition_prefix).await;
        let floor = sync_metadata.in_progress_floor().cloned();
        Self {
            sync_metadata,
            floor,
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

    /// Returns the selected or persisted in-progress state sync floor.
    pub const fn floor(&self) -> Option<&Finalization<S, V::Commitment>> {
        self.floor.as_ref()
    }

    /// Attach a finalized floor to state sync from.
    ///
    /// Has no effect if state sync has already completed. When resuming an
    /// interrupted sync, a lagging selection is ignored in favor of the
    /// persisted floor.
    #[must_use]
    pub fn with_floor(mut self, floor: Finalization<S, V::Commitment>) -> Self {
        if !self.may_state_sync() {
            return self;
        }

        if let Some(selected) = &self.floor {
            if floor.round() <= selected.round() {
                warn!(
                    candidate = ?floor.round(),
                    selected = ?selected.round(),
                    "state sync floor not updated, candidate is not newer",
                );
                return self;
            }
        }

        self.floor = Some(floor);
        self
    }

    /// Returns marshal's startup anchor for this plan.
    ///
    /// If a finalized floor was attached or persisted by an interrupted sync,
    /// marshal starts from that floor. Otherwise marshal starts from genesis
    /// and relies on its own durable progress to override that anchor when
    /// available.
    pub fn marshal_start<B>(&self, genesis: B) -> Start<S, V::Commitment, B> {
        self.floor
            .as_ref()
            .cloned()
            .map_or_else(|| Start::Genesis(genesis), Start::Floor)
    }

    /// Returns whether startup must resume an interrupted state sync.
    ///
    /// This is `true` after a previous process crashed while state sync was
    /// in progress. In that case [`Self::may_state_sync`] is also `true`, and
    /// the persisted floor keeps partially synced database state on the same
    /// recovery path.
    pub fn requires_state_sync_floor(&self) -> bool {
        self.sync_metadata.in_progress()
    }

    /// Returns whether this startup should run peer state sync.
    ///
    /// A caller can request peer state sync for a fresh node. An interrupted
    /// state sync always requires peer state sync, even if the caller did not
    /// explicitly request it.
    pub fn should_state_sync(&self, requested: bool) -> bool {
        self.may_state_sync() && (requested || self.requires_state_sync_floor())
    }

    /// Consumes this plan and returns its durable state-sync metadata handle.
    pub(crate) fn into_sync_metadata(self) -> StateSyncMetadata<E, S, V::Commitment> {
        self.sync_metadata
    }
}

#[cfg(test)]
mod tests {
    use super::SyncPlan;
    use crate::stateful::{
        actor::syncer::StateSyncMetadata,
        tests::mocks::{TestScheme, TestVariant},
    };
    use commonware_consensus::{
        marshal::Start,
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner as _};

    fn finalization(
        schemes: &[TestScheme],
        view: u64,
        digest_byte: u8,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal {
            round: Round::new(Epoch::zero(), View::new(view)),
            parent: View::new(view.saturating_sub(1)),
            payload: Sha256::fill(digest_byte),
        };
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
            .expect("recover finalization")
    }

    #[test]
    fn stored_sync_height_disables_state_sync() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "stored_sync_height";

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(plan.may_state_sync());
            assert!(plan.should_state_sync(true));
            assert!(!plan.should_state_sync(false));
            assert_eq!(plan.sync_height(), None);
            drop(plan);

            let mut metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, partition_prefix)
                    .await;
            metadata.set_complete(Height::new(7)).await;
            drop(metadata);

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(!plan.may_state_sync());
            assert!(!plan.should_state_sync(true));
            assert_eq!(plan.sync_height(), Some(Height::new(7)));
            assert!(plan.floor().is_none());
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync cannot be marked in-progress")]
    fn completed_sync_cannot_be_marked_in_progress() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "completed_sync_cannot_be_marked_in_progress";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let mut metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, partition_prefix)
                    .await;
            metadata.set_complete(Height::new(7)).await;
            metadata
                .begin_sync(finalization(&fixture.schemes, 8, 8))
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync height cannot move backward")]
    fn complete_height_cannot_move_backward() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "complete_height_cannot_move_backward";
            let mut metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, partition_prefix)
                    .await;
            metadata.set_complete(Height::new(7)).await;
            metadata.set_complete(Height::new(6)).await;
        });
    }

    #[test]
    fn in_progress_sync_requires_compatible_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "in_progress_sync_requires_compatible_floor";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let stored = finalization(&fixture.schemes, 7, 7);
            let mut metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, partition_prefix)
                    .await;
            metadata.begin_sync(stored.clone()).await;
            drop(metadata);

            let mut plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(plan.may_state_sync());
            assert!(plan.requires_state_sync_floor());
            assert!(plan.should_state_sync(false));
            plan.sync_metadata.begin_sync(stored).await;
            plan.sync_metadata
                .begin_sync(finalization(&fixture.schemes, 9, 9))
                .await;
        });
    }

    #[test]
    fn interrupted_sync_reuses_persisted_floor_when_probe_lags() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "interrupted_sync_reuses_persisted_floor";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let stored = finalization(&fixture.schemes, 7, 7);

            let mut metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, partition_prefix)
                    .await;
            metadata.begin_sync(stored.clone()).await;
            drop(metadata);

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            assert!(plan.should_state_sync(false));
            assert_eq!(
                plan.floor().expect("interrupted sync must have a floor"),
                &stored,
            );
            assert!(matches!(
                plan.marshal_start(()),
                Start::Floor(ref floor) if floor == &stored
            ));

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            let plan = plan.with_floor(finalization(&fixture.schemes, 6, 6));
            assert_eq!(
                plan.floor().expect("interrupted sync must have a floor"),
                &stored,
                "a lagging probe must not replace the persisted in-progress floor",
            );

            let newer = finalization(&fixture.schemes, 9, 9);
            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix).await;
            let plan = plan.with_floor(newer.clone());
            assert_eq!(plan.floor(), Some(&newer));
        });
    }

    #[test]
    fn with_floor_does_not_replace_newer_selection() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let newer = finalization(&fixture.schemes, 9, 9);

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                &context,
                "with_floor_does_not_replace_newer_selection",
            )
            .await;
            let plan =
                plan.with_floor(newer.clone())
                    .with_floor(finalization(&fixture.schemes, 8, 8));

            assert_eq!(plan.floor(), Some(&newer));
        });
    }

    #[test]
    #[should_panic(
        expected = "selected state sync floor cannot move behind the persisted in-progress floor"
    )]
    fn in_progress_sync_panics_for_backward_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                "in_progress_sync_panics_for_backward_floor",
            )
            .await;
            metadata
                .begin_sync(finalization(&fixture.schemes, 7, 7))
                .await;
            metadata
                .begin_sync(finalization(&fixture.schemes, 6, 6))
                .await;
        });
    }

    #[test]
    #[should_panic(
        expected = "selected state sync floor conflicts with the persisted in-progress round"
    )]
    fn in_progress_sync_panics_for_conflicting_round() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                "in_progress_sync_panics_for_conflicting_round",
            )
            .await;
            metadata
                .begin_sync(finalization(&fixture.schemes, 7, 7))
                .await;
            metadata
                .begin_sync(finalization(&fixture.schemes, 7, 8))
                .await;
        });
    }
}
