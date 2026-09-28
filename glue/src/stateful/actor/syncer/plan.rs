use super::StateSyncMetadata;
use commonware_consensus::{
    marshal::{Start, core::Variant},
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
/// 2. If [`SyncPlan::may_sync`] returns `true`, the caller may fetch a
///    finalized floor and persist it via [`SyncPlan::set_floor`]. An interrupted
///    sync already has a persisted floor, while a fresh sync needs one from the
///    caller. Otherwise the caller skips floor selection entirely.
///
/// Marshal (via [`SyncPlan::marshal_start`]) and [`Stateful`](crate::stateful::Stateful)
/// only use the persisted floor, so a crash before either actor starts still resumes
/// state sync on the next startup.
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
    metadata: StateSyncMetadata<E, S, V::Commitment>,
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
    pub async fn init(context: E, partition_prefix: impl AsRef<str>) -> Self {
        let metadata = StateSyncMetadata::<E, S, V::Commitment>::init(
            context.child("metadata"),
            partition_prefix,
        )
        .await;
        Self { metadata }
    }

    /// Returns whether state sync can still run on this node.
    ///
    /// When `false`, the caller should skip floor selection: any floor passed
    /// to [`SyncPlan::set_floor`] would be ignored. The node already has a
    /// durable completed state sync height, so future boots must recover from that
    /// height or marshal's processed height instead of running peer state sync again.
    ///
    /// When `true`, the caller can optionally persist a finalized floor via
    /// [`SyncPlan::set_floor`]. If no floor is persisted, the node will
    /// attempt to sync from genesis via marshal.
    pub fn may_sync(&self) -> bool {
        self.metadata.completed().is_none()
    }

    /// Returns the durable completed state sync height, if one has been stored.
    pub fn completed(&self) -> Option<Height> {
        self.metadata.completed()
    }

    /// Returns the persisted in-progress state sync floor.
    ///
    /// The floor is present from the time [`Self::set_floor`] persists it until
    /// state sync completes, including across restarts. While it is present,
    /// [`Self::may_sync`] is also `true` and every startup runs state sync instead
    /// of recovery, so partially synced database state stays on the state sync path.
    pub fn floor(&self) -> Option<&Finalization<S, V::Commitment>> {
        self.metadata.floor()
    }

    /// Persist a finalized floor to state sync from.
    ///
    /// Once persisted, every startup runs state sync until it completes,
    /// whether or not it is requested. Has no effect if state sync has already
    /// completed. A floor that is not newer than the persisted floor is ignored,
    /// so a lagging selection cannot move it backward. The metadata write
    /// underneath panics on a backward or conflicting floor instead.
    ///
    /// The durable write consumes the plan, so callers reassign the returned plan.
    ///
    /// # Panics
    ///
    /// Panics if the floor cannot be persisted.
    #[must_use]
    pub async fn set_floor(mut self, finalization: Finalization<S, V::Commitment>) -> Self {
        if !self.may_sync() {
            return self;
        }

        if let Some(persisted) = self.floor()
            && finalization.round() <= persisted.round()
        {
            warn!(
                finalization = ?finalization.round(),
                persisted = ?persisted.round(),
                "state sync floor not updated, finalization is not newer",
            );
            return self;
        }

        self.metadata = self.metadata.set_floor(finalization).await;
        self
    }

    /// Returns marshal's startup anchor for this plan.
    ///
    /// If a floor is persisted, marshal starts from that floor. Otherwise
    /// marshal starts from genesis and relies on its own durable progress to
    /// override that anchor when available.
    pub fn marshal_start<B>(&self, genesis: B) -> Start<S, V::Commitment, B> {
        self.floor()
            .cloned()
            .map_or_else(|| Start::Genesis(genesis), Start::Floor)
    }

    /// Returns whether this startup should run peer state sync.
    ///
    /// A caller can request peer state sync for a fresh node. A persisted floor
    /// always requires peer state sync, even if the caller did not explicitly
    /// request it on this startup.
    pub fn should_sync(&self, requested: bool) -> bool {
        self.may_sync() && (requested || self.floor().is_some())
    }

    /// Consumes this plan and returns its durable state-sync metadata handle.
    pub(crate) fn into_metadata(self) -> StateSyncMetadata<E, S, V::Commitment> {
        self.metadata
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
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::non_empty;

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
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
            .expect("recover finalization")
    }

    /// A selected floor is durable before marshal or Stateful starts, so every restart without a
    /// state sync request resumes from the latest selection.
    #[test]
    fn selected_floor_survives_restart_before_actor_start() {
        let mut checkpoint = None;
        let mut state = None;
        for boot in 0..3 {
            let runner =
                checkpoint.map_or_else(deterministic::Runner::default, deterministic::Runner::from);
            let (next, recovered) = runner.start_and_recover(move |mut context| async move {
                let (schemes, previous) = state.unwrap_or_else(|| {
                    let fixture =
                        scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
                    (fixture.schemes, None)
                });

                // Each restart finds the previous boot's selection without a request.
                let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                    context.child("plan"),
                    "selected_floor_before_actor_start",
                )
                .await;
                if let Some(previous) = previous {
                    assert!(plan.should_sync(false));
                    assert_eq!(plan.floor(), Some(&previous));
                }

                // Select a newer floor for marshal, then stop before either actor starts.
                let selected = finalization(&schemes, 7 + boot, 7 + boot as u8);
                let plan = plan.set_floor(selected.clone()).await;
                assert!(matches!(
                    plan.marshal_start(()),
                    Start::Floor(ref floor) if floor == &selected
                ));
                (schemes, Some(selected))
            });
            state = Some(next);
            checkpoint = Some(recovered);
        }
    }

    #[test]
    fn stored_completion_disables_state_sync() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "stored_completion";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            assert!(plan.may_sync());
            assert!(plan.should_sync(true));
            assert!(!plan.should_sync(false));
            assert_eq!(plan.completed(), None);
            drop(plan);

            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                context.child("metadata"),
                partition_prefix,
            )
            .await;
            metadata.set_completed(Height::new(7)).await;

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            assert!(!plan.may_sync());
            assert!(!plan.should_sync(true));
            assert_eq!(plan.completed(), Some(Height::new(7)));
            assert!(plan.floor().is_none());

            // A completed sync ignores a later selection instead of persisting it.
            let plan = plan.set_floor(finalization(&fixture.schemes, 8, 8)).await;
            assert!(plan.floor().is_none());
            assert_eq!(plan.completed(), Some(Height::new(7)));
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync cannot be marked in-progress")]
    fn completed_sync_cannot_be_marked_in_progress() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "completed_sync_cannot_be_marked_in_progress";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                context.child("metadata"),
                partition_prefix,
            )
            .await;
            let metadata = metadata.set_completed(Height::new(7)).await;
            metadata
                .set_floor(finalization(&fixture.schemes, 8, 8))
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync height cannot move backward")]
    fn complete_height_cannot_move_backward() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "complete_height_cannot_move_backward";
            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                context.child("metadata"),
                partition_prefix,
            )
            .await;
            let metadata = metadata.set_completed(Height::new(7)).await;
            metadata.set_completed(Height::new(6)).await;
        });
    }

    #[test]
    fn in_progress_sync_persists_newer_resume_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "in_progress_sync_requires_compatible_floor";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let stored = finalization(&fixture.schemes, 7, 7);
            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                context.child("metadata"),
                partition_prefix,
            )
            .await;
            metadata.set_floor(stored.clone()).await;

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            assert!(plan.may_sync());
            assert!(plan.floor().is_some());
            assert!(plan.should_sync(false));
            let metadata = plan.metadata.set_floor(stored).await;
            let newer = finalization(&fixture.schemes, 9, 9);
            let metadata = metadata.set_floor(newer.clone()).await;
            assert_eq!(metadata.floor(), Some(&newer));
        });
    }

    #[test]
    fn interrupted_sync_reuses_persisted_floor_when_probe_lags() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "interrupted_sync_reuses_persisted_floor";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let stored = finalization(&fixture.schemes, 7, 7);

            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                context.child("metadata"),
                partition_prefix,
            )
            .await;
            metadata.set_floor(stored.clone()).await;

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            assert!(plan.should_sync(false));
            assert_eq!(
                plan.floor().expect("interrupted sync must have a floor"),
                &stored,
            );
            assert!(matches!(
                plan.marshal_start(()),
                Start::Floor(ref floor) if floor == &stored
            ));

            drop(plan);
            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            let plan = plan.set_floor(finalization(&fixture.schemes, 6, 6)).await;
            assert_eq!(
                plan.floor().expect("interrupted sync must have a floor"),
                &stored,
                "a lagging probe must not replace the persisted in-progress floor",
            );

            let newer = finalization(&fixture.schemes, 9, 9);
            drop(plan);
            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            let plan = plan.set_floor(newer.clone()).await;
            assert_eq!(plan.floor(), Some(&newer));
        });
    }

    #[test]
    fn set_floor_does_not_replace_newer_selection() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let newer = finalization(&fixture.schemes, 9, 9);

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                "set_floor_does_not_replace_newer_selection",
            )
            .await;
            let plan = plan
                .set_floor(newer.clone())
                .await
                .set_floor(finalization(&fixture.schemes, 8, 8))
                .await;

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
            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                context.child("metadata"),
                "in_progress_sync_panics_for_backward_floor",
            )
            .await;
            let metadata = metadata
                .set_floor(finalization(&fixture.schemes, 7, 7))
                .await;
            metadata
                .set_floor(finalization(&fixture.schemes, 6, 6))
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
            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                context.child("metadata"),
                "in_progress_sync_panics_for_conflicting_round",
            )
            .await;
            let metadata = metadata
                .set_floor(finalization(&fixture.schemes, 7, 7))
                .await;
            metadata
                .set_floor(finalization(&fixture.schemes, 7, 8))
                .await;
        });
    }
}
