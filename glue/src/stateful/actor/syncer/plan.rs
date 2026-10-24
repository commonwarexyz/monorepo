use super::SyncState;
use commonware_consensus::{
    marshal::{Start, core::Variant},
    simplex::types::Finalization,
    types::Height,
};
use commonware_cryptography::certificate::Scheme;
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use tracing::warn;

const SYNC_METADATA_SUFFIX: &str = "state_sync_metadata";
const SYNC_STATE_KEY: FixedBytes<1> = fixed_bytes!("C0");

/// Durable startup decision between peer state sync and recovery from marshal.
///
/// Marshal (via [`SyncPlan::marshal_start`]) and [`Stateful`](crate::stateful::Stateful) (via
/// [`Config::plan`](crate::stateful::Config::plan)) both start from the persisted floor. See
/// [Startup](crate::stateful#startup) for the sequence.
///
/// Mutating functions consume the plan and return it only on success. Storage failures panic.
pub struct SyncPlan<E, S, V>
where
    E: Context,
    S: Scheme,
    V: Variant,
{
    metadata: Metadata<E, FixedBytes<1>, SyncState<S, V::Commitment>>,
}

impl<E, S, V> SyncPlan<E, S, V>
where
    E: Context,
    S: Scheme,
    V: Variant,
{
    /// Loads the state sync metadata stored under `partition_prefix`, creating it if needed.
    ///
    /// # Panics
    ///
    /// Panics if the metadata store cannot be opened. A node that cannot
    /// determine whether state sync already completed cannot safely choose a
    /// startup path.
    pub async fn init(context: E, partition_prefix: impl AsRef<str>) -> Self {
        let partition_prefix = partition_prefix.as_ref();
        let metadata = Metadata::init(
            context.child("metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}{SYNC_METADATA_SUFFIX}"),
                codec_config: S::certificate_codec_config_unbounded(),
            },
        )
        .await
        .expect("failed to load sync metadata");
        Self { metadata }
    }

    /// Returns whether peer state sync can still run on this node.
    ///
    /// Returns `false` once completion is recorded, which happens when state sync converges and
    /// when [`Stateful`](crate::stateful::Stateful) starts without a persisted floor.
    /// [`SyncPlan::set_floor`] then has no effect.
    pub fn may_sync(&self) -> bool {
        self.completed().is_none()
    }

    /// Returns the recorded completion height, if any.
    pub fn completed(&self) -> Option<Height> {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::Complete(height)) => Some(*height),
            _ => None,
        }
    }

    /// Returns the persisted state sync floor, if any.
    ///
    /// A floor persists from [`Self::set_floor`] until state sync completes, across restarts. While
    /// one is persisted, [`Self::may_sync`] returns `true` and every startup runs state sync.
    pub fn floor(&self) -> Option<&Finalization<S, V::Commitment>> {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress(finalization)) => Some(finalization),
            _ => None,
        }
    }

    /// Persists `finalization` as the state sync floor and returns the updated plan.
    ///
    /// Once a floor is persisted, every startup runs state sync until it completes, whether or not
    /// it is requested. Has no effect once completion is recorded. A floor that is not at a later
    /// round than the persisted floor is ignored, so a lagging selection cannot move it backward.
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

        self.metadata = self
            .metadata
            .put_sync(SYNC_STATE_KEY, SyncState::InProgress(finalization))
            .await
            .expect("failed to set state sync state to in-progress");
        self
    }

    /// Records completion at `height`, which permanently disables peer state sync.
    ///
    /// Later startups recover from the later of the block at this height and the block backing
    /// marshal's processed position.
    ///
    /// # Panics
    ///
    /// Panics if `height` is below the recorded completion height or completion cannot be
    /// persisted.
    pub(crate) async fn set_completed(mut self, height: Height) -> Self {
        if let Some(existing) = self.completed() {
            assert!(
                height >= existing,
                "completed state sync height cannot move backward",
            );
        }

        self.metadata = self
            .metadata
            .put_sync(SYNC_STATE_KEY, SyncState::Complete(height))
            .await
            .expect("failed to set state sync state to complete");
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
    /// Returns `true` if [`Self::may_sync`] holds and either `requested` is set or a floor is
    /// persisted. If this returns `true` without a persisted floor, the caller should select one
    /// with [`Self::set_floor`]: [`Stateful`](crate::stateful::Stateful) started without a floor
    /// recovers from marshal and records completion.
    pub fn should_sync(&self, requested: bool) -> bool {
        self.may_sync() && (requested || self.floor().is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::SyncPlan;
    use crate::stateful::tests::mocks::{TestScheme, TestVariant};
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
            plan.set_completed(Height::new(7)).await;

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
    #[should_panic(expected = "completed state sync height cannot move backward")]
    fn complete_height_cannot_move_backward() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "complete_height_cannot_move_backward";
            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            let plan = plan.set_completed(Height::new(7)).await;
            plan.set_completed(Height::new(6)).await;
        });
    }

    #[test]
    fn in_progress_sync_persists_newer_resume_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "in_progress_sync_requires_compatible_floor";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let stored = finalization(&fixture.schemes, 7, 7);
            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            drop(plan.set_floor(stored.clone()).await);

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            assert!(plan.may_sync());
            assert!(plan.floor().is_some());
            assert!(plan.should_sync(false));
            let plan = plan.set_floor(stored).await;
            let newer = finalization(&fixture.schemes, 9, 9);
            let plan = plan.set_floor(newer.clone()).await;
            assert_eq!(plan.floor(), Some(&newer));
        });
    }

    #[test]
    fn interrupted_sync_reuses_persisted_floor_when_probe_lags() {
        deterministic::Runner::default().start(|mut context| async move {
            let partition_prefix = "interrupted_sync_reuses_persisted_floor";
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let stored = finalization(&fixture.schemes, 7, 7);

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                partition_prefix,
            )
            .await;
            drop(plan.set_floor(stored.clone()).await);

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

    /// A selection at the persisted floor's round is ignored, even with a different payload.
    #[test]
    fn set_floor_ignores_selection_at_persisted_round() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"_COMMONWARE_GLUE_SYNC_PLAN", 1);
            let stored = finalization(&fixture.schemes, 7, 7);

            // Persist a floor at round 7.
            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                "set_floor_ignores_selection_at_persisted_round",
            )
            .await;
            let plan = plan.set_floor(stored.clone()).await;

            // A selection at round 7 with another payload leaves the persisted floor unchanged.
            let plan = plan.set_floor(finalization(&fixture.schemes, 7, 8)).await;
            assert_eq!(plan.floor(), Some(&stored));
        });
    }
}
