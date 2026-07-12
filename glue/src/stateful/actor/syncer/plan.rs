use super::StateSyncMetadata;
use commonware_codec::Read;
use commonware_consensus::{
    marshal::{core::Variant, Start},
    simplex::types::Finalization,
    types::Height,
};
use commonware_cryptography::certificate::Scheme;
use commonware_storage::Context;

/// The floor to state sync from (if any) and the durable metadata handle.
type PlanParts<E, S, V> = (
    Option<Finalization<S, <V as Variant>::Commitment>>,
    StateSyncMetadata<E, S, <V as Variant>::Commitment>,
);

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
/// Once state sync completes, this plan never selects peer state sync again.
/// Future startups recover from the later of that synced height and marshal's
/// processed height instead.
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
    /// `certificate_cfg` is the scheme's certificate codec configuration,
    /// used to read the stored state sync floor finalization.
    ///
    /// # Panics
    ///
    /// Panics if the metadata store cannot be opened. A node that cannot
    /// determine whether state sync already completed cannot safely choose a
    /// startup path.
    pub async fn init(
        context: &E,
        partition_prefix: impl AsRef<str>,
        certificate_cfg: <S::Certificate as Read>::Cfg,
    ) -> Self {
        let sync_metadata = StateSyncMetadata::<E, S, V::Commitment>::init(
            context,
            partition_prefix,
            certificate_cfg,
        )
        .await;
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
    /// Has no effect if state sync has already completed. An interrupted
    /// state sync keeps its persisted floor unless the attached one is
    /// strictly newer: floors are probed from peers near the tip, so a
    /// sampled floor can lag what this node already durably armed.
    #[must_use]
    pub fn with_floor(mut self, floor: Finalization<S, V::Commitment>) -> Self {
        if !self.may_state_sync() {
            return self;
        }

        if let Some(stored) = self.sync_metadata.in_progress_floor() {
            if floor.round() <= stored.round() {
                self.floor = Some(stored.clone());
                return self;
            }
        }

        self.floor = Some(floor);
        self
    }

    /// Returns marshal's startup anchor for this plan.
    ///
    /// A newly attached state sync floor takes precedence. Otherwise a node
    /// with an interrupted or completed state sync re-anchors marshal at its
    /// persisted floor, which marshal ignores (or re-installs idempotently
    /// in the brief window before the first post-sync acknowledgement) once
    /// its durable progress covers it. The floor a node provides therefore
    /// never advances after state sync, so marshal never jumps above the
    /// databases. Nodes that never state synced start from genesis and rely
    /// on marshal's durable progress to override that anchor when available.
    pub fn marshal_start<B>(&self, genesis: B) -> Start<S, V::Commitment, B> {
        if let Some(floor) = &self.floor {
            return Start::Floor(floor.clone());
        }
        if let Some(floor) = self.sync_metadata.completed_floor() {
            return Start::Floor(floor.clone());
        }
        if let Some(floor) = self.sync_metadata.in_progress_floor() {
            return Start::Floor(floor.clone());
        }
        Start::Genesis(genesis)
    }

    /// Returns whether startup must resume an interrupted state sync.
    ///
    /// This is `true` after a previous process crashed while state sync was
    /// in progress. In that case [`Self::may_state_sync`] is also `true`, but
    /// starting from marshal/genesis is not allowed because partially synced
    /// database state must be reopened through the state-sync path. The sync
    /// resumes from the persisted floor unless [`Self::with_floor`] attaches
    /// a strictly newer one.
    pub fn requires_state_sync_floor(&self) -> bool {
        self.sync_metadata.in_progress()
    }

    /// Returns whether this startup should run peer state sync.
    ///
    /// A caller can request peer state sync for a fresh node. An interrupted
    /// state sync always requires peer state sync, even if the caller did not
    /// explicitly request it.
    ///
    /// Callers must keep requesting state sync until a completed height is
    /// recorded (this method returns `false`). Withdrawing the request after
    /// marshal anchored at the floor but before durable sync progress exists
    /// leaves marshal above a database set that never synced, which startup
    /// treats as fatal.
    pub fn should_state_sync(&self, requested: bool) -> bool {
        self.may_state_sync() && (requested || self.requires_state_sync_floor())
    }

    /// Consumes this plan, returning the floor to state sync from (if any)
    /// and the durable state-sync metadata handle.
    ///
    /// An interrupted state sync always yields a floor: the persisted one,
    /// unless [`Self::with_floor`] attached a strictly newer selection.
    pub(crate) fn into_parts(self) -> PlanParts<E, S, V> {
        let floor = self
            .floor
            .or_else(|| self.sync_metadata.in_progress_floor().cloned());
        (floor, self.sync_metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::SyncPlan;
    use crate::stateful::{
        actor::syncer::{tests::make_finalization, StateSyncMetadata},
        tests::mocks::{TestBlock, TestScheme, TestVariant},
    };
    use commonware_consensus::{
        marshal::Start,
        simplex::{mocks::scheme as scheme_mocks, types::Finalization},
        types::Height,
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};

    /// Builds a finalization whose payload matches `Sha256::fill(height)`.
    fn finalization(
        context: &deterministic::Context,
        height: u64,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let mut signing = context.child("signing");
        let fixture = scheme_mocks::fixture(&mut signing, b"plan-floor", 1);
        make_finalization(&fixture, &TestBlock::new(height, height as u8))
    }

    #[test]
    fn stored_sync_height_disables_state_sync() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "stored_sync_height";

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix, ()).await;
            assert!(plan.may_state_sync());
            assert!(plan.should_state_sync(true));
            assert!(!plan.should_state_sync(false));
            assert_eq!(plan.sync_height(), None);
            drop(plan);

            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                partition_prefix,
                (),
            )
            .await;
            metadata.set_complete(Height::new(7)).await;
            drop(metadata);

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix, ()).await;
            assert!(!plan.may_state_sync());
            assert!(!plan.should_state_sync(true));
            assert_eq!(plan.sync_height(), Some(Height::new(7)));
            assert!(plan.floor().is_none());
        });
    }

    /// An interrupted state sync restarts from its persisted floor when the
    /// caller attaches nothing, keeps the persisted floor over a lagging
    /// probe selection, and retargets to a strictly newer one.
    #[test]
    fn interrupted_sync_resumes_from_persisted_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "interrupted_sync_resumes";
            let stored = finalization(&context, 7);
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                partition_prefix,
                (),
            )
            .await;
            metadata.begin_sync(Height::new(7), stored.clone()).await;
            drop(metadata);

            // No floor attached: resume from the persisted one, and anchor
            // marshal at it.
            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix, ()).await;
            assert!(plan.should_state_sync(false));
            assert!(matches!(
                plan.marshal_start(TestBlock::new(0, 0)),
                Start::Floor(f) if f.proposal.payload == stored.proposal.payload
            ));
            let (floor, _) = plan.into_parts();
            assert_eq!(
                floor
                    .expect("interrupted sync must yield a floor")
                    .proposal
                    .payload,
                stored.proposal.payload,
            );

            // A lagging probe selection is ignored in favor of the persisted
            // floor.
            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix, ()).await;
            let plan = plan.with_floor(finalization(&context, 6));
            assert_eq!(
                plan.floor()
                    .expect("floor must be selected")
                    .proposal
                    .payload,
                stored.proposal.payload,
            );

            // A strictly newer selection retargets the sync.
            let newer = finalization(&context, 9);
            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix, ()).await;
            let plan = plan.with_floor(newer.clone());
            assert_eq!(
                plan.floor()
                    .expect("floor must be selected")
                    .proposal
                    .payload,
                newer.proposal.payload,
            );
        });
    }

    #[test]
    #[should_panic(expected = "state sync cannot restart after completion")]
    fn completed_sync_cannot_be_rearmed() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "completed_sync_cannot_be_rearmed";
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                partition_prefix,
                (),
            )
            .await;
            metadata.set_complete(Height::new(7)).await;
            metadata
                .begin_sync(Height::new(8), finalization(&context, 8))
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync height cannot move backward")]
    fn complete_height_cannot_move_backward() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "complete_height_cannot_move_backward";
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                partition_prefix,
                (),
            )
            .await;
            metadata.set_complete(Height::new(7)).await;
            metadata.set_complete(Height::new(6)).await;
        });
    }

    #[test]
    #[should_panic(expected = "completed state sync height cannot be behind the in-progress floor")]
    fn complete_height_cannot_be_behind_in_progress_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "complete_height_cannot_be_behind_in_progress_floor";
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                partition_prefix,
                (),
            )
            .await;
            metadata
                .begin_sync(Height::new(7), finalization(&context, 7))
                .await;
            metadata.set_complete(Height::new(6)).await;
        });
    }

    #[test]
    fn in_progress_sync_requires_compatible_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "in_progress_sync_requires_compatible_floor";
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                partition_prefix,
                (),
            )
            .await;
            metadata
                .begin_sync(Height::new(7), finalization(&context, 7))
                .await;
            drop(metadata);

            let mut plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix, ()).await;
            assert!(plan.may_state_sync());
            assert!(plan.requires_state_sync_floor());
            assert!(plan.should_state_sync(false));
            plan.sync_metadata
                .begin_sync(Height::new(7), finalization(&context, 7))
                .await;
            plan.sync_metadata
                .begin_sync(Height::new(9), finalization(&context, 9))
                .await;
        });
    }

    /// A node that completed state sync re-anchors marshal at the stored
    /// floor on every future boot, while a node that never state synced
    /// starts marshal from genesis.
    #[test]
    fn completed_sync_reanchors_marshal_at_stored_floor() {
        deterministic::Runner::default().start(|context| async move {
            let partition_prefix = "completed_sync_reanchors";
            let floor = finalization(&context, 7);
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                partition_prefix,
                (),
            )
            .await;
            metadata.begin_sync(Height::new(7), floor.clone()).await;
            metadata.set_complete(Height::new(7)).await;
            drop(metadata);

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, partition_prefix, ()).await;
            match plan.marshal_start(TestBlock::new(0, 0)) {
                Start::Floor(stored) => {
                    assert_eq!(stored.proposal.payload, floor.proposal.payload);
                }
                Start::Genesis(_) => panic!("completed sync must re-anchor marshal at its floor"),
            }

            // A completed plan ignores late floor attachments and never arms
            // state sync again.
            let plan = plan.with_floor(finalization(&context, 9));
            assert!(plan.floor().is_none());
            let (armed, _) = plan.into_parts();
            assert!(armed.is_none(), "a completed plan must not arm state sync");

            // A marshal-path-only completion stores no floor and starts from
            // genesis.
            let other_prefix = "completed_sync_reanchors_marshal_only";
            let mut metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, other_prefix, ())
                    .await;
            metadata.set_complete(Height::new(3)).await;
            drop(metadata);

            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(&context, other_prefix, ()).await;
            assert!(matches!(
                plan.marshal_start(TestBlock::new(0, 0)),
                Start::Genesis(_)
            ));
        });
    }

    #[test]
    #[should_panic(
        expected = "selected state sync floor cannot move behind the persisted in-progress floor"
    )]
    fn in_progress_sync_panics_for_backward_floor() {
        deterministic::Runner::default().start(|context| async move {
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                "backward_floor",
                (),
            )
            .await;
            metadata
                .begin_sync(Height::new(7), finalization(&context, 7))
                .await;
            metadata
                .begin_sync(Height::new(6), finalization(&context, 6))
                .await;
        });
    }

    #[test]
    #[should_panic(
        expected = "selected state sync floor conflicts with the persisted in-progress floor"
    )]
    fn in_progress_sync_panics_for_conflicting_floor() {
        deterministic::Runner::default().start(|context| async move {
            let mut metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                "conflicting_floor",
                (),
            )
            .await;
            metadata
                .begin_sync(Height::new(7), finalization(&context, 7))
                .await;
            // A different block at the same height.
            let mut signing = context.child("signing_conflict");
            let fixture = scheme_mocks::fixture(&mut signing, b"plan-floor-conflict", 1);
            let conflicting = make_finalization(&fixture, &TestBlock::new(7, 8));
            metadata.begin_sync(Height::new(7), conflicting).await;
        });
    }
}
