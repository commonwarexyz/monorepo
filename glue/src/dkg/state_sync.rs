//! Durable startup material for DKG actors.
//!
//! Restart derives the active epoch from marshal's processed height, but marshal may have
//! pruned the finalized boundary block that introduced it or, after application state sync,
//! never stored it. [`Plan`] keeps that epoch's public material in two partitions under one
//! prefix and is shared by the reshare and orchestrator actors.
//! [Marshal Retention](crate::dkg#marshal-retention) describes how restart uses them:
//!
//! - [`StateSync`] material is persisted by [`Plan::init`] and deleted by a later startup
//!   once marshal's recovered epoch is past the synced epoch.
//! - A [`Checkpoint`] is recorded for each epoch the orchestrator enters from its boundary
//!   block. At an epoch's final block, the next epoch's checkpoint is recorded before the
//!   block is acknowledged.

use crate::dkg::{network::Directory, types::EpochInfo};
use bytes::BufMut;
use commonware_codec::{
    Buf, Decode as _, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Epochable as _,
    marshal::core::Processed,
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, Epocher, FixedEpocher},
};
#[cfg(feature = "arbitrary")]
use commonware_cryptography::bls12381::dkg::feldman_desmedt::Output;
use commonware_cryptography::{
    Digest,
    bls12381::primitives::{sharing::ModeVersion, variant::Variant},
};
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::{
    fixed_bytes,
    sequence::{FixedBytes, U64, Unit},
    sync::AsyncMutex,
};
use std::{fmt, num::NonZeroU32, sync::Arc};

const STATE_SYNC_KEY: FixedBytes<1> = fixed_bytes!("00");
const STATE_SYNC_SUFFIX: &str = "_dkg_state_sync";
const CHECKPOINT_SUFFIX: &str = "_dkg_checkpoint";
type EpochInfoCodecConfig = (NonZeroU32, ModeVersion);

/// Storage settings for a DKG state-sync recovery plan.
#[derive(Clone, Debug)]
pub struct Config {
    /// Stable node-wide partition prefix.
    pub partition_prefix: String,

    /// Maximum entries accepted in each persisted participant set.
    pub max_participants: NonZeroU32,

    /// Maximum sharing mode version accepted in persisted epoch information.
    pub max_supported_mode: ModeVersion,
}

/// Public material needed to start DKG actors in a state-synced epoch.
///
/// The epoch info replaces the boundary block that may be absent locally. The
/// floor is the finalized block selected for application state sync and gives
/// marshal a block from which to resume delivery.
///
/// The info must describe the epoch containing the floor, and [`Plan::init`]
/// panics otherwise. See [State Sync](crate::dkg#state-sync) for how startup
/// pairs a probe artifact with a persisted floor.
pub struct StateSync<S, D, V, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    /// Public information for the epoch containing the state-sync floor.
    pub info: EpochInfo<V, S::PublicKey, Dir>,

    /// Finalized floor selected for application state sync.
    pub floor: Finalization<S, D>,
}

impl<S, D, V, Dir> Clone for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            floor: self.floor.clone(),
        }
    }
}

impl<S, D, V, Dir> fmt::Debug for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateSync")
            .field("info", &self.info)
            .field("floor", &self.floor)
            .finish()
    }
}

impl<S, D, V, Dir> PartialEq for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info && self.floor == other.floor
    }
}

impl<S, D, V, Dir> Eq for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
}

impl<S, D, V, Dir> Write for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.info.write(writer);
        self.floor.write(writer);
    }
}

impl<S, D, V, Dir> EncodeSize for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn encode_size(&self) -> usize {
        self.info.encode_size() + self.floor.encode_size()
    }
}

impl<S, D, V, Dir> Read for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    type Cfg = (EpochInfoCodecConfig, <S::Certificate as Read>::Cfg);

    fn read_cfg(
        reader: &mut impl Buf,
        (epoch_info, certificate): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            info: EpochInfo::read_cfg(reader, epoch_info)?,
            floor: Finalization::read_cfg(reader, certificate)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S, D, V, Dir> arbitrary::Arbitrary<'_> for StateSync<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    V: Variant,
    Dir: Directory<S::PublicKey> + for<'a> arbitrary::Arbitrary<'a>,
    S::PublicKey: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    Output<V, S::PublicKey>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            info: u.arbitrary()?,
            floor: u.arbitrary()?,
        })
    }
}

/// Public information of an epoch and the commitment of the boundary block it starts from.
///
/// Restart resumes an epoch from its checkpoint without reading the boundary block, so marshal
/// can prune that block. [Marshal Retention](crate::dkg#marshal-retention) describes when
/// restart still reads it.
pub struct Checkpoint<S, D, V, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    /// Public information for the epoch.
    pub info: EpochInfo<V, S::PublicKey, Dir>,

    /// Commitment of the boundary block that carried the info: genesis for epoch zero, or
    /// the final block of the previous epoch. The epoch's Simplex engine starts from it.
    pub boundary: D,
}

impl<S, D, V, Dir> Clone for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            boundary: self.boundary,
        }
    }
}

impl<S, D, V, Dir> fmt::Debug for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Checkpoint")
            .field("info", &self.info)
            .field("boundary", &self.boundary)
            .finish()
    }
}

impl<S, D, V, Dir> PartialEq for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info && self.boundary == other.boundary
    }
}

impl<S, D, V, Dir> Eq for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
}

impl<S, D, V, Dir> Write for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.info.write(writer);
        self.boundary.write(writer);
    }
}

impl<S, D, V, Dir> EncodeSize for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn encode_size(&self) -> usize {
        self.info.encode_size() + self.boundary.encode_size()
    }
}

impl<S, D, V, Dir> Read for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    type Cfg = EpochInfoCodecConfig;

    fn read_cfg(reader: &mut impl Buf, epoch_info: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            info: EpochInfo::read_cfg(reader, epoch_info)?,
            boundary: D::read(reader)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S, D, V, Dir> arbitrary::Arbitrary<'_> for Checkpoint<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    V: Variant,
    Dir: Directory<S::PublicKey> + for<'a> arbitrary::Arbitrary<'a>,
    S::PublicKey: for<'a> arbitrary::Arbitrary<'a>,
    Output<V, S::PublicKey>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            info: u.arbitrary()?,
            boundary: u.arbitrary()?,
        })
    }
}

/// Returns the epoch containing the first height after `processed`.
pub(crate) fn recovered_epoch(processed: Processed, epocher: &FixedEpocher) -> Epoch {
    epocher
        .containing(processed.height().next())
        .expect("epocher must know recovered height")
        .epoch()
}

/// Partition prefix and codec limits shared by the plan's records.
#[derive(Clone)]
struct Storage {
    partition_prefix: String,
    codec_config: EpochInfoCodecConfig,
}

enum PlanState<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    Pending(Option<StateSync<S, D, V, Dir>>),
    Resolved(Option<StateSync<S, D, V, Dir>>),
}

/// Shared startup recovery plan for DKG actors.
///
/// Initialize one plan after obtaining optional application state-sync material
/// and before starting either DKG actor, and give each actor a clone. Clones share
/// the resolution decision, so both actors observe the same material, and they
/// serialize their storage access. Separately initialized plans do not, so
/// initialize only one plan per partition prefix.
///
/// A [`Plan::disabled`] plan stores nothing, so every restart reads its epoch's
/// boundary block from marshal. Use it for deployments that never restart into a
/// later epoch, such as a one-shot DKG.
pub struct Plan<S, D, V, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    state: Arc<AsyncMutex<PlanState<S, D, V, Dir>>>,
    storage: Option<Storage>,
}

impl<S, D, V, Dir> Clone for Plan<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            storage: self.storage.clone(),
        }
    }
}

impl<S, D, V, Dir> fmt::Debug for Plan<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Plan").finish_non_exhaustive()
    }
}

impl<S, D, V, Dir> Plan<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    /// Initializes and durably records a DKG state-sync recovery candidate.
    ///
    /// Provided material replaces any existing record and is durable when this
    /// method returns. Without provided material, the existing record (if any)
    /// is loaded. The returned plan may be passed to the actors immediately.
    ///
    /// # Panics
    ///
    /// Panics if storage cannot be loaded or synchronized, if provided or
    /// persisted material has mismatched artifact and floor epochs, or if
    /// provided material violates the configured codec limits.
    pub async fn init<E: Context>(
        context: E,
        config: Config,
        provided: Option<StateSync<S, D, V, Dir>>,
    ) -> Self {
        let codec_config = (config.max_participants, config.max_supported_mode);
        if let Some(provided) = &provided {
            assert_provided(provided, codec_config);
        }
        let storage = Storage {
            partition_prefix: config.partition_prefix,
            codec_config,
        };
        let mut store = open_state_sync::<E, S, D, V, Dir>(context, &storage).await;
        if let Some(provided) = provided {
            store.put(STATE_SYNC_KEY, provided);
            store = store
                .sync()
                .await
                .expect("failed to persist DKG state sync metadata");
        }
        let candidate = store.get(&STATE_SYNC_KEY).cloned();
        if let Some(candidate) = &candidate {
            assert_epoch(candidate);
        }
        drop(store);

        Self {
            state: Arc::new(AsyncMutex::new(PlanState::Pending(candidate))),
            storage: Some(storage),
        }
    }

    /// Creates a plan that never accesses storage, so it resolves to no material and
    /// records no checkpoints.
    pub fn disabled() -> Self {
        Self {
            state: Arc::new(AsyncMutex::new(PlanState::Resolved(None))),
            storage: None,
        }
    }

    /// Returns the persisted material if `recovered_epoch` is `None` or not past
    /// the floor's epoch, and `None` if there is no material. Otherwise deletes
    /// the material and returns `None`.
    ///
    /// The first call decides the result for every clone of the plan. Panics if
    /// storage fails while deleting stale material.
    pub(crate) async fn resolve<E: Context>(
        &self,
        context: E,
        recovered_epoch: Option<Epoch>,
    ) -> Option<StateSync<S, D, V, Dir>> {
        let mut state = self.state.lock().await;
        let candidate = match &*state {
            PlanState::Resolved(resolved) => return resolved.clone(),
            PlanState::Pending(candidate) => candidate.clone(),
        };

        let Some(candidate) = candidate else {
            *state = PlanState::Resolved(None);
            return None;
        };
        if recovered_epoch.is_none_or(|epoch| epoch <= candidate.floor.epoch()) {
            *state = PlanState::Resolved(Some(candidate.clone()));
            return Some(candidate);
        }

        let storage = self
            .storage
            .as_ref()
            .expect("pending plan must have storage");
        let mut store = open_state_sync::<E, S, D, V, Dir>(context, storage).await;
        store.remove(&STATE_SYNC_KEY);
        store
            .sync()
            .await
            .expect("failed to delete stale DKG state sync metadata");
        *state = PlanState::Resolved(None);
        None
    }

    /// Returns the checkpoint recorded for `epoch`, if any.
    ///
    /// Panics if storage fails to load.
    pub(crate) async fn checkpoint<E: Context>(
        &self,
        context: E,
        epoch: Epoch,
    ) -> Option<Checkpoint<S, D, V, Dir>> {
        let storage = self.storage.as_ref()?;

        // Every access to the checkpoint partition holds the shared state lock. Opening the
        // partition truncates a copy that fails validation, and the runtime allows one open
        // handle per blob.
        let _serialized = self.state.lock().await;
        let store = open_checkpoints::<E, S, D, V, Dir>(context, storage).await;
        store.get(&U64::new(epoch.get())).cloned()
    }

    /// Durably records `checkpoint` and drops every other checkpoint for an epoch before
    /// `retained_from`.
    ///
    /// `retained_from` must not be later than the epoch any later restart recovers from
    /// marshal's processed height. A disabled plan records nothing. Panics if storage fails
    /// or if `checkpoint` exceeds the plan's codec limits, since every later load of a stored
    /// record that exceeds them would panic.
    pub(crate) async fn record<E: Context>(
        &self,
        context: E,
        checkpoint: Checkpoint<S, D, V, Dir>,
        retained_from: Epoch,
    ) {
        let Some(storage) = &self.storage else {
            return;
        };
        Checkpoint::<S, D, V, Dir>::decode_cfg(checkpoint.encode(), &storage.codec_config)
            .expect("checkpoint must satisfy codec config");
        let epoch = checkpoint.info.epoch;
        let _serialized = self.state.lock().await;
        let mut store = open_checkpoints::<E, S, D, V, Dir>(context, storage).await;
        store.retain(|key, _| Epoch::new(u64::from(key)) >= retained_from);
        store.put(U64::new(epoch.get()), checkpoint);
        store
            .sync()
            .await
            .expect("failed to persist DKG checkpoint metadata");
    }
}

async fn open_state_sync<E, S, D, V, Dir>(
    context: E,
    storage: &Storage,
) -> Metadata<E, FixedBytes<1>, StateSync<S, D, V, Dir>>
where
    E: Context,
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    Metadata::init(
        context,
        metadata::Config {
            partition: format!("{}{STATE_SYNC_SUFFIX}", storage.partition_prefix),
            codec_config: (
                storage.codec_config,
                S::certificate_codec_config_unbounded(),
            ),
        },
    )
    .await
    .expect("failed to load DKG state sync metadata")
}

async fn open_checkpoints<E, S, D, V, Dir>(
    context: E,
    storage: &Storage,
) -> Metadata<E, U64, Checkpoint<S, D, V, Dir>>
where
    E: Context,
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    Metadata::init(
        context,
        metadata::Config {
            partition: format!("{}{CHECKPOINT_SUFFIX}", storage.partition_prefix),
            codec_config: storage.codec_config,
        },
    )
    .await
    .expect("failed to load DKG checkpoint metadata")
}

fn assert_provided<S, D, V, Dir>(
    state_sync: &StateSync<S, D, V, Dir>,
    codec_config: EpochInfoCodecConfig,
) where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    assert_epoch(state_sync);
    StateSync::<S, D, V, Dir>::decode_cfg(
        state_sync.encode(),
        &(codec_config, S::certificate_codec_config_unbounded()),
    )
    .expect("provided state sync material must satisfy codec config");
}

fn assert_epoch<S, D, V, Dir>(state_sync: &StateSync<S, D, V, Dir>)
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    assert!(
        state_sync.info.epoch == state_sync.floor.epoch(),
        "state sync artifact and floor must be in the same epoch"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{network::Addresses, tests::mocks, types::EpochOutcome};
    use commonware_consensus::{
        simplex::types::{Finalize, Proposal},
        types::{Round, View},
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, Signer as _,
        bls12381::{dkg::feldman_desmedt::deal, primitives::sharing::Mode},
        ed25519,
    };
    use commonware_p2p::Address;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{N3f1, NZU32, TestRng, non_empty, ordered::Set};
    use std::net::SocketAddr;

    type TestStateSync = StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>;

    fn state_sync(context: &mut deterministic::Context, epoch: Epoch) -> TestStateSync {
        let fixture = mocks::scheme_fixture_n(context, 4);
        let participants = Set::from_iter_dedup(fixture.participants);
        let (output, _) = deal::<mocks::TestBlsVariant, _, N3f1>(
            TestRng::new(epoch.get() + 1),
            Mode::NonZeroCounter,
            participants.clone(),
        )
        .expect("test DKG output");
        let proposal = Proposal::new(
            Round::new(epoch, View::new(1)),
            View::zero(),
            Sha256::hash(&[b"state sync floor"]),
        );
        let finalizes = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("test finalize"))
            .collect::<Vec<_>>();
        let floor = Finalization::from_finalizes(
            &fixture.schemes[0],
            non_empty![@finalizes.iter()],
            &Sequential,
        )
        .expect("test finalization quorum");
        TestStateSync {
            info: EpochInfo {
                outcome: EpochOutcome::Success,
                epoch,
                output,
                players: participants.clone(),
                next_players: participants,
                directory: Unit,
            },
            floor,
        }
    }

    type TestPlan = Plan<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>;

    fn config(partition: &str) -> Config {
        Config {
            partition_prefix: partition.into(),
            max_participants: NZU32!(16),
            max_supported_mode: crate::dkg::tests::max_supported_mode(),
        }
    }

    async fn plan(
        context: deterministic::Context,
        partition: &str,
        provided: Option<TestStateSync>,
    ) -> TestPlan {
        Plan::init(context, config(partition), provided).await
    }

    fn assert_state_sync(actual: Option<TestStateSync>, expected: &TestStateSync) {
        assert_eq!(actual.as_ref(), Some(expected));
    }

    type TestCheckpoint = Checkpoint<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>;

    fn checkpoint(context: &mut deterministic::Context, epoch: Epoch) -> TestCheckpoint {
        TestCheckpoint {
            info: state_sync(context, epoch).info,
            boundary: Sha256::hash(&[&epoch.get().to_be_bytes()]),
        }
    }

    /// Checkpoints survive reopening the plan, and each record keeps only the checkpoints
    /// from its `retained_from` epoch onward.
    #[test]
    fn checkpoint_survives_reopen_and_retains_from_recovered_epoch() {
        deterministic::Runner::default().start(|mut context| async move {
            let first = checkpoint(&mut context, Epoch::new(3));
            let second = checkpoint(&mut context, Epoch::new(4));
            let third = checkpoint(&mut context, Epoch::new(5));
            let recorder = plan(context.child("recorder"), "checkpoints", None).await;
            for (checkpoint, retained_from) in [(&first, 3), (&second, 3), (&third, 4)] {
                recorder
                    .record(
                        context.child("record"),
                        checkpoint.clone(),
                        Epoch::new(retained_from),
                    )
                    .await;
            }
            drop(recorder);

            // The last record dropped epoch three and kept every later epoch.
            let reopened = plan(context.child("reopened"), "checkpoints", None).await;
            let read = |epoch| reopened.checkpoint(context.child("read"), Epoch::new(epoch));
            assert_eq!(read(5).await.as_ref(), Some(&third));
            assert_eq!(read(4).await.as_ref(), Some(&second));
            assert!(read(3).await.is_none());
            assert!(read(6).await.is_none());
        });
    }

    /// Deleting stale state-sync material keeps the checkpoint recorded for the same epoch.
    #[test]
    fn checkpoint_is_independent_of_state_sync_material() {
        deterministic::Runner::default().start(|mut context| async move {
            let material = state_sync(&mut context, Epoch::new(2));
            let recorded = checkpoint(&mut context, Epoch::new(2));
            let plan = plan(context.child("plan"), "independent", Some(material.clone())).await;
            plan.record(context.child("record"), recorded.clone(), Epoch::new(2))
                .await;

            assert!(
                plan.resolve(context.child("resolve"), Some(Epoch::new(3)))
                    .await
                    .is_none()
            );
            assert_eq!(
                plan.checkpoint(context.child("read"), Epoch::new(2))
                    .await
                    .as_ref(),
                Some(&recorded)
            );
        });
    }

    /// A disabled plan records no checkpoint and reads none back.
    #[test]
    fn disabled_plan_records_nothing() {
        deterministic::Runner::default().start(|mut context| async move {
            let recorded = checkpoint(&mut context, Epoch::new(1));
            let plan = TestPlan::disabled();
            plan.record(context.child("record"), recorded, Epoch::new(1))
                .await;
            assert!(
                plan.checkpoint(context.child("read"), Epoch::new(1))
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn init_persists_before_resolve() {
        deterministic::Runner::default().start(|mut context| async move {
            let expected = state_sync(&mut context, Epoch::new(2));
            let initialized = plan(
                context.child("initialized"),
                "persist-before-resolve",
                Some(expected.clone()),
            )
            .await;
            drop(initialized);

            let reopened = plan(context.child("reopened"), "persist-before-resolve", None).await;
            assert_state_sync(
                reopened.resolve(context.child("resolve"), None).await,
                &expected,
            );
        });
    }

    #[test]
    fn two_clones_resolve_identically() {
        deterministic::Runner::default().start(|mut context| async move {
            let expected = state_sync(&mut context, Epoch::new(2));
            let first = plan(context.child("init"), "clones", Some(expected.clone())).await;
            let second = first.clone();

            assert_state_sync(first.resolve(context.child("first"), None).await, &expected);
            assert_state_sync(
                second.resolve(context.child("second"), None).await,
                &expected,
            );
        });
    }

    #[test]
    fn stale_resolution_deletes_once_and_reopen_sees_none() {
        deterministic::Runner::default().start(|mut context| async move {
            let expected = state_sync(&mut context, Epoch::new(2));
            let first = plan(context.child("init"), "stale", Some(expected)).await;
            let second = first.clone();

            assert!(
                first
                    .resolve(context.child("first"), Some(Epoch::new(3)))
                    .await
                    .is_none()
            );
            assert!(
                second
                    .resolve(context.child("second"), Some(Epoch::new(3)))
                    .await
                    .is_none()
            );
            drop(first);
            drop(second);

            let reopened = plan(context.child("reopened"), "stale", None).await;
            assert!(
                reopened
                    .resolve(context.child("reopened_resolve"), None)
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn provided_material_overwrites_persisted_record() {
        deterministic::Runner::default().start(|mut context| async move {
            let first_value = state_sync(&mut context, Epoch::new(1));
            let replacement = state_sync(&mut context, Epoch::new(2));
            drop(plan(context.child("first"), "overwrite", Some(first_value)).await);
            drop(
                plan(
                    context.child("replacement"),
                    "overwrite",
                    Some(replacement.clone()),
                )
                .await,
            );

            let reopened = plan(context.child("reopened"), "overwrite", None).await;
            assert_state_sync(
                reopened.resolve(context.child("resolve"), None).await,
                &replacement,
            );
        });
    }

    #[test]
    #[should_panic(expected = "state sync artifact and floor must be in the same epoch")]
    fn artifact_beyond_floor_panics_at_init() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut mismatched = state_sync(&mut context, Epoch::new(2));
            mismatched.info.epoch = Epoch::new(3);
            let _ = plan(context.child("init"), "mismatch", Some(mismatched)).await;
        });
    }

    #[test]
    #[should_panic(expected = "state sync artifact and floor must be in the same epoch")]
    fn artifact_below_floor_panics_at_init() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut mismatched = state_sync(&mut context, Epoch::new(3));
            mismatched.info.epoch = Epoch::new(2);
            let _ = plan(context.child("init"), "mismatch-below", Some(mismatched)).await;
        });
    }

    #[test]
    #[should_panic(expected = "provided state sync material must satisfy codec config")]
    fn oversized_provided_material_panics_at_init() {
        deterministic::Runner::default().start(|mut context| async move {
            let provided = state_sync(&mut context, Epoch::new(2));
            let mut config = config("oversized-provided");
            config.max_participants = NZU32!(3);
            let _ = TestPlan::init(context.child("init"), config, Some(provided)).await;
        });
    }

    #[test]
    #[should_panic(expected = "provided state sync material must satisfy codec config")]
    fn invalid_addressed_directory_panics_at_init() {
        deterministic::Runner::default().start(|mut context| async move {
            let StateSync { info, floor } = state_sync(&mut context, Epoch::new(2));
            let peers = info
                .participants()
                .tracked_peers()
                .union()
                .into_iter()
                .chain([ed25519::PrivateKey::from_seed(10_000).public_key()]);
            let directory = peers
                .enumerate()
                .map(|(index, peer)| {
                    let socket = SocketAddr::from(([127, 0, 0, 1], index as u16 + 1));
                    (peer, Address::Symmetric(socket))
                })
                .collect::<Addresses<_>>();
            let EpochInfo {
                outcome,
                epoch,
                output,
                players,
                next_players,
                ..
            } = info;
            let invalid = StateSync {
                info: EpochInfo {
                    outcome,
                    epoch,
                    output,
                    players,
                    next_players,
                    directory,
                },
                floor,
            };

            let _ = Plan::<
                mocks::TestScheme,
                mocks::TestDigest,
                mocks::TestBlsVariant,
                Addresses<mocks::TestPublicKey>,
            >::init(
                context.child("init"),
                config("invalid-directory"),
                Some(invalid),
            )
            .await;
        });
    }

    #[test]
    fn disabled_resolves_none_without_storage() {
        deterministic::Runner::default().start(|context| async move {
            let plan = TestPlan::disabled();
            assert!(plan.resolve(context, None).await.is_none());
        });
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use crate::dkg::{network::Addresses, tests::mocks};
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>> => 8192,
        CodecConformance<StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant, Addresses<mocks::TestPublicKey>>> => 8192,
        CodecConformance<Checkpoint<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>> => 8192,
        CodecConformance<Checkpoint<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant, Addresses<mocks::TestPublicKey>>> => 8192,
    }
}
