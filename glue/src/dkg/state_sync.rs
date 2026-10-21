//! Durable startup material for DKG actors after application state sync.
//!
//! A state-synced node may not have the finalized boundary block that introduced
//! its active epoch, nor the inclusion-window blocks between that epoch's
//! midpoint and its floor. [`Plan`] persists that public material before actors
//! start and shares one recovery decision between the reshare and orchestrator
//! actors. A later startup removes the record after marshal's recovered epoch
//! advances beyond the synced epoch.

use crate::dkg::{ReshareBlock, network::Directory, types::EpochInfo};
use bytes::BufMut;
use commonware_codec::{
    Buf, Decode as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, Write,
};
use commonware_consensus::{
    Epochable as _,
    marshal::core::{Processed, Variant as MarshalVariant},
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, Epocher, FixedEpocher},
};
#[cfg(feature = "arbitrary")]
use commonware_cryptography::bls12381::dkg::feldman_desmedt::Output;
use commonware_cryptography::{
    Digest, Signer,
    bls12381::{
        dkg::feldman_desmedt::SignedDealerLog,
        primitives::{sharing::ModeVersion, variant::Variant},
    },
};
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::{
    fixed_bytes,
    sequence::{FixedBytes, Unit},
    sync::AsyncMutex,
};
use std::{
    fmt,
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
};

const STATE_SYNC_KEY: FixedBytes<1> = fixed_bytes!("00");
const STATE_SYNC_SUFFIX: &str = "_dkg_state_sync";

/// Codec limits shared by [`EpochInfo`] and the window's dealer logs, plus the
/// number of logs a window may carry.
type CodecConfig = (NonZeroU32, ModeVersion, RangeCfg<usize>);

/// Storage settings for a DKG state-sync recovery plan.
#[derive(Clone, Debug)]
pub struct Config {
    /// Stable node-wide partition prefix.
    pub partition_prefix: String,

    /// Maximum entries accepted in each persisted participant set.
    pub max_participants: NonZeroU32,

    /// Maximum sharing mode version accepted in persisted epoch information.
    pub max_supported_mode: ModeVersion,

    /// Number of blocks in each epoch, which bounds the dealer logs a persisted
    /// inclusion window may carry.
    pub blocks_per_epoch: NonZeroU64,
}

impl Config {
    fn codec_config(&self) -> CodecConfig {
        let epocher = FixedEpocher::new(self.blocks_per_epoch);
        let capacity = inclusion_window_capacity(&epocher);
        (
            self.max_participants,
            self.max_supported_mode,
            RangeCfg::new(0..=capacity),
        )
    }
}

/// Returns the number of blocks that may carry dealer logs in an epoch: those
/// from the midpoint up to, but not including, the final block.
fn inclusion_window_capacity(epocher: &FixedEpocher) -> usize {
    let epoch = Epoch::zero();
    let midpoint = epocher
        .midpoint(epoch)
        .expect("epoch zero must be supported");
    let last = epocher.last(epoch).expect("epoch zero must be supported");
    usize::try_from(last.get() - midpoint.get()).expect("inclusion window must fit in usize")
}

/// Public material needed to start DKG actors in a state-synced epoch.
///
/// The epoch info replaces the boundary block that may be absent locally. The
/// floor is the finalized block selected for application state sync and gives
/// marshal a block from which to resume delivery. The window carries the dealer
/// logs of the finalized blocks marshal never delivers below the floor.
///
/// The info must describe the epoch containing the floor, and [`Plan::init`]
/// panics otherwise. See [State Sync](crate::dkg#state-sync) for how startup
/// pairs a probe artifact with a persisted floor.
pub struct StateSync<S, D, V, C, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    /// Public information for the epoch containing the state-sync floor.
    pub info: EpochInfo<V, S::PublicKey, Dir>,

    /// Finalized floor selected for application state sync.
    pub floor: Finalization<S, D>,

    /// Dealer logs carried by the finalized blocks from the floor epoch's
    /// midpoint up to the floor's parent, in ascending height order.
    ///
    /// Must be complete when the floor is in the late phase of its epoch and
    /// is empty otherwise (see [`probe::Artifact::window`](crate::dkg::probe::Artifact::window)).
    pub window: Vec<SignedDealerLog<V, C>>,
}

impl<S, D, V, C, Dir> Clone for StateSync<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            floor: self.floor.clone(),
            window: self.window.clone(),
        }
    }
}

impl<S, D, V, C, Dir> fmt::Debug for StateSync<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateSync")
            .field("info", &self.info)
            .field("floor", &self.floor)
            .field("window", &self.window.len())
            .finish()
    }
}

impl<S, D, V, C, Dir> PartialEq for StateSync<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info && self.floor == other.floor && self.window == other.window
    }
}

impl<S, D, V, C, Dir> Write for StateSync<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.info.write(writer);
        self.floor.write(writer);
        self.window.write(writer);
    }
}

impl<S, D, V, C, Dir> EncodeSize for StateSync<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    fn encode_size(&self) -> usize {
        self.info.encode_size() + self.floor.encode_size() + self.window.encode_size()
    }
}

impl<S, D, V, C, Dir> Read for StateSync<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    type Cfg = (CodecConfig, <S::Certificate as Read>::Cfg);

    fn read_cfg(
        reader: &mut impl Buf,
        ((max_participants, max_supported_mode, window), certificate): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            info: EpochInfo::read_cfg(reader, &(*max_participants, *max_supported_mode))?,
            floor: Finalization::read_cfg(reader, certificate)?,
            window: Vec::read_cfg(reader, &(*window, *max_participants))?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S, D, V, C, Dir> arbitrary::Arbitrary<'_> for StateSync<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey> + for<'a> arbitrary::Arbitrary<'a>,
    S::PublicKey: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    Output<V, S::PublicKey>: for<'a> arbitrary::Arbitrary<'a>,
    SignedDealerLog<V, C>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            info: u.arbitrary()?,
            floor: u.arbitrary()?,
            window: u.arbitrary()?,
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

enum PlanState<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    Pending {
        candidate: Option<StateSync<S, D, V, C, Dir>>,
        partition: String,
        codec_config: CodecConfig,
    },
    Resolved(Option<StateSync<S, D, V, C, Dir>>),
}

/// Shared startup recovery plan for DKG actors.
///
/// Initialize one plan after obtaining optional application state-sync material
/// and before starting either DKG actor. Clones share the resolution decision,
/// so both actors observe the same material while using one durable partition.
/// Use [`Plan::disabled`] for deployments that never use application state sync.
pub struct Plan<S, D, V, C, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    state: SharedState<S, D, V, C, Dir>,
}

type SharedState<S, D, V, C, Dir> = Arc<AsyncMutex<PlanState<S, D, V, C, Dir>>>;

/// [`Plan`] for the blocks of marshal variant `MV`, whose payloads use the BLS
/// variant `V`.
pub type MarshalPlan<S, MV, V> = Plan<
    S,
    <MV as MarshalVariant>::Commitment,
    V,
    <<MV as MarshalVariant>::ApplicationBlock as ReshareBlock>::Signer,
    <<MV as MarshalVariant>::ApplicationBlock as ReshareBlock>::Directory,
>;

impl<S, D, V, C, Dir> Clone for Plan<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<S, D, V, C, Dir> fmt::Debug for Plan<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Plan").finish_non_exhaustive()
    }
}

impl<S, D, V, C, Dir> Plan<S, D, V, C, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
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
    /// provided material violates the configured codec limits. A persisted
    /// record that does not decode under the current encoding also panics;
    /// clearing the partition lets the node start without it.
    pub async fn init<E: Context>(
        context: E,
        config: Config,
        provided: Option<StateSync<S, D, V, C, Dir>>,
    ) -> Self {
        let codec_config = config.codec_config();
        if let Some(provided) = &provided {
            assert_provided(provided, codec_config);
        }
        let partition = format!("{}{STATE_SYNC_SUFFIX}", config.partition_prefix);
        let mut store =
            open_store::<E, S, D, V, C, Dir>(context, partition.clone(), codec_config).await;
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
            state: Arc::new(AsyncMutex::new(PlanState::Pending {
                candidate,
                partition,
                codec_config,
            })),
        }
    }

    /// Creates a plan that never accesses storage and always resolves to none.
    pub fn disabled() -> Self {
        Self {
            state: Arc::new(AsyncMutex::new(PlanState::Resolved(None))),
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
    ) -> Option<StateSync<S, D, V, C, Dir>> {
        let mut state = self.state.lock().await;
        let (candidate, partition, codec_config) = match &*state {
            PlanState::Resolved(resolved) => return resolved.clone(),
            PlanState::Pending {
                candidate,
                partition,
                codec_config,
            } => (candidate.clone(), partition.clone(), *codec_config),
        };

        let Some(candidate) = candidate else {
            *state = PlanState::Resolved(None);
            return None;
        };
        if recovered_epoch.is_none_or(|epoch| epoch <= candidate.floor.epoch()) {
            *state = PlanState::Resolved(Some(candidate.clone()));
            return Some(candidate);
        }

        let mut store = open_store::<E, S, D, V, C, Dir>(context, partition, codec_config).await;
        store.remove(&STATE_SYNC_KEY);
        store
            .sync()
            .await
            .expect("failed to delete stale DKG state sync metadata");
        *state = PlanState::Resolved(None);
        None
    }
}

async fn open_store<E, S, D, V, C, Dir>(
    context: E,
    partition: String,
    codec_config: CodecConfig,
) -> Metadata<E, FixedBytes<1>, StateSync<S, D, V, C, Dir>>
where
    E: Context,
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    Metadata::init(
        context,
        metadata::Config {
            partition,
            codec_config: (codec_config, S::certificate_codec_config_unbounded()),
        },
    )
    .await
    .expect("failed to load DKG state sync metadata")
}

fn assert_provided<S, D, V, C, Dir>(
    state_sync: &StateSync<S, D, V, C, Dir>,
    codec_config: CodecConfig,
) where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    assert_epoch(state_sync);
    StateSync::<S, D, V, C, Dir>::decode_cfg(
        state_sync.encode(),
        &(codec_config, S::certificate_codec_config_unbounded()),
    )
    .expect("provided state sync material must satisfy codec config");
}

fn assert_epoch<S, D, V, C, Dir>(state_sync: &StateSync<S, D, V, C, Dir>)
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    C: Signer,
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
        Hasher as _, Sha256,
        bls12381::{
            dkg::feldman_desmedt::{Dealer, Info, Reveal, deal},
            primitives::sharing::Mode,
        },
        ed25519,
    };
    use commonware_p2p::Address;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{N3f1, NZU32, NZU64, TestRng, non_empty, ordered::Set, test_rng};
    use std::net::SocketAddr;

    const TEST_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_STATE_SYNC_TEST";

    type TestStateSync =
        StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant, mocks::TestSigner>;

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
            window: Vec::new(),
        }
    }

    /// Builds `count` signed dealer logs for a ceremony among four ed25519
    /// signers, one per dealer.
    fn window(count: usize) -> Vec<SignedDealerLog<mocks::TestBlsVariant, mocks::TestSigner>> {
        let signers = (0..4)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let players = Set::from_iter_dedup(signers.iter().map(ed25519::PrivateKey::public_key));
        let info = Info::<mocks::TestBlsVariant, _>::new::<N3f1>(
            TEST_NAMESPACE,
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            players.clone(),
            players,
        )
        .expect("valid info");
        signers
            .iter()
            .cycle()
            .take(count)
            .map(|signer| {
                let (dealer, _, _) =
                    Dealer::start::<N3f1>(test_rng(), info.clone(), signer.clone(), None)
                        .expect("dealer should start");
                dealer.finalize::<N3f1>()
            })
            .collect()
    }

    type TestPlan =
        Plan<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant, mocks::TestSigner>;

    fn config(partition: &str) -> Config {
        Config {
            partition_prefix: partition.into(),
            max_participants: NZU32!(16),
            max_supported_mode: crate::dkg::tests::max_supported_mode(),
            blocks_per_epoch: NZU64!(8),
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

    #[test]
    fn init_persists_before_resolve() {
        deterministic::Runner::default().start(|mut context| async move {
            // An eight-block epoch carries dealer logs in three blocks, so the
            // widest window a floor can skip holds three logs.
            let mut expected = state_sync(&mut context, Epoch::new(2));
            expected.window = window(3);
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
    #[should_panic(expected = "provided state sync material must satisfy codec config")]
    fn window_beyond_inclusion_capacity_panics_at_init() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut provided = state_sync(&mut context, Epoch::new(2));
            provided.window = window(4);
            let _ = plan(context.child("init"), "oversized-window", Some(provided)).await;
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
            let StateSync {
                info,
                floor,
                window,
            } = state_sync(&mut context, Epoch::new(2));
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
                window,
            };

            let _ = Plan::<
                mocks::TestScheme,
                mocks::TestDigest,
                mocks::TestBlsVariant,
                mocks::TestSigner,
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
        CodecConformance<StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant, mocks::TestSigner>> => 8192,
        CodecConformance<StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant, mocks::TestSigner, Addresses<mocks::TestPublicKey>>> => 8192,
    }
}
