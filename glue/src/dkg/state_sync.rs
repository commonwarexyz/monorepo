//! Durable startup material for DKG actors after application state sync.
//!
//! A state-synced node may not have the finalized boundary block that introduced
//! its active epoch. [`Plan`] persists that public material before actors start
//! and shares one recovery decision between the reshare and orchestrator actors.
//! A later startup removes the record after marshal's recovered epoch advances
//! beyond the synced epoch.

use crate::dkg::types::EpochInfo;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
use commonware_consensus::{
    Epochable as _,
    marshal::core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
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
use commonware_utils::{fixed_bytes, sequence::FixedBytes, sync::AsyncMutex};
use std::{fmt, num::NonZeroU32, sync::Arc};

const STATE_SYNC_KEY: FixedBytes<1> = fixed_bytes!("00");
const STATE_SYNC_SUFFIX: &str = "_dkg_state_sync";
type EpochInfoCodecConfig = (NonZeroU32, ModeVersion);

/// Storage settings for a DKG state-sync recovery plan.
#[derive(Clone, Debug)]
pub struct Config {
    /// Stable node-wide partition prefix.
    pub partition_prefix: String,

    /// Maximum participants accepted in persisted epoch information.
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
/// The probe fixes the floor and the epoch info atomically, so the info
/// always describes the epoch containing the floor.
pub struct StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    /// Public information for the epoch containing the state-sync floor.
    pub info: EpochInfo<V, S::PublicKey>,

    /// Finalized floor selected for application state sync.
    pub floor: Finalization<S, D>,
}

impl<S, D, V> Clone for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            floor: self.floor.clone(),
        }
    }
}

impl<S, D, V> fmt::Debug for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateSync")
            .field("info", &self.info)
            .field("floor", &self.floor)
            .finish()
    }
}

impl<S, D, V> PartialEq for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info && self.floor == other.floor
    }
}

impl<S, D, V> Eq for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
}

impl<S, D, V> Write for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.info.write(writer);
        self.floor.write(writer);
    }
}

impl<S, D, V> EncodeSize for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        self.info.encode_size() + self.floor.encode_size()
    }
}

impl<S, D, V> Read for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
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
impl<S, D, V> arbitrary::Arbitrary<'_> for StateSync<S, D, V>
where
    S: Scheme<D>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    V: Variant,
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

/// Returns the epoch containing marshal's next unprocessed height.
pub(crate) async fn recovered_epoch<S, V>(
    marshal: &MarshalMailbox<S, V>,
    epocher: &FixedEpocher,
) -> Option<Epoch>
where
    S: commonware_cryptography::certificate::Scheme,
    V: MarshalVariant,
{
    let height = marshal.get_processed_height().await?.next();
    Some(
        epocher
            .containing(height)
            .expect("epocher must know recovered height")
            .epoch(),
    )
}

enum PlanState<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    Pending {
        candidate: Option<StateSync<S, D, V>>,
        partition: String,
        codec_config: EpochInfoCodecConfig,
    },
    Resolved(Option<StateSync<S, D, V>>),
}

/// Shared startup recovery plan for DKG actors.
///
/// Initialize one plan after obtaining optional application state-sync material
/// and before starting either DKG actor. Clones share the resolution decision,
/// so both actors observe the same material while using one durable partition.
/// Use [`Plan::disabled`] for deployments that never use application state sync.
pub struct Plan<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    state: Arc<AsyncMutex<PlanState<S, D, V>>>,
}

impl<S, D, V> Clone for Plan<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<S, D, V> fmt::Debug for Plan<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Plan").finish_non_exhaustive()
    }
}

impl<S, D, V> Plan<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    /// Initializes and durably records a DKG state-sync recovery candidate.
    ///
    /// Provided material replaces any existing record. Without provided
    /// material, the existing record is loaded. The store is closed before this
    /// method returns, making the plan safe to pass to actors immediately.
    ///
    /// # Panics
    ///
    /// Panics if storage cannot be loaded or synchronized, or if provided or
    /// persisted material has mismatched artifact and floor epochs.
    pub async fn init<E: Context>(
        context: E,
        config: Config,
        provided: Option<StateSync<S, D, V>>,
    ) -> Self {
        if let Some(provided) = &provided {
            assert_epoch(provided);
        }
        let partition = format!("{}{STATE_SYNC_SUFFIX}", config.partition_prefix);
        let codec_config = (config.max_participants, config.max_supported_mode);
        let mut store = open_store::<E, S, D, V>(context, partition.clone(), codec_config).await;
        if let Some(provided) = provided {
            store.put(STATE_SYNC_KEY, provided);
            store
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

    pub(crate) async fn resolve<E: Context>(
        &self,
        context: E,
        recovered_epoch: Option<Epoch>,
    ) -> Option<StateSync<S, D, V>> {
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

        let mut store = open_store::<E, S, D, V>(context, partition, codec_config).await;
        store.remove(&STATE_SYNC_KEY);
        store
            .sync()
            .await
            .expect("failed to delete stale DKG state sync metadata");
        drop(store);
        *state = PlanState::Resolved(None);
        None
    }
}

async fn open_store<E, S, D, V>(
    context: E,
    partition: String,
    epoch_info_codec_config: EpochInfoCodecConfig,
) -> Metadata<E, FixedBytes<1>, StateSync<S, D, V>>
where
    E: Context,
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    Metadata::init(
        context,
        metadata::Config {
            partition,
            codec_config: (
                epoch_info_codec_config,
                S::certificate_codec_config_unbounded(),
            ),
        },
    )
    .await
    .expect("failed to load DKG state sync metadata")
}

fn assert_epoch<S, D, V>(state_sync: &StateSync<S, D, V>)
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
{
    assert!(
        state_sync.info.epoch == state_sync.floor.epoch(),
        "state sync artifact and floor must be in the same epoch"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{tests::mocks, types::EpochOutcome};
    use commonware_consensus::{
        simplex::types::{Finalize, Proposal},
        types::{Round, View},
    };
    use commonware_cryptography::{
        Hasher as _, Sha256,
        bls12381::{dkg::feldman_desmedt::deal, primitives::sharing::Mode},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{N3f1, NZU32, TestRng, ordered::Set};

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
        let floor = Finalization::from_finalizes(&fixture.schemes[0], &finalizes, &Sequential)
            .expect("test finalization quorum");
        TestStateSync {
            info: EpochInfo {
                outcome: EpochOutcome::Success,
                epoch,
                output,
                players: participants.clone(),
                next_players: participants,
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
    use crate::dkg::tests::mocks;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>> => 8192,
    }
}
