//! Durable state-sync material and epoch checkpoints for DKG restart and probe serving.
//!
//! Restart derives the active epoch from marshal's processed height, but marshal may have pruned
//! the boundary block that introduced it or, after application state sync, never stored it. The DKG
//! actors therefore store what they need while they process each block, and [`Plan`] keeps it
//! outside marshal in two partitions under one prefix. Restart and the [`probe`](crate::dkg::probe)
//! read them as [Marshal Retention](crate::dkg#marshal-retention) describes.
//!
//! - The state-sync partition holds the [`StateSync`] material given to [`Plan::init`] and the
//!   height of its floor block. The reshare actor records that height when a startup first receives
//!   the floor block from marshal. A later startup deletes the record once marshal's recovered
//!   epoch is past the synced epoch.
//! - The checkpoint partition holds a [`Checkpoint`] for each epoch the orchestrator enters from
//!   its boundary block. The orchestrator records it when it reads the block from marshal at
//!   startup, and at each live boundary before it acknowledges the final block. Recording a
//!   checkpoint drops those of epochs before the one recovered from marshal's processed height.
//!
//! A plan loads the retained checkpoints when it opens, and its clones share that copy in memory,
//! so reading a checkpoint does not touch storage. Recording one syncs the partition before it
//! updates the copy in memory.

use crate::dkg::{
    ReshareBlock,
    network::Directory,
    types::{EpochInfo, Payload},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, Decode as _, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Epochable as _,
    marshal::core::{Processed, Variant as MarshalVariant},
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, Epocher, FixedEpocher, Height},
};
#[cfg(feature = "arbitrary")]
use commonware_cryptography::bls12381::dkg::feldman_desmedt::Output;
use commonware_cryptography::{
    Digest,
    bls12381::primitives::{sharing::ModeVersion, variant::Variant},
    certificate::Verifier,
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
use std::{collections::BTreeMap, fmt, num::NonZeroU32, sync::Arc};

const STATE_SYNC_KEY: FixedBytes<1> = fixed_bytes!("00");
const STATE_SYNC_SUFFIX: &str = "_dkg_state_sync";
const CHECKPOINT_SUFFIX: &str = "_dkg_checkpoint";
type EpochInfoCodecConfig = (NonZeroU32, ModeVersion);

/// Storage settings for a DKG state-sync recovery plan.
///
/// The participant and mode limits bound every [`EpochInfo`] in persisted state-sync material, and
/// the block codec configuration bounds the boundary block of each checkpoint.
#[derive(Clone, Debug)]
pub struct Config<B> {
    /// Stable node-wide partition prefix.
    pub partition_prefix: String,

    /// Maximum entries accepted in each persisted participant set.
    pub max_participants: NonZeroU32,

    /// Maximum sharing mode version accepted in persisted epoch information.
    pub max_supported_mode: ModeVersion,

    /// Marshal's codec configuration for the application's blocks.
    pub block_codec_config: B,
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

/// BLS variant carried by a marshal variant's application block.
pub(crate) type BlsVariant<MV> =
    <<MV as MarshalVariant>::ApplicationBlock as ReshareBlock>::Variant;

/// Directory carried by a marshal variant's application block.
type Dir<MV> = <<MV as MarshalVariant>::ApplicationBlock as ReshareBlock>::Directory;

/// Codec configuration of a marshal variant's application block.
type BlockCfg<MV> = <<MV as MarshalVariant>::ApplicationBlock as Read>::Cfg;

/// State-sync material for a marshal variant.
type Material<S, MV> = StateSync<S, <MV as MarshalVariant>::Commitment, BlsVariant<MV>, Dir<MV>>;

/// The stored state-sync record for a marshal variant.
type Stored<S, MV> = Record<S, <MV as MarshalVariant>::Commitment, BlsVariant<MV>, Dir<MV>>;

/// Epoch info for a marshal variant.
type Info<S, MV> = EpochInfo<BlsVariant<MV>, <S as Verifier>::PublicKey, Dir<MV>>;

/// The boundary block an epoch starts from, with marshal's finalization of it when marshal has one.
///
/// The orchestrator copies the block from marshal when it enters the epoch, so restart and the
/// [`probe`](crate::dkg::probe) read the epoch from here after marshal prunes the block. The block
/// carries the epoch's [`EpochInfo`], and its commitment is the root the epoch's Simplex engine
/// starts from.
///
/// Marshal may hold a boundary block without its finalization when it repaired the block by walking
/// back from a later finalized block, and genesis has none. A checkpoint without a finalization
/// still restarts its epoch, but the probe does not serve that epoch.
pub struct Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    block: MV::StoredBlock,
    commitment: MV::Commitment,
    finalization: Option<Finalization<S, MV::Commitment>>,
}

impl<S, MV> Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    /// Creates a checkpoint of the boundary `block` with marshal's `finalization` of it, if any.
    pub(crate) fn new(
        block: MV::Block,
        finalization: Option<Finalization<S, MV::Commitment>>,
    ) -> Self {
        let commitment = MV::commitment(&block);
        Self {
            block: block.into(),
            commitment,
            finalization,
        }
    }

    /// Returns the commitment of the boundary block.
    pub(crate) const fn commitment(&self) -> MV::Commitment {
        self.commitment
    }

    /// Returns the finalization of the boundary block, if the checkpoint holds one.
    pub(crate) const fn finalization(&self) -> Option<&Finalization<S, MV::Commitment>> {
        self.finalization.as_ref()
    }

    /// Returns the boundary block.
    pub(crate) fn block(&self) -> MV::Block {
        MV::restore(self.block.clone(), MV::commitment_to_inner(self.commitment))
    }

    /// Returns the epoch info carried by the boundary block.
    ///
    /// The checkpoint keeps no separate copy, so this reads the info from the block's payload.
    /// Panics if the block carries no epoch info. [`Plan::record`] rejects such a checkpoint.
    pub(crate) fn info(&self) -> Info<S, MV> {
        let block = MV::into_shared(self.block());
        match block.inner().payload() {
            Some(Payload::EpochInfo(info)) => info,
            _ => panic!("checkpoint block must carry epoch info"),
        }
    }
}

impl<S, MV> Clone for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            block: self.block.clone(),
            commitment: self.commitment,
            finalization: self.finalization.clone(),
        }
    }
}

impl<S, MV> fmt::Debug for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Checkpoint")
            .field("commitment", &self.commitment)
            .field("finalization", &self.finalization)
            .finish_non_exhaustive()
    }
}

impl<S, MV> PartialEq for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
    MV::StoredBlock: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.block == other.block
            && self.commitment == other.commitment
            && self.finalization == other.finalization
    }
}

impl<S, MV> Eq for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
    MV::StoredBlock: Eq,
{
}

impl<S, MV> Write for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.block.write(writer);
        self.commitment.write(writer);
        self.finalization.write(writer);
    }
}

impl<S, MV> EncodeSize for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    fn encode_size(&self) -> usize {
        self.block.encode_size() + self.commitment.encode_size() + self.finalization.encode_size()
    }
}

impl<S, MV> Read for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    type Cfg = (BlockCfg<MV>, <S::Certificate as Read>::Cfg);

    fn read_cfg(
        reader: &mut impl Buf,
        (block, certificate): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            block: MV::StoredBlock::read_cfg(reader, block)?,
            commitment: MV::Commitment::read(reader)?,
            finalization: Option::<Finalization<S, MV::Commitment>>::read_cfg(reader, certificate)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S, MV> arbitrary::Arbitrary<'_> for Checkpoint<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
    MV::StoredBlock: for<'a> arbitrary::Arbitrary<'a>,
    MV::Commitment: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            block: u.arbitrary()?,
            commitment: u.arbitrary()?,
            finalization: u.arbitrary()?,
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

/// Persisted state-sync material and the height of its floor block, once a startup has
/// received that block from marshal.
///
/// A restart in the synced epoch that finds the floor block processed takes the height from
/// here and resumes from marshal's processed position, so marshal may prune the block.
/// Material provided to [`Plan::init`] starts with no height.
struct Record<S, D, V, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    material: StateSync<S, D, V, Dir>,
    floor_height: Option<Height>,
}

impl<S, D, V, Dir> Clone for Record<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            material: self.material.clone(),
            floor_height: self.floor_height,
        }
    }
}

impl<S, D, V, Dir> fmt::Debug for Record<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Record")
            .field("material", &self.material)
            .field("floor_height", &self.floor_height)
            .finish()
    }
}

impl<S, D, V, Dir> PartialEq for Record<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn eq(&self, other: &Self) -> bool {
        self.material == other.material && self.floor_height == other.floor_height
    }
}

impl<S, D, V, Dir> Eq for Record<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
}

impl<S, D, V, Dir> Write for Record<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.material.write(writer);
        self.floor_height.write(writer);
    }
}

impl<S, D, V, Dir> EncodeSize for Record<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    fn encode_size(&self) -> usize {
        self.material.encode_size() + self.floor_height.encode_size()
    }
}

impl<S, D, V, Dir> Read for Record<S, D, V, Dir>
where
    S: Scheme<D>,
    D: Digest,
    V: Variant,
    Dir: Directory<S::PublicKey>,
{
    type Cfg = <StateSync<S, D, V, Dir> as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            material: StateSync::read_cfg(reader, cfg)?,
            floor_height: Option::<Height>::read_cfg(reader, &())?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S, D, V, Dir> arbitrary::Arbitrary<'_> for Record<S, D, V, Dir>
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
            material: u.arbitrary()?,
            floor_height: u.arbitrary()?,
        })
    }
}

/// Partition prefix and codec limits shared by the plan's records.
#[derive(Clone)]
struct Storage<C> {
    partition_prefix: String,
    codec_config: EpochInfoCodecConfig,
    block_codec_config: C,
}

enum MaterialState<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    Pending(Option<Stored<S, MV>>),
    Resolved(Option<Stored<S, MV>>),
}

/// The plan's records, with every retained checkpoint mirrored from storage so reads do not
/// reopen the partition.
struct PlanState<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    material: MaterialState<S, MV>,
    checkpoints: BTreeMap<Epoch, Checkpoint<S, MV>>,
}

/// Shared startup recovery plan for DKG actors.
///
/// Initialize one plan after obtaining optional application state-sync material and before starting
/// either DKG actor. Give a clone to the reshare actor, the orchestrator, and the probe through
/// [`Mailbox::attach`](crate::dkg::probe::Mailbox::attach). Clones share the material decision and
/// the checkpoints, and they serialize their storage access. Separately initialized plans do not,
/// so initialize only one plan per partition prefix.
///
/// A [`Plan::disabled`] plan stores nothing, so every restart reads its epoch's boundary block from
/// marshal and the probe serves no epoch. Use it for deployments that never restart into a later
/// epoch, such as a one-shot DKG.
pub struct Plan<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    state: Arc<AsyncMutex<PlanState<S, MV>>>,
    storage: Option<Storage<BlockCfg<MV>>>,
}

impl<S, MV> Clone for Plan<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            storage: self.storage.clone(),
        }
    }
}

impl<S, MV> fmt::Debug for Plan<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Plan").finish_non_exhaustive()
    }
}

impl<S, MV> Plan<S, MV>
where
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    /// Opens the plan's partitions, durably stores any provided state-sync material, and loads the
    /// retained checkpoints into memory.
    ///
    /// Provided material replaces any existing material and the floor height recorded for it.
    /// Without provided material, the plan loads the existing material, if any. The returned plan
    /// may be passed to the actors immediately.
    ///
    /// # Panics
    ///
    /// Panics if storage cannot be loaded or synchronized, if provided or
    /// persisted material has mismatched artifact and floor epochs, or if
    /// provided material violates the configured codec limits.
    pub async fn init<E: Context>(
        context: E,
        config: Config<BlockCfg<MV>>,
        provided: Option<Material<S, MV>>,
    ) -> Self {
        let codec_config = (config.max_participants, config.max_supported_mode);
        if let Some(provided) = &provided {
            assert_provided(provided, codec_config);
        }
        let storage = Storage {
            partition_prefix: config.partition_prefix,
            codec_config,
            block_codec_config: config.block_codec_config,
        };
        let checkpoints_context = context.child("checkpoints");
        let mut store = open_state_sync::<E, S, MV>(context, &storage).await;
        if let Some(provided) = provided {
            store.put(
                STATE_SYNC_KEY,
                Record {
                    material: provided,
                    floor_height: None,
                },
            );
            store = store
                .sync()
                .await
                .expect("failed to persist DKG state sync metadata");
        }
        let candidate = store.get(&STATE_SYNC_KEY).cloned();
        if let Some(candidate) = &candidate {
            assert_epoch(&candidate.material);
        }
        drop(store);

        let store = open_checkpoints::<E, S, MV>(checkpoints_context, &storage).await;
        let checkpoints = store
            .keys()
            .map(|key| {
                let checkpoint = store.get(key).expect("key must have a value").clone();
                (Epoch::new(u64::from(key)), checkpoint)
            })
            .collect();
        drop(store);

        Self {
            state: Arc::new(AsyncMutex::new(PlanState {
                material: MaterialState::Pending(candidate),
                checkpoints,
            })),
            storage: Some(storage),
        }
    }

    /// Creates a plan that never accesses storage, so it resolves to no material and
    /// records no checkpoints.
    pub fn disabled() -> Self {
        Self {
            state: Arc::new(AsyncMutex::new(PlanState {
                material: MaterialState::Resolved(None),
                checkpoints: BTreeMap::new(),
            })),
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
    ) -> Option<Material<S, MV>> {
        let mut state = self.state.lock().await;
        let candidate = match &state.material {
            MaterialState::Resolved(resolved) => {
                return resolved.as_ref().map(|record| record.material.clone());
            }
            MaterialState::Pending(candidate) => candidate.clone(),
        };

        let Some(candidate) = candidate else {
            state.material = MaterialState::Resolved(None);
            return None;
        };
        if recovered_epoch.is_none_or(|epoch| epoch <= candidate.material.floor.epoch()) {
            let material = candidate.material.clone();
            state.material = MaterialState::Resolved(Some(candidate));
            return Some(material);
        }

        let storage = self
            .storage
            .as_ref()
            .expect("pending plan must have storage");
        let mut store = open_state_sync::<E, S, MV>(context, storage).await;
        store.remove(&STATE_SYNC_KEY);
        store
            .sync()
            .await
            .expect("failed to delete stale DKG state sync metadata");
        state.material = MaterialState::Resolved(None);
        None
    }

    /// Returns the floor block height recorded with the material [`Self::resolve`]
    /// kept, if any.
    pub(crate) async fn floor_height(&self) -> Option<Height> {
        match &self.state.lock().await.material {
            MaterialState::Resolved(Some(record)) => record.floor_height,
            _ => None,
        }
    }

    /// Durably records `height` as the floor block height of the material
    /// [`Self::resolve`] kept.
    ///
    /// Does nothing unless [`Self::resolve`] has kept material. Panics if storage fails.
    pub(crate) async fn record_floor_height<E: Context>(&self, context: E, height: Height) {
        let mut state = self.state.lock().await;
        let MaterialState::Resolved(Some(record)) = &mut state.material else {
            return;
        };
        record.floor_height = Some(height);
        let storage = self
            .storage
            .as_ref()
            .expect("kept material must have storage");
        let mut store = open_state_sync::<E, S, MV>(context, storage).await;
        store.put(STATE_SYNC_KEY, record.clone());
        store
            .sync()
            .await
            .expect("DKG state sync floor height must persist");
    }

    /// Returns the checkpoint recorded for `epoch`, if any, from memory.
    pub(crate) async fn checkpoint(&self, epoch: Epoch) -> Option<Checkpoint<S, MV>> {
        self.state.lock().await.checkpoints.get(&epoch).cloned()
    }

    /// Durably records `checkpoint` for `epoch` and drops every other checkpoint for an epoch
    /// before `retained_from`, in storage and then in memory.
    ///
    /// `retained_from` must not be later than the epoch any later restart recovers from marshal's
    /// processed height. A disabled plan records nothing.
    ///
    /// Panics if storage fails or if the checkpoint's block does not carry the info of `epoch`.
    /// Also panics if the checkpoint does not decode under the plan's block codec configuration,
    /// since every later load of it would fail.
    pub(crate) async fn record<E: Context>(
        &self,
        context: E,
        epoch: Epoch,
        checkpoint: Checkpoint<S, MV>,
        retained_from: Epoch,
    ) {
        let Some(storage) = &self.storage else {
            return;
        };
        assert!(
            checkpoint.info().epoch == epoch,
            "checkpoint block must carry the info of its epoch"
        );
        Checkpoint::<S, MV>::decode_cfg(
            checkpoint.encode(),
            &(
                storage.block_codec_config.clone(),
                S::certificate_codec_config_unbounded(),
            ),
        )
        .expect("checkpoint must satisfy codec config");

        // Opening a metadata store repairs a copy that fails validation, so the lock keeps clones
        // from opening the partition while another clone writes it.
        let mut state = self.state.lock().await;
        let mut store = open_checkpoints::<E, S, MV>(context, storage).await;
        store.retain(|key, _| Epoch::new(u64::from(key)) >= retained_from);
        store.put(U64::new(epoch.get()), checkpoint.clone());
        store
            .sync()
            .await
            .expect("failed to persist DKG checkpoint metadata");

        state.checkpoints.retain(|kept, _| *kept >= retained_from);
        state.checkpoints.insert(epoch, checkpoint);
    }
}

async fn open_state_sync<E, S, MV>(
    context: E,
    storage: &Storage<BlockCfg<MV>>,
) -> Metadata<E, FixedBytes<1>, Stored<S, MV>>
where
    E: Context,
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
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

async fn open_checkpoints<E, S, MV>(
    context: E,
    storage: &Storage<BlockCfg<MV>>,
) -> Metadata<E, U64, Checkpoint<S, MV>>
where
    E: Context,
    S: Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
{
    Metadata::init(
        context,
        metadata::Config {
            partition: format!("{}{CHECKPOINT_SUFFIX}", storage.partition_prefix),
            codec_config: (
                storage.block_codec_config.clone(),
                S::certificate_codec_config_unbounded(),
            ),
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

    /// Marshal variant whose blocks carry addressed directories.
    type AddressedVariant = commonware_consensus::marshal::standard::Standard<
        mocks::MockBlock<mocks::TestDigest, mocks::TestContext, Addresses<mocks::TestPublicKey>>,
    >;
    use commonware_consensus::{
        simplex::types::{Finalize, Proposal},
        types::{Round, View},
    };
    use commonware_cryptography::{
        Digested, Digestible as _, Hasher as _, Sha256, Signer as _,
        bls12381::{dkg::feldman_desmedt::deal, primitives::sharing::Mode},
        ed25519,
    };
    use commonware_p2p::Address;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{N3f1, NZU32, TestRng, non_empty, ordered::Set};
    use std::net::SocketAddr;

    type TestStateSync = StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>;

    /// A quorum finalization of `payload` in the first view of `epoch`.
    fn finalization(
        schemes: &[mocks::TestScheme],
        epoch: Epoch,
        payload: mocks::TestDigest,
    ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
        let proposal = Proposal::new(Round::new(epoch, View::new(1)), View::zero(), payload);
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("scheme must sign"))
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
            .expect("test finalizes must form a quorum")
    }

    fn state_sync(context: &mut deterministic::Context, epoch: Epoch) -> TestStateSync {
        let fixture = mocks::scheme_fixture_n(context, 4);
        let participants = Set::from_iter_dedup(fixture.participants);
        let (output, _) = deal::<mocks::TestBlsVariant, _, N3f1>(
            TestRng::new(epoch.get() + 1),
            Mode::NonZeroCounter,
            participants.clone(),
        )
        .expect("test DKG output");
        let floor = finalization(
            &fixture.schemes,
            epoch,
            Sha256::hash(&[b"state sync floor"]),
        );
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

    type TestPlan = Plan<mocks::TestScheme, mocks::TestMarshalVariant>;

    fn config(partition: &str) -> Config<()> {
        Config {
            partition_prefix: partition.into(),
            max_participants: NZU32!(16),
            max_supported_mode: crate::dkg::tests::max_supported_mode(),
            block_codec_config: (),
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

    type TestCheckpoint = Checkpoint<mocks::TestScheme, mocks::TestMarshalVariant>;

    /// A block at the height of `epoch`'s boundary carrying `info`.
    fn boundary_block(
        epoch: Epoch,
        info: EpochInfo<mocks::TestBlsVariant, mocks::TestPublicKey>,
    ) -> mocks::TestBlock {
        let leader = info
            .players
            .iter()
            .next()
            .expect("test epoch must have players")
            .clone();
        let parent = Sha256::hash(&[&epoch.get().to_be_bytes()]);
        let height = Height::new(epoch.get() * 10);
        mocks::TestBlock::new::<Sha256>(
            mocks::TestContext {
                round: Round::new(epoch, View::new(1)),
                leader,
                parent: (View::zero(), parent),
            },
            parent,
            height,
            height.get(),
        )
        .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestPublicKey>(
            NZU32!(16),
            Payload::EpochInfo(info),
        )
    }

    /// A checkpoint of a boundary block carrying `epoch`'s info, without a finalization.
    fn checkpoint(context: &mut deterministic::Context, epoch: Epoch) -> TestCheckpoint {
        let block = boundary_block(epoch, state_sync(context, epoch).info);
        let digest = block.digest();
        Checkpoint::new(Digested::precomputed(block, digest), None)
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
            for (epoch, checkpoint, retained_from) in
                [(3, &first, 3), (4, &second, 3), (5, &third, 4)]
            {
                recorder
                    .record(
                        context.child("record"),
                        Epoch::new(epoch),
                        checkpoint.clone(),
                        Epoch::new(retained_from),
                    )
                    .await;
            }
            drop(recorder);

            // The last record dropped epoch three and kept every later epoch.
            let reopened = plan(context.child("reopened"), "checkpoints", None).await;
            let read = |epoch| reopened.checkpoint(Epoch::new(epoch));
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
            plan.record(
                context.child("record"),
                Epoch::new(2),
                recorded.clone(),
                Epoch::new(2),
            )
            .await;

            assert!(
                plan.resolve(context.child("resolve"), Some(Epoch::new(3)))
                    .await
                    .is_none()
            );
            assert_eq!(
                plan.checkpoint(Epoch::new(2)).await.as_ref(),
                Some(&recorded)
            );
        });
    }

    /// A reopened plan restores the recorded boundary block with its commitment, its
    /// finalization, and the epoch info the block carries.
    #[test]
    fn checkpoint_restores_recorded_block() {
        deterministic::Runner::default().start(|mut context| async move {
            let info = state_sync(&mut context, Epoch::new(3)).info;
            let block = boundary_block(Epoch::new(3), info.clone());
            let digest = block.digest();
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let boundary_finalization = finalization(&fixture.schemes, Epoch::new(2), digest);
            let recorder = plan(context.child("recorder"), "restore", None).await;
            recorder
                .record(
                    context.child("record"),
                    Epoch::new(3),
                    Checkpoint::new(
                        Digested::precomputed(block.clone(), digest),
                        Some(boundary_finalization.clone()),
                    ),
                    Epoch::new(3),
                )
                .await;
            drop(recorder);

            let reopened = plan(context.child("reopened"), "restore", None).await;
            let restored = reopened
                .checkpoint(Epoch::new(3))
                .await
                .expect("checkpoint must survive reopening");
            let restored_block = restored.block();
            assert_eq!(restored_block.inner(), &block);
            assert_eq!(restored_block.digest(), digest);
            assert_eq!(restored.commitment(), digest);
            assert_eq!(restored.finalization(), Some(&boundary_finalization));
            assert_eq!(restored.info(), info);
        });
    }

    #[test]
    #[should_panic(expected = "checkpoint block must carry the info of its epoch")]
    fn record_rejects_checkpoint_for_another_epoch() {
        deterministic::Runner::default().start(|mut context| async move {
            let recorded = checkpoint(&mut context, Epoch::new(3));
            let plan = plan(context.child("plan"), "another-epoch", None).await;
            plan.record(
                context.child("record"),
                Epoch::new(4),
                recorded,
                Epoch::new(4),
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "checkpoint block must carry epoch info")]
    fn record_rejects_checkpoint_without_epoch_info() {
        deterministic::Runner::default().start(|context| async move {
            let block = mocks::genesis_block(ed25519::PrivateKey::from_seed(0).public_key());
            let digest = block.digest();
            let plan = plan(context.child("plan"), "no-info", None).await;
            plan.record(
                context.child("record"),
                Epoch::zero(),
                Checkpoint::new(Digested::precomputed(block, digest), None),
                Epoch::zero(),
            )
            .await;
        });
    }

    /// A disabled plan records no checkpoint and reads none back.
    #[test]
    fn disabled_plan_records_nothing() {
        deterministic::Runner::default().start(|mut context| async move {
            let recorded = checkpoint(&mut context, Epoch::new(1));
            let plan = TestPlan::disabled();
            plan.record(
                context.child("record"),
                Epoch::new(1),
                recorded,
                Epoch::new(1),
            )
            .await;
            assert!(plan.checkpoint(Epoch::new(1)).await.is_none());
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

    /// A recorded floor height survives reopening the plan until provided material replaces
    /// the material it was recorded for.
    #[test]
    fn floor_height_persists_until_material_is_replaced() {
        deterministic::Runner::default().start(|mut context| async move {
            // A height recorded for kept material is visible at once.
            let material = state_sync(&mut context, Epoch::new(2));
            let first = plan(
                context.child("first"),
                "floor-height",
                Some(material.clone()),
            )
            .await;
            assert_state_sync(
                first
                    .resolve(context.child("resolve"), Some(Epoch::new(2)))
                    .await,
                &material,
            );
            assert!(first.floor_height().await.is_none());
            first
                .record_floor_height(context.child("record"), Height::new(70))
                .await;
            assert_eq!(first.floor_height().await, Some(Height::new(70)));
            drop(first);

            // Reopening the plan loads the height with the material.
            let reopened = plan(context.child("reopened"), "floor-height", None).await;
            assert_state_sync(
                reopened
                    .resolve(context.child("resolve"), Some(Epoch::new(2)))
                    .await,
                &material,
            );
            assert_eq!(reopened.floor_height().await, Some(Height::new(70)));
            drop(reopened);

            // New material replaces the record, so it starts with no height.
            let replacement = state_sync(&mut context, Epoch::new(3));
            let replaced = plan(
                context.child("replaced"),
                "floor-height",
                Some(replacement.clone()),
            )
            .await;
            assert_state_sync(
                replaced
                    .resolve(context.child("resolve"), Some(Epoch::new(2)))
                    .await,
                &replacement,
            );
            assert!(replaced.floor_height().await.is_none());
        });
    }

    /// Recording a floor height does nothing without kept material, and a disabled plan
    /// reports no height.
    #[test]
    fn floor_height_requires_kept_material() {
        deterministic::Runner::default().start(|context| async move {
            // A plan with no stored material ignores a recorded height.
            let empty = plan(context.child("empty"), "no-material", None).await;
            assert!(
                empty
                    .resolve(context.child("resolve"), None)
                    .await
                    .is_none()
            );
            empty
                .record_floor_height(context.child("record"), Height::new(5))
                .await;
            assert!(empty.floor_height().await.is_none());

            // A disabled plan stores no material, so it has no height.
            let disabled = TestPlan::disabled();
            assert!(disabled.floor_height().await.is_none());
        });
    }

    /// Provided material leaves every checkpoint in place, so once startup deletes stale
    /// material, the recovered epoch still starts from its checkpoint.
    #[test]
    fn provided_material_keeps_checkpoints() {
        deterministic::Runner::default().start(|mut context| async move {
            // A plan without material records a checkpoint for epoch three.
            let recorded = checkpoint(&mut context, Epoch::new(3));
            let recorder = plan(context.child("recorder"), "kept", None).await;
            recorder
                .record(
                    context.child("record"),
                    Epoch::new(3),
                    recorded.clone(),
                    Epoch::new(3),
                )
                .await;
            drop(recorder);

            // Material for epoch two is stale once epoch three is recovered, so resolving
            // deletes it and the epoch-three checkpoint remains.
            let material = state_sync(&mut context, Epoch::new(2));
            let provided = plan(context.child("provided"), "kept", Some(material)).await;
            assert!(
                provided
                    .resolve(context.child("resolve"), Some(Epoch::new(3)))
                    .await
                    .is_none()
            );
            assert_eq!(
                provided.checkpoint(Epoch::new(3)).await.as_ref(),
                Some(&recorded)
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

            let _ = Plan::<mocks::TestScheme, AddressedVariant>::init(
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
        CodecConformance<Record<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>> => 8192,
        CodecConformance<Record<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant, Addresses<mocks::TestPublicKey>>> => 8192,
        CodecConformance<Checkpoint<mocks::TestScheme, mocks::TestMarshalVariant>> => 8192,
        CodecConformance<Checkpoint<mocks::TestScheme, commonware_consensus::marshal::standard::Standard<mocks::MockBlock<mocks::TestDigest, mocks::TestContext, Addresses<mocks::TestPublicKey>>>>> => 8192,
    }
}
