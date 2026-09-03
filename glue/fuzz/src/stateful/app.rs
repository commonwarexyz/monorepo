//! The correct and faulty applications driven by the glue `Stateful` actor.
//!
//! The correct application is a pure function of the context, ancestry, and
//! batches it is given: all mutable state lives in the batches, so clones
//! invoked concurrently agree. It commits to its execution result in the block
//! it proposes and rejects a block whose committed state disagrees with the
//! result of executing it.
//!
//! The faulty application deviates only where the `Application` trait permits:
//! it may withhold a verdict, abstain from a verification, decline a proposal,
//! or propose a block committing to a different execution result. It never
//! returns a proposal whose commitments disagree with its merkleized result and
//! never returns a replay result that disagrees with the block being replayed,
//! because `Stateful` panics deliberately on both.

use super::{Ctx, Databases, Digest, PublicKey, Scheme, invariants::EngineObservations};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
    marshal::ancestry::Ancestry,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digest as _, Digestible, Hasher, Sha256};
use commonware_glue::stateful::{
    Application, Input, Proposed,
    db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
};
use commonware_runtime::{Buf, BufMut, deterministic};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
use commonware_utils::{FuzzRng, non_empty_range, range::NonEmptyRange};
use futures::StreamExt;
use rand::RngExt as _;
use std::sync::Arc;

/// Unmerkleized batches handed to the application.
pub(super) type Batches = <Databases as DatabaseSet<deterministic::Context>>::Unmerkleized;

/// Merkleized batches produced by the application.
pub(super) type MerkleizedBatches = <Databases as DatabaseSet<deterministic::Context>>::Merkleized;

/// Read-only database handles handed to `finalized`.
pub(super) type Readers = <Databases as DatabaseSet<deterministic::Context>>::Readers;

/// The state transition the correct application applies to the counter.
const CORRECT_BUMP: u64 = 1;

/// The state transition the faulty application applies instead.
const DIVERGENT_BUMP: u64 = 2;

/// Views covered by a fault schedule before it repeats.
const FAULT_VIEWS: usize = 64;

fn u64_to_digest(value: u64) -> Digest {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    Digest::from(bytes)
}

fn digest_to_u64(digest: &Digest) -> u64 {
    let bytes: &[u8] = digest.as_ref();
    u64::from_be_bytes(bytes[..8].try_into().expect("digest is 32 bytes"))
}

/// A block committing to the database state its execution produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Block {
    pub(super) context: Ctx,
    pub(super) parent: Digest,
    pub(super) height: Height,
    pub(super) state_root: Digest,
    pub(super) range: NonEmptyRange<Location>,
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.state_root.write(buf);
        self.range.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.state_root.encode_size()
            + self.range.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: Digest::read(buf)?,
            height: Height::read(buf)?,
            state_root: Digest::read(buf)?,
            range: NonEmptyRange::read(buf)?,
        })
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl CertifiableBlock for Block {
    type Context = Ctx;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl Block {
    /// The genesis block every engine starts from.
    pub(super) fn genesis(
        leader: PublicKey,
        state_root: Digest,
        range: NonEmptyRange<Location>,
    ) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), Digest::EMPTY),
            },
            parent: Digest::EMPTY,
            height: Height::zero(),
            state_root,
            range,
        }
    }

    /// Commit to an execution result.
    fn committing(
        context: Ctx,
        parent: Digest,
        height: Height,
        merkleized: &MerkleizedBatches,
    ) -> Self {
        let bounds = merkleized.bounds();
        Self {
            context,
            parent,
            height,
            state_root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
        }
    }
}

/// Execute one block: bump a counter and record the height.
async fn execute(height: Height, bump: u64, mut batches: Batches) -> MerkleizedBatches {
    let counter = Sha256::hash(&[b"counter"]);
    let current = batches
        .get(&counter)
        .await
        .expect("counter read must succeed")
        .map_or(0, |value| digest_to_u64(&value));
    batches = batches.write(counter, Some(u64_to_digest(current + bump)));
    batches = batches.write(
        Sha256::hash(&[&height.get().to_be_bytes()]),
        Some(u64_to_digest(height.get())),
    );
    batches.merkleize().await.expect("merkleize must succeed")
}

/// The application every correct node and the compromised identity's primary
/// half runs, identically configured.
#[derive(Clone)]
pub(super) struct CorrectApp {
    genesis: Block,
    observations: EngineObservations,
}

impl CorrectApp {
    pub(super) const fn new(genesis: Block, observations: EngineObservations) -> Self {
        Self {
            genesis,
            observations,
        }
    }
}

impl Application<deterministic::Context> for CorrectApp {
    type SigningScheme = Scheme;
    type Context = Ctx;
    type Block = Block;
    type Databases = Databases;
    type Provider = ();
    type Input = ();

    fn sync_targets(block: &Self::Block) -> Target<commonware_storage::mmr::Family, Digest> {
        Target::new(block.state_root, block.range.clone())
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: Batches,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let height = Height::new(parent.height().get() + 1);
        let merkleized = execute(height, CORRECT_BUMP, batches).await;
        let block = Block::committing(context.1, parent.digest(), height, &merkleized);
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: Batches,
    ) -> Option<MerkleizedBatches> {
        let mut ancestry = Box::pin(ancestry);
        let tip = ancestry.next().await?;
        let merkleized = execute(tip.height(), CORRECT_BUMP, batches).await;
        let bounds = merkleized.bounds();
        let accepted = merkleized.root() == tip.state_root
            && non_empty_range!(bounds.inactivity_floor, bounds.tip.size) == tip.range;
        self.observations.record_verdict(tip.digest(), accepted);
        accepted.then_some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: Batches,
    ) -> MerkleizedBatches {
        execute(block.height(), CORRECT_BUMP, batches).await
    }

    async fn finalized(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        readers: Readers,
    ) {
        // The reader exposes the set's current root, which is this block's root
        // only because the stateful actor invokes `finalized` synchronously
        // inside finalization, after the batch is applied and before any later
        // height can be. A configuration that notifies without applying (the
        // skipped-block path taken when a finalized floor is attached) would
        // record a later height's root here and trip the intra-node arm of I2;
        // no node attaches a floor, so that path is never entered.
        let root = readers.read().await.root();
        self.observations
            .record_state(block.height(), block.context.round.view(), root);
    }
}

/// One deviation the faulty application may take in a view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// Behave exactly like the correct application.
    None,
    /// Return no verdict, which the trait models as permanent invalidity.
    RejectVerification,
    /// Decline to resolve a verification, which the trait defines as abstention.
    AbstainVerification,
    /// Propose a block committing to a different execution result.
    DivergentProposal,
    /// Decline to build a proposal.
    DeclineProposal,
}

/// Which deviations the faulty application may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultArming {
    /// Arm [`Fault::RejectVerification`].
    pub reject_verification: bool,
    /// Arm [`Fault::AbstainVerification`].
    pub abstain_verification: bool,
    /// Arm [`Fault::DivergentProposal`].
    pub divergent_proposal: bool,
    /// Arm [`Fault::DeclineProposal`].
    pub decline_proposal: bool,
}

impl FaultArming {
    fn armed(self) -> Vec<Fault> {
        let mut armed = Vec::with_capacity(4);
        if self.reject_verification {
            armed.push(Fault::RejectVerification);
        }
        if self.abstain_verification {
            armed.push(Fault::AbstainVerification);
        }
        if self.divergent_proposal {
            armed.push(Fault::DivergentProposal);
        }
        if self.decline_proposal {
            armed.push(Fault::DeclineProposal);
        }
        armed
    }
}

/// Per-view fault decisions, generated once from the run's byte tape and then
/// indexed by view rather than by call order, so concurrently invoked clones
/// agree.
#[derive(Clone)]
pub(super) struct FaultSchedule(Arc<[Fault; FAULT_VIEWS]>);

impl FaultSchedule {
    pub(super) fn new(rng: &mut FuzzRng, arming: FaultArming) -> Self {
        let mut faults = [Fault::None; FAULT_VIEWS];
        let armed = arming.armed();
        if armed.is_empty() {
            return Self(Arc::new(faults));
        }
        let mut density = [0u8; 1];
        rng.fill(&mut density[..]);
        let density = u32::from(density[0] % 4) + 1;
        let mut samples = [0u8; FAULT_VIEWS];
        rng.fill(&mut samples[..]);
        for (slot, sample) in faults.iter_mut().zip(samples) {
            if u32::from(sample % 8) >= density {
                continue;
            }
            *slot = armed[usize::from(sample >> 3) % armed.len()];
        }
        Self(Arc::new(faults))
    }

    fn at(&self, view: View) -> Fault {
        self.0[(view.get() % FAULT_VIEWS as u64) as usize]
    }
}

/// The application the compromised identity's secondary half runs.
#[derive(Clone)]
pub(super) struct FaultyApp {
    inner: CorrectApp,
    schedule: FaultSchedule,
}

impl FaultyApp {
    pub(super) const fn new(inner: CorrectApp, schedule: FaultSchedule) -> Self {
        Self { inner, schedule }
    }
}

impl Application<deterministic::Context> for FaultyApp {
    type SigningScheme = Scheme;
    type Context = Ctx;
    type Block = Block;
    type Databases = Databases;
    type Provider = ();
    type Input = ();

    fn sync_targets(block: &Self::Block) -> Target<commonware_storage::mmr::Family, Digest> {
        <CorrectApp as Application<deterministic::Context>>::sync_targets(block)
    }

    async fn genesis(&mut self) -> Self::Block {
        self.inner.genesis().await
    }

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: Batches,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        match self.schedule.at(context.1.round.view()) {
            Fault::DeclineProposal => None,
            Fault::DivergentProposal => {
                let mut ancestry = Box::pin(ancestry);
                let parent = ancestry.next().await?;
                let height = Height::new(parent.height().get() + 1);
                let merkleized = execute(height, DIVERGENT_BUMP, batches).await;
                let block = Block::committing(context.1, parent.digest(), height, &merkleized);
                Some(Proposed { block, merkleized })
            }
            _ => {
                let proposed = self
                    .inner
                    .propose(context, ancestry, batches, input)
                    .await?;
                Some(Proposed {
                    block: proposed.block,
                    merkleized: proposed.merkleized,
                })
            }
        }
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: Batches,
    ) -> Option<MerkleizedBatches> {
        match self.schedule.at(context.1.round.view()) {
            Fault::RejectVerification => None,
            Fault::AbstainVerification => std::future::pending().await,
            _ => self.inner.verify(context, ancestry, batches).await,
        }
    }

    async fn apply(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: Batches,
    ) -> MerkleizedBatches {
        self.inner.apply(context, block, batches).await
    }

    async fn finalized(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        readers: Readers,
    ) {
        self.inner.finalized(context, block, readers).await;
    }
}
