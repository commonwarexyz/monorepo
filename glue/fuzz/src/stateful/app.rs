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
//!
//! Both applications are generic over the database backend, which owns the
//! workload one block applies and the extraction of the commitment a block
//! carries, and over the marshal variant, which owns the payload the block's
//! embedded consensus context names. The block itself is generic over the
//! variant only: every backend commits through the same [`StateCommitment`],
//! so consensus sees one block type per variant.

use super::{
    Ctx, Digest, PublicKey, Scheme,
    backend::{
        Backend, Batches, Databases, MerkleizedBatches, Readers, StateCommitment, Transition,
    },
    invariants::{Applied, EngineObservations},
    marshal::Marshal,
};
use commonware_codec::{Buf, Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
    marshal::ancestry::Ancestry,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digest as _, Digestible, Hasher, Sha256};
use commonware_glue::stateful::{Application, Input, Proposed};
use commonware_runtime::{BufMut, deterministic};
use commonware_utils::FuzzRng;
use futures::StreamExt;
use rand::RngExt as _;
use std::{fmt, marker::PhantomData, sync::Arc};

/// The state transition the correct application applies.
const CORRECT_BUMP: u64 = 1;

/// The state transition the faulty application applies instead.
const DIVERGENT_BUMP: u64 = 2;

/// Views covered by a fault schedule before it repeats.
const FAULT_VIEWS: usize = 64;

/// A block committing to the database state its execution produced.
pub(super) struct Block<M: Marshal> {
    pub(super) context: Ctx<M>,
    pub(super) parent: Digest,
    pub(super) height: Height,
    pub(super) commitment: StateCommitment,
}

impl<M: Marshal> Clone for Block<M> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            parent: self.parent,
            height: self.height,
            commitment: self.commitment.clone(),
        }
    }
}

impl<M: Marshal> fmt::Debug for Block<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("context", &self.context)
            .field("parent", &self.parent)
            .field("height", &self.height)
            .field("commitment", &self.commitment)
            .finish()
    }
}

impl<M: Marshal> PartialEq for Block<M> {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.parent == other.parent
            && self.height == other.height
            && self.commitment == other.commitment
    }
}

impl<M: Marshal> Eq for Block<M> {}

impl<M: Marshal> Write for Block<M> {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.commitment.write(buf);
    }
}

impl<M: Marshal> EncodeSize for Block<M> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.commitment.encode_size()
    }
}

impl<M: Marshal> Read for Block<M> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: Digest::read(buf)?,
            height: Height::read(buf)?,
            commitment: StateCommitment::read(buf)?,
        })
    }
}

impl<M: Marshal> Digestible for Block<M> {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl<M: Marshal> Heightable for Block<M> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<M: Marshal> ConsensusBlock for Block<M> {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl<M: Marshal> CertifiableBlock for Block<M> {
    type Context = Ctx<M>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<M: Marshal> Block<M> {
    /// The genesis block every engine starts from.
    pub(super) fn genesis(leader: PublicKey, commitment: StateCommitment) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), M::genesis_parent()),
            },
            parent: Digest::EMPTY,
            height: Height::zero(),
            commitment,
        }
    }

    /// Commit to an execution result.
    const fn committing(
        context: Ctx<M>,
        parent: Digest,
        height: Height,
        commitment: StateCommitment,
    ) -> Self {
        Self {
            context,
            parent,
            height,
            commitment,
        }
    }

    /// The block digest the embedded consensus context names as its parent.
    pub(super) fn context_parent(&self) -> Digest {
        M::payload_block(&self.context.parent.1)
    }
}

/// The application every correct node and the compromised identity's primary
/// half runs, identically configured.
pub(super) struct CorrectApp<B: Backend, M: Marshal> {
    genesis: Block<M>,
    observations: EngineObservations,
    backend: PhantomData<B>,
}

impl<B: Backend, M: Marshal> Clone for CorrectApp<B, M> {
    fn clone(&self) -> Self {
        Self {
            genesis: self.genesis.clone(),
            observations: self.observations.clone(),
            backend: PhantomData,
        }
    }
}

impl<B: Backend, M: Marshal> CorrectApp<B, M> {
    pub(super) const fn new(genesis: Block<M>, observations: EngineObservations) -> Self {
        Self {
            genesis,
            observations,
            backend: PhantomData,
        }
    }
}

impl<B: Backend, M: Marshal> Application<deterministic::Context> for CorrectApp<B, M> {
    type SigningScheme = Scheme;
    type Context = Ctx<M>;
    type Block = Block<M>;
    type Databases = Databases<B>;
    type Captured = ();
    type Provider = ();
    type Input = ();

    fn sync_targets(block: &Self::Block) -> super::backend::SyncTarget<B> {
        B::sync_target(&block.commitment)
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: Batches<B>,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let height = Height::new(parent.height().get() + 1);
        let merkleized = B::execute(
            Transition {
                view: context.1.round.view(),
                parent: parent.digest(),
                height,
                bump: CORRECT_BUMP,
            },
            batches,
        )
        .await;
        let commitment = B::commitment(&merkleized);
        let block = Block::committing(context.1, parent.digest(), height, commitment);
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: Batches<B>,
    ) -> Option<MerkleizedBatches<B>> {
        let mut ancestry = Box::pin(ancestry);
        let tip = ancestry.next().await?;
        let merkleized = B::execute(
            Transition {
                view: tip.context.round.view(),
                parent: tip.parent,
                height: tip.height(),
                bump: CORRECT_BUMP,
            },
            batches,
        )
        .await;
        let accepted = B::commitment(&merkleized) == tip.commitment;
        self.observations.record_verdict(tip.digest(), accepted);
        accepted.then_some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: Batches<B>,
    ) -> Option<MerkleizedBatches<B>> {
        Some(
            B::execute(
                Transition {
                    view: block.context.round.view(),
                    parent: block.parent,
                    height: block.height(),
                    bump: CORRECT_BUMP,
                },
                batches,
            )
            .await,
        )
    }

    async fn capture(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _block: &Self::Block,
        _batches: &MerkleizedBatches<B>,
        _readers: Readers<B>,
    ) {
    }

    async fn finalized(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        _captured: Self::Captured,
        readers: Readers<B>,
    ) {
        // The reader exposes the set's current root, which is this block's root
        // only because the stateful actor invokes `finalized` synchronously
        // inside finalization, after the batch is applied and before any later
        // height can be. A configuration that notifies without applying (the
        // skipped-block path taken when a finalized floor is attached) would
        // record a later height's root here and trip the intra-node arm of I2;
        // no node attaches a floor, so that path is never entered.
        let (root, oldest_retained) = {
            let db = readers.read().await;
            (B::canonical_root(&db), B::oldest_retained(&db))
        };
        self.observations.record_applied(Applied {
            height: block.height(),
            view: block.context.round.view(),
            root,
            prune_floor: B::prune_floor(&block.commitment),
            oldest_retained,
        });
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
pub(super) struct FaultyApp<B: Backend, M: Marshal> {
    inner: CorrectApp<B, M>,
    schedule: FaultSchedule,
}

impl<B: Backend, M: Marshal> Clone for FaultyApp<B, M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            schedule: self.schedule.clone(),
        }
    }
}

impl<B: Backend, M: Marshal> FaultyApp<B, M> {
    pub(super) const fn new(inner: CorrectApp<B, M>, schedule: FaultSchedule) -> Self {
        Self { inner, schedule }
    }
}

impl<B: Backend, M: Marshal> Application<deterministic::Context> for FaultyApp<B, M> {
    type SigningScheme = Scheme;
    type Context = Ctx<M>;
    type Block = Block<M>;
    type Databases = Databases<B>;
    type Captured = <CorrectApp<B, M> as Application<deterministic::Context>>::Captured;
    type Provider = ();
    type Input = ();

    fn sync_targets(block: &Self::Block) -> super::backend::SyncTarget<B> {
        <CorrectApp<B, M> as Application<deterministic::Context>>::sync_targets(block)
    }

    async fn genesis(&mut self) -> Self::Block {
        self.inner.genesis().await
    }

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: Batches<B>,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        match self.schedule.at(context.1.round.view()) {
            Fault::DeclineProposal => None,
            Fault::DivergentProposal => {
                let mut ancestry = Box::pin(ancestry);
                let parent = ancestry.next().await?;
                let height = Height::new(parent.height().get() + 1);
                let merkleized = B::execute(
                    Transition {
                        view: context.1.round.view(),
                        parent: parent.digest(),
                        height,
                        bump: DIVERGENT_BUMP,
                    },
                    batches,
                )
                .await;
                let commitment = B::commitment(&merkleized);
                let block = Block::committing(context.1, parent.digest(), height, commitment);
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
        batches: Batches<B>,
    ) -> Option<MerkleizedBatches<B>> {
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
        batches: Batches<B>,
    ) -> Option<MerkleizedBatches<B>> {
        self.inner.apply(context, block, batches).await
    }

    async fn capture(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: &MerkleizedBatches<B>,
        readers: Readers<B>,
    ) -> Self::Captured {
        self.inner.capture(context, block, batches, readers).await
    }

    async fn finalized(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        readers: Readers<B>,
    ) {
        self.inner
            .finalized(context, block, captured, readers)
            .await;
    }
}
