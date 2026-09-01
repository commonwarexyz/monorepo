//! Capabilities the machine issues to the attached runtime.

use crate::{
    multimmit::{
        machine::{
            da::DaChoice,
            durability::{DurableJob, EffectId, PersistDirective},
            finality::LqcAggregateJob,
            producer::{BuildJob, CustodyCancellation, CustodyJob, ProductionTimer},
            resolution::ResolutionJob,
            verification::{Observation, VerifyJob},
            view::{NullificationRecoveryJob, ViewTimer, VqcAggregateJob},
        },
        types::{Artifact, ArtifactId, BlockRef, ChainId, DaVote, SignedTransactionBlock},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// Immutable work the machine issues, grouped by the runtime piece that executes it.
#[derive(Clone, Debug)]
pub(crate) enum Capability<V: Variant, D: Digest> {
    /// Cryptographically verify retained decoded artifacts.
    Verify(VerifyJob<V, D>),
    /// Quarantine identities named by self-contained authenticated equivocation evidence.
    Quarantine(Vec<Participant>),
    /// Append domain events after installing pre-publication resolver custody.
    Journal(PersistDirective<V, D>),
    /// Install resolver custody and accounting released by a durable acknowledgement.
    Acknowledged {
        /// Proofs the acknowledged batch made servable.
        retention: Vec<Arc<Artifact<V, D>>>,
        /// Nullifications the acknowledged batch forwarded.
        forwarded_nullifications: usize,
    },
    /// Execute an action released from the durable outbox.
    Released(DurableJob<V, D>),
    /// Expose an independently verifiable resolver proof whose own-signature floor is durable.
    Retain(Arc<Artifact<V, D>>),
    /// Retire volatile publication attempts after every successor command has executed.
    Retire(Vec<EffectId>),
    /// Application work for the local producer.
    Application(AppJob<D>),
    /// Aggregation and recovery work on the critical crypto pool.
    Crypto(CryptoJob<V, D>),
    /// A logical timer to arm.
    Timer(TimerCommand<D>),
    /// A command for the chain plane of one producer chain.
    Validator(ChainId, ValidatorCommand<V, D>),
    /// A command for the own-chain DA recovery task.
    OwnChainDa(ChainCommand<V, D>),
    /// A command for the resolver.
    Resolver(ResolverCommand),
}

/// Application work for the local producer.
#[derive(Clone, Debug)]
pub(crate) enum AppJob<D: Digest> {
    /// Build an application block against an immutable parent.
    Build(BuildJob<D>),
    /// Validate and durably retain one locally prepared block before signing its header.
    Custody(CustodyJob<D>),
    /// Stop custody work for one superseded prepared block.
    CancelCustody(CustodyCancellation),
}

/// Aggregation and recovery work on the critical crypto pool.
#[derive(Clone, Debug)]
pub(crate) enum CryptoJob<V: Variant, D: Digest> {
    /// Recover a certificate from one canonical subset of nullification shares.
    RecoverNullification(NullificationRecoveryJob<V>),
    /// Aggregate one canonical V-QC transcript.
    AggregateVqc(VqcAggregateJob<V, D>),
    /// Assemble one L-QC from complete votes selected by the core.
    AggregateLqc(LqcAggregateJob<V, D>),
}

/// A logical timer the runtime arms.
#[derive(Copy, Clone, Debug)]
pub(crate) enum TimerCommand<D: Digest> {
    /// The timeout of one view.
    View(ViewTimer),
    /// A production deadline bound to one parent.
    Production(ProductionTimer<D>),
}

/// One authenticated block routed to its producer chain's chain plane.
///
/// The machine assigned its observation identity and recorded its producer ancestry first.
#[derive(Clone, Debug)]
pub(crate) struct ObservedBlock<V: Variant, D: Digest> {
    /// The observation identity the machine assigned.
    pub(crate) id: ArtifactId<D>,
    /// The observation order the machine assigned.
    pub(crate) observation: Observation,
    /// The authenticated block.
    pub(crate) block: Arc<SignedTransactionBlock<V, D>>,
    /// Whether this is the local producer's own custodied block, valid without a check.
    pub(crate) custodied: bool,
}

/// A command for the chain plane of one producer chain.
#[derive(Clone, Debug)]
pub(crate) enum ValidatorCommand<V: Variant, D: Digest> {
    /// Route an authenticated block to the plane.
    Observe(ObservedBlock<V, D>),
    /// The chain's certified anchor advanced to this block; blocks at or below it are settled.
    AnchorAdvanced(BlockRef<D>),
    /// Replace the plane's read-copy of the machine's durable DA choices above the anchor.
    Chosen(Vec<DaChoice<D>>),
}

/// A command for the own-chain DA recovery task.
#[derive(Clone, Debug)]
pub(crate) enum ChainCommand<V: Variant, D: Digest> {
    /// Forward a structurally checked own-chain data-availability share.
    Observe(Arc<DaVote<V, D>>),
    /// The own chain's certified anchor advanced to this height.
    AnchorAdvanced(Height),
}

/// A command for the resolver.
#[derive(Copy, Clone, Debug)]
pub(crate) enum ResolverCommand {
    /// Fetch a view proof (V-QC, nullification, or covering L-QC) for one view.
    Resolve(ResolutionJob),
    /// Stop one resolver job whose owner no longer needs it.
    Cancel(ResolutionJob),
    /// Reject cryptographically invalid content returned by one queried resolver peer.
    Reject(ResolutionJob),
    /// Retire view evidence below the core's current retention frontier.
    Prune(View),
}

/// Capabilities in deterministic issuance order.
pub(crate) type Capabilities<V, D> = Vec<Capability<V, D>>;
