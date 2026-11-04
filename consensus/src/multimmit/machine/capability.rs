//! Capabilities the machine issues to the attached runtime.

use crate::{
    multimmit::{
        machine::{
            da::DaChoice,
            durability::{DurableJob, EffectId, PersistDirective, SendRequest},
            finality::LqcAggregateJob,
            producer::{BuildJob, CustodyCancellation, CustodyJob, ProductionTimer},
            resolution::ResolutionJob,
            verification::{Observation, VerifyJob},
            view::{NullificationRecoveryJob, ViewTimer, VqcAggregateJob},
        },
        scheme::Scheme,
        types::{Artifact, ArtifactId, BlockRef, ChainId, DaVote, SignedTransactionBlock},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::Digest;
use std::sync::Arc;

/// Immutable work the machine issues, grouped by the runtime piece that executes it.
#[derive(Clone, Debug)]
pub(crate) enum Capability<S: Scheme, D: Digest> {
    /// Cryptographically verify retained decoded artifacts.
    Verify(VerifyJob<S, D>),
    /// Quarantine identities named by self-contained authenticated equivocation evidence.
    Quarantine(Vec<Participant>),
    /// Append domain events after installing pre-publication resolver custody.
    Journal(PersistDirective<S, D>),
    /// Install resolver custody and accounting released by a durable acknowledgement.
    Acknowledged {
        /// Proofs the acknowledged batch made servable.
        retention: Vec<Arc<Artifact<S, D>>>,
        /// Nullifications the acknowledged batch forwarded.
        forwarded_nullifications: usize,
    },
    /// Execute an action released from the durable outbox.
    Released(DurableJob<S, D>),
    /// Expose an independently verifiable resolver proof whose own-signature floor is durable.
    Retain(Arc<Artifact<S, D>>),
    /// Retire volatile publication attempts after every successor command has executed.
    Retire(Vec<EffectId>),
    /// Send each already-public artifact once to its recipient, without retries.
    ///
    /// A node forwards only DA certificates it did not produce: ones it received, or recovered as
    /// a non-producer on a receipt chain. Such a certificate is already public and authorizes
    /// nothing, so forwarding it needs no durable record. A producer's own certificate leaves only
    /// through its durable publication. A lost send is repeated at a later view entry while it
    /// still matters.
    Forward(Vec<SendRequest<S, D>>),
    /// Application work for the local producer.
    Application(AppJob<D>),
    /// Aggregation and recovery work on the critical crypto pool.
    Crypto(CryptoJob<S, D>),
    /// A logical timer to arm.
    Timer(TimerCommand<D>),
    /// A command for the chain plane of one producer chain.
    Validator(ChainId, ValidatorCommand<S, D>),
    /// A command for one chain's DA recovery task: the chain this node produces, or a receipt
    /// chain.
    ChainDa(ChainId, ChainCommand<S, D>),
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
pub(crate) enum CryptoJob<S: Scheme, D: Digest> {
    /// Recover a certificate from one canonical subset of nullification shares.
    RecoverNullification(NullificationRecoveryJob<S>),
    /// Aggregate one canonical V-QC transcript.
    AggregateVqc(VqcAggregateJob<S, D>),
    /// Assemble one L-QC from complete votes selected by the core.
    AggregateLqc(LqcAggregateJob<S, D>),
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
pub(crate) struct ObservedBlock<S: Scheme, D: Digest> {
    /// The observation identity the machine assigned.
    pub(crate) id: ArtifactId<D>,
    /// The observation order the machine assigned.
    pub(crate) observation: Observation,
    /// The authenticated block.
    pub(crate) block: Arc<SignedTransactionBlock<S, D>>,
    /// Whether this is the local producer's own custodied block, valid without a check.
    pub(crate) custodied: bool,
}

/// A command for the chain plane of one producer chain.
#[derive(Clone, Debug)]
pub(crate) enum ValidatorCommand<S: Scheme, D: Digest> {
    /// Route an authenticated block to the plane.
    Observe(ObservedBlock<S, D>),
    /// The chain's certified anchor advanced to this block; blocks at or below it are settled.
    AnchorAdvanced(BlockRef<D>),
    /// Replace the plane's read-copy of the machine's durable DA choices above the anchor.
    Chosen(Vec<DaChoice<D>>),
}

/// A command for one chain's DA recovery task.
#[derive(Clone, Debug)]
pub(crate) enum ChainCommand<S: Scheme, D: Digest> {
    /// Forward a structurally checked data-availability share of the chain.
    Observe(Arc<DaVote<S, D>>),
    /// The chain's certified anchor advanced to this height.
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
pub(crate) type Capabilities<S, D> = Vec<Capability<S, D>>;
