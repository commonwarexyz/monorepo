//! Capabilities the machine issues to the attached runtime, and the jobs they carry.

use crate::{
    multimmit::{
        machine::{
            durability::{DurableJob, EffectId, PersistDirective},
            input::{Now, TimerFamily},
            job::{Issued, SequenceId},
            resolution::ResolutionJob,
            verification::VerifyJob,
        },
        types::{
            Artifact, Attestation, BlockRef, CertificateId, ChainId, LeaderBlock, ResolutionPath,
            SignedTransactionBlock, TransactionBlockHeader, VoteContent,
        },
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
    /// Install resolver custody released by a durable acknowledgement.
    Acknowledged {
        /// Artifacts the acknowledged batch made servable.
        retention: Vec<Arc<Artifact<V, D>>>,
    },
    /// Execute an action released from the durable outbox.
    Released(DurableJob<V, D>),
    /// Expose an independently verifiable artifact whose own-signature record is durable.
    Retain(Arc<Artifact<V, D>>),
    /// Retire volatile publication attempts after every successor command has executed.
    Retire(Vec<EffectId>),
    /// Application work for the local producer.
    Application(AppJob<D>),
    /// Certificate aggregation on the critical crypto pool.
    Crypto(CryptoJob<V, D>),
    /// Arm or cancel one logical deadline.
    Timer(TimerCommand),
    /// A command for the chain plane of one producer chain.
    Chain(ChainId, ChainCommand<V, D>),
    /// A command for the resolver.
    Resolver(ResolverCommand<D>),
}

/// Capabilities in deterministic issuance order.
pub(crate) type Capabilities<V, D> = Vec<Capability<V, D>>;

/// Identifies one volatile application build within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BuildId(u64);

impl SequenceId for BuildId {
    fn at(sequence: u64) -> Self {
        Self(sequence)
    }
}

/// Application work for the local producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppJob<D: Digest> {
    /// Build an application block on an immutable parent.
    Build(BuildJob<D>),
    /// Durably retain one built block's body before its header is signed.
    Custody(CustodyJob<D>),
    /// Check again that the body of an own header, already in custody before this process
    /// started, is held, so the relay can serve it to peers. The outcome is not reported.
    Recall(TransactionBlockHeader<D>),
}

/// Application build request for the local producer's next block.
///
/// The machine issues it at the block's slot, so the application answers at once with whatever
/// it has to include. An empty body is an ordinary payload: it consumes the next height like any
/// other block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuildJob<D: Digest> {
    issued: Issued<BuildId>,
    parent: BlockRef<D>,
}

impl<D: Digest> BuildJob<D> {
    pub(crate) const fn new(issued: Issued<BuildId>, parent: BlockRef<D>) -> Self {
        Self { issued, parent }
    }

    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<BuildId> {
        self.issued
    }

    /// Returns the producer parent the block extends.
    pub(crate) const fn parent(&self) -> BlockRef<D> {
        self.parent
    }
}

/// Application custody request for one built block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyJob<D: Digest> {
    issued: Issued<BuildId>,
    header: TransactionBlockHeader<D>,
}

impl<D: Digest> CustodyJob<D> {
    pub(crate) const fn new(issued: Issued<BuildId>, header: TransactionBlockHeader<D>) -> Self {
        Self { issued, header }
    }

    /// Returns the originating build's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<BuildId> {
        self.issued
    }

    /// Returns the header whose body must enter custody.
    pub(crate) const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }
}

/// Identifies one volatile certificate aggregation within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AggregateId(u64);

impl SequenceId for AggregateId {
    fn at(sequence: u64) -> Self {
        Self(sequence)
    }
}

/// One verified vote: its signed content and the signer's attestation.
pub(crate) type AttestedVote<V, D> = (VoteContent<D>, Attestation<V>);

/// Certificate aggregation on the critical crypto pool.
#[derive(Clone, Debug)]
pub(crate) enum CryptoJob<V: Variant, D: Digest> {
    /// Aggregate one V-QC from final votes the machine selected.
    AggregateVqc(VqcAggregateJob<V, D>),
    /// Aggregate one L-QC from votes for one leader block the machine selected.
    AggregateLqc(LqcAggregateJob<V, D>),
}

impl<V: Variant, D: Digest> CryptoJob<V, D> {
    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<AggregateId> {
        match self {
            Self::AggregateVqc(job) => job.issued,
            Self::AggregateLqc(job) => job.issued,
        }
    }

    /// Returns the view whose votes the job aggregates.
    pub(crate) const fn view(&self) -> View {
        match self {
            Self::AggregateVqc(job) => job.view,
            Self::AggregateLqc(job) => job.leader.round().view(),
        }
    }
}

/// The inputs of one V-QC: exactly `n - f` verified final votes of one round, in ascending signer
/// order, the parent certificate, and the header paths resolving tips above the base.
#[derive(Clone, Debug)]
pub(crate) struct VqcAggregateJob<V: Variant, D: Digest> {
    issued: Issued<AggregateId>,
    view: View,
    parent: CertificateId<D>,
    votes: Vec<AttestedVote<V, D>>,
    paths: Vec<ResolutionPath<D>>,
}

impl<V: Variant, D: Digest> VqcAggregateJob<V, D> {
    pub(crate) const fn new(
        issued: Issued<AggregateId>,
        view: View,
        parent: CertificateId<D>,
        votes: Vec<AttestedVote<V, D>>,
        paths: Vec<ResolutionPath<D>>,
    ) -> Self {
        Self {
            issued,
            view,
            parent,
            votes,
            paths,
        }
    }

    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<AggregateId> {
        self.issued
    }

    /// Returns the parent certificate the V-QC names.
    pub(crate) const fn parent(&self) -> CertificateId<D> {
        self.parent
    }

    /// Returns the selected final votes in ascending signer order.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn votes(&self) -> &[AttestedVote<V, D>] {
        &self.votes
    }

    /// Returns the resolution paths for tips above the base.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn paths(&self) -> &[ResolutionPath<D>] {
        &self.paths
    }

    /// Returns the selected final votes and the resolution paths, consuming the job.
    pub(crate) fn into_votes_and_paths(self) -> (Vec<AttestedVote<V, D>>, Vec<ResolutionPath<D>>) {
        (self.votes, self.paths)
    }
}

/// The inputs of one L-QC: the leader block and exactly `n - f` verified votes for it, in
/// ascending signer order.
#[derive(Clone, Debug)]
pub(crate) struct LqcAggregateJob<V: Variant, D: Digest> {
    issued: Issued<AggregateId>,
    leader: LeaderBlock<D>,
    votes: Vec<AttestedVote<V, D>>,
}

impl<V: Variant, D: Digest> LqcAggregateJob<V, D> {
    pub(crate) const fn new(
        issued: Issued<AggregateId>,
        leader: LeaderBlock<D>,
        votes: Vec<AttestedVote<V, D>>,
    ) -> Self {
        Self {
            issued,
            leader,
            votes,
        }
    }

    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<AggregateId> {
        self.issued
    }

    /// Returns the finalized leader block.
    pub(crate) const fn leader(&self) -> &LeaderBlock<D> {
        &self.leader
    }

    /// Returns the selected votes in ascending signer order.
    pub(crate) fn votes(&self) -> &[AttestedVote<V, D>] {
        &self.votes
    }
}

/// A logical deadline command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TimerCommand {
    /// Fire [`Input::Tick`](super::input::Input::Tick) for `family` once the clock reaches `at`,
    /// replacing the family's earlier deadline.
    Arm {
        /// The deadline family.
        family: TimerFamily,
        /// The clock reading at which the deadline fires.
        at: Now,
    },
    /// Drop the family's deadline.
    Cancel(TimerFamily),
}

/// A command for the chain plane of one producer chain.
#[derive(Clone, Debug)]
pub(crate) enum ChainCommand<V: Variant, D: Digest> {
    /// Run the application's verification of one authenticated block, the fence for its full
    /// acceptance.
    Validate(Arc<SignedTransactionBlock<V, D>>),
    /// The chain's accepted tip reached this height; the plane drops work at or below it.
    Accepted(Height),
}

/// A command for the resolver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolverCommand<D: Digest> {
    /// Fetch the artifact one retrieval key names.
    Resolve(ResolutionJob<D>),
    /// Stop one retrieval whose owner no longer needs it.
    Cancel(ResolutionJob<D>),
    /// Reject cryptographically invalid content returned for one retrieval.
    Reject(ResolutionJob<D>),
    /// Retire retrievals and served evidence for views at or below this one.
    Prune(View),
    /// Stop serving the headers of `chain` at or below `height`; the machine retains none of them.
    SettleHeaders {
        /// The producer chain.
        chain: ChainId,
        /// The highest settled height.
        height: Height,
    },
}
