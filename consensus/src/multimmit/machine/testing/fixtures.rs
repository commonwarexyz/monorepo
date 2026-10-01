//! Symbolic fixtures shared by the machine tests, the fuzz world, and the benchmarks.
//!
//! Artifacts built here carry fabricated signatures. Every harness completes verification
//! symbolically, so no fixture is ever checked against a key.

use crate::{
    Epochable as _,
    multimmit::{
        config::Protocol,
        types::{
            Anchor, Attestation, BlockRef, CertificateId, ChainId, ChainProposal, CodecConfig,
            DaCertificate, DigestedLeader, EpochGenesis, Extension, LeaderBlock, Lqc,
            Nullification, PathLimits, Position, Tally, ThresholdShare, TransactionBlockHeader,
            ViewMessage, Vote, VoteBody, Vqc, genesis_tip_commitment,
        },
    },
    types::{Attributable as _, Epoch, Height, Participant, Round, View},
};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::{
        certificate::threshold::Certificate as ThresholdCertificate,
        primitives::{
            ops::aggregate,
            variant::{MinPk, Variant},
        },
    },
    certificate::Signers,
    sha256::Digest,
};
use commonware_math::algebra::Additive;
#[cfg(any(test, not(target_arch = "wasm32")))]
use std::cell::Cell;
#[cfg(test)]
use {
    super::driver::{Until, start},
    crate::{
        multimmit::{
            config::{Profile, ResourceLimits, Role, Tuning},
            machine::{durability::DischargeKind, input::Step, reducer::machine::Machine},
        },
        types::ViewDelta,
    },
    commonware_utils::{Faults as _, N5f1, NZUsize},
    core::time::Duration,
};

/// The namespace machine test configurations sign under.
pub(crate) const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MACHINE_TEST";

/// Returns the digest of `label`.
pub(crate) fn digest(label: &[u8]) -> Digest {
    Sha256::hash(&[label])
}

/// Returns the digest of `label` followed by `marker`.
pub(crate) fn marked_digest(label: &[u8], marker: u64) -> Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

/// SHA-256 that counts, per thread, every digest it computes.
///
/// A one-part hash counts one digest, a pair counts two, and each streaming finalize counts one.
#[cfg(any(test, not(target_arch = "wasm32")))]
#[derive(Debug, Default)]
pub(crate) struct CountingHasher(Sha256);

#[cfg(any(test, not(target_arch = "wasm32")))]
thread_local! {
    static COUNTED_DIGESTS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(any(test, not(target_arch = "wasm32")))]
impl CountingHasher {
    /// Returns the digests this thread computed since the last reset.
    #[cfg(test)]
    pub(crate) fn count() -> usize {
        COUNTED_DIGESTS.with(Cell::get)
    }

    /// Restarts this thread's count at zero.
    #[cfg(test)]
    pub(crate) fn reset() {
        COUNTED_DIGESTS.with(|count| count.set(0));
    }

    /// Returns this thread's count and restarts it at zero.
    pub(crate) fn take() -> usize {
        COUNTED_DIGESTS.with(|count| count.replace(0))
    }

    fn record(digests: usize) {
        COUNTED_DIGESTS.with(|count| count.set(count.get() + digests));
    }
}

#[cfg(any(test, not(target_arch = "wasm32")))]
impl Hasher for CountingHasher {
    type Digest = Digest;

    fn hash(parts: &[&[u8]]) -> Self::Digest {
        Self::record(1);
        Sha256::hash(parts)
    }

    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        Self::record(2);
        Sha256::hash_pair(left, right)
    }

    fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    fn finalize(self) -> (Self, Self::Digest) {
        Self::record(1);
        let (hasher, digest) = self.0.finalize();
        (Self(hasher), digest)
    }
}

/// Builds a validated protocol configuration over fabricated genesis facts.
///
/// Unless set otherwise, every participant produces the chain at its own index, pipelines reach
/// depth two with extension bound one, the epoch is seven, and the genesis facts come from
/// [`synthetic_genesis`].
#[derive(Clone, Debug)]
pub(crate) struct TestConfig {
    participants: usize,
    producers: Option<Vec<Participant>>,
    pipeline_depth: u32,
    extension_bound: u32,
    epoch: Epoch,
    namespace: &'static [u8],
    genesis: Option<EpochGenesis<Digest>>,
}

impl TestConfig {
    /// Starts a configuration for a committee of `participants`.
    pub(crate) const fn new(participants: usize) -> Self {
        Self {
            participants,
            producers: None,
            pipeline_depth: 2,
            extension_bound: 1,
            epoch: Epoch::new(7),
            namespace: NAMESPACE,
            genesis: None,
        }
    }

    /// Assigns one producer chain to each entry of `producers`, in chain order.
    #[cfg(test)]
    pub(crate) fn producers(mut self, producers: Vec<Participant>) -> Self {
        self.producers = Some(producers);
        self
    }

    /// Bounds proposal pipelines by `pipeline_depth`.
    pub(crate) const fn depth(mut self, pipeline_depth: u32) -> Self {
        self.pipeline_depth = pipeline_depth;
        self
    }

    /// Bounds vote extensions by `extension_bound`.
    pub(crate) const fn extensions(mut self, extension_bound: u32) -> Self {
        self.extension_bound = extension_bound;
        self
    }

    /// Labels the configuration with `epoch`.
    #[cfg(test)]
    pub(crate) const fn epoch(mut self, epoch: Epoch) -> Self {
        self.epoch = epoch;
        self
    }

    /// Signs under `namespace`.
    pub(crate) const fn namespace(mut self, namespace: &'static [u8]) -> Self {
        self.namespace = namespace;
        self
    }

    /// Uses `genesis` instead of [`synthetic_genesis`].
    pub(crate) fn genesis(mut self, genesis: EpochGenesis<Digest>) -> Self {
        self.genesis = Some(genesis);
        self
    }

    /// Validates and returns the configuration.
    ///
    /// # Panics
    ///
    /// Panics if the settings do not describe a valid epoch configuration.
    pub(crate) fn build(self) -> Protocol<Digest> {
        let producers = self.producers.unwrap_or_else(|| {
            (0..self.participants)
                .map(Participant::from_usize)
                .collect()
        });
        let genesis = self
            .genesis
            .unwrap_or_else(|| synthetic_genesis(self.epoch, producers.len()));
        Protocol::new(
            self.namespace,
            self.participants,
            producers,
            PathLimits::new(self.pipeline_depth, self.extension_bound)
                .expect("test path limits are valid"),
            genesis,
        )
        .expect("test configuration is valid")
    }
}

/// Fabricates the genesis facts of `chains` producer chains at `epoch`.
pub(crate) fn synthetic_genesis(epoch: Epoch, chains: usize) -> EpochGenesis<Digest> {
    let tips = (0..chains)
        .map(|chain| {
            let label = format!("genesis {chain}");
            BlockRef::new(
                ChainId::new(u32::try_from(chain).expect("chain count is representable")),
                Height::zero(),
                digest(label.as_bytes()),
            )
        })
        .collect();
    EpochGenesis::new(
        epoch,
        digest(b"leader genesis"),
        CertificateId::new(digest(b"vqc genesis")),
        CertificateId::new(digest(b"lqc genesis")),
        tips,
    )
    .expect("synthetic genesis is valid")
}

/// Returns the commitment to `protocol`'s genesis history and tips.
pub(crate) fn genesis_tip_history(protocol: &Protocol<Digest>) -> Digest {
    genesis_tip_commitment::<Sha256>(protocol.genesis())
}

/// Returns the unsigned leader block for `view` that proposes every genesis tip.
pub(crate) fn genesis_leader(
    protocol: &Protocol<Digest>,
    view: View,
) -> LeaderBlock<MinPk, Digest> {
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                Vec::new(),
                protocol.codec_config().pipeline_depth(),
            )
            .expect("a genesis proposal is valid")
        })
        .collect();
    LeaderBlock::new(
        Round::new(protocol.epoch(), view),
        protocol.genesis().vqc(),
        genesis_tip_history(protocol),
        proposals,
        protocol.codec_config(),
    )
    .expect("a genesis leader block is valid")
}

/// Fabricates `signer`'s attributed signature.
pub(crate) fn attestation(signer: u32) -> Attestation<MinPk> {
    Attestation::new(
        Participant::new(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

/// Fabricates `signer`'s threshold signature share.
pub(crate) fn threshold_share(signer: u32) -> ThresholdShare<MinPk> {
    ThresholdShare::new(
        Participant::new(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

/// Fabricates a nullification for `round` whose certificate is the identity signature.
///
/// Every call for one round returns the same bytes.
pub(crate) fn unsigned_nullification(round: Round) -> Nullification<MinPk> {
    Nullification::new(
        round,
        ThresholdCertificate::new(<MinPk as Variant>::Signature::zero()),
    )
    .expect("a symbolic nullification is valid")
}

/// Fabricates a DA certificate for `header` whose certificate is the identity signature.
pub(crate) fn unsigned_da_certificate(
    header: TransactionBlockHeader<Digest>,
) -> DaCertificate<MinPk, Digest> {
    DaCertificate::new(
        header,
        ThresholdCertificate::new(<MinPk as Variant>::Signature::zero()),
    )
}

/// Fabricates `signer`'s vote for `leader` at `positions`, one per chain, with empty extensions.
pub(crate) fn vote(
    leader: &LeaderBlock<MinPk, Digest>,
    signer: u32,
    positions: &[u32],
    codec: CodecConfig,
) -> Vote<MinPk, Digest> {
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(leader),
        positions.iter().copied().map(Position::new).collect(),
        vec![Extension::empty(); codec.chains()],
        codec,
    )
    .expect("a symbolic vote is valid");
    Vote::new(body, attestation(signer))
}

/// Fabricates a V-QC for `leader` over `messages`.
///
/// Votes for another leader are left out of the designated tally; novotes are attributed.
pub(crate) fn symbolic_vqc(
    leader: LeaderBlock<MinPk, Digest>,
    messages: &[ViewMessage<MinPk, Digest>],
    codec: CodecConfig,
) -> Vqc<MinPk, Digest> {
    let leader_digest = leader.digest::<Sha256>();
    let votes = messages.iter().filter_map(|message| match message {
        ViewMessage::Vote(vote) if vote.body().leader() == leader_digest => {
            Some((vote.signer(), vote.body().clone()))
        }
        _ => None,
    });
    let tally = Tally::from_votes(DigestedLeader::new::<Sha256>(&leader), votes, codec)
        .expect("symbolic votes tally");
    let novoters = Signers::new(
        u32::try_from(codec.participants()).expect("committee size is representable"),
        messages.iter().filter_map(|message| match message {
            ViewMessage::NoVote(vote) => Some(vote.signer()),
            ViewMessage::Vote(_) => None,
        }),
    )
    .expect("symbolic novoters are distinct");
    Vqc::new(
        leader,
        tally,
        novoters,
        Vec::new(),
        aggregate::Signature::<MinPk>::zero(),
        codec,
    )
    .expect("a symbolic V-QC is valid")
}

/// Fabricates an L-QC for `leader` over `votes`.
pub(crate) fn symbolic_lqc<'a>(
    leader: LeaderBlock<MinPk, Digest>,
    votes: impl IntoIterator<Item = &'a Vote<MinPk, Digest>>,
    codec: CodecConfig,
) -> Lqc<MinPk, Digest> {
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&leader),
        votes
            .into_iter()
            .map(|vote| (vote.signer(), vote.body().clone())),
        codec,
    )
    .expect("symbolic votes tally");
    Lqc::new(leader, tally, aggregate::Signature::<MinPk>::zero(), codec)
        .expect("a symbolic L-QC is valid")
}

/// Where a crash interrupts one persistence barrier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BarrierCut {
    /// Before the barrier's events are appended.
    BeforeAppend,
    /// After the events are durable, before the machine sees the acknowledgement.
    AfterAppend,
    /// After the machine applied the acknowledgement.
    AfterAck,
}

/// One family of durable facts that discharges a publication, as [`DischargeKind`] names them.
#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DischargeFamily {
    /// [`DischargeKind::BlockCertifiedAtLeast`].
    BlockCertifiedAtLeast,
    /// [`DischargeKind::VoteCertifiedAtLeast`].
    VoteCertifiedAtLeast,
    /// [`DischargeKind::CertificateSupersededAbove`].
    CertificateSupersededAbove,
    /// [`DischargeKind::ExitReplacedAfter`].
    ExitReplacedAfter,
    /// [`DischargeKind::ViewRetired`].
    ViewRetired,
}

#[cfg(test)]
impl DischargeFamily {
    /// Every family, in [`DischargeKind`] declaration order.
    pub(crate) const ALL: [Self; 5] = [
        Self::BlockCertifiedAtLeast,
        Self::VoteCertifiedAtLeast,
        Self::CertificateSupersededAbove,
        Self::ExitReplacedAfter,
        Self::ViewRetired,
    ];

    /// Returns the family of `kind`.
    pub(crate) const fn of(kind: &DischargeKind) -> Self {
        match kind {
            DischargeKind::BlockCertifiedAtLeast { .. } => Self::BlockCertifiedAtLeast,
            DischargeKind::VoteCertifiedAtLeast { .. } => Self::VoteCertifiedAtLeast,
            DischargeKind::CertificateSupersededAbove { .. } => Self::CertificateSupersededAbove,
            DischargeKind::ExitReplacedAfter { .. } => Self::ExitReplacedAfter,
            DischargeKind::ViewRetired { .. } => Self::ViewRetired,
        }
    }
}

/// The resource limits machine unit tests start from.
#[cfg(test)]
pub(crate) const TEST_RESOURCES: ResourceLimits = ResourceLimits::new(
    NZUsize!(16 * 1024),
    NZUsize!(32),
    NZUsize!(8),
    NZUsize!(4),
    2,
    NZUsize!(8),
    NZUsize!(8),
    NZUsize!(32),
    NZUsize!(64),
);

/// Derives the widest retention window `resources` can carry for a committee of `participants`.
///
/// Production derives the bounds from the window; these tests fix the bounds first to drive the
/// overflow paths that derivation avoids, so the window follows from them instead.
#[cfg(test)]
pub(crate) fn retention_for(resources: ResourceLimits, participants: usize) -> ViewDelta {
    let live = u64::from(N5f1::quorum(participants)) + 3;
    let cache = (resources.max_cached_artifacts() as u64).saturating_sub(live);
    let forwarding = (resources.max_forwarded_certificates() as u64 / 2).saturating_sub(1);
    ViewDelta::new(cache.min(forwarding))
}

/// Builds the profile of one machine under test, and optionally starts it.
///
/// Unless set otherwise, the committee has one participant, pipelines reach depth two, the
/// resources are [`TEST_RESOURCES`], and the view retention is the widest those resources carry.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct Harness {
    role: Role,
    participants: usize,
    pipeline_depth: u32,
    producers: Option<Vec<Participant>>,
    resources: ResourceLimits,
    retention: Option<ViewDelta>,
}

#[cfg(test)]
impl Harness {
    /// Starts a profile for `role`.
    pub(crate) const fn builder(role: Role) -> Self {
        Self {
            role,
            participants: 1,
            pipeline_depth: 2,
            producers: None,
            resources: TEST_RESOURCES,
            retention: None,
        }
    }

    /// Starts an observer profile.
    pub(crate) const fn observer() -> Self {
        Self::builder(Role::Observer)
    }

    /// Starts a profile for the validator at `participant`.
    pub(crate) const fn validator(participant: u32) -> Self {
        Self::builder(Role::Validator(Participant::new(participant)))
    }

    /// Sizes the committee to `participants`.
    pub(crate) const fn participants(mut self, participants: usize) -> Self {
        self.participants = participants;
        self
    }

    /// Bounds proposal pipelines by `pipeline_depth`.
    pub(crate) const fn depth(mut self, pipeline_depth: u32) -> Self {
        self.pipeline_depth = pipeline_depth;
        self
    }

    /// Assigns one producer chain to each entry of `producers`, in chain order.
    pub(crate) fn producers(mut self, producers: Vec<Participant>) -> Self {
        self.producers = Some(producers);
        self
    }

    /// Uses `resources` instead of [`TEST_RESOURCES`].
    pub(crate) const fn resources(mut self, resources: ResourceLimits) -> Self {
        self.resources = resources;
        self
    }

    /// Retains `retention` views instead of the widest the resources carry.
    pub(crate) const fn retention(mut self, retention: ViewDelta) -> Self {
        self.retention = Some(retention);
        self
    }

    /// Validates and returns the profile.
    ///
    /// # Panics
    ///
    /// Panics if the settings do not describe a valid profile.
    pub(crate) fn profile(self) -> Profile<Digest> {
        self.profile_with_hasher::<Sha256>()
    }

    /// Validates and returns the profile for a machine hashing with `H`.
    ///
    /// # Panics
    ///
    /// Panics if the settings do not describe a valid profile.
    pub(crate) fn profile_with_hasher<H: Hasher<Digest = Digest>>(self) -> Profile<H::Digest> {
        let mut config = TestConfig::new(self.participants).depth(self.pipeline_depth);
        if let Some(producers) = self.producers {
            config = config.producers(producers);
        }
        Profile::with_limits(
            config.build(),
            self.role,
            Tuning {
                view_timeout: Duration::from_secs(1),
                production_interval: Duration::from_millis(100),
                view_retention: self
                    .retention
                    .unwrap_or_else(|| retention_for(self.resources, self.participants)),
                ..Tuning::default()
            },
            self.resources,
        )
        .expect("test profile is valid")
    }

    /// Starts a machine with this profile and acknowledges its generation barrier.
    ///
    /// The returned step merges the start's volatile effects with the acknowledgement's follow-up
    /// work, folded until the applied cursor advances.
    pub(crate) fn start(self) -> (Machine<Sha256, MinPk>, Step<MinPk, Digest>) {
        start(self.profile(), Until::CursorAdvance)
    }
}
