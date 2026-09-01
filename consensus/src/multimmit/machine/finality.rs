//! Per-leader vote pools and local leader finality.
//!
//! Raw votes enter arrival-first pools only after cryptographic authentication. These pools are
//! independent from the per-view message selection used to build V-QCs: a participant can vote for
//! multiple equivocating leaders, and each leader retains its own first authenticated vote.
//!
//! Reaching `n-f` finalizes the leader immediately. L-QC assembly is asynchronous evidence for
//! other replicas and never gates the local finality fact.
//!
//! # Claims
//!
//! A vote, V-QC, or L-QC claims the pools of the leaders it votes for when it is observed, before
//! verification. A verified vote settles into a pool only once no earlier claim on that pool is
//! still pending, so the votes a pool keeps depend on arrival order, not on the order in which
//! verifications complete. The first vote a pool settles from each signer is sticky: a later vote
//! from that signer for the same leader can only supply the complete witness of the same body,
//! and the pool's finality evidence commits to the sticky votes.
//!
//! # Capacity
//!
//! Each pool's owner is the scheduled leader of its view. Pools live in three tiers:
//!
//! - Primary: `f+1` slots, at most one unfinalized pool per owner.
//! - Best-effort: the remaining bounded space, for pools of other leader digests.
//! - Pinned: finalized and certificate-referenced pools, held outside the bounded tiers until
//!   their view retires, so ordering work cannot evict a live owner's pool.
//!
//! # Signing floor
//!
//! The highest admitted L-QC above the durable signing floor is the floor candidate, whether or
//! not it covers the current view. An L-QC whose aggregation completes after its view exits is
//! still portable finality evidence, and the floor it raises retires the same signing authority
//! whether or not it also advances the view. Requiring it to cover the current view would make
//! floor progress a race against the ordinary exit, which the aggregation loses whenever it is not
//! inline.

use super::{
    artifact::{Held, VoteKind},
    capability::{Capabilities, Capability, CryptoJob},
    job::{Admit, Generation, IdSequence, Issued, JobTable, SequenceId},
    util::OneOrMany,
    verification::Observation,
};
use crate::{
    Epochable, Viewable,
    multimmit::{
        algebra::{
            CertificateDerivations, DerivedVqc, FinalTips, PoolExtractor, ValidatedLqc,
            VerifiedVote, validate_lqc, vote_evidence,
        },
        config::Profile,
        scheme::bls12381_threshold::{CertificateVotes, Error as SchemeError},
        types::{
            Artifact, ArtifactId, CodecConfig, DigestedLeader, FinalityFact, FinalityId,
            LeaderBlock, Lqc, PoolSummary, SelectedCommitments, Vote, VoteBody, Vqc,
        },
    },
    types::{Attributable, Participant, Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::{Faults as _, N5f1};
use core::{
    convert::Infallible,
    mem::{replace, take},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const FINALITY_EVIDENCE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_FINALITY_EVIDENCE";

/// The complete votes an L-QC aggregates, in participant order.
type VoteArtifacts<V, D> = Arc<[Held<VoteKind, V, D>]>;

/// Identifies the finality pool of one designated leader block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PoolKey<D: Digest> {
    round: Round,
    leader: D,
}

impl<D: Digest> PoolKey<D> {
    const fn new(round: Round, leader: D) -> Self {
        Self { round, leader }
    }

    const fn view(&self) -> View {
        self.round.view()
    }
}

/// A verified L-QC released in claim order, which may advance the signing floor.
pub(super) struct FinalityOutput<V: Variant, D: Digest> {
    /// The certificate's earliest observation.
    pub(super) observation: Observation,
    /// The verified L-QC artifact.
    pub(super) certificate: Arc<Artifact<V, D>>,
    /// The V-QC projection verification derived from the certificate, if any.
    pub(super) derived: Option<DerivedVqc<V, D>>,
}

impl<V: Variant, D: Digest> FinalityOutput<V, D> {
    /// Releases a verified L-QC, taking the V-QC projection its verification derived.
    fn lqc(
        observation: Observation,
        certificate: &Arc<Artifact<V, D>>,
        derivations: Option<&mut CertificateDerivations<V, D>>,
    ) -> Self {
        Self {
            observation,
            certificate: Arc::clone(certificate),
            derived: derivations.and_then(CertificateDerivations::take_derived),
        }
    }
}

/// The L-QCs one finality transition releases, in claim order.
type FinalityOutputs<V, D> = Vec<FinalityOutput<V, D>>;

/// One per-leader vote slot an artifact claims before cryptographic verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct VoteClaim<D: Digest> {
    pool: PoolKey<D>,
    signer: Participant,
}

/// Visits every vote slot `artifact` claims, in ascending signer order.
///
/// A certificate's tallied signers all vote for its designated leader, so `leader` passes a digest
/// the caller already holds instead of re-encoding the leader block.
fn visit_vote_claims<H, V, D>(
    artifact: &Artifact<V, D>,
    leader: Option<D>,
    mut visit: impl FnMut(VoteClaim<D>),
) where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    match artifact {
        Artifact::Vote(vote) => visit(VoteClaim {
            pool: PoolKey::new(vote.body().round(), vote.body().leader()),
            signer: vote.signer(),
        }),
        Artifact::Vqc(certificate) => {
            let round = certificate.leader().round();
            let designated = leader.unwrap_or_else(|| certificate.leader().digest::<H>());
            let mut tally = certificate.tally().signers().iter().peekable();
            let mut conflicting = certificate.conflicting_votes().iter().peekable();
            loop {
                let next_conflicting = conflicting.peek().map(|vote| vote.signer());
                match (tally.peek().copied(), next_conflicting) {
                    (Some(signer), other) if other.is_none_or(|other| signer < other) => {
                        tally.next();
                        visit(VoteClaim {
                            pool: PoolKey::new(round, designated),
                            signer,
                        });
                    }
                    (None, None) => break,
                    _ => {
                        let vote = conflicting.next().expect("a conflicting vote was peeked");
                        visit(VoteClaim {
                            pool: PoolKey::new(round, vote.leader()),
                            signer: vote.signer(),
                        });
                    }
                }
            }
        }
        Artifact::Lqc(certificate) => {
            let round = certificate.leader().round();
            let designated = leader.unwrap_or_else(|| certificate.leader().digest::<H>());
            for signer in certificate.tally().signers().iter() {
                visit(VoteClaim {
                    pool: PoolKey::new(round, designated),
                    signer,
                });
            }
        }
        Artifact::TransactionBlock(_)
        | Artifact::DaVote(_)
        | Artifact::DaCertificate(_)
        | Artifact::LeaderBlock(_)
        | Artifact::NoVote(_)
        | Artifact::Nullify(_)
        | Artifact::Nullification(_) => {}
    }
}

/// Returns the finality pool of `leader`, reusing `cached` as its digest when the caller holds it.
fn pool_key<H, V, D>(leader: &LeaderBlock<V, D>, cached: Option<D>) -> PoolKey<D>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    PoolKey::new(
        leader.round(),
        cached.unwrap_or_else(|| leader.digest::<H>()),
    )
}

/// Returns the finality pool of the leader `artifact` proposes or certifies.
///
/// `cached` is the leader digest when the caller already derived it.
fn leader_key<H, V, D>(artifact: &Artifact<V, D>, cached: Option<D>) -> Option<PoolKey<D>>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    artifact
        .designated_leader()
        .map(|leader| pool_key::<H, V, D>(leader, cached))
}

/// A change to a leader's local finality fact, with the producer commitments its tips select.
pub(super) enum FinalityUpdate<D: Digest> {
    Finalized(FinalityFact<D>, SelectedCommitments<D>),
    Advanced(FinalityFact<D>, SelectedCommitments<D>),
}

/// Everything retained for one leader's finality pool.
///
/// The entry is removed once every part is empty. The direct pool and certified fact are boxed,
/// so pools that hold only unsettled votes stay small in the map.
struct PoolEntry<V: Variant, D: Digest> {
    /// The pool of authenticated votes, once the leader block itself is known.
    direct: Option<Box<DirectPool<V, D>>>,
    /// The earliest verified L-QC fact for the leader.
    certified: Option<Box<CertifiedRecord<D>>>,
    /// Artifacts that reserved the pool before verification.
    claims: BTreeSet<ArtifactId<D>>,
    /// Authenticated votes and unverified vote claims not yet settled into the direct pool.
    pending: PendingPool<V, D>,
}

impl<V: Variant, D: Digest> Default for PoolEntry<V, D> {
    fn default() -> Self {
        Self {
            direct: None,
            certified: None,
            claims: BTreeSet::new(),
            pending: PendingPool::default(),
        }
    }
}

impl<V: Variant, D: Digest> PoolEntry<V, D> {
    /// Returns whether the pool knows its leader, directly or through an L-QC.
    const fn has_leader(&self) -> bool {
        self.direct.is_some() || self.certified.is_some()
    }

    fn is_empty(&self) -> bool {
        !self.has_leader() && self.claims.is_empty() && self.pending.is_empty()
    }
}

/// Finality state for one epoch.
pub(crate) struct FinalityState<V: Variant, D: Digest> {
    config: CodecConfig,
    capacity: FinalityPoolCapacity<D>,
    pools: BTreeMap<PoolKey<D>, PoolEntry<V, D>>,
    claims: BTreeMap<ArtifactId<D>, FinalityClaim<V, D>>,
    claim_order: BTreeMap<Participant, BTreeSet<(Observation, ArtifactId<D>)>>,
    pub(super) ready_lqcs: BTreeSet<(Observation, PoolKey<D>)>,
    pub(super) lqc_aggregate_jobs: JobTable<LqcAggregateId, AggregateRecord<V, D>>,
    lqc_aggregate_ids: IdSequence<LqcAggregateId>,
    capabilities: Capabilities<V, D>,
    updates: Vec<FinalityUpdate<D>>,
    /// Views at or below this one are retired; zero before any retirement, since no finality
    /// artifact has the genesis view.
    retired_through: View,
    /// The highest admitted L-QC not yet consumed by the durable signing floor.
    ///
    /// Finality evidence owns its proof because it can outlive its general ready-artifact cache
    /// entry. Equal-view arrivals retain the first proof.
    proof: Option<FinalityProof<V, D>>,
}

/// An admitted L-QC with the V-QC projection it implies.
struct FinalityProof<V: Variant, D: Digest> {
    view: View,
    artifact: Arc<Artifact<V, D>>,
    derived: DerivedVqc<V, D>,
}

/// The verification verdict of one finality claim.
#[derive(Copy, Clone)]
enum ClaimVerdict {
    Pending,
    Rejected,
    Valid,
}

/// One pool a finality claim reserves.
#[derive(Copy, Clone)]
struct PoolReservation<D: Digest> {
    owner: Participant,
    key: PoolKey<D>,
    liveness: bool,
    retained: bool,
}

/// A pool an artifact would reserve, and whether the reservation is liveness-critical.
#[derive(Copy, Clone)]
struct ReservationKey<D: Digest> {
    key: PoolKey<D>,
    liveness: bool,
}

/// Adds `key` to the pools an artifact reserves, merging a repeated pool's liveness.
fn push_reservation_key<D: Digest>(
    keys: &mut Option<OneOrMany<ReservationKey<D>>>,
    key: PoolKey<D>,
    liveness: bool,
) {
    let Some(keys) = keys else {
        *keys = Some(OneOrMany::One(ReservationKey { key, liveness }));
        return;
    };
    match keys
        .as_mut_slice()
        .iter_mut()
        .find(|existing| existing.key == key)
    {
        Some(existing) => existing.liveness |= liveness,
        None => keys.push(ReservationKey { key, liveness }),
    }
}

/// The pools one finality claim reserves; almost every claim reserves exactly one.
struct PoolReservations<D: Digest>(OneOrMany<PoolReservation<D>>);

impl<D: Digest> PoolReservations<D> {
    fn as_slice(&self) -> &[PoolReservation<D>] {
        self.0.as_slice()
    }

    fn as_mut_slice(&mut self) -> &mut [PoolReservation<D>] {
        self.0.as_mut_slice()
    }

    fn owner(&self) -> Participant {
        self.as_slice()
            .iter()
            .next()
            .expect("a finality claim reserves at least one pool")
            .owner
    }

    fn retains(&self, key: PoolKey<D>) -> bool {
        self.as_slice()
            .iter()
            .any(|reservation| reservation.key == key && reservation.retained)
    }

    fn ordered(&self) -> bool {
        self.as_slice()
            .iter()
            .any(|reservation| reservation.liveness)
    }

    fn retain(&mut self, key: PoolKey<D>) {
        if let Some(reservation) = self
            .as_mut_slice()
            .iter_mut()
            .find(|reservation| reservation.key == key)
        {
            reservation.retained = true;
        }
    }
}

/// An artifact holding finality pool reservations while it awaits or passes verification.
pub(super) struct FinalityClaim<V: Variant, D: Digest> {
    pub(super) observation: Observation,
    pub(super) artifact: Arc<Artifact<V, D>>,
    reservations: PoolReservations<D>,
    verdict: ClaimVerdict,
    /// Vote and tip derivations produced while verifying a certificate, reused when the claim
    /// is observed instead of re-expanding and hashing its attested votes.
    derivations: Option<CertificateDerivations<V, D>>,
}

impl<V: Variant, D: Digest> FinalityClaim<V, D> {
    const fn new(
        observation: Observation,
        artifact: Arc<Artifact<V, D>>,
        reservations: PoolReservations<D>,
    ) -> Self {
        Self {
            observation,
            artifact,
            reservations,
            verdict: ClaimVerdict::Pending,
            derivations: None,
        }
    }

    fn owner(&self) -> Participant {
        self.reservations.owner()
    }

    fn retains(&self, key: PoolKey<D>) -> bool {
        self.reservations.retains(key)
    }

    /// Returns the leader-block digest off-pool verification already derived for this claim.
    const fn derived_leader(&self) -> Option<D> {
        match self.derivations.as_ref() {
            Some(CertificateDerivations::Vqc { leader, .. })
            | Some(CertificateDerivations::Lqc { leader, .. }) => Some(*leader),
            None => None,
        }
    }

    fn ordered(&self) -> bool {
        self.reservations.ordered()
    }
}

/// Where the capacity tiers placed a pool.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PoolAdmission<D: Digest> {
    Admitted,
    Pinned,
    Dropped,
    Replaced(PoolKey<D>),
}

/// The primary pool of one owner, with the observation that placed it and whether a
/// liveness-critical claim activated it.
#[derive(Copy, Clone)]
struct PrimaryPool<D: Digest> {
    key: PoolKey<D>,
    observation: Observation,
    active: bool,
}

/// Finality-pool ownership under the protocol's `<= f` fault model.
///
/// Unfinalized pools reserve `f+1` slots for distinct scheduled leaders. Secondary digests use
/// only the remaining best-effort space. Finalized and certificate-referenced pools move outside
/// that bounded partition so ordering work cannot consume a live identity's slot.
pub(super) struct FinalityPoolCapacity<D: Digest> {
    primary_limit: usize,
    best_effort_limit: usize,
    primary_by_owner: BTreeMap<Participant, PrimaryPool<D>>,
    primary_by_key: BTreeMap<PoolKey<D>, Participant>,
    best_effort: BTreeSet<PoolKey<D>>,
    pinned: BTreeSet<PoolKey<D>>,
}

impl<D: Digest> FinalityPoolCapacity<D> {
    /// Splits `max_pools` into the primary, best-effort, and pinned tiers.
    pub(super) fn new(participants: usize, max_pools: usize, pinned_reserve: usize) -> Self {
        let primary_limit = (N5f1::max_faults(participants) + 1) as usize;
        let best_effort_limit = max_pools
            .checked_sub(primary_limit)
            .and_then(|remaining| remaining.checked_sub(pinned_reserve))
            .expect("profile validation reserves the primary and pinned tiers");
        Self {
            primary_limit,
            best_effort_limit,
            primary_by_owner: BTreeMap::new(),
            primary_by_key: BTreeMap::new(),
            best_effort: BTreeSet::new(),
            pinned: BTreeSet::new(),
        }
    }

    fn reserve_unverified(
        &mut self,
        owner: Participant,
        key: PoolKey<D>,
        observation: Observation,
        liveness: bool,
    ) -> PoolAdmission<D> {
        if self.pinned.contains(&key) || self.primary_by_key.contains_key(&key) {
            return PoolAdmission::Admitted;
        }

        if self.best_effort.contains(&key) {
            if liveness
                && !self.primary_by_owner.contains_key(&owner)
                && self.primary_by_owner.len() < self.primary_limit
            {
                self.best_effort.remove(&key);
                self.insert_primary(owner, key, observation, false);
            }
            return PoolAdmission::Admitted;
        }

        if !liveness || self.primary_by_owner.contains_key(&owner) {
            return self.admit_best_effort(key);
        }

        if self.primary_by_owner.len() < self.primary_limit {
            self.insert_primary(owner, key, observation, false);
            return PoolAdmission::Admitted;
        }

        self.admit_best_effort(key)
    }

    fn activate_unfinalized(
        &mut self,
        owner: Participant,
        key: PoolKey<D>,
        observation: Observation,
        liveness: bool,
    ) -> PoolAdmission<D> {
        if self.pinned.contains(&key) {
            return PoolAdmission::Pinned;
        }
        if let Some(primary_owner) = self.primary_by_key.get(&key).copied() {
            if liveness {
                let primary = self
                    .primary_by_owner
                    .get_mut(&primary_owner)
                    .expect("the primary indexes agree");
                primary.active = true;
            }
            return PoolAdmission::Admitted;
        }
        if !liveness {
            return self.reserve_unverified(owner, key, observation, false);
        }

        if let Some(existing) = self.primary_by_owner.get(&owner).copied() {
            if existing.key.view() >= key.view() {
                return self.reserve_unverified(owner, key, observation, false);
            }
            return self.replace_primary(owner, existing, owner, key, observation);
        }

        if self.primary_by_owner.len() < self.primary_limit {
            self.best_effort.remove(&key);
            self.insert_primary(owner, key, observation, true);
            return PoolAdmission::Admitted;
        }

        let (&evicted_owner, &evicted) = self
            .primary_by_owner
            .iter()
            .min_by_key(|(owner, primary)| {
                (
                    primary.active,
                    primary.key.view(),
                    primary.observation,
                    **owner,
                )
            })
            .expect("a full primary tier contains a victim");
        if evicted.active && evicted.key.view() >= key.view() {
            return self.reserve_unverified(owner, key, observation, false);
        }
        self.replace_primary(evicted_owner, evicted, owner, key, observation)
    }

    /// Moves `key` outside the bounded partition.
    ///
    /// Quorum evidence remains pinned until its view leaves the retained diagnostic window.
    fn pin(&mut self, key: PoolKey<D>) {
        if self.pinned.contains(&key) {
            return;
        }
        self.release_unfinalized(key);
        self.pinned.insert(key);
    }

    fn retire_through(&mut self, floor: View) {
        let primary = self
            .primary_by_key
            .keys()
            .filter(|key| key.view() <= floor)
            .copied()
            .collect::<Vec<_>>();
        for key in primary {
            self.release_unfinalized(key);
        }
        self.best_effort.retain(|key| key.view() > floor);
        self.pinned.retain(|key| key.view() > floor);
    }

    fn release_unfinalized(&mut self, key: PoolKey<D>) {
        self.best_effort.remove(&key);
        let Some(owner) = self.primary_by_key.remove(&key) else {
            return;
        };
        self.primary_by_owner.remove(&owner);
    }

    fn admit_best_effort(&mut self, key: PoolKey<D>) -> PoolAdmission<D> {
        if self.best_effort.len() >= self.best_effort_limit {
            return PoolAdmission::Dropped;
        }
        self.best_effort.insert(key);
        PoolAdmission::Admitted
    }

    fn insert_primary(
        &mut self,
        owner: Participant,
        key: PoolKey<D>,
        observation: Observation,
        active: bool,
    ) {
        self.primary_by_owner.insert(
            owner,
            PrimaryPool {
                key,
                observation,
                active,
            },
        );
        self.primary_by_key.insert(key, owner);
    }

    /// Replaces `evicted_owner`'s primary pool with `owner`'s pool at `key`, demoting the evicted
    /// pool to best-effort space when it fits.
    fn replace_primary(
        &mut self,
        evicted_owner: Participant,
        evicted: PrimaryPool<D>,
        owner: Participant,
        key: PoolKey<D>,
        observation: Observation,
    ) -> PoolAdmission<D> {
        self.remove_primary(evicted_owner, evicted.key);
        self.best_effort.remove(&key);
        self.insert_primary(owner, key, observation, true);
        if matches!(self.admit_best_effort(evicted.key), PoolAdmission::Dropped) {
            return PoolAdmission::Replaced(evicted.key);
        }
        PoolAdmission::Admitted
    }

    fn remove_primary(&mut self, owner: Participant, key: PoolKey<D>) {
        let removed = self.primary_by_owner.remove(&owner);
        debug_assert!(removed.is_some_and(|primary| primary.key == key));
        self.primary_by_key.remove(&key);
    }

    fn retain_earlier_observation(&mut self, key: PoolKey<D>, observation: Observation) {
        if let Some(owner) = self.primary_by_key.get(&key) {
            let primary = self
                .primary_by_owner
                .get_mut(owner)
                .expect("the primary indexes agree");
            primary.observation = primary.observation.min(observation);
        }
    }
}

/// Identifies one L-QC aggregation request within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LqcAggregateId(u64);

impl LqcAggregateId {
    /// Returns the generation-local sequence.
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

impl SequenceId for LqcAggregateId {
    fn at(sequence: u64) -> Self {
        Self(sequence)
    }
}

/// Immutable work for assembling one L-QC from a machine-selected vote set.
#[derive(Clone, Debug)]
pub(crate) struct LqcAggregateJob<V: Variant, D: Digest> {
    issued: Issued<LqcAggregateId>,
    leader: LeaderBlock<V, D>,
    votes: VoteArtifacts<V, D>,
}

impl<V: Variant, D: Digest> LqcAggregateJob<V, D> {
    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<LqcAggregateId> {
        self.issued
    }

    /// Returns the unsigned leader finalized by the selected votes.
    pub(crate) const fn leader(&self) -> &LeaderBlock<V, D> {
        &self.leader
    }

    /// Returns the selected complete votes in ascending participant order.
    pub(crate) fn votes(&self) -> impl ExactSizeIterator<Item = &Vote<V, D>> {
        self.votes.iter().map(Held::get)
    }

    /// Returns whether `certificate` aggregates exactly this job's leader and votes.
    fn matches<H: Hasher<Digest = D>>(&self, certificate: &Lqc<V, D>, config: CodecConfig) -> bool {
        if certificate.leader() != self.leader()
            || certificate.signature().is_none()
            || certificate.tally().signers().count() != config.view_quorum()
        {
            return false;
        }
        let votes = self.votes().collect::<Vec<_>>();
        let signers = votes.iter().map(|vote| vote.signer()).collect::<Vec<_>>();
        if certificate.tally().signers().iter().collect::<Vec<_>>() != signers {
            return false;
        }
        let Ok(expanded) = certificate.expand_votes(certificate.leader().digest::<H>(), config)
        else {
            return false;
        };
        expanded
            .iter()
            .zip(votes)
            .all(|((_, body), vote)| body == vote.body())
    }
}

/// Completion of one L-QC aggregation request.
#[derive(Clone, Debug)]
pub(crate) struct LqcAggregateCompletion<V: Variant, D: Digest> {
    issued: Issued<LqcAggregateId>,
    certificate: Lqc<V, D>,
    validated: ValidatedLqc<V, D>,
}

impl<V: Variant, D: Digest> LqcAggregateCompletion<V, D> {
    /// Prepares certificate projections in the aggregation worker.
    pub(crate) fn prepare<H: Hasher<Digest = D>>(
        job: &LqcAggregateJob<V, D>,
        certificate: Lqc<V, D>,
        config: CodecConfig,
    ) -> Result<Self, SchemeError> {
        let leader = certificate.leader().digest::<H>();
        let designated = job
            .votes()
            .map(|vote| (vote.signer(), vote.body().clone()))
            .collect();
        let validated = validate_lqc::<H, V, D>(
            &certificate,
            config,
            CertificateVotes {
                leader,
                designated,
                conflicting: Vec::new(),
            },
        )
        .map_err(|_| SchemeError::Transcript)?;
        Ok(Self {
            issued: job.issued,
            certificate,
            validated,
        })
    }

    /// Returns the aggregated certificate.
    pub(crate) const fn certificate(&self) -> &Lqc<V, D> {
        &self.certificate
    }
}

/// One authenticated vote in a pool, with its complete artifact once a witness is held.
#[derive(Clone, Debug)]
struct VoteRecord<V: Variant, D: Digest> {
    id: ArtifactId<D>,
    observation: Observation,
    body: VoteBody<D>,
    evidence: D,
    artifact: Option<Held<VoteKind, V, D>>,
}

/// Unverified vote claims and authenticated votes not yet settled into a pool, in arrival
/// order.
pub(super) struct PendingPool<V: Variant, D: Digest> {
    claims: BTreeMap<Participant, BTreeMap<ArtifactId<D>, Observation>>,
    claim_order: BTreeSet<(Observation, Participant, ArtifactId<D>)>,
    candidates: BTreeMap<Participant, BTreeMap<ArtifactId<D>, VoteRecord<V, D>>>,
    candidate_order: BTreeSet<(Observation, Participant, ArtifactId<D>)>,
}

impl<V: Variant, D: Digest> Default for PendingPool<V, D> {
    fn default() -> Self {
        Self {
            claims: BTreeMap::new(),
            claim_order: BTreeSet::new(),
            candidates: BTreeMap::new(),
            candidate_order: BTreeSet::new(),
        }
    }
}

impl<V: Variant, D: Digest> PendingPool<V, D> {
    fn claim(&mut self, signer: Participant, id: ArtifactId<D>, observation: Observation) {
        let claims = self.claims.entry(signer).or_default();
        if let Some(previous) = claims.insert(id, observation) {
            self.claim_order.remove(&(previous, signer, id));
        }
        self.claim_order.insert((observation, signer, id));
    }

    fn remove_claim(&mut self, signer: Participant, id: ArtifactId<D>) {
        let Some(claims) = self.claims.get_mut(&signer) else {
            return;
        };
        if let Some(observation) = claims.remove(&id) {
            self.claim_order.remove(&(observation, signer, id));
        }
        if claims.is_empty() {
            self.claims.remove(&signer);
        }
    }

    fn insert_candidate(&mut self, signer: Participant, candidate: VoteRecord<V, D>) {
        let candidates = self.candidates.entry(signer).or_default();
        if let Some(previous) = candidates.get(&candidate.id) {
            if previous.observation <= candidate.observation {
                return;
            }
            self.candidate_order
                .remove(&(previous.observation, signer, candidate.id));
        }
        self.candidate_order
            .insert((candidate.observation, signer, candidate.id));
        candidates.insert(candidate.id, candidate);
    }

    fn remove_candidate(&mut self, signer: Participant, id: ArtifactId<D>) {
        let Some(candidates) = self.candidates.get_mut(&signer) else {
            return;
        };
        if let Some(candidate) = candidates.remove(&id) {
            self.candidate_order
                .remove(&(candidate.observation, signer, id));
        }
        if candidates.is_empty() {
            self.candidates.remove(&signer);
        }
    }

    fn pop_candidate(
        &mut self,
        signer: Participant,
        id: ArtifactId<D>,
    ) -> Option<VoteRecord<V, D>> {
        let candidates = self.candidates.get_mut(&signer)?;
        let selected = candidates.remove(&id)?;
        self.candidate_order
            .remove(&(selected.observation, signer, id));
        if candidates.is_empty() {
            self.candidates.remove(&signer);
        }
        Some(selected)
    }

    fn witness(&self, signer: Participant, body: &VoteBody<D>) -> Option<Held<VoteKind, V, D>> {
        self.candidates
            .get(&signer)?
            .values()
            .find_map(|candidate| {
                if candidate.body != *body {
                    return None;
                }
                candidate.artifact.clone()
            })
    }

    fn clear_signer(&mut self, signer: Participant) {
        if let Some(candidates) = self.candidates.remove(&signer) {
            for (candidate_id, candidate) in candidates {
                self.candidate_order
                    .remove(&(candidate.observation, signer, candidate_id));
            }
        }
        if let Some(claims) = self.claims.remove(&signer) {
            for (claim_id, observation) in claims {
                self.claim_order.remove(&(observation, signer, claim_id));
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.candidates.is_empty()
    }
}

/// Where a direct pool is in its lifecycle.
#[derive(Clone, Debug)]
enum PoolPhase<V: Variant, D: Digest> {
    /// The pool holds fewer than a view quorum of votes.
    ///
    /// `certified` records that an L-QC for the leader was already observed, so reaching the
    /// quorum owes no local aggregate.
    Collecting { certified: bool },
    /// The pool holds a view quorum of votes, so the leader is final.
    Finalized {
        tips: FinalTips<D>,
        /// Commits to every vote the pool holds.
        evidence: D,
        lqc: LqcProgress<V, D>,
    },
}

/// Progress toward the L-QC a finalized direct pool owes other replicas.
#[derive(Clone, Debug)]
enum LqcProgress<V: Variant, D: Digest> {
    /// The quorum that finalized the pool, in ascending order, waits for a complete witness of
    /// every vote.
    AwaitingWitnesses(Vec<Participant>),
    /// The witnessed votes wait for an aggregation job.
    Ready {
        votes: VoteArtifacts<V, D>,
        observation: Observation,
    },
    /// An aggregation job over the witnessed votes is outstanding.
    Pending {
        votes: VoteArtifacts<V, D>,
        id: LqcAggregateId,
    },
    /// An L-QC for the leader is held, locally assembled or observed.
    Complete,
}

/// How a direct pool took one vote.
enum Inserted {
    /// The extractor rejected the vote.
    Rejected,
    /// The pool holds the vote and still lacks a view quorum.
    Collecting,
    /// The pool holds the vote and a view quorum.
    Quorum,
}

/// The first authenticated vote of each participant for one leader block.
struct DirectPool<V: Variant, D: Digest> {
    leader: LeaderBlock<V, D>,
    leader_observation: Observation,
    votes: Vec<Option<VoteRecord<V, D>>>,
    /// The participants holding a vote in `votes`, ascending, tracked until the pool finalizes.
    signers: Vec<Participant>,
    extractor: PoolExtractor<D>,
    phase: PoolPhase<V, D>,
    sources: BTreeSet<ArtifactId<D>>,
}

impl<V: Variant, D: Digest> DirectPool<V, D> {
    fn new<H: Hasher<Digest = D>>(
        leader: LeaderBlock<V, D>,
        observation: Observation,
        source: ArtifactId<D>,
        config: CodecConfig,
    ) -> Result<Self, FinalityError> {
        let extractor =
            PoolExtractor::new::<H, V>(&leader, config).map_err(|_| FinalityError::Invariant)?;
        Ok(Self {
            leader,
            leader_observation: observation,
            votes: vec![None; config.participants()],
            signers: Vec::with_capacity(config.view_quorum()),
            extractor,
            phase: PoolPhase::Collecting { certified: false },
            sources: BTreeSet::from([source]),
        })
    }

    /// Inserts the first vote of `signer`, which holds no vote yet.
    fn insert<H: Hasher<Digest = D>>(
        &mut self,
        signer: Participant,
        vote: VoteRecord<V, D>,
        config: CodecConfig,
    ) -> Inserted {
        if self
            .extractor
            .insert::<H, V>(&self.leader, signer, &vote.body)
            .is_err()
        {
            return Inserted::Rejected;
        }
        self.votes[usize::from(signer)] = Some(vote);
        if matches!(self.phase, PoolPhase::Collecting { .. }) {
            let position = self.signers.partition_point(|held| *held < signer);
            self.signers.insert(position, signer);
        }
        if self.extractor.len() >= config.view_quorum() {
            Inserted::Quorum
        } else {
            Inserted::Collecting
        }
    }

    /// Records the final tips and evidence of a pool holding a view quorum.
    ///
    /// Returns the update to report when the tips changed.
    fn finalize<H: Hasher<Digest = D>>(
        &mut self,
        leader: D,
        config: CodecConfig,
    ) -> Result<Option<FinalityUpdate<D>>, FinalityError> {
        let tips = self
            .extractor
            .final_tips()
            .map_err(|_| FinalityError::Invariant)?;
        let evidence = self.evidence::<H>();
        let first = match &mut self.phase {
            PoolPhase::Finalized {
                tips: current,
                evidence: held,
                ..
            } => {
                *held = evidence;
                if *current == tips {
                    return Ok(None);
                }
                *current = tips;
                false
            }
            PoolPhase::Collecting { certified } => {
                let lqc = if *certified {
                    LqcProgress::Complete
                } else {
                    LqcProgress::AwaitingWitnesses(take(&mut self.signers))
                };
                self.phase = PoolPhase::Finalized {
                    tips,
                    evidence,
                    lqc,
                };
                true
            }
        };
        let fact = self
            .finality_fact(leader, config)?
            .expect("the pool finalized above");
        let PoolPhase::Finalized { tips, .. } = &self.phase else {
            unreachable!("the pool finalized above");
        };
        let commitments = self.extractor.selected(self.leader.round().epoch(), tips);
        Ok(Some(if first {
            FinalityUpdate::Finalized(fact, commitments)
        } else {
            FinalityUpdate::Advanced(fact, commitments)
        }))
    }

    /// Freezes the finalizing quorum once every vote in it has a complete witness.
    ///
    /// Returns the observation at which the L-QC became ready to aggregate.
    fn stage_lqc(&mut self, view_quorum: usize) -> Result<Option<Observation>, FinalityError> {
        let PoolPhase::Finalized {
            lqc: LqcProgress::AwaitingWitnesses(signers),
            ..
        } = &self.phase
        else {
            return Ok(None);
        };
        if signers.len() != view_quorum {
            return Err(FinalityError::Invariant);
        }
        let record = |signer: &Participant| {
            self.votes[usize::from(*signer)]
                .as_ref()
                .expect("a finalizing signer remains selected")
        };
        if signers
            .iter()
            .any(|signer| record(signer).artifact.is_none())
        {
            return Ok(None);
        }
        let votes = signers
            .iter()
            .map(|signer| {
                record(signer)
                    .artifact
                    .clone()
                    .expect("every finalizing vote has a complete witness")
            })
            .collect::<VoteArtifacts<V, D>>();
        let observation = signers
            .iter()
            .map(|signer| record(signer).observation)
            .chain([self.leader_observation])
            .max()
            .expect("a finalized pool contains votes");
        let PoolPhase::Finalized { lqc, .. } = &mut self.phase else {
            unreachable!("the phase was matched above");
        };
        *lqc = LqcProgress::Ready { votes, observation };
        Ok(Some(observation))
    }

    /// Marks an L-QC for the leader as held, returning the progress it replaces.
    const fn complete_lqc(&mut self) -> Option<LqcProgress<V, D>> {
        match &mut self.phase {
            PoolPhase::Collecting { certified } => {
                *certified = true;
                None
            }
            PoolPhase::Finalized { lqc, .. } => Some(replace(lqc, LqcProgress::Complete)),
        }
    }

    /// Returns the outstanding aggregation progress, if the pool is finalized.
    const fn lqc(&self) -> Option<&LqcProgress<V, D>> {
        match &self.phase {
            PoolPhase::Collecting { .. } => None,
            PoolPhase::Finalized { lqc, .. } => Some(lqc),
        }
    }

    const fn lqc_mut(&mut self) -> Option<&mut LqcProgress<V, D>> {
        match &mut self.phase {
            PoolPhase::Collecting { .. } => None,
            PoolPhase::Finalized { lqc, .. } => Some(lqc),
        }
    }

    const fn finalized(&self) -> bool {
        matches!(self.phase, PoolPhase::Finalized { .. })
    }

    /// Returns whether the pool holds finality evidence: a view quorum or an observed L-QC.
    const fn holds_evidence(&self) -> bool {
        !matches!(self.phase, PoolPhase::Collecting { certified: false })
    }

    /// Commits to the evidence of every vote the pool holds, in participant order.
    fn evidence<H: Hasher<Digest = D>>(&self) -> D {
        let mut transcript = Vec::with_capacity(self.extractor.len() + 1);
        transcript.push(FINALITY_EVIDENCE_NAMESPACE);
        transcript.extend(
            self.votes
                .iter()
                .flatten()
                .map(|vote| vote.evidence.as_ref()),
        );
        H::hash(&transcript)
    }

    /// Returns the direct finality fact of a finalized pool.
    fn finality_fact(
        &self,
        leader_digest: D,
        config: CodecConfig,
    ) -> Result<Option<FinalityFact<D>>, FinalityError> {
        let PoolPhase::Finalized { tips, evidence, .. } = &self.phase else {
            return Ok(None);
        };
        tips.fact(
            FinalityId::Direct(*evidence),
            DigestedLeader::with_digest(&self.leader, leader_digest),
            self.extractor.len(),
            config,
        )
        .map(Some)
        .map_err(|_| FinalityError::Invariant)
    }
}

/// An outstanding L-QC aggregation job and the pool it serves.
#[derive(Clone, Debug)]
pub(super) struct AggregateRecord<V: Variant, D: Digest> {
    key: PoolKey<D>,
    observation: Observation,
    job: LqcAggregateJob<V, D>,
}

/// The finality fact of the earliest verified L-QC for a leader.
struct CertifiedRecord<D: Digest> {
    observation: Observation,
    fact: FinalityFact<D>,
}

/// A locally prepared L-QC awaiting canonical self-admission.
pub(crate) struct PreparedLqc<V: Variant, D: Digest> {
    pub(crate) issued: Issued<LqcAggregateId>,
    pub(crate) artifact: Arc<Artifact<V, D>>,
    pub(crate) artifact_id: ArtifactId<D>,
    pub(crate) encoded_len: usize,
    pub(crate) observation: Observation,
    /// The worker's validation, taken when the certificate is admitted.
    pub(crate) validated: Option<ValidatedLqc<V, D>>,
}

/// A finality operation that cannot proceed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FinalityError {
    /// The L-QC aggregation identifier space is exhausted.
    #[error("finality aggregation identifiers exhausted")]
    IdentifierExhausted,
    /// An aggregation completion does not match the job it names.
    #[error("finality completion does not match its job")]
    CompletionMismatch,
    /// Two distinct leader blocks share one pool key.
    #[error("two leader blocks share one finality pool key")]
    LeaderCollision,
    /// Finality indexes disagree, or a validated input failed to re-derive.
    #[error("finality state invariant violated")]
    Invariant,
}

impl<V: Variant, D: Digest> FinalityState<V, D> {
    /// Creates the finality state for the profile's epoch.
    pub(crate) fn new(profile: &Profile<D>) -> Self {
        let participants = profile.codec().participants();
        Self {
            config: profile.codec(),
            capacity: FinalityPoolCapacity::new(
                participants,
                profile.resources().max_finality_pools(),
                profile.pinned_finality_pools(),
            ),
            pools: BTreeMap::new(),
            claims: BTreeMap::new(),
            claim_order: BTreeMap::new(),
            ready_lqcs: BTreeSet::new(),
            lqc_aggregate_jobs: JobTable::new(),
            lqc_aggregate_ids: IdSequence::new(),
            capabilities: Vec::new(),
            updates: Vec::new(),
            retired_through: View::zero(),
            proof: None,
        }
    }

    /// Retains an admitted L-QC as the finality proof when it is above the one already held.
    ///
    /// Returns whether the retained proof changed.
    pub(crate) fn retain_proof<H: Hasher<Digest = D>>(
        &mut self,
        artifact: &Arc<Artifact<V, D>>,
        derived: Option<DerivedVqc<V, D>>,
    ) -> Result<bool, FinalityError> {
        let Artifact::Lqc(certificate) = artifact.as_ref() else {
            return Err(FinalityError::Invariant);
        };
        if self
            .proof
            .as_ref()
            .is_some_and(|proof| proof.view >= certificate.view())
        {
            return Ok(false);
        }
        let derived = match derived {
            Some(derived) => derived,
            None => DerivedVqc::from_lqc::<H>(certificate, self.config)
                .map_err(|_| FinalityError::Invariant)?,
        };
        self.proof = Some(FinalityProof {
            view: certificate.view(),
            artifact: Arc::clone(artifact),
            derived,
        });
        Ok(true)
    }

    /// Returns the highest admitted L-QC above the durable signing floor, whether or not it
    /// covers the current view.
    pub(crate) fn signing_floor_candidate(&self, floor: View) -> Option<Arc<Artifact<V, D>>> {
        self.proof
            .as_ref()
            .and_then(|proof| (proof.view > floor).then(|| Arc::clone(&proof.artifact)))
    }

    /// Reuses the projection only for the immutable proof that owns it.
    pub(crate) fn finality_anchor(
        &self,
        artifact: &Arc<Artifact<V, D>>,
    ) -> Option<&DerivedVqc<V, D>> {
        self.proof
            .as_ref()
            .and_then(|proof| Arc::ptr_eq(&proof.artifact, artifact).then_some(&proof.derived))
    }

    /// Returns the selected paths of the retained proof `artifact`.
    pub(crate) fn selected_commitments(
        &self,
        artifact: &Arc<Artifact<V, D>>,
    ) -> Option<&SelectedCommitments<D>> {
        self.finality_anchor(artifact)
            .map(|derived| derived.validated.commitments())
    }

    /// Drops the retained proof once the signing floor reaches its view.
    pub(crate) fn retire_proofs_through(&mut self, floor: View) {
        if self.proof.as_ref().is_some_and(|proof| proof.view <= floor) {
            self.proof = None;
        }
    }

    /// Reserves the pools `artifact` votes in before its verification completes.
    ///
    /// A repeated claim on the same artifact keeps the earlier observation.
    pub(crate) fn claim_finality<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: Arc<Artifact<V, D>>,
        profile: &Profile<H::Digest>,
    ) -> Result<(), FinalityError> {
        if self.is_retired(&artifact) {
            return Ok(());
        }
        // Artifact identity is content-addressed, so a duplicate claim reconciles the exact
        // object to the minimum observation instead of overwriting the pending claim and
        // stranding its owner-order entry.
        if let Some(existing) = self.claims.get(&id) {
            if observation < existing.observation {
                self.reobserve_finality_claim::<H>(id, observation)?;
            }
            return Ok(());
        }
        let Some(keys) = self.reservation_keys::<H>(&artifact) else {
            return Ok(());
        };
        let reservations =
            PoolReservations(keys.try_map(|key| self.reserve_pool(profile, key, observation))?);

        let claim = FinalityClaim::new(observation, Arc::clone(&artifact), reservations);
        let owner = claim.owner();
        debug_assert!(
            claim
                .reservations
                .as_slice()
                .iter()
                .all(|reservation| reservation.owner == owner),
            "one artifact cannot span views"
        );
        if claim.ordered() {
            self.claim_order
                .entry(owner)
                .or_default()
                .insert((observation, id));
        }
        self.register_finality_claims::<H>(id, observation, &artifact, &claim, None);
        self.claims.insert(id, claim);
        Ok(())
    }

    fn reserve_pool(
        &mut self,
        profile: &Profile<D>,
        reservation: ReservationKey<D>,
        observation: Observation,
    ) -> Result<PoolReservation<D>, FinalityError> {
        let owner = profile.protocol().leader(reservation.key.view());
        let admission = self.capacity.reserve_unverified(
            owner,
            reservation.key,
            observation,
            reservation.liveness,
        );
        Ok(PoolReservation {
            owner,
            key: reservation.key,
            liveness: reservation.liveness,
            retained: !matches!(admission, PoolAdmission::Dropped),
        })
    }

    /// Resolves a claim whose artifact failed verification, releasing its reservations.
    pub(super) fn reject_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        profile: &Profile<H::Digest>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        self.resolve_finality_claim::<H>(
            id,
            observation,
            artifact,
            ClaimVerdict::Rejected,
            profile,
            None,
        )
    }

    /// Resolves a claim whose artifact passed verification, settling its votes into their pools
    /// and releasing the L-QCs now due in claim order.
    pub(super) fn validate_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        profile: &Profile<H::Digest>,
        mut derivations: Option<CertificateDerivations<V, D>>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        if matches!(artifact.as_ref(), Artifact::Lqc(_)) && self.is_retired(artifact) {
            // Diagnostic retention may discard an L-QC claim before verification completes.
            // The verified certificate remains portable consensus evidence and must still reach
            // the durable signing-floor transition.
            return Ok(vec![FinalityOutput::lqc(
                observation,
                artifact,
                derivations.as_mut(),
            )]);
        }
        self.resolve_finality_claim::<H>(
            id,
            observation,
            artifact,
            ClaimVerdict::Valid,
            profile,
            derivations,
        )
    }

    fn resolve_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        verdict: ClaimVerdict,
        profile: &Profile<H::Digest>,
        derivations: Option<CertificateDerivations<V, D>>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        let Some(claim) = self.claims.get(&id) else {
            // A discarded artifact may already have drained its claim as valid; the rejection
            // that accompanies its removal must still release every registered claim it holds,
            // or the dropped artifact pins finality capacity forever.
            if matches!(verdict, ClaimVerdict::Rejected) {
                self.reject_finality::<H>(id, artifact.as_ref())?;
            }
            return Ok(Vec::new());
        };
        // The identifier hashes the exact encoding, so the retained claim holds this artifact;
        // comparing the values would force both copies' lazy signature decodes on every verdict.
        debug_assert!(
            artifact.as_ref() == claim.artifact.as_ref(),
            "two artifacts encode to one identifier"
        );
        // Validation is content-addressed, so duplicate completions share one verdict while the
        // claim retains its earliest observation for deterministic arrival ordering.
        if observation < claim.observation {
            self.reobserve_finality_claim::<H>(id, observation)?;
        }
        let claim = self
            .claims
            .get_mut(&id)
            .expect("the reconciled finality claim remains retained");
        claim.verdict = verdict;
        if derivations.is_some() {
            claim.derivations = derivations;
        }
        if !claim.ordered() {
            let claim = self
                .claims
                .remove(&id)
                .expect("the resolved finality claim remains retained");
            let mut outputs = Vec::new();
            self.apply_finality_claim::<H>(id, claim, profile, &mut outputs)?;
            return Ok(outputs);
        }
        let owner = claim.owner();
        self.drain_finality_claims::<H>(owner, profile)
    }

    fn reobserve_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
    ) -> Result<(), FinalityError> {
        let claim = self
            .claims
            .get(&id)
            .expect("the finality claim was checked above");
        let previous = claim.observation;
        let owner = claim.owner();
        let ordered = claim.ordered();
        if ordered {
            let Some(order) = self.claim_order.get(&owner) else {
                return Err(FinalityError::Invariant);
            };
            if !order.contains(&(previous, id)) || order.contains(&(observation, id)) {
                return Err(FinalityError::Invariant);
            }
        }

        let Self {
            capacity,
            pools,
            claims,
            claim_order,
            ..
        } = self;
        let claim = claims
            .get_mut(&id)
            .expect("the finality claim remains retained");
        if ordered {
            let order = claim_order
                .get_mut(&owner)
                .expect("the owner order was checked above");
            order.remove(&(previous, id));
            order.insert((observation, id));
        }
        claim.observation = observation;
        for reservation in claim
            .reservations
            .as_slice()
            .iter()
            .filter(|reservation| reservation.retained)
        {
            capacity.retain_earlier_observation(reservation.key, observation);
        }
        visit_vote_claims::<H, V, D>(&claim.artifact, claim.derived_leader(), |vote| {
            if claim.retains(vote.pool) {
                pools
                    .entry(vote.pool)
                    .or_default()
                    .pending
                    .claim(vote.signer, id, observation);
            }
        });
        Ok(())
    }

    fn drain_finality_claims<H: Hasher<Digest = D>>(
        &mut self,
        owner: Participant,
        profile: &Profile<H::Digest>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        let mut outputs = Vec::new();
        loop {
            let Some((observation, id)) = self
                .claim_order
                .get(&owner)
                .and_then(BTreeSet::first)
                .copied()
            else {
                return Ok(outputs);
            };
            let Some(claim) = self.claims.get(&id) else {
                return Err(FinalityError::Invariant);
            };
            if matches!(claim.verdict, ClaimVerdict::Pending) {
                return Ok(outputs);
            }
            if claim.observation != observation || claim.owner() != owner {
                return Err(FinalityError::Invariant);
            }

            let claim = self
                .claims
                .remove(&id)
                .expect("a ready finality claim remains retained");
            self.remove_claim_order(owner, observation, id);

            self.apply_finality_claim::<H>(id, claim, profile, &mut outputs)?;
        }
    }

    fn apply_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        mut claim: FinalityClaim<V, D>,
        profile: &Profile<H::Digest>,
        outputs: &mut FinalityOutputs<V, D>,
    ) -> Result<(), FinalityError> {
        let observation = claim.observation;
        match claim.verdict {
            ClaimVerdict::Rejected => {
                self.reject_finality::<H>(id, claim.artifact.as_ref())?;
            }
            ClaimVerdict::Valid => {
                let certificate_key =
                    if matches!(claim.artifact.as_ref(), Artifact::Vqc(_) | Artifact::Lqc(_)) {
                        leader_key::<H, V, D>(&claim.artifact, claim.derived_leader())
                    } else {
                        None
                    };
                if let Some(key) = certificate_key {
                    self.pin_claimed_pool(key, &mut claim.reservations);
                }
                for reservation in claim.reservations.as_mut_slice() {
                    if Some(reservation.key) == certificate_key && reservation.liveness {
                        continue;
                    }
                    let admission = self.capacity.activate_unfinalized(
                        reservation.owner,
                        reservation.key,
                        observation,
                        reservation.liveness,
                    );
                    if let PoolAdmission::Replaced(evicted) = admission {
                        self.discard_replaced_pool(evicted)?;
                    }
                    reservation.retained = !matches!(admission, PoolAdmission::Dropped);
                }
                // The certificate key already resolved the leader digest, so the rest of the
                // lifecycle reuses it instead of re-encoding the leader block.
                let leader = certificate_key.map(|key| key.leader);
                self.remove_dropped_claims::<H>(id, claim.artifact.as_ref(), &claim, leader)?;
                self.register_finality_claims::<H>(
                    id,
                    observation,
                    &claim.artifact,
                    &claim,
                    leader,
                );
                if matches!(claim.artifact.as_ref(), Artifact::Lqc(_)) {
                    outputs.push(FinalityOutput::lqc(
                        observation,
                        &claim.artifact,
                        claim.derivations.as_mut(),
                    ));
                }
                self.observe_finality::<H>(id, observation, &mut claim, profile)?;
            }
            ClaimVerdict::Pending => unreachable!("pending claims do not drain"),
        }
        for reservation in claim.reservations.as_slice() {
            self.release_capacity_if_unused(reservation.key);
        }
        Ok(())
    }

    fn reservation_keys<H: Hasher<Digest = D>>(
        &self,
        artifact: &Artifact<V, D>,
    ) -> Option<OneOrMany<ReservationKey<D>>> {
        let mut keys = None;
        let leader = leader_key::<H, V, D>(artifact, None);
        if let Some(key) = leader {
            push_reservation_key(&mut keys, key, true);
        }
        visit_vote_claims::<H, V, D>(artifact, leader.map(|key| key.leader), |claim| {
            push_reservation_key(&mut keys, claim.pool, false)
        });
        keys
    }

    fn register_finality_claims<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Artifact<V, D>,
        batch: &FinalityClaim<V, D>,
        leader: Option<D>,
    ) {
        let leader_key = leader_key::<H, V, D>(artifact, leader);
        if let Some(key) = leader_key.filter(|key| batch.retains(*key)) {
            self.pools.entry(key).or_default().claims.insert(id);
        }
        let certificate = matches!(artifact, Artifact::Vqc(_) | Artifact::Lqc(_));
        let Ok(()) = self.for_each_distinct_pool::<H, Infallible>(
            artifact,
            leader_key.map(|key| key.leader),
            |state, key| {
                let retained = batch.retains(key);
                if retained && certificate {
                    state.pools.entry(key).or_default().claims.insert(id);
                }
                retained
            },
            |state, claim| {
                state.pools.entry(claim.pool).or_default().pending.claim(
                    claim.signer,
                    id,
                    observation,
                );
                Ok(())
            },
        );
    }

    /// Visits the vote claims of `artifact` whose pool `settle` accepts.
    ///
    /// A certificate's tallied signers all share its designated pool, so `settle` (and its side
    /// effects) runs once per run of equal pools rather than once per signer. Visiting stops at the
    /// first error `visit` returns.
    fn for_each_distinct_pool<H, E>(
        &mut self,
        artifact: &Artifact<V, D>,
        leader: Option<D>,
        mut settle: impl FnMut(&mut Self, PoolKey<D>) -> bool,
        mut visit: impl FnMut(&mut Self, VoteClaim<D>) -> Result<(), E>,
    ) -> Result<(), E>
    where
        H: Hasher<Digest = D>,
    {
        let mut result = Ok(());
        let mut settled: Option<(PoolKey<D>, bool)> = None;
        visit_vote_claims::<H, V, D>(artifact, leader, |claim| {
            if result.is_err() {
                return;
            }
            let accepted = match settled {
                Some((previous, accepted)) if previous == claim.pool => accepted,
                _ => {
                    let accepted = settle(self, claim.pool);
                    settled = Some((claim.pool, accepted));
                    accepted
                }
            };
            if accepted {
                result = visit(self, claim);
            }
        });
        result
    }

    fn reject_finality<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
    ) -> Result<(), FinalityError> {
        if self.is_retired(artifact) {
            return Ok(());
        }
        self.release_unretained_finality::<H, _>(id, artifact, None, |_| false)
    }

    fn remove_dropped_claims<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
        claim: &FinalityClaim<V, D>,
        leader: Option<D>,
    ) -> Result<(), FinalityError> {
        self.release_unretained_finality::<H, _>(id, artifact, leader, |key| claim.retains(key))
    }

    fn release_unretained_finality<H, F>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
        leader: Option<D>,
        retained: F,
    ) -> Result<(), FinalityError>
    where
        H: Hasher<Digest = D>,
        F: Fn(PoolKey<D>) -> bool,
    {
        if let Artifact::LeaderBlock(block) = artifact {
            let key = pool_key::<H, V, D>(block.block(), leader);
            if retained(key) {
                return Ok(());
            }
            self.release_pool_claim(key, id);
            self.remove_source(key, id);
            self.settle_pool::<H>(key)?;
            self.prune(key);
        }

        self.for_each_distinct_pool::<H, _>(
            artifact,
            leader,
            |state, key| {
                let release = !retained(key);
                if release {
                    state.release_pool_claim(key, id);
                }
                release
            },
            |state, claim| {
                if let Some(entry) = state.pools.get_mut(&claim.pool) {
                    entry.pending.remove_claim(claim.signer, id);
                    entry.pending.remove_candidate(claim.signer, id);
                }
                state.settle_pool::<H>(claim.pool)?;
                state.prune(claim.pool);
                Ok(())
            },
        )
    }

    fn observe_finality<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        claim: &mut FinalityClaim<V, D>,
        profile: &Profile<H::Digest>,
    ) -> Result<(), FinalityError> {
        let artifact = Arc::clone(&claim.artifact);
        if artifact.epoch() != profile.protocol().epoch() {
            return Err(FinalityError::Invariant);
        }
        if self.is_retired(&artifact) {
            return Ok(());
        }
        if let Some(vote) = Held::<VoteKind, V, D>::try_new(&artifact) {
            let key = Self::pool_key_and_signer(vote.get()).0;
            if claim.retains(key) {
                self.observe_vote::<H>(id, observation, vote)?;
            }
            return Ok(());
        }
        match artifact.as_ref() {
            Artifact::LeaderBlock(block) => {
                let key = pool_key::<H, V, D>(block.block(), None);
                self.observe_leader::<H>(
                    id,
                    observation,
                    block.block().clone(),
                    Some(key.leader),
                    claim.retains(key),
                )?;
            }
            Artifact::Vqc(certificate) => {
                let derived = claim.derived_leader();
                self.observe_leader::<H>(
                    id,
                    observation,
                    certificate.leader().clone(),
                    derived,
                    true,
                )?;
                let derivations = claim.derivations.take();
                self.observe_vqc::<H>(id, observation, certificate, claim, derivations)?;
            }
            Artifact::Lqc(certificate) => {
                let derived = claim.derived_leader();
                self.observe_leader::<H>(
                    id,
                    observation,
                    certificate.leader().clone(),
                    derived,
                    true,
                )?;
                let derivations = claim.derivations.take();
                self.observe_lqc::<H>(id, observation, certificate, derivations)?;
            }
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::NoVote(_)
            | Artifact::Nullify(_)
            | Artifact::Nullification(_) => {}
            Artifact::Vote(_) => unreachable!("votes are observed above"),
        }
        Ok(())
    }

    /// Issues aggregation jobs for up to `job_slots` ready L-QCs, earliest first.
    pub(crate) fn drive_aggregate(
        &mut self,
        generation: Generation,
        mut job_slots: usize,
    ) -> Result<(), FinalityError> {
        while job_slots > 0 {
            let Some((observation, key)) = self.ready_lqcs.pop_first() else {
                break;
            };
            job_slots -= 1;
            let Some(pool) = self.direct_pool(key) else {
                continue;
            };
            let Some(LqcProgress::Ready {
                votes,
                observation: current,
            }) = pool.lqc()
            else {
                continue;
            };
            if *current != observation {
                continue;
            }
            let leader = pool.leader.clone();
            let votes = Arc::clone(votes);
            let id = self
                .lqc_aggregate_ids
                .issue()
                .ok_or(FinalityError::IdentifierExhausted)?;
            let issued = Issued::new(id, generation);
            let job = LqcAggregateJob {
                issued,
                leader,
                votes: Arc::clone(&votes),
            };
            self.lqc_aggregate_jobs.insert(
                issued,
                AggregateRecord {
                    key,
                    observation,
                    job: job.clone(),
                },
            );
            *self
                .direct_pool_mut(key)
                .and_then(DirectPool::lqc_mut)
                .expect("the selected direct pool remains retained") =
                LqcProgress::Pending { votes, id };
            self.capabilities
                .push(Capability::Crypto(CryptoJob::AggregateLqc(job)));
        }
        Ok(())
    }

    /// Returns whether a pool waits for an aggregation job.
    pub(crate) fn has_ready_aggregate(&self) -> bool {
        !self.ready_lqcs.is_empty()
    }

    /// Returns whether a local pool above `floor` already reached finality and owes an L-QC.
    ///
    /// Such a pool holds every vote the certificate needs, so the aggregate arrives without any
    /// network round trip and a peer request for the same evidence would be wasted.
    pub(crate) fn assembling_above(&self, floor: View) -> bool {
        self.ready_lqcs.iter().any(|(_, key)| key.view() > floor)
            || self
                .lqc_aggregate_jobs
                .values()
                .any(|record| record.key.view() > floor)
    }

    /// Takes the work issued since the last call.
    pub(crate) fn take_capabilities(&mut self) -> Capabilities<V, D> {
        take(&mut self.capabilities)
    }

    /// Returns the number of aggregation jobs in flight.
    pub(crate) fn aggregate_reservations(&self) -> usize {
        self.lqc_aggregate_jobs.len()
    }

    /// Prepares an L-QC aggregation completion, or consumes a stale completion.
    ///
    /// Returning `None` releases a matching reservation whose dispatch generation is no longer
    /// current and returns its pool to the ready set, so a completion that cannot commit can
    /// never strand the pool in a pending state that blocks re-aggregation.
    pub(crate) fn prepare_lqc<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H::Digest>,
        completion: LqcAggregateCompletion<V, D>,
        generation: Generation,
    ) -> Result<Option<PreparedLqc<V, D>>, FinalityError> {
        let record = match self.lqc_aggregate_jobs.admit(completion.issued, generation) {
            Admit::Current(record) => record,
            Admit::Stale => return Ok(None),
            Admit::Abandoned(record) => {
                self.release_lqc(record);
                return Ok(None);
            }
        };
        if !record
            .job
            .matches::<H>(&completion.certificate, profile.codec())
        {
            return Err(FinalityError::CompletionMismatch);
        }
        let artifact = Arc::new(Artifact::Lqc(completion.certificate));
        Ok(Some(PreparedLqc {
            issued: completion.issued,
            artifact_id: artifact.id::<H>(),
            encoded_len: artifact.encoded_len(),
            artifact,
            observation: record.observation,
            validated: Some(completion.validated),
        }))
    }

    /// Returns whether the aggregation `issued` is still outstanding as issued.
    pub(crate) fn lqc_aggregation_is_current(&self, issued: Issued<LqcAggregateId>) -> bool {
        self.lqc_aggregate_jobs
            .get(issued.id())
            .is_some_and(|record| record.job.issued == issued)
    }

    /// Releases a committed aggregation job and marks its pool's L-QC complete.
    pub(crate) fn finish_lqc(&mut self, id: LqcAggregateId) {
        let Some(record) = self.lqc_aggregate_jobs.remove(id) else {
            return;
        };
        if let Some(lqc) = self
            .direct_pool_mut(record.key)
            .and_then(DirectPool::lqc_mut)
            && matches!(lqc, LqcProgress::Pending { id: current, .. } if *current == id)
        {
            *lqc = LqcProgress::Complete;
        }
    }

    /// Releases an aggregation reservation without a certificate and re-readies its pool.
    ///
    /// The witnessed votes survive the job, so the pool re-aggregates on the next drive instead of
    /// waiting behind a pending marker whose completion was consumed.
    pub(crate) fn abandon_lqc(&mut self, id: LqcAggregateId) {
        if let Some(record) = self.lqc_aggregate_jobs.remove(id) {
            self.release_lqc(record);
        }
    }

    fn release_lqc(&mut self, record: AggregateRecord<V, D>) {
        let id = record.job.issued.id();
        if let Some(lqc) = self
            .direct_pool_mut(record.key)
            .and_then(DirectPool::lqc_mut)
            && let LqcProgress::Pending { votes, id: current } = lqc
            && *current == id
        {
            *lqc = LqcProgress::Ready {
                votes: Arc::clone(votes),
                observation: record.observation,
            };
            self.ready_lqcs.insert((record.observation, record.key));
        }
    }

    /// Returns each pool's direct finality fact, then its certified one, in pool order.
    pub(crate) fn facts(&self) -> Vec<FinalityFact<D>> {
        self.pools
            .iter()
            .flat_map(|(key, entry)| {
                let direct = entry.direct.as_ref().and_then(|pool| {
                    pool.finality_fact(key.leader, self.config)
                        .expect("direct finality was validated when the pool finalized")
                });
                let certified = entry
                    .certified
                    .as_ref()
                    .map(|certified| certified.fact.clone());
                direct.into_iter().chain(certified)
            })
            .collect()
    }

    /// Returns a summary of every pool that knows its leader block.
    pub(crate) fn pools(&self) -> Vec<PoolSummary<D>> {
        self.pools
            .iter()
            .filter_map(|(key, entry)| {
                let pool = entry.direct.as_ref()?;
                Some(PoolSummary::new(
                    pool.leader.round(),
                    key.leader,
                    pool.extractor.len(),
                    pool.finalized(),
                    matches!(
                        pool.lqc(),
                        Some(LqcProgress::Ready { .. } | LqcProgress::Pending { .. })
                    ),
                ))
            })
            .collect()
    }

    /// Retires finality diagnostics outside the retained view window.
    ///
    /// This bounds local evidence by age; it does not infer that a higher-view certificate
    /// dominates the retired chain-local facts.
    pub(super) fn retire_through<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H::Digest>,
        floor: View,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        if floor <= self.retired_through {
            return Ok(Vec::new());
        }
        self.retired_through = floor;
        self.capacity.retire_through(floor);

        let retired_claims = self
            .claims
            .iter()
            .filter_map(|(id, claim)| {
                claim
                    .artifact
                    .view()
                    .is_some_and(|claim_view| claim_view <= floor)
                    .then_some((*id, claim.observation, claim.owner()))
            })
            .collect::<Vec<_>>();
        let mut released_owners = BTreeSet::new();
        for (id, observation, owner) in retired_claims {
            self.claims.remove(&id);
            released_owners.insert(owner);
            self.remove_claim_order(owner, observation, id);
        }

        let retained = |key: &PoolKey<D>| key.view() > floor;
        self.pools.retain(|key, _| retained(key));
        self.ready_lqcs.retain(|(_, key)| retained(key));
        self.lqc_aggregate_jobs
            .retain(|record| retained(&record.key));
        self.capabilities.retain(|capability| {
            !matches!(
                capability,
                Capability::Crypto(CryptoJob::AggregateLqc(job))
                    if job.leader().round().view() <= floor
            )
        });

        let mut outputs = Vec::new();
        for owner in released_owners {
            outputs.extend(self.drain_finality_claims::<H>(owner, profile)?);
        }
        Ok(outputs)
    }

    fn observe_leader<H: Hasher<Digest = D>>(
        &mut self,
        source: ArtifactId<D>,
        observation: Observation,
        leader: LeaderBlock<V, D>,
        digest: Option<D>,
        retained: bool,
    ) -> Result<(), FinalityError> {
        let key = pool_key::<H, V, D>(&leader, digest);
        if !retained {
            // Without a direct pool or another claim, nothing can settle the pool's pending
            // votes.
            if let Some(entry) = self.pools.get_mut(&key) {
                entry.claims.remove(&source);
                if entry.direct.is_none() && entry.claims.is_empty() {
                    entry.pending = PendingPool::default();
                }
            }
            self.prune(key);
            return Ok(());
        }

        if let Some(pool) = self.direct_pool_mut(key) {
            if pool.leader != leader {
                return Err(FinalityError::LeaderCollision);
            }
            pool.leader_observation = pool.leader_observation.min(observation);
            pool.sources.insert(source);
            self.release_pool_claim(key, source);
            return Ok(());
        }

        let direct = DirectPool::new::<H>(leader, observation, source, self.config)?;
        let entry = self.pools.entry(key).or_default();
        entry.direct = Some(Box::new(direct));
        entry.claims.remove(&source);
        self.settle_pool::<H>(key)
    }

    fn pin_claimed_pool(&mut self, key: PoolKey<D>, reservations: &mut PoolReservations<D>) {
        self.capacity.pin(key);
        reservations.retain(key);
    }

    fn observe_vote<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: Held<VoteKind, V, D>,
    ) -> Result<(), FinalityError> {
        let vote = artifact.get();
        let (key, signer) = Self::pool_key_and_signer(vote);
        let pending = &mut self.pools.entry(key).or_default().pending;
        pending.remove_claim(signer, id);
        pending.insert_candidate(
            signer,
            VoteRecord {
                id,
                observation,
                body: vote.body().clone(),
                evidence: vote_evidence::<H, D>(signer, vote.body()),
                artifact: Some(artifact),
            },
        );
        self.settle_pool::<H>(key)
    }

    fn observe_vqc<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &Vqc<V, D>,
        claim: &FinalityClaim<V, D>,
        derivations: Option<CertificateDerivations<V, D>>,
    ) -> Result<(), FinalityError> {
        let votes = match derivations {
            Some(CertificateDerivations::Vqc { votes, .. }) => votes,
            _ => Self::expand_vqc_votes::<H>(certificate, self.config)?,
        };
        for vote in votes {
            if claim.retains(PoolKey::new(vote.body.round(), vote.body.leader())) {
                self.observe_aggregate_vote::<H>(
                    id,
                    observation,
                    vote.signer,
                    vote.body,
                    vote.evidence,
                )?;
            }
        }
        Ok(())
    }

    /// Rebuilds every attested vote of a V-QC in place: the recovery path, where no compute-pool
    /// derivation accompanies the certificate.
    fn expand_vqc_votes<H: Hasher<Digest = D>>(
        certificate: &Vqc<V, D>,
        config: CodecConfig,
    ) -> Result<Vec<VerifiedVote<D>>, FinalityError> {
        let designated = certificate
            .expand_votes(certificate.leader().digest::<H>(), config)
            .map_err(|_| FinalityError::Invariant)?;
        let conflicting = certificate
            .conflicting_bodies()
            .map_err(|_| FinalityError::Invariant)?;
        Ok(designated
            .into_iter()
            .chain(conflicting)
            .map(|(signer, body)| VerifiedVote::new::<H>(signer, body))
            .collect())
    }

    fn observe_aggregate_vote<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        signer: Participant,
        body: VoteBody<D>,
        evidence: D,
    ) -> Result<(), FinalityError> {
        let key = PoolKey::new(body.round(), body.leader());
        let entry = self.pools.entry(key).or_default();
        entry.pending.remove_claim(signer, id);
        entry.pending.insert_candidate(
            signer,
            VoteRecord {
                id,
                observation,
                evidence,
                body,
                artifact: None,
            },
        );
        if entry.direct.is_some() {
            entry.claims.remove(&id);
        }
        self.settle_pool::<H>(key)
    }

    fn observe_lqc<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &Lqc<V, D>,
        derivations: Option<CertificateDerivations<V, D>>,
    ) -> Result<(), FinalityError> {
        let leader = certificate.leader();
        let (leader_digest, tips, votes) = match derivations {
            Some(CertificateDerivations::Lqc {
                leader,
                tips,
                votes,
                ..
            }) => (leader, tips, votes),
            _ => {
                // Recovery path: no compute-pool derivation accompanies the certificate.
                let leader_digest = leader.digest::<H>();
                let expanded = certificate
                    .expand_votes(leader_digest, self.config)
                    .map_err(|_| FinalityError::Invariant)?;
                let tips = FinalTips::from_pool::<H, V, _>(
                    leader,
                    expanded.iter().map(|(signer, body)| (*signer, body)),
                    self.config,
                )
                .map_err(|_| FinalityError::Invariant)?;
                let votes = expanded
                    .into_iter()
                    .map(|(signer, body)| VerifiedVote::new::<H>(signer, body))
                    .collect();
                (leader_digest, tips, votes)
            }
        };
        let key = PoolKey::new(leader.round(), leader_digest);
        let fact = tips
            .fact(
                FinalityId::Lqc(id),
                DigestedLeader::with_digest(leader, key.leader),
                votes.len(),
                self.config,
            )
            .map_err(|_| FinalityError::Invariant)?;
        let entry = self
            .pools
            .get_mut(&key)
            .filter(|entry| entry.has_leader())
            .ok_or(FinalityError::Invariant)?;
        if entry
            .certified
            .as_ref()
            .is_none_or(|record| observation < record.observation)
        {
            entry.certified = Some(Box::new(CertifiedRecord { observation, fact }));
        }

        // The observed certificate supersedes any local aggregation.
        match entry
            .direct
            .as_deref_mut()
            .and_then(DirectPool::complete_lqc)
        {
            Some(LqcProgress::Ready { observation, .. }) => {
                self.ready_lqcs.remove(&(observation, key));
            }
            Some(LqcProgress::Pending { id, .. }) => {
                self.lqc_aggregate_jobs.remove(id);
            }
            Some(LqcProgress::AwaitingWitnesses(_) | LqcProgress::Complete) | None => {}
        }

        for vote in votes {
            self.observe_aggregate_vote::<H>(
                id,
                observation,
                vote.signer,
                vote.body,
                vote.evidence,
            )?;
        }
        Ok(())
    }

    /// Settles pending votes into the direct pool in arrival order.
    ///
    /// Settling stops at the first candidate an earlier unverified claim on the pool precedes,
    /// since that claim may still carry an earlier vote from the same signer.
    fn settle_pool<H: Hasher<Digest = D>>(&mut self, key: PoolKey<D>) -> Result<(), FinalityError> {
        let Self {
            config,
            capacity,
            pools,
            ready_lqcs,
            updates,
            ..
        } = self;
        let Some(PoolEntry {
            direct: Some(pool),
            pending,
            ..
        }) = pools.get_mut(&key)
        else {
            return Ok(());
        };
        while let Some(next) = pending.candidate_order.first().copied() {
            if pending
                .claim_order
                .first()
                .is_some_and(|claim| *claim < next)
            {
                break;
            }
            let (_, signer, id) = next;
            let mut candidate = pending
                .pop_candidate(signer, id)
                .expect("the candidate was checked above");
            let signer_index = usize::from(signer);
            let selected = pool
                .votes
                .get(signer_index)
                .ok_or(FinalityError::Invariant)?;
            match selected {
                Some(selected) if selected.artifact.is_some() => {
                    pending.clear_signer(signer);
                    continue;
                }
                Some(selected) if selected.body != candidate.body => continue,
                _ => {}
            }
            let witnessing = selected.is_some();
            if candidate.artifact.is_none() {
                candidate.artifact = pending.witness(signer, &candidate.body);
            }
            if witnessing {
                if let Some(witness) = candidate.artifact {
                    pool.votes[signer_index]
                        .as_mut()
                        .expect("the signer was checked above")
                        .artifact = Some(witness);
                    if let Some(observation) = pool.stage_lqc(config.view_quorum())? {
                        ready_lqcs.insert((observation, key));
                    }
                    pending.clear_signer(signer);
                }
                continue;
            }
            match pool.insert::<H>(signer, candidate, *config) {
                Inserted::Rejected => {}
                Inserted::Collecting => pending.clear_signer(signer),
                Inserted::Quorum => {
                    capacity.pin(key);
                    if let Some(update) = pool.finalize::<H>(key.leader, *config)? {
                        updates.push(update);
                    }
                    if let Some(observation) = pool.stage_lqc(config.view_quorum())? {
                        ready_lqcs.insert((observation, key));
                    }
                    pending.clear_signer(signer);
                }
            }
        }
        Ok(())
    }

    /// Takes the finality updates recorded since the last drain.
    pub(super) fn drain_updates(&mut self) -> Vec<FinalityUpdate<D>> {
        take(&mut self.updates)
    }

    /// Discards recorded finality updates.
    pub(crate) fn clear_updates(&mut self) {
        self.updates.clear();
    }

    fn pool_key_and_signer(vote: &Vote<V, D>) -> (PoolKey<D>, Participant) {
        (
            PoolKey::new(vote.body().round(), vote.body().leader()),
            vote.signer(),
        )
    }

    /// Removes one claim from its owner's arrival order, dropping the owner once empty.
    fn remove_claim_order(
        &mut self,
        owner: Participant,
        observation: Observation,
        id: ArtifactId<D>,
    ) {
        let empty = self.claim_order.get_mut(&owner).is_some_and(|order| {
            order.remove(&(observation, id));
            order.is_empty()
        });
        if empty {
            self.claim_order.remove(&owner);
        }
    }

    fn is_retired(&self, artifact: &Artifact<V, D>) -> bool {
        artifact
            .view()
            .is_some_and(|view| view <= self.retired_through)
    }

    fn release_pool_claim(&mut self, key: PoolKey<D>, id: ArtifactId<D>) {
        if let Some(entry) = self.pools.get_mut(&key) {
            entry.claims.remove(&id);
        }
    }

    /// Removes the entry of `key` once nothing in it remains.
    fn prune(&mut self, key: PoolKey<D>) {
        if self.pools.get(&key).is_some_and(PoolEntry::is_empty) {
            self.pools.remove(&key);
        }
    }

    fn remove_source(&mut self, key: PoolKey<D>, source: ArtifactId<D>) {
        let remove = self.direct_pool_mut(key).is_some_and(|pool| {
            pool.sources.remove(&source);
            pool.sources.is_empty() && !pool.holds_evidence()
        });
        if remove {
            self.remove_direct_pool(key);
        }
    }

    fn direct_pool(&self, key: PoolKey<D>) -> Option<&DirectPool<V, D>> {
        self.pools.get(&key)?.direct.as_deref()
    }

    fn direct_pool_mut(&mut self, key: PoolKey<D>) -> Option<&mut DirectPool<V, D>> {
        self.pools.get_mut(&key)?.direct.as_deref_mut()
    }

    fn remove_direct_pool(&mut self, key: PoolKey<D>) {
        let Some(entry) = self.pools.get_mut(&key) else {
            return;
        };
        entry.direct = None;
        if entry.certified.is_none() && entry.claims.is_empty() {
            self.capacity.release_unfinalized(key);
        }
        self.prune(key);
    }

    /// Returns whether the pool of `key` holds finality evidence or owes an L-QC.
    fn pool_holds_evidence(&self, key: PoolKey<D>) -> bool {
        self.pools.get(&key).is_some_and(|entry| {
            entry.certified.is_some()
                || entry
                    .direct
                    .as_deref()
                    .is_some_and(DirectPool::holds_evidence)
        }) || self.ready_lqcs.iter().any(|(_, ready)| *ready == key)
            || self
                .lqc_aggregate_jobs
                .values()
                .any(|record| record.key == key)
    }

    fn discard_replaced_pool(&mut self, key: PoolKey<D>) -> Result<(), FinalityError> {
        if self.pool_holds_evidence(key) {
            return Err(FinalityError::Invariant);
        }
        self.pools.remove(&key);
        Ok(())
    }

    fn release_capacity_if_unused(&mut self, key: PoolKey<D>) {
        if self.pools.get(&key).is_some_and(|entry| {
            entry.direct.is_some() || !entry.claims.is_empty() || !entry.pending.is_empty()
        }) {
            return;
        }
        self.capacity.release_unfinalized(key);
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> FinalityState<V, D> {
    /// Returns the number of retained finality proofs, zero or one.
    pub(crate) fn retained_finality_proofs(&self) -> usize {
        usize::from(self.proof.is_some())
    }

    /// Returns how many pools retain any state.
    pub(crate) fn retained_pools(&self) -> usize {
        self.pools.len()
    }
}
