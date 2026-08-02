//! Per-leader vote pools and local leader finality.
//!
//! Raw votes enter arrival-first pools only after cryptographic authentication. These pools are
//! independent from the per-view message selection used to build V-QCs: a participant can vote for
//! multiple equivocating leaders, and each leader retains its own first authenticated vote.
//!
//! Reaching `n-f` finalizes the leader immediately. L-QC assembly is asynchronous evidence for
//! other replicas and never gates the local finality fact.

use super::{
    Artifact, ArtifactId, Observation, Profile,
    algebra::{FinalTips, PoolExtractor},
};
use crate::{
    Epochable,
    multimmit::{
        config::CodecConfig,
        types::{
            BlockRef, CertificateId, ChainId, LeaderBlock, Lqc, Position, Vote, VoteBody, Vqc,
        },
    },
    types::{Attributable, Participant, Round, View},
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::Arc,
};

const FINALITY_EVIDENCE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_FINALITY_EVIDENCE";
const FINALITY_VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_FINALITY_VOTE";

pub(super) type PoolKey<D> = (Round, D);
type VoteArtifacts<V, D> = Arc<[Arc<Artifact<V, D>>]>;
pub(super) enum FinalityOutput<V: Variant, D: Digest> {
    Finality(ArtifactId<D>, Observation, Arc<Artifact<V, D>>),
}

type FinalityOutputs<V, D> = Vec<FinalityOutput<V, D>>;

pub(super) struct FinalityLeaderRecord<V: Variant, D: Digest> {
    pub(super) finality: Option<DirectPool<V, D>>,
    pub(super) certified_finality: Option<CertifiedRecord<D>>,
}

/// Finality state for one epoch.
pub(crate) struct FinalityState<V: Variant, D: Digest> {
    pub(super) config: CodecConfig,
    pub(super) finality_capacity: FinalityPoolCapacity<D>,
    pub(super) leaders: BTreeMap<PoolKey<D>, FinalityLeaderRecord<V, D>>,
    pub(super) finality_pool_claims: BTreeMap<PoolKey<D>, BTreeSet<ArtifactId<D>>>,
    pub(super) finality_claims: BTreeMap<ArtifactId<D>, FinalityClaim<V, D>>,
    pub(super) finality_claim_order: BTreeMap<Participant, BTreeSet<(Observation, ArtifactId<D>)>>,
    pub(super) pending_finality: BTreeMap<PoolKey<D>, PendingPool<V, D>>,
    pub(super) ready_lqcs: BTreeSet<(Observation, PoolKey<D>)>,
    pub(super) lqc_aggregate_jobs: BTreeMap<LqcAggregateId, AggregateRecord<V, D>>,
    pub(super) next_lqc_aggregate: u64,
    pub(super) finality_effects: Vec<FinalityEffect<V, D>>,
    pub(super) retired_finality_through: Option<View>,
}

impl<V: Variant, D: Digest> FinalityState<V, D> {
    pub(crate) fn new<H: Hasher<Digest = D>>(profile: &Profile<H, V>) -> Self {
        let participants = profile.protocol().codec_config().participants();
        Self {
            config: profile.protocol().codec_config(),
            finality_capacity: FinalityPoolCapacity::new(
                participants,
                profile.resources().max_finality_pools(),
                profile.pinned_finality_pools(),
            ),
            leaders: BTreeMap::new(),
            finality_pool_claims: BTreeMap::new(),
            finality_claims: BTreeMap::new(),
            finality_claim_order: BTreeMap::new(),
            pending_finality: BTreeMap::new(),
            ready_lqcs: BTreeSet::new(),
            lqc_aggregate_jobs: BTreeMap::new(),
            next_lqc_aggregate: 0,
            finality_effects: Vec::new(),
            retired_finality_through: None,
        }
    }
}

#[derive(Copy, Clone)]
enum ClaimVerdict {
    Pending,
    Rejected,
    Valid,
}

#[derive(Copy, Clone)]
struct PoolReservation<D: Digest> {
    owner: Participant,
    key: PoolKey<D>,
    liveness: bool,
    retained: bool,
}

#[derive(Copy, Clone)]
struct ReservationKey<D: Digest> {
    key: PoolKey<D>,
    liveness: bool,
}

enum ReservationKeys<D: Digest> {
    None,
    Single(ReservationKey<D>),
    Many(Vec<ReservationKey<D>>),
}

impl<D: Digest> ReservationKeys<D> {
    fn push(&mut self, key: PoolKey<D>, liveness: bool) {
        match self {
            Self::None => {
                *self = Self::Single(ReservationKey { key, liveness });
            }
            Self::Single(existing) if existing.key == key => {
                existing.liveness |= liveness;
            }
            Self::Single(existing) => {
                *self = Self::Many(vec![*existing, ReservationKey { key, liveness }]);
            }
            Self::Many(keys) => {
                if let Some(existing) = keys.iter_mut().find(|existing| existing.key == key) {
                    existing.liveness |= liveness;
                } else {
                    keys.push(ReservationKey { key, liveness });
                }
            }
        }
    }
}

enum PoolReservations<D: Digest> {
    Single(PoolReservation<D>),
    Many(Vec<PoolReservation<D>>),
}

impl<D: Digest> PoolReservations<D> {
    fn as_slice(&self) -> &[PoolReservation<D>] {
        match self {
            Self::Single(reservation) => std::slice::from_ref(reservation),
            Self::Many(reservations) => reservations,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [PoolReservation<D>] {
        match self {
            Self::Single(reservation) => std::slice::from_mut(reservation),
            Self::Many(reservations) => reservations,
        }
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

pub(super) struct FinalityClaim<V: Variant, D: Digest> {
    pub(super) observation: Observation,
    pub(super) artifact: Arc<Artifact<V, D>>,
    reservations: PoolReservations<D>,
    verdict: ClaimVerdict,
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
        }
    }

    fn owner(&self) -> Participant {
        self.reservations.owner()
    }

    fn retains(&self, key: PoolKey<D>) -> bool {
        self.reservations.retains(key)
    }

    fn ordered(&self) -> bool {
        self.reservations.ordered()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PoolAdmission<D: Digest> {
    Admitted,
    Pinned,
    Dropped,
    Replaced(PoolKey<D>),
}

#[derive(Copy, Clone)]
struct PrimaryPool<D: Digest> {
    key: PoolKey<D>,
    observation: Observation,
    active: bool,
}

/// Finality-pool ownership under the protocol's `<= f` fault model.
///
/// Unfinalized pools reserve `f+1` slots for distinct scheduled identities. Secondary digests use
/// only the remaining best-effort space. Finalized and certificate-referenced pools move outside
/// that bounded partition so ordering work cannot consume a live identity's slot.
pub(super) struct FinalityPoolCapacity<D: Digest> {
    primary_limit: usize,
    best_effort_limit: usize,
    primary_by_owner: BTreeMap<Participant, PrimaryPool<D>>,
    primary_by_key: BTreeMap<PoolKey<D>, Participant>,
    best_effort: BTreeMap<PoolKey<D>, Observation>,
    best_effort_order: BTreeSet<(Observation, PoolKey<D>)>,
    pinned: BTreeSet<PoolKey<D>>,
}

impl<D: Digest> FinalityPoolCapacity<D> {
    pub(super) const fn new(participants: usize, max_pools: usize, pinned_reserve: usize) -> Self {
        let primary_limit = participants.saturating_sub(1) / 5 + 1;
        Self {
            primary_limit,
            best_effort_limit: max_pools - primary_limit - pinned_reserve,
            primary_by_owner: BTreeMap::new(),
            primary_by_key: BTreeMap::new(),
            best_effort: BTreeMap::new(),
            best_effort_order: BTreeSet::new(),
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

        if self.best_effort.contains_key(&key) {
            self.retain_earlier_best_effort_observation(key, observation);
            if liveness
                && !self.primary_by_owner.contains_key(&owner)
                && self.primary_by_owner.len() < self.primary_limit
            {
                self.remove_best_effort(key);
                self.insert_primary(owner, key, observation, false);
            }
            return PoolAdmission::Admitted;
        }

        if !liveness || self.primary_by_owner.contains_key(&owner) {
            return self.admit_best_effort(key, observation);
        }

        if self.primary_by_owner.len() < self.primary_limit {
            self.insert_primary(owner, key, observation, false);
            return PoolAdmission::Admitted;
        }

        self.admit_best_effort(key, observation)
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
            if existing.key.0.view() >= key.0.view() {
                return self.reserve_unverified(owner, key, observation, false);
            }
            return self.replace_primary(owner, existing, key, observation);
        }

        if self.primary_by_owner.len() < self.primary_limit {
            self.remove_best_effort(key);
            self.insert_primary(owner, key, observation, true);
            return PoolAdmission::Admitted;
        }

        let (&evicted_owner, &evicted) = self
            .primary_by_owner
            .iter()
            .min_by_key(|(owner, primary)| {
                (
                    primary.active,
                    primary.key.0.view(),
                    primary.observation,
                    **owner,
                )
            })
            .expect("a full primary tier contains a victim");
        if evicted.active && evicted.key.0.view() >= key.0.view() {
            return self.reserve_unverified(owner, key, observation, false);
        }
        self.remove_primary(evicted_owner, evicted.key);
        self.install_replacement(owner, evicted, key, observation)
    }

    fn pin(&mut self, key: PoolKey<D>) -> PoolAdmission<D> {
        if self.pinned.contains(&key) {
            return PoolAdmission::Pinned;
        }

        // Quorum evidence remains pinned until its view leaves the retained diagnostic window.
        self.release_unfinalized(key);
        self.pinned.insert(key);
        PoolAdmission::Pinned
    }

    fn retire_through(&mut self, floor: View) {
        let primary = self
            .primary_by_key
            .keys()
            .filter(|key| key.0.view() <= floor)
            .copied()
            .collect::<Vec<_>>();
        for key in primary {
            self.release_unfinalized(key);
        }
        let best_effort = self
            .best_effort
            .keys()
            .filter(|key| key.0.view() <= floor)
            .copied()
            .collect::<Vec<_>>();
        for key in best_effort {
            self.remove_best_effort(key);
        }
        self.pinned.retain(|key| key.0.view() > floor);
    }

    fn release_unfinalized(&mut self, key: PoolKey<D>) {
        self.remove_best_effort(key);
        let Some(owner) = self.primary_by_key.remove(&key) else {
            return;
        };
        self.primary_by_owner.remove(&owner);
    }

    fn admit_best_effort(&mut self, key: PoolKey<D>, observation: Observation) -> PoolAdmission<D> {
        if self.best_effort.len() >= self.best_effort_limit {
            return PoolAdmission::Dropped;
        }
        self.best_effort.insert(key, observation);
        self.best_effort_order.insert((observation, key));
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

    fn replace_primary(
        &mut self,
        owner: Participant,
        evicted: PrimaryPool<D>,
        key: PoolKey<D>,
        observation: Observation,
    ) -> PoolAdmission<D> {
        self.remove_primary(owner, evicted.key);
        self.install_replacement(owner, evicted, key, observation)
    }

    fn install_replacement(
        &mut self,
        owner: Participant,
        evicted: PrimaryPool<D>,
        key: PoolKey<D>,
        observation: Observation,
    ) -> PoolAdmission<D> {
        self.remove_best_effort(key);
        self.insert_primary(owner, key, observation, true);
        if matches!(
            self.admit_best_effort(evicted.key, evicted.observation),
            PoolAdmission::Dropped
        ) {
            return PoolAdmission::Replaced(evicted.key);
        }
        PoolAdmission::Admitted
    }

    fn remove_primary(&mut self, owner: Participant, key: PoolKey<D>) {
        let removed = self.primary_by_owner.remove(&owner);
        debug_assert!(removed.is_some_and(|primary| primary.key == key));
        self.primary_by_key.remove(&key);
    }

    fn retain_earlier_best_effort_observation(
        &mut self,
        key: PoolKey<D>,
        observation: Observation,
    ) {
        let previous = self.best_effort[&key];
        if observation >= previous {
            return;
        }
        self.best_effort_order.remove(&(previous, key));
        self.best_effort.insert(key, observation);
        self.best_effort_order.insert((observation, key));
    }

    fn retain_earlier_observation(&mut self, key: PoolKey<D>, observation: Observation) {
        if let Some(owner) = self.primary_by_key.get(&key) {
            let primary = self
                .primary_by_owner
                .get_mut(owner)
                .expect("the primary indexes agree");
            primary.observation = primary.observation.min(observation);
            return;
        }
        if self.best_effort.contains_key(&key) {
            self.retain_earlier_best_effort_observation(key, observation);
        }
    }

    fn remove_best_effort(&mut self, key: PoolKey<D>) -> bool {
        let Some(observation) = self.best_effort.remove(&key) else {
            return false;
        };
        self.best_effort_order.remove(&(observation, key));
        true
    }
}

/// Identifies one exact L-QC aggregation request within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LqcAggregateId(u64);

impl LqcAggregateId {
    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Immutable work for assembling one L-QC from an exact machine-selected vote set.
#[derive(Clone, Debug)]
pub(crate) struct LqcAggregateJob<V: Variant, D: Digest> {
    id: LqcAggregateId,
    generation: u64,
    leader: LeaderBlock<V, D>,
    votes: VoteArtifacts<V, D>,
}

impl<V: Variant, D: Digest> LqcAggregateJob<V, D> {
    /// Returns the job identifier.
    pub const fn id(&self) -> LqcAggregateId {
        self.id
    }

    /// Returns the process generation issuing the job.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact unsigned leader finalized by the selected votes.
    pub const fn leader(&self) -> &LeaderBlock<V, D> {
        &self.leader
    }

    /// Returns the selected complete votes in ascending participant order.
    pub fn votes(&self) -> impl ExactSizeIterator<Item = &Vote<V, D>> {
        self.votes.iter().map(|artifact| {
            let Artifact::Vote(vote) = artifact.as_ref() else {
                unreachable!("L-QC jobs contain only complete votes");
            };
            vote
        })
    }
}

/// Completion of one exact L-QC aggregation request.
#[derive(Clone, Debug)]
pub(crate) struct LqcAggregateCompletion<V: Variant, D: Digest> {
    id: LqcAggregateId,
    generation: u64,
    certificate: Lqc<V, D>,
}

impl<V: Variant, D: Digest> LqcAggregateCompletion<V, D> {
    /// Creates a completion for one machine-issued job.
    pub const fn new(id: LqcAggregateId, generation: u64, certificate: Lqc<V, D>) -> Self {
        Self {
            id,
            generation,
            certificate,
        }
    }
}

/// Identifies the evidence underlying one leader-finality fact.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FinalityId<D: Digest> {
    /// Digest of the canonical arrival-first vote evidence in a local pool.
    Direct(D),
    /// One independently authenticated L-QC witness.
    Lqc(ArtifactId<D>),
}

/// A normalized chain-local finality projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityFact<D: Digest> {
    id: FinalityId<D>,
    round: Round,
    leader: D,
    parent: CertificateId<D>,
    votes: usize,
    blocks: Vec<BlockRef<D>>,
    positions: Vec<Position>,
    settled: Vec<bool>,
}

impl<D: Digest> FinalityFact<D> {
    /// Returns the exact evidence identifier.
    pub const fn id(&self) -> FinalityId<D> {
        self.id
    }

    /// Returns the finalized leader's epoch and view.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the finalized unsigned leader digest.
    pub const fn leader(&self) -> D {
        self.leader
    }

    /// Returns the parent V-QC named by the finalized leader.
    pub const fn parent(&self) -> CertificateId<D> {
        self.parent
    }

    /// Returns the number of distinct votes represented by the evidence.
    pub const fn votes(&self) -> usize {
        self.votes
    }

    /// Returns one final block per chain in canonical chain order.
    pub fn blocks(&self) -> &[BlockRef<D>] {
        &self.blocks
    }

    /// Returns one final proposal position per chain in canonical chain order.
    pub fn positions(&self) -> &[Position] {
        &self.positions
    }

    /// Returns one settledness flag per chain in canonical chain order.
    pub fn settled(&self) -> &[bool] {
        &self.settled
    }
}

/// A normalized direct-pool summary for diagnostics and tests.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoolSummary<D: Digest> {
    round: Round,
    leader: D,
    votes: usize,
    finalized: bool,
    lqc_pending: bool,
}

impl<D: Digest> PoolSummary<D> {
    /// Returns the pool leader's epoch and view.
    pub const fn round(self) -> Round {
        self.round
    }

    /// Returns the unsigned leader digest.
    pub const fn leader(self) -> D {
        self.leader
    }

    /// Returns the number of sticky authenticated votes.
    pub const fn votes(self) -> usize {
        self.votes
    }

    /// Returns whether the pool has reached `n-f`.
    pub const fn finalized(self) -> bool {
        self.finalized
    }

    /// Returns whether local L-QC construction remains outstanding.
    pub const fn lqc_pending(self) -> bool {
        self.lqc_pending
    }
}

#[derive(Clone, Debug)]
struct VoteRecord<V: Variant, D: Digest> {
    id: ArtifactId<D>,
    observation: Observation,
    body: VoteBody<D>,
    evidence: D,
    artifact: Option<Arc<Artifact<V, D>>>,
}

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

    fn witness(&self, signer: Participant, body: &VoteBody<D>) -> Option<Arc<Artifact<V, D>>> {
        self.candidates
            .get(&signer)?
            .values()
            .find_map(|candidate| {
                if candidate.body != *body {
                    return None;
                }
                candidate.artifact.as_ref().map(Arc::clone)
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

#[derive(Clone, Debug)]
enum LqcState {
    None,
    Ready(Observation),
    Pending(LqcAggregateId),
    Complete,
}

pub(super) struct DirectPool<V: Variant, D: Digest> {
    pub(super) leader: LeaderBlock<V, D>,
    leader_observation: Observation,
    votes: Vec<Option<VoteRecord<V, D>>>,
    pub(super) extractor: PoolExtractor<D>,
    pub(super) final_tips: Option<FinalTips<D>>,
    finality_evidence: Option<D>,
    lqc_signers: Option<Vec<Participant>>,
    frozen: Option<VoteArtifacts<V, D>>,
    lqc: LqcState,
    sources: BTreeSet<ArtifactId<D>>,
}

impl<V: Variant, D: Digest> DirectPool<V, D> {
    fn finality_fact(
        &self,
        leader_digest: D,
        config: CodecConfig,
    ) -> Result<Option<FinalityFact<D>>, FinalityError> {
        let Some(tips) = self.final_tips.as_ref() else {
            return Ok(None);
        };
        let evidence = self.finality_evidence.ok_or(FinalityError::Algebra)?;
        finality_fact(
            FinalityId::Direct(evidence),
            &self.leader,
            leader_digest,
            self.extractor.len(),
            tips,
            config,
        )
        .map(Some)
    }
}

#[derive(Clone, Debug)]
pub(super) struct AggregateRecord<V: Variant, D: Digest> {
    key: PoolKey<D>,
    observation: Observation,
    job: LqcAggregateJob<V, D>,
}

pub(super) struct CertifiedRecord<D: Digest> {
    observation: Observation,
    fact: FinalityFact<D>,
}

/// A locally prepared L-QC awaiting canonical self-admission.
pub(crate) struct PreparedLqc<V: Variant, D: Digest> {
    pub aggregate: LqcAggregateId,
    pub generation: u64,
    pub artifact: Arc<Artifact<V, D>>,
    pub artifact_id: ArtifactId<D>,
    pub encoded_len: usize,
    pub observation: Observation,
}

#[derive(Clone, Debug)]
pub(crate) enum FinalityEffect<V: Variant, D: Digest> {
    AggregateLqc(LqcAggregateJob<V, D>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum FinalityError {
    IdentifierExhausted,
    CompletionMismatch,
    LeaderCollision,
    Algebra,
}

impl<V: Variant, D: Digest> FinalityState<V, D> {
    pub(crate) fn claim_finality<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: Arc<Artifact<V, D>>,
        profile: &Profile<H, V>,
    ) -> Result<(), FinalityError> {
        if self.is_retired(&artifact) {
            return Ok(());
        }
        // Artifact identity is content-addressed, so a duplicate claim reconciles the exact
        // object to the minimum observation instead of overwriting the pending claim and
        // stranding its owner-order entry.
        if let Some(existing) = self.finality_claims.get(&id) {
            if observation < existing.observation {
                self.reobserve_finality_claim::<H>(id, observation)?;
            }
            return Ok(());
        }
        let reservations = match self.reservation_keys::<H>(&artifact) {
            ReservationKeys::None => return Ok(()),
            ReservationKeys::Single(key) => {
                PoolReservations::Single(self.reserve_pool(profile, key, observation)?)
            }
            ReservationKeys::Many(keys) => {
                let mut reservations = Vec::with_capacity(keys.len());
                for key in keys {
                    reservations.push(self.reserve_pool(profile, key, observation)?);
                }
                PoolReservations::Many(reservations)
            }
        };

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
            self.finality_claim_order
                .entry(owner)
                .or_default()
                .insert((observation, id));
        }
        self.register_finality_claims::<H>(id, observation, &artifact, &claim);
        self.finality_claims.insert(id, claim);
        Ok(())
    }

    fn reserve_pool<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        reservation: ReservationKey<D>,
        observation: Observation,
    ) -> Result<PoolReservation<D>, FinalityError> {
        let owner = profile.protocol().leader(reservation.key.0.view());
        let admission = self.finality_capacity.reserve_unverified(
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

    pub(super) fn reject_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        profile: &Profile<H, V>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        self.resolve_finality_claim::<H>(id, observation, artifact, ClaimVerdict::Rejected, profile)
    }

    pub(super) fn validate_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        profile: &Profile<H, V>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        if matches!(artifact.as_ref(), Artifact::Lqc(_)) && self.is_retired(artifact) {
            // Diagnostic retention may discard an L-QC claim before verification completes.
            // The verified certificate remains portable consensus evidence and must still reach
            // the durable signing-floor transition.
            return Ok(vec![FinalityOutput::Finality(
                id,
                observation,
                Arc::clone(artifact),
            )]);
        }
        self.resolve_finality_claim::<H>(id, observation, artifact, ClaimVerdict::Valid, profile)
    }

    fn resolve_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        verdict: ClaimVerdict,
        profile: &Profile<H, V>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        let Some(claim) = self.finality_claims.get(&id) else {
            // A discarded artifact may already have drained its claim as valid; the rejection
            // that accompanies its removal must still release every registered claim it holds,
            // or the dropped artifact pins finality capacity forever.
            if matches!(verdict, ClaimVerdict::Rejected) {
                self.reject_finality::<H>(id, artifact.as_ref())?;
            }
            return Ok(Vec::new());
        };
        if artifact.as_ref() != claim.artifact.as_ref() {
            return Err(FinalityError::Algebra);
        }
        // Validation is content-addressed, so duplicate completions share one verdict while the
        // claim retains its earliest observation for deterministic arrival ordering.
        if observation < claim.observation {
            self.reobserve_finality_claim::<H>(id, observation)?;
        }
        let claim = self
            .finality_claims
            .get_mut(&id)
            .expect("the reconciled finality claim remains retained");
        claim.verdict = verdict;
        if !claim.ordered() {
            let claim = self
                .finality_claims
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
            .finality_claims
            .get(&id)
            .expect("the finality claim was checked above");
        let previous = claim.observation;
        let owner = claim.owner();
        let ordered = claim.ordered();
        if ordered {
            let Some(order) = self.finality_claim_order.get(&owner) else {
                return Err(FinalityError::Algebra);
            };
            if !order.contains(&(previous, id)) || order.contains(&(observation, id)) {
                return Err(FinalityError::Algebra);
            }
        }

        let Self {
            finality_capacity,
            finality_claims,
            finality_claim_order,
            pending_finality,
            ..
        } = self;
        let claim = finality_claims
            .get_mut(&id)
            .expect("the finality claim remains retained");
        if ordered {
            let order = finality_claim_order
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
            finality_capacity.retain_earlier_observation(reservation.key, observation);
        }
        claim.artifact.visit_finality_vote_claims::<H>(|vote| {
            let key = vote.pool();
            if claim.retains(key) {
                pending_finality
                    .entry(key)
                    .or_default()
                    .claim(vote.signer(), id, observation);
            }
        });
        Ok(())
    }

    fn drain_finality_claims<H: Hasher<Digest = D>>(
        &mut self,
        owner: Participant,
        profile: &Profile<H, V>,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        let mut outputs = Vec::new();
        loop {
            let Some((observation, id)) = self
                .finality_claim_order
                .get(&owner)
                .and_then(BTreeSet::first)
                .copied()
            else {
                return Ok(outputs);
            };
            let Some(claim) = self.finality_claims.get(&id) else {
                return Err(FinalityError::Algebra);
            };
            if matches!(claim.verdict, ClaimVerdict::Pending) {
                return Ok(outputs);
            }
            if claim.observation != observation || claim.owner() != owner {
                return Err(FinalityError::Algebra);
            }

            let claim = self
                .finality_claims
                .remove(&id)
                .expect("a ready finality claim remains retained");
            let empty = self
                .finality_claim_order
                .get_mut(&owner)
                .is_some_and(|order| {
                    order.remove(&(observation, id));
                    order.is_empty()
                });
            if empty {
                self.finality_claim_order.remove(&owner);
            }

            self.apply_finality_claim::<H>(id, claim, profile, &mut outputs)?;
        }
    }

    fn apply_finality_claim<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        mut claim: FinalityClaim<V, D>,
        profile: &Profile<H, V>,
        outputs: &mut FinalityOutputs<V, D>,
    ) -> Result<(), FinalityError> {
        let observation = claim.observation;
        match claim.verdict {
            ClaimVerdict::Rejected => {
                self.reject_finality::<H>(id, claim.artifact.as_ref())?;
            }
            ClaimVerdict::Valid => {
                let certificate_key = match claim.artifact.as_ref() {
                    Artifact::Vqc(certificate) => Some((
                        certificate.leader().round(),
                        certificate.leader().digest::<H>(),
                    )),
                    Artifact::Lqc(certificate) => Some((
                        certificate.leader().round(),
                        certificate.leader().digest::<H>(),
                    )),
                    _ => None,
                };
                if let Some(key) = certificate_key {
                    self.pin_claimed_pool(key, &mut claim.reservations);
                }
                for reservation in claim.reservations.as_mut_slice() {
                    if Some(reservation.key) == certificate_key && reservation.liveness {
                        continue;
                    }
                    let admission = self.finality_capacity.activate_unfinalized(
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
                self.remove_dropped_claims::<H>(id, claim.artifact.as_ref(), &claim)?;
                self.register_finality_claims::<H>(id, observation, &claim.artifact, &claim);
                if matches!(claim.artifact.as_ref(), Artifact::Lqc(_)) {
                    outputs.push(FinalityOutput::Finality(
                        id,
                        observation,
                        Arc::clone(&claim.artifact),
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
    ) -> ReservationKeys<D> {
        let mut keys = ReservationKeys::None;
        match artifact {
            Artifact::LeaderBlock(block) => {
                keys.push((block.block().round(), block.block().digest::<H>()), true);
            }
            Artifact::Vqc(certificate) => {
                keys.push(
                    (
                        certificate.leader().round(),
                        certificate.leader().digest::<H>(),
                    ),
                    true,
                );
            }
            Artifact::Lqc(certificate) => {
                keys.push(
                    (
                        certificate.leader().round(),
                        certificate.leader().digest::<H>(),
                    ),
                    true,
                );
            }
            _ => {}
        }
        artifact.visit_finality_vote_claims::<H>(|claim| keys.push(claim.pool(), false));
        keys
    }

    fn register_finality_claims<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Artifact<V, D>,
        batch: &FinalityClaim<V, D>,
    ) {
        let leader_key = match artifact {
            Artifact::LeaderBlock(block) => {
                Some((block.block().round(), block.block().digest::<H>()))
            }
            Artifact::Vqc(certificate) => Some((
                certificate.leader().round(),
                certificate.leader().digest::<H>(),
            )),
            Artifact::Lqc(certificate) => Some((
                certificate.leader().round(),
                certificate.leader().digest::<H>(),
            )),
            _ => None,
        };
        if let Some(key) = leader_key.filter(|key| batch.retains(*key)) {
            self.finality_pool_claims.entry(key).or_default().insert(id);
        }
        artifact.visit_finality_vote_claims::<H>(|claim| {
            let key = claim.pool();
            if !batch.retains(key) {
                return;
            }
            if matches!(artifact, Artifact::Vqc(_) | Artifact::Lqc(_)) {
                self.finality_pool_claims.entry(key).or_default().insert(id);
            }
            self.pending_finality
                .entry(key)
                .or_default()
                .claim(claim.signer(), id, observation);
        });
    }

    fn reject_finality<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
    ) -> Result<(), FinalityError> {
        if self.is_retired(artifact) {
            return Ok(());
        }
        self.release_unretained_finality::<H, _>(id, artifact, |_| false)
    }

    fn remove_dropped_claims<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
        claim: &FinalityClaim<V, D>,
    ) -> Result<(), FinalityError> {
        self.release_unretained_finality::<H, _>(id, artifact, |key| claim.retains(key))
    }

    fn release_unretained_finality<H, F>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
        retained: F,
    ) -> Result<(), FinalityError>
    where
        H: Hasher<Digest = D>,
        F: Fn(PoolKey<D>) -> bool,
    {
        if let Artifact::LeaderBlock(block) = artifact {
            let key = (block.block().round(), block.block().digest::<H>());
            if retained(key) {
                return Ok(());
            }
            self.release_pool_claim(key, id);
            self.remove_source(key, id);
            self.remove_empty_pending(key);
            self.settle_pool::<H>(key)?;
        }

        let mut result = Ok(());
        artifact.visit_finality_vote_claims::<H>(|claim| {
            if result.is_err() {
                return;
            }
            let key = claim.pool();
            if retained(key) {
                return;
            }
            self.release_pool_claim(key, id);
            if let Some(pending) = self.pending_finality.get_mut(&key) {
                pending.remove_claim(claim.signer(), id);
                pending.remove_candidate(claim.signer(), id);
            }
            self.remove_empty_pending(key);
            result = self.settle_pool::<H>(key);
        });
        result
    }

    fn observe_finality<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        claim: &mut FinalityClaim<V, D>,
        profile: &Profile<H, V>,
    ) -> Result<(), FinalityError> {
        let artifact = Arc::clone(&claim.artifact);
        if artifact.epoch() != profile.protocol().epoch() {
            return Err(FinalityError::Algebra);
        }
        if self.is_retired(&artifact) {
            return Ok(());
        }
        match artifact.as_ref() {
            Artifact::LeaderBlock(block) => {
                let key = (block.block().round(), block.block().digest::<H>());
                self.observe_leader::<H>(
                    id,
                    observation,
                    block.block().clone(),
                    claim.retains(key),
                )?;
            }
            Artifact::Vqc(certificate) => {
                self.observe_leader::<H>(id, observation, certificate.leader().clone(), true)?;
                self.observe_vqc::<H>(id, observation, certificate, claim)?;
            }
            Artifact::Lqc(certificate) => {
                self.observe_leader::<H>(id, observation, certificate.leader().clone(), true)?;
                self.observe_lqc::<H>(id, observation, certificate)?;
            }
            Artifact::Vote(vote) => {
                let key = Self::slot(vote).0;
                if claim.retains(key) {
                    self.observe_vote::<H>(id, observation, vote, Arc::clone(&artifact))?;
                }
            }
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::NoVote(_)
            | Artifact::Nullify(_)
            | Artifact::Nullification(_) => {}
        }
        Ok(())
    }

    pub(crate) fn drive_aggregate(
        &mut self,
        generation: u64,
        mut slots: usize,
    ) -> Result<(), FinalityError> {
        while slots > 0 {
            let Some((observation, key)) = self.ready_lqcs.pop_first() else {
                break;
            };
            slots -= 1;
            let Some(pool) = self.direct_pool(key) else {
                continue;
            };
            if !matches!(pool.lqc, LqcState::Ready(current) if current == observation) {
                continue;
            }
            let leader = pool.leader.clone();
            let votes = pool.frozen.clone().ok_or(FinalityError::Algebra)?;
            let id = LqcAggregateId(self.next_lqc_aggregate);
            self.next_lqc_aggregate = self
                .next_lqc_aggregate
                .checked_add(1)
                .ok_or(FinalityError::IdentifierExhausted)?;
            let job = LqcAggregateJob {
                id,
                generation,
                leader,
                votes,
            };
            self.lqc_aggregate_jobs.insert(
                id,
                AggregateRecord {
                    key,
                    observation,
                    job: job.clone(),
                },
            );
            self.direct_pool_mut(key)
                .expect("the selected direct pool remains retained")
                .lqc = LqcState::Pending(id);
            self.finality_effects
                .push(FinalityEffect::AggregateLqc(job));
        }
        Ok(())
    }

    pub(crate) fn has_ready_aggregate(&self) -> bool {
        !self.ready_lqcs.is_empty()
    }

    pub(crate) fn take_finality_effects(&mut self) -> Vec<FinalityEffect<V, D>> {
        self.finality_effects.drain(..).collect()
    }

    pub(crate) fn aggregate_reservations(&self) -> usize {
        self.lqc_aggregate_jobs.len()
    }

    #[cfg(test)]
    pub(crate) fn pending_pools(&self) -> usize {
        self.pending_finality.len()
    }

    /// Prepares an L-QC aggregation completion, or consumes a stale completion.
    ///
    /// Returning `None` releases a matching reservation whose dispatch generation is no longer
    /// current and returns its pool to the ready set, so a completion that cannot commit can
    /// never strand the pool in a pending state that blocks re-aggregation.
    pub(crate) fn prepare_lqc<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        completion: LqcAggregateCompletion<V, D>,
        generation: u64,
    ) -> Result<Option<PreparedLqc<V, D>>, FinalityError> {
        if self
            .lqc_aggregate_jobs
            .get(&completion.id)
            .is_some_and(|record| record.job.generation != generation)
        {
            self.abandon_lqc(completion.id);
            return Ok(None);
        }
        if completion.generation != generation {
            return Ok(None);
        }
        let Some(record) = self.lqc_aggregate_jobs.get(&completion.id) else {
            return Ok(None);
        };
        if !lqc_matches_job::<H, V, D>(
            &completion.certificate,
            &record.job,
            profile.protocol().codec_config(),
        ) {
            return Err(FinalityError::CompletionMismatch);
        }
        let artifact = Arc::new(Artifact::Lqc(completion.certificate));
        Ok(Some(PreparedLqc {
            aggregate: completion.id,
            generation: completion.generation,
            artifact_id: artifact.id::<H>(),
            encoded_len: artifact.encoded_len(),
            artifact,
            observation: record.observation,
        }))
    }

    pub(crate) fn lqc_aggregation_is_current(
        &self,
        aggregate: LqcAggregateId,
        generation: u64,
    ) -> bool {
        self.lqc_aggregate_jobs
            .get(&aggregate)
            .is_some_and(|record| record.job.generation == generation)
    }

    pub(crate) fn finish_lqc(&mut self, id: LqcAggregateId) {
        let Some(record) = self.lqc_aggregate_jobs.remove(&id) else {
            return;
        };
        if let Some(pool) = self.direct_pool_mut(record.key)
            && matches!(pool.lqc, LqcState::Pending(current) if current == id)
        {
            pool.lqc = LqcState::Complete;
        }
    }

    /// Releases an aggregation reservation without a certificate and re-readies its pool.
    ///
    /// The frozen votes survive the job, so the pool re-aggregates on the next drive instead of
    /// waiting behind a pending marker whose completion was consumed.
    pub(crate) fn abandon_lqc(&mut self, id: LqcAggregateId) {
        let Some(record) = self.lqc_aggregate_jobs.remove(&id) else {
            return;
        };
        if let Some(pool) = self.direct_pool_mut(record.key)
            && matches!(pool.lqc, LqcState::Pending(current) if current == id)
        {
            pool.lqc = LqcState::Ready(record.observation);
            self.ready_lqcs.insert((record.observation, record.key));
        }
    }

    pub(crate) fn facts(&self) -> Vec<FinalityFact<D>> {
        self.leaders
            .iter()
            .filter_map(|((_, leader), record)| {
                record.finality.as_ref().and_then(|pool| {
                    pool.finality_fact(*leader, self.config)
                        .expect("direct finality was validated when the pool finalized")
                })
            })
            .chain(self.leaders.values().filter_map(|record| {
                record
                    .certified_finality
                    .as_ref()
                    .map(|certified| certified.fact.clone())
            }))
            .collect()
    }

    pub(crate) fn pools(&self) -> Vec<PoolSummary<D>> {
        self.leaders
            .iter()
            .filter_map(|((_, leader), record)| {
                let pool = record.finality.as_ref()?;
                Some(PoolSummary {
                    round: pool.leader.round(),
                    leader: *leader,
                    votes: pool.extractor.len(),
                    finalized: pool.extractor.len() >= self.config.view_quorum(),
                    lqc_pending: matches!(pool.lqc, LqcState::Ready(_) | LqcState::Pending(_)),
                })
            })
            .collect()
    }

    /// Retires finality diagnostics outside the retained view window.
    ///
    /// This bounds local evidence by age; it does not infer that a higher-view certificate
    /// dominates the retired chain-local facts.
    pub(super) fn retire_through<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        floor: View,
    ) -> Result<FinalityOutputs<V, D>, FinalityError> {
        if self
            .retired_finality_through
            .is_some_and(|retired| floor <= retired)
        {
            return Ok(Vec::new());
        }
        self.retired_finality_through = Some(floor);
        self.finality_capacity.retire_through(floor);

        let retired_claims = self
            .finality_claims
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
            self.finality_claims.remove(&id);
            released_owners.insert(owner);
            let empty = self
                .finality_claim_order
                .get_mut(&owner)
                .is_some_and(|order| {
                    order.remove(&(observation, id));
                    order.is_empty()
                });
            if empty {
                self.finality_claim_order.remove(&owner);
            }
        }

        let retained = |key: &PoolKey<D>| key.0.view() > floor;
        self.finality_pool_claims.retain(|key, _| retained(key));
        self.pending_finality.retain(|key, _| retained(key));
        self.leaders.retain(|key, _| key.0.view() > floor);
        self.ready_lqcs.retain(|(_, key)| retained(key));
        self.lqc_aggregate_jobs
            .retain(|_, record| retained(&record.key));
        self.finality_effects.retain(|effect| match effect {
            FinalityEffect::AggregateLqc(job) => job.leader().round().view() > floor,
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
        retained: bool,
    ) -> Result<(), FinalityError> {
        let key = (leader.round(), leader.digest::<H>());
        if !retained {
            self.release_pool_claim(key, source);
            self.discard_unretained_pool(key);
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

        let extractor =
            PoolExtractor::new::<H, V>(&leader, self.config).map_err(|_| FinalityError::Algebra)?;
        let direct = DirectPool {
            leader,
            leader_observation: observation,
            votes: vec![None; self.config.participants()],
            extractor,
            final_tips: None,
            finality_evidence: None,
            lqc_signers: None,
            frozen: None,
            lqc: LqcState::None,
            sources: BTreeSet::from([source]),
        };
        match self.leaders.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(FinalityLeaderRecord {
                    finality: Some(direct),
                    certified_finality: None,
                });
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().finality = Some(direct);
            }
        }
        self.release_pool_claim(key, source);
        self.settle_pool::<H>(key)?;
        Ok(())
    }

    fn pin_claimed_pool(&mut self, key: PoolKey<D>, reservations: &mut PoolReservations<D>) {
        let PoolAdmission::Pinned = self.finality_capacity.pin(key) else {
            unreachable!("pinning returns a pinned admission");
        };
        reservations.retain(key);
    }

    fn observe_vote<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        vote: &Vote<V, D>,
        artifact: Arc<Artifact<V, D>>,
    ) -> Result<(), FinalityError> {
        let (key, signer) = Self::slot(vote);
        let pending = self.pending_finality.entry(key).or_default();
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
    ) -> Result<(), FinalityError> {
        let leader = certificate.leader();
        for signer in certificate.tally().signers().iter() {
            let body = certificate
                .tally()
                .vote::<V, H>(leader, signer, self.config)
                .map_err(|_| FinalityError::Algebra)?;
            if claim.retains((body.round(), body.leader())) {
                self.observe_aggregate_vote::<H>(id, observation, signer, body)?;
            }
        }
        for conflict in certificate.conflicting_votes() {
            let body = conflict
                .vote_body(leader.round(), self.config)
                .map_err(|_| FinalityError::Algebra)?;
            if claim.retains((body.round(), body.leader())) {
                self.observe_aggregate_vote::<H>(id, observation, conflict.signer(), body)?;
            }
        }
        Ok(())
    }

    fn observe_aggregate_vote<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        signer: Participant,
        body: VoteBody<D>,
    ) -> Result<(), FinalityError> {
        let key = (body.round(), body.leader());
        let pending = self.pending_finality.entry(key).or_default();
        pending.remove_claim(signer, id);
        pending.insert_candidate(
            signer,
            VoteRecord {
                id,
                observation,
                evidence: vote_evidence::<H, D>(signer, &body),
                body,
                artifact: None,
            },
        );
        if self.direct_pool(key).is_some() {
            self.release_pool_claim(key, id);
        }
        self.settle_pool::<H>(key)
    }

    fn observe_lqc<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &Lqc<V, D>,
    ) -> Result<(), FinalityError> {
        let leader = certificate.leader();
        let mut votes = Vec::with_capacity(certificate.tally().signers().count());
        for signer in certificate.tally().signers().iter() {
            let body = certificate
                .tally()
                .vote::<V, H>(leader, signer, self.config)
                .map_err(|_| FinalityError::Algebra)?;
            votes.push((signer, body));
        }
        let tips = FinalTips::from_pool::<H, V, _>(
            leader,
            votes.iter().map(|(signer, body)| (*signer, body)),
            self.config,
        )
        .map_err(|_| FinalityError::Algebra)?;
        let key = (leader.round(), leader.digest::<H>());
        let fact = finality_fact(
            FinalityId::Lqc(id),
            leader,
            key.1,
            votes.len(),
            &tips,
            self.config,
        )?;
        let leader_record = self.leaders.get_mut(&key).ok_or(FinalityError::Algebra)?;
        if leader_record
            .certified_finality
            .as_ref()
            .is_none_or(|record| observation < record.observation)
        {
            leader_record.certified_finality = Some(CertifiedRecord { observation, fact });
        }

        if let Some(lqc) = self.direct_pool(key).map(|pool| pool.lqc.clone()) {
            match lqc {
                LqcState::Ready(observation) => {
                    self.ready_lqcs.remove(&(observation, key));
                }
                LqcState::Pending(job) => {
                    self.lqc_aggregate_jobs.remove(&job);
                }
                LqcState::None | LqcState::Complete => {}
            }
            self.direct_pool_mut(key)
                .expect("the direct pool was checked above")
                .lqc = LqcState::Complete;
        }

        for (signer, body) in votes {
            self.observe_aggregate_vote::<H>(id, observation, signer, body)?;
        }
        Ok(())
    }

    fn settle_pool<H: Hasher<Digest = D>>(&mut self, key: PoolKey<D>) -> Result<(), FinalityError> {
        if self.direct_pool(key).is_none() {
            return Ok(());
        }
        loop {
            let Some(pending) = self.pending_finality.get(&key) else {
                return Ok(());
            };
            let claim = pending.claim_order.first().copied();
            let candidate = pending.candidate_order.first().copied();
            let Some((_, signer, id)) = candidate else {
                if pending.is_empty() {
                    self.pending_finality.remove(&key);
                }
                return Ok(());
            };
            if claim.is_some_and(|claim| claim < candidate.expect("candidate exists")) {
                return Ok(());
            }

            let pending = self
                .pending_finality
                .get_mut(&key)
                .expect("pending pool exists");
            let mut candidate = pending
                .pop_candidate(signer, id)
                .expect("the candidate was checked above");
            if candidate.artifact.is_none() {
                candidate.artifact = pending.witness(signer, &candidate.body);
            }
            let signer_index = usize::from(signer);
            let selected = self
                .direct_pool(key)
                .and_then(|pool| pool.votes.get(signer_index))
                .ok_or(FinalityError::Algebra)?;
            if let Some(selected) = selected {
                if selected.artifact.is_some() {
                    self.pending_finality
                        .get_mut(&key)
                        .expect("pending pool exists")
                        .clear_signer(signer);
                    continue;
                }
                if selected.body != candidate.body {
                    continue;
                }
                if let Some(witness) = candidate.artifact {
                    self.direct_pool_mut(key)
                        .expect("the pool was checked above")
                        .votes[signer_index]
                        .as_mut()
                        .expect("the signer was checked above")
                        .artifact = Some(witness);
                    self.stage_lqc_if_witnessed(key)?;
                    self.pending_finality
                        .get_mut(&key)
                        .expect("pending pool exists")
                        .clear_signer(signer);
                }
                continue;
            }
            if self.insert_vote::<H>(key, signer, candidate)? {
                self.pending_finality
                    .get_mut(&key)
                    .expect("pending pool exists")
                    .clear_signer(signer);
            }
        }
    }

    fn insert_vote<H: Hasher<Digest = D>>(
        &mut self,
        key: PoolKey<D>,
        signer: Participant,
        candidate: VoteRecord<V, D>,
    ) -> Result<bool, FinalityError> {
        let signer_index = usize::from(signer);
        let config = self.config;
        let finalized = {
            let pool = self
                .direct_pool_mut(key)
                .expect("the pool was checked above");
            if pool
                .extractor
                .insert::<H, V>(&pool.leader, signer, &candidate.body)
                .is_err()
            {
                return Ok(false);
            }
            pool.votes[signer_index] = Some(candidate);
            pool.extractor.len() >= config.view_quorum()
        };
        if !finalized {
            return Ok(true);
        }
        let PoolAdmission::Pinned = self.finality_capacity.pin(key) else {
            unreachable!("pinning returns a pinned admission");
        };
        let tips_changed = {
            let pool = self
                .direct_pool_mut(key)
                .expect("the finalized pool remains retained after pinning");
            let tips = pool
                .extractor
                .final_tips()
                .map_err(|_| FinalityError::Algebra)?;
            let tips_changed = pool.final_tips.as_ref() != Some(&tips);
            pool.final_tips = Some(tips);
            pool.finality_evidence = Some(pool_evidence::<H, V, D>(pool));
            pool.finality_fact(key.1, config)?;

            if pool.lqc_signers.is_none() && matches!(pool.lqc, LqcState::None) {
                pool.lqc_signers = Some(
                    pool.votes
                        .iter()
                        .enumerate()
                        .filter_map(|(signer, vote)| {
                            vote.as_ref().map(|_| {
                                Participant::new(
                                    u32::try_from(signer).expect("participant is bounded"),
                                )
                            })
                        })
                        .collect(),
                );
            }
            tips_changed
        };
        let _ = tips_changed;
        self.stage_lqc_if_witnessed(key)?;
        Ok(true)
    }

    fn stage_lqc_if_witnessed(&mut self, key: PoolKey<D>) -> Result<(), FinalityError> {
        let view_quorum = self.config.view_quorum();
        let Some(pool) = self.direct_pool_mut(key) else {
            return Ok(());
        };
        if pool.frozen.is_some() || !matches!(pool.lqc, LqcState::None) {
            return Ok(());
        }
        let Some(signers) = pool.lqc_signers.as_ref() else {
            return Ok(());
        };
        if signers.len() != view_quorum {
            return Err(FinalityError::Algebra);
        }
        let record = |signer: &Participant| {
            pool.votes[usize::from(*signer)]
                .as_ref()
                .expect("a frozen signer remains selected")
        };
        if signers
            .iter()
            .any(|signer| record(signer).artifact.is_none())
        {
            return Ok(());
        }
        let selected = signers
            .iter()
            .map(|signer| {
                Arc::clone(
                    record(signer)
                        .artifact
                        .as_ref()
                        .expect("every selected vote has a complete witness"),
                )
            })
            .collect::<Vec<_>>();
        let observation = signers
            .iter()
            .map(|signer| record(signer).observation)
            .chain([pool.leader_observation])
            .max()
            .expect("a finalized pool contains votes");
        pool.frozen = Some(selected.into());
        pool.lqc = LqcState::Ready(observation);
        self.ready_lqcs.insert((observation, key));
        Ok(())
    }

    fn slot(vote: &Vote<V, D>) -> (PoolKey<D>, Participant) {
        ((vote.body().round(), vote.body().leader()), vote.signer())
    }

    fn is_retired(&self, artifact: &Artifact<V, D>) -> bool {
        self.retired_finality_through
            .is_some_and(|floor| artifact.view().is_some_and(|view| view <= floor))
    }

    fn release_pool_claim(&mut self, key: PoolKey<D>, id: ArtifactId<D>) {
        let empty = self
            .finality_pool_claims
            .get_mut(&key)
            .is_some_and(|claims| {
                claims.remove(&id);
                claims.is_empty()
            });
        if empty {
            self.finality_pool_claims.remove(&key);
        }
    }

    fn remove_empty_pending(&mut self, key: PoolKey<D>) {
        if self
            .pending_finality
            .get(&key)
            .is_some_and(PendingPool::is_empty)
        {
            self.pending_finality.remove(&key);
        }
    }

    fn remove_source(&mut self, key: PoolKey<D>, source: ArtifactId<D>) {
        let view_quorum = self.config.view_quorum();
        let remove = self.direct_pool_mut(key).is_some_and(|pool| {
            pool.sources.remove(&source);
            pool.sources.is_empty()
                && pool.extractor.len() < view_quorum
                && !matches!(pool.lqc, LqcState::Complete)
        });
        if remove {
            self.remove_direct_pool(key);
        }
    }

    fn direct_pool(&self, key: PoolKey<D>) -> Option<&DirectPool<V, D>> {
        self.leaders.get(&key)?.finality.as_ref()
    }

    fn direct_pool_mut(&mut self, key: PoolKey<D>) -> Option<&mut DirectPool<V, D>> {
        self.leaders.get_mut(&key)?.finality.as_mut()
    }

    fn remove_direct_pool(&mut self, key: PoolKey<D>) {
        let remove_record = self.leaders.get_mut(&key).is_some_and(|record| {
            record.finality = None;
            record.certified_finality.is_none()
        });
        if remove_record {
            self.leaders.remove(&key);
            if !self.finality_pool_claims.contains_key(&key) {
                self.finality_capacity.release_unfinalized(key);
            }
        }
    }

    fn discard_replaced_pool(&mut self, key: PoolKey<D>) -> Result<(), FinalityError> {
        if self.leaders.get(&key).is_some_and(|record| {
            record.certified_finality.is_some()
                || record.finality.as_ref().is_some_and(|pool| {
                    pool.extractor.len() >= self.config.view_quorum()
                        || pool.final_tips.is_some()
                        || pool.finality_evidence.is_some()
                        || !matches!(pool.lqc, LqcState::None)
                })
        }) || self.ready_lqcs.iter().any(|(_, ready)| *ready == key)
            || self
                .lqc_aggregate_jobs
                .values()
                .any(|record| record.key == key)
        {
            return Err(FinalityError::Algebra);
        }
        self.leaders.remove(&key);
        self.finality_pool_claims.remove(&key);
        self.pending_finality.remove(&key);
        Ok(())
    }

    fn discard_unretained_pool(&mut self, key: PoolKey<D>) {
        if self.direct_pool(key).is_none() && !self.finality_pool_claims.contains_key(&key) {
            self.pending_finality.remove(&key);
        }
    }

    fn release_capacity_if_unused(&mut self, key: PoolKey<D>) {
        if self.direct_pool(key).is_some()
            || self.finality_pool_claims.contains_key(&key)
            || self.pending_finality.contains_key(&key)
        {
            return;
        }
        self.finality_capacity.release_unfinalized(key);
    }
}

fn pool_evidence<H, V, D>(pool: &DirectPool<V, D>) -> D
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let mut transcript = Vec::with_capacity(pool.extractor.len() + 1);
    transcript.push(FINALITY_EVIDENCE_NAMESPACE);
    transcript.extend(
        pool.votes
            .iter()
            .flatten()
            .map(|vote| vote.evidence.as_ref()),
    );
    H::hash(&transcript)
}

fn vote_evidence<H, D>(signer: Participant, body: &VoteBody<D>) -> D
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let signer = u64::from(signer.get()).to_be_bytes();
    let body = body.encode();
    H::hash(&[FINALITY_VOTE_NAMESPACE, &signer, body.as_ref()])
}

fn finality_fact<V: Variant, D: Digest>(
    id: FinalityId<D>,
    leader: &LeaderBlock<V, D>,
    leader_digest: D,
    votes: usize,
    tips: &FinalTips<D>,
    config: CodecConfig,
) -> Result<FinalityFact<D>, FinalityError> {
    let mut positions = Vec::with_capacity(config.chains());
    let mut settled = Vec::with_capacity(config.chains());
    for chain in 0..config.chains() {
        let chain = ChainId::new(chain as u32);
        positions.push(tips.position(chain).ok_or(FinalityError::Algebra)?);
        settled.push(tips.settled(chain).ok_or(FinalityError::Algebra)?);
    }
    Ok(FinalityFact {
        id,
        round: leader.round(),
        leader: leader_digest,
        parent: leader.parent(),
        votes,
        blocks: tips.blocks().to_vec(),
        positions,
        settled,
    })
}

fn lqc_matches_job<H, V, D>(
    certificate: &Lqc<V, D>,
    job: &LqcAggregateJob<V, D>,
    config: CodecConfig,
) -> bool
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    if certificate.leader() != job.leader()
        || certificate.signature().is_none()
        || certificate.tally().signers().count() != config.view_quorum()
    {
        return false;
    }
    let votes = job.votes().collect::<Vec<_>>();
    let signers = votes.iter().map(|vote| vote.signer()).collect::<Vec<_>>();
    if certificate.tally().signers().iter().collect::<Vec<_>>() != signers {
        return false;
    }
    votes.into_iter().all(|vote| {
        certificate
            .tally()
            .vote::<V, H>(certificate.leader(), vote.signer(), config)
            .is_ok_and(|body| body == *vote.body())
    })
}
