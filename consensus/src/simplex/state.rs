use crate::{
    simplex::{
        interesting, min_active,
        signing_scheme::Scheme,
        types::{
            Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, OrderedExt,
            Proposal, VoteTracker,
        },
    },
    types::{Epoch, Round as Rnd, View},
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::set::Ordered;
use std::{collections::BTreeMap, time::SystemTime};
use tracing::debug;

/// Tracks the leader of a round.
#[derive(Debug, Clone)]
pub struct Leader<P: PublicKey> {
    pub(crate) idx: u32,
    pub(crate) key: P,
}

/// Proposal verification status within a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProposalStatus {
    #[default]
    None,
    Unverified,
    Verified,
    Replaced,
}

/// Describes how a proposal slot changed after an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalChange<D>
where
    D: Digest,
{
    New,
    Unchanged,
    Replaced {
        previous: Proposal<D>,
        new: Proposal<D>,
    },
    Skipped,
}

/// Tracks proposal state, build/verify flags, and conflicts.
#[derive(Default)]
pub struct ProposalSlot<D>
where
    D: Digest,
{
    proposal: Option<Proposal<D>>,
    status: ProposalStatus,
    requested_build: bool,
    requested_verify: bool,
}

impl<D> ProposalSlot<D>
where
    D: Digest + Clone + PartialEq,
{
    pub fn new() -> Self {
        Self {
            proposal: None,
            status: ProposalStatus::None,
            requested_build: false,
            requested_verify: false,
        }
    }

    pub fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.as_ref()
    }

    pub fn status(&self) -> ProposalStatus {
        self.status
    }

    pub fn should_build(&self) -> bool {
        !self.requested_build && self.proposal.is_none()
    }

    pub fn set_building(&mut self) {
        self.requested_build = true;
    }

    pub fn has_requested_verify(&self) -> bool {
        self.requested_verify
    }

    pub fn request_verify(&mut self) -> bool {
        if self.requested_verify {
            return false;
        }
        self.requested_verify = true;
        true
    }

    pub fn record_our_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
        assert!(self.proposal.is_none() || replay, "proposal already set");
        self.proposal = Some(proposal);
        self.status = ProposalStatus::Verified;
        self.requested_build = true;
        self.requested_verify = true;
    }

    pub fn mark_verified(&mut self) -> bool {
        if self.status != ProposalStatus::Unverified {
            return false;
        }
        self.status = ProposalStatus::Verified;
        true
    }

    pub fn update(&mut self, proposal: &Proposal<D>, recovered: bool) -> ProposalChange<D> {
        match &self.proposal {
            None => {
                self.proposal = Some(proposal.clone());
                self.status = if recovered {
                    ProposalStatus::Verified
                } else {
                    ProposalStatus::Unverified
                };
                ProposalChange::New
            }
            Some(existing) if existing == proposal => {
                if recovered {
                    self.status = ProposalStatus::Verified;
                }
                ProposalChange::Unchanged
            }
            Some(existing) => {
                if self.status == ProposalStatus::Replaced {
                    return ProposalChange::Skipped;
                }
                self.status = ProposalStatus::Replaced;
                ProposalChange::Replaced {
                    previous: existing.clone(),
                    new: proposal.clone(),
                }
            }
        }
    }
}

/// Per-view state machine shared between actors and tests.
pub struct RoundState<S: Scheme, D: Digest> {
    pub(crate) start: SystemTime,
    pub(crate) scheme: S,
    pub(crate) round: Rnd,
    pub(crate) leader: Option<Leader<S::PublicKey>>,
    pub(crate) proposal: ProposalSlot<D>,
    pub(crate) leader_deadline: Option<SystemTime>,
    pub(crate) advance_deadline: Option<SystemTime>,
    pub(crate) nullify_retry: Option<SystemTime>,
    pub(crate) votes: VoteTracker<S, D>,
    pub(crate) notarization: Option<Notarization<S, D>>,
    pub(crate) broadcast_notarize: bool,
    pub(crate) broadcast_notarization: bool,
    pub(crate) nullification: Option<Nullification<S>>,
    pub(crate) broadcast_nullify: bool,
    pub(crate) broadcast_nullification: bool,
    pub(crate) finalization: Option<Finalization<S, D>>,
    pub(crate) broadcast_finalize: bool,
    pub(crate) broadcast_finalization: bool,
}

impl<S: Scheme, D: Digest> RoundState<S, D> {
    pub fn new(scheme: S, round: Rnd, start: SystemTime) -> Self {
        let participants = scheme.participants().len();
        Self {
            start,
            scheme,
            round,
            leader: None,
            proposal: ProposalSlot::new(),
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,
            votes: VoteTracker::new(participants),
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,
        }
    }

    pub fn start(&self) -> SystemTime {
        self.start
    }

    pub fn leader(&self) -> Option<Leader<S::PublicKey>> {
        self.leader.clone()
    }

    fn clear_votes(&mut self) {
        self.votes.clear_notarizes();
        self.votes.clear_finalizes();
    }

    fn record_equivocation_and_clear(&mut self) -> Option<S::PublicKey> {
        self.clear_votes();
        self.leader().map(|leader| leader.key)
    }

    pub fn clear_deadlines(&mut self) {
        self.leader_deadline = None;
        self.advance_deadline = None;
    }

    pub fn set_leader(&mut self, seed: Option<S::Seed>) {
        let (leader, leader_idx) = crate::simplex::select_leader::<S, _>(
            self.scheme.participants().as_ref(),
            self.round,
            seed,
        );
        debug!(round=?self.round, ?leader, ?leader_idx, "leader elected");
        self.leader = Some(Leader {
            idx: leader_idx,
            key: leader,
        });
    }

    fn add_recovered_proposal(&mut self, proposal: Proposal<D>) -> Option<S::PublicKey> {
        match self.proposal.update(&proposal, true) {
            ProposalChange::New => {
                debug!(?proposal, "setting verified proposal from certificate");
                None
            }
            ProposalChange::Unchanged => None,
            ProposalChange::Replaced { previous, new } => {
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "certificate conflicts with proposal (equivocation detected)"
                );
                equivocator
            }
            ProposalChange::Skipped => None,
        }
    }

    pub fn add_verified_notarize(&mut self, notarize: Notarize<S, D>) -> Option<S::PublicKey> {
        match self.proposal.update(&notarize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { previous, new } => {
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "notarize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.votes.insert_notarize(notarize);
        None
    }

    pub fn add_verified_nullify(&mut self, nullify: Nullify<S>) {
        self.votes.insert_nullify(nullify);
    }

    pub fn add_verified_finalize(&mut self, finalize: Finalize<S, D>) -> Option<S::PublicKey> {
        match self.proposal.update(&finalize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { previous, new } => {
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "finalize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.votes.insert_finalize(finalize);
        None
    }

    pub fn add_verified_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        if self.notarization.is_some() {
            return (false, None);
        }
        self.clear_deadlines();
        let equivocator = self.add_recovered_proposal(notarization.proposal.clone());
        self.notarization = Some(notarization);
        (true, equivocator)
    }

    pub fn add_verified_nullification(&mut self, nullification: Nullification<S>) -> bool {
        if self.nullification.is_some() {
            return false;
        }
        self.clear_deadlines();
        self.nullification = Some(nullification);
        true
    }

    pub fn add_verified_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        if self.finalization.is_some() {
            return (false, None);
        }
        self.clear_deadlines();
        let equivocator = self.add_recovered_proposal(finalization.proposal.clone());
        self.finalization = Some(finalization);
        (true, equivocator)
    }

    pub fn notarizable(&mut self, force: bool) -> Option<Notarization<S, D>> {
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            return None;
        }
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_notarizes() < quorum {
            return None;
        }
        let notarization = Notarization::from_notarizes(&self.scheme, self.votes.iter_notarizes())
            .expect("failed to recover notarization certificate");
        self.broadcast_notarization = true;
        Some(notarization)
    }

    pub fn nullifiable(&mut self, force: bool) -> Option<Nullification<S>> {
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_nullifies() < quorum {
            return None;
        }
        let nullification =
            Nullification::from_nullifies(&self.scheme, self.votes.iter_nullifies())
                .expect("failed to recover nullification certificate");
        self.broadcast_nullification = true;
        Some(nullification)
    }

    pub fn finalizable(&mut self, force: bool) -> Option<Finalization<S, D>> {
        if !force && self.broadcast_finalization {
            return None;
        }
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_finalizes() < quorum {
            return None;
        }
        if let Some(notarization) = &self.notarization {
            let proposal = self.proposal.proposal().expect("proposal missing");
            assert_eq!(
                notarization.proposal, *proposal,
                "finalization proposal does not match notarization"
            );
        }
        let finalization = Finalization::from_finalizes(&self.scheme, self.votes.iter_finalizes())
            .expect("failed to recover finalization certificate");
        self.broadcast_finalization = true;
        Some(finalization)
    }

    pub fn proposal_ancestry_supported(&self) -> bool {
        if self.proposal.proposal().is_none() {
            return false;
        }
        if self.finalization.is_some() || self.notarization.is_some() {
            return true;
        }
        let max_faults = self.scheme.participants().max_faults() as usize;
        self.votes.len_notarizes() > max_faults
    }

    pub fn notarize_candidate(&mut self) -> Option<&Proposal<D>> {
        if self.broadcast_notarize || self.broadcast_nullify {
            return None;
        }
        if self.proposal.status() != ProposalStatus::Verified {
            return None;
        }
        self.broadcast_notarize = true;
        self.proposal.proposal()
    }

    pub fn finalize_candidate(&mut self) -> Option<&Proposal<D>> {
        if self.broadcast_finalize || self.broadcast_nullify {
            return None;
        }
        if !self.broadcast_notarize || !self.broadcast_notarization {
            return None;
        }
        if self.proposal.status() != ProposalStatus::Verified {
            return None;
        }
        self.broadcast_finalize = true;
        self.proposal.proposal()
    }
}

/// Configuration for initializing [`SimplexCore`].
pub struct CoreConfig<S: Scheme> {
    pub scheme: S,
    pub epoch: Epoch,
    pub activity_timeout: View,
    pub start_view: View,
    pub last_finalized: View,
}

/// Core simplex state machine extracted from actors for easier testing and recovery.
pub struct SimplexCore<S: Scheme, D: Digest> {
    scheme: S,
    epoch: Epoch,
    activity_timeout: View,
    view: View,
    last_finalized: View,
    views: BTreeMap<View, RoundState<S, D>>,
}

impl<S: Scheme, D: Digest> SimplexCore<S, D> {
    pub fn new(cfg: CoreConfig<S>) -> Self {
        Self {
            scheme: cfg.scheme,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            view: cfg.start_view,
            last_finalized: cfg.last_finalized,
            views: BTreeMap::new(),
        }
    }

    pub fn scheme(&self) -> &S {
        &self.scheme
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn current_view(&self) -> View {
        self.view
    }

    pub fn set_current_view(&mut self, view: View) {
        self.view = view;
    }

    pub fn last_finalized(&self) -> View {
        self.last_finalized
    }

    pub fn set_last_finalized(&mut self, view: View) {
        self.last_finalized = view;
    }

    pub fn tracked_views(&self) -> usize {
        self.views.len()
    }

    pub fn min_active(&self) -> View {
        min_active(self.activity_timeout, self.last_finalized)
    }

    pub fn is_interesting(&self, pending: View, allow_future: bool) -> bool {
        interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            pending,
            allow_future,
        )
    }

    pub fn is_me(&self, idx: u32) -> bool {
        self.scheme.me().map(|me| me == idx).unwrap_or(false)
    }

    pub fn participants(&self) -> &Ordered<S::PublicKey> {
        self.scheme.participants()
    }

    pub fn enter_view(
        &mut self,
        view: View,
        now: SystemTime,
        leader_deadline: SystemTime,
        advance_deadline: SystemTime,
        seed: Option<S::Seed>,
    ) -> bool {
        if view <= self.view {
            return false;
        }
        let round = self.ensure_round(view, now);
        round.leader_deadline = Some(leader_deadline);
        round.advance_deadline = Some(advance_deadline);
        round.set_leader(seed);
        self.view = view;
        true
    }

    pub fn ensure_round(&mut self, view: View, start: SystemTime) -> &mut RoundState<S, D> {
        self.views.entry(view).or_insert_with(|| {
            RoundState::new(self.scheme.clone(), Rnd::new(self.epoch, view), start)
        })
    }

    pub fn round(&self, view: View) -> Option<&RoundState<S, D>> {
        self.views.get(&view)
    }

    pub fn round_mut(&mut self, view: View) -> Option<&mut RoundState<S, D>> {
        self.views.get_mut(&view)
    }

    pub fn remove_round(&mut self, view: View) -> Option<RoundState<S, D>> {
        self.views.remove(&view)
    }

    pub fn first_view(&self) -> Option<View> {
        self.views.keys().next().copied()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&View, &RoundState<S, D>)> {
        self.views.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&View, &mut RoundState<S, D>)> {
        self.views.iter_mut()
    }

    pub fn prune(&mut self) -> Vec<View> {
        let min = self.min_active();
        let mut removed = Vec::new();
        while let Some(view) = self.first_view() {
            if view >= min {
                break;
            }
            self.views.remove(&view);
            removed.push(view);
        }
        removed
    }

    pub fn notarized_payload(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(notarization) = &round.notarization {
            return Some(&notarization.proposal.payload);
        }
        let proposal = round.proposal.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.votes.len_notarizes() >= quorum {
            return Some(&proposal.payload);
        }
        None
    }

    pub fn finalized_payload(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(finalization) = &round.finalization {
            return Some(&finalization.proposal.payload);
        }
        let proposal = round.proposal.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.votes.len_finalizes() >= quorum {
            return Some(&proposal.payload);
        }
        None
    }

    pub fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let quorum = self.scheme.participants().quorum() as usize;
        round.nullification.is_some() || round.votes.len_nullifies() >= quorum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        mocks::fixtures::{ed25519, Fixture},
        types::{Notarize, Proposal},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::Duration;

    #[test]
    fn equivocation_detected_on_notarize_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture {
            schemes,
            participants,
            ..
        } = ed25519(&mut rng, 4);
        let scheme = schemes.into_iter().next().unwrap();
        let proposal_a = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([1u8; 32]),
        };
        let proposal_b = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([2u8; 32]),
        };
        let vote_a = Notarize::sign(&scheme, b"ns", proposal_a.clone()).unwrap();
        let vote_b = Notarize::sign(&scheme, b"ns", proposal_b.clone()).unwrap();
        let mut round = RoundState::new(scheme.clone(), proposal_a.round, SystemTime::UNIX_EPOCH);
        round.set_leader(None);
        assert!(round.add_verified_notarize(vote_a).is_none());
        let equivocator = round.add_verified_notarize(vote_b);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.unwrap(), participants[2]);
    }

    #[test]
    fn round_prunes_with_min_active() {
        let mut rng = StdRng::seed_from_u64(1337);
        let Fixture { schemes, .. } = ed25519(&mut rng, 4);
        let scheme = schemes.into_iter().next().unwrap();
        let cfg = CoreConfig {
            scheme,
            epoch: 7,
            activity_timeout: 10,
            start_view: 0,
            last_finalized: 0,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        for view in 0..5 {
            core.ensure_round(view, SystemTime::UNIX_EPOCH + Duration::from_secs(view));
        }
        core.set_last_finalized(20);
        let removed = core.prune();
        assert_eq!(removed, vec![0, 1, 2, 3, 4]);
        assert_eq!(core.tracked_views(), 0);
    }
}
