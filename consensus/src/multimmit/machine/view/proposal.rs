//! Local proposals, votes, timeouts, and proposal validity.

use super::{
    claims::{Claim, ClaimKind},
    state::{ViewError, ViewState},
    store::{ParentProof, ParentRecord},
};
use crate::{
    Epochable,
    multimmit::{
        config::Profile,
        machine::{
            chain::ChainState,
            durability::{ProposalParent, ProposalRequest, SignRequest},
            util::Drive,
            vote_body::{VoteBodyPass, VoteBodyProgress, VoteBuild, VoteBuilds},
        },
        types::{Anchor, ChainProposal, CodecConfig, LeaderBlock, SignedLeaderBlock, VoteBody},
    },
    types::{Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{mem::take, sync::Arc};

/// The in-flight construction of this node's regular signing request for one view.
pub(super) enum RegularSignPass<V: Variant, D: Digest> {
    Vote {
        view: View,
        pass: VoteBodyPass<V, D>,
        ready: Option<VoteBody<D>>,
    },
    Proposal {
        view: View,
        parent: ParentRecord<V, D>,
        attach_parent: bool,
        proposals: Vec<ChainProposal<V, D>>,
    },
}

impl<V: Variant, D: Digest> RegularSignPass<V, D> {
    const fn view(&self) -> View {
        match self {
            Self::Vote { view, .. } | Self::Proposal { view, .. } => *view,
        }
    }
}

/// A bounded prefix of the regular signing pass and the request it produced, if any.
pub(crate) type RegularSignDrive<V, D> = Drive<Option<SignRequest<V, D>>>;

/// Header-triggered restarts consumed by one view's proposal pass.
#[derive(Copy, Clone, Debug)]
pub(super) struct PassRestarts {
    pub(super) view: View,
    pub(super) count: u8,
}

/// Proposal diagnostics exported as metrics. They never influence protocol decisions.
#[derive(Copy, Clone, Debug, Default)]
pub(super) struct ViewMetrics {
    /// Cumulative verified headers admitted after this leader sealed its proposal, while that
    /// proposal's view was still current.
    headers_after_seal: u64,
    /// Cumulative proposal-pass restarts triggered by verified header admissions, making a
    /// zero `headers_after_seal` interpretable against constant restarting.
    header_restarts: u64,
}

/// The choice frozen for one view when its timer fires.
#[derive(Clone, Debug)]
pub(crate) enum TimeoutCutoff<D: Digest> {
    /// A valid proposal was held, so this node still signs the vote it would have cast.
    Vote(VoteBody<D>),
    /// No valid proposal was held, so this node abstains and nullifies.
    Timeout,
}

impl<V: Variant, D: Digest> ViewState<V, D> {
    /// Advances this node's proposal or vote pass for `view` by at most `budget` steps.
    ///
    /// The drive produces the signing request once the pass completes; a pass for another view is
    /// discarded first.
    pub(crate) fn drive_regular_sign_request<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H::Digest>,
        view: View,
        chain: &ChainState<V, D>,
        budget: usize,
    ) -> Result<RegularSignDrive<V, D>, ViewError> {
        if !self.can_sign_regular(view) {
            self.discard_regular_sign_pass();
            return Ok(Drive::idle());
        }
        if self
            .regular_sign_pass
            .as_ref()
            .is_some_and(|pass| pass.view() != view)
        {
            self.discard_regular_sign_pass();
        }
        if !self.regular_pass_in_flight(view) {
            self.regular_sign_pass = self.begin_regular_sign_pass::<H>(profile, view, chain)?;
            if let Some(RegularSignPass::Vote { pass, .. }) = &self.regular_sign_pass {
                self.vote_builds.push(pass.started());
            }
        }
        let (epoch, config) = (self.epoch, self.config);
        let drive = match self.regular_sign_pass.as_mut() {
            None => return Ok(Drive::idle()),
            Some(RegularSignPass::Vote { pass, ready, .. }) => {
                Self::step_vote::<H>(chain, pass, ready, &mut self.vote_builds, budget)?
            }
            Some(RegularSignPass::Proposal {
                view,
                parent,
                attach_parent,
                proposals,
            }) => Self::step_proposal(
                chain,
                Round::new(epoch, *view),
                config,
                parent,
                *attach_parent,
                proposals,
                budget,
            )?,
        };
        if matches!(drive.output, Some(SignRequest::LeaderBlock(_))) {
            self.regular_sign_pass = None;
        }
        Ok(drive)
    }

    /// Returns whether this node can still sign its proposal or vote for `view`.
    fn can_sign_regular(&self, view: View) -> bool {
        self.me.is_some() && self.can_vote(view)
    }

    /// Returns whether this node's proposal or vote pass for `view` is in flight.
    fn regular_pass_in_flight(&self, view: View) -> bool {
        self.regular_sign_pass
            .as_ref()
            .is_some_and(|pass| pass.view() == view)
    }

    /// Returns whether driving the regular signing request for `view` now begins a vote pass.
    ///
    /// It shares [`Self::drive_regular_sign_request`]'s conditions: this node can still sign, no
    /// pass for the view is in flight, and it holds a valid proposal, which makes the pass a vote.
    pub(crate) fn vote_pass_begins(&self, view: View) -> Result<bool, ViewError> {
        Ok(self.can_sign_regular(view)
            && !self.regular_pass_in_flight(view)
            && self.valid_proposal(view)?.is_some())
    }

    /// Discards the in-flight pass, reporting a vote pass that never produced its body.
    fn discard_regular_sign_pass(&mut self) {
        if let Some(RegularSignPass::Vote { ready: None, .. }) = self.regular_sign_pass.take() {
            self.vote_builds.push(VoteBuild::Abandoned);
        }
    }

    /// Advances a vote pass one chain per unit of `budget` until its body is complete.
    ///
    /// A completed body is kept, so later drives return it again without further work.
    fn step_vote<H: Hasher<Digest = D>>(
        chain: &ChainState<V, D>,
        pass: &mut VoteBodyPass<V, D>,
        ready: &mut Option<VoteBody<D>>,
        builds: &mut VoteBuilds,
        budget: usize,
    ) -> Result<RegularSignDrive<V, D>, ViewError> {
        if let Some(body) = ready {
            return Ok(Drive::done(0, Some(SignRequest::Vote(body.clone()))));
        }
        for processed in 1..=budget {
            if let VoteBodyProgress::Complete { body, stats } = chain
                .resume_vote_body_pass::<H>(pass)
                .map_err(|_| ViewError::Chain)?
            {
                builds.push(VoteBuild::Completed(stats));
                *ready = Some(body.clone());
                return Ok(Drive::done(processed, Some(SignRequest::Vote(body))));
            }
        }
        Ok(Drive::yielded(budget, None))
    }

    /// Advances a proposal pass one chain per unit of `budget`, then seals the leader block.
    fn step_proposal(
        chain: &ChainState<V, D>,
        round: Round,
        config: CodecConfig,
        parent: &ParentRecord<V, D>,
        attach_parent: bool,
        proposals: &mut Vec<ChainProposal<V, D>>,
        budget: usize,
    ) -> Result<RegularSignDrive<V, D>, ViewError> {
        for processed in 1..=budget {
            match parent.tips.blocks().get(proposals.len()).copied() {
                Some(tip) => {
                    proposals.push(chain.propose_chain(tip).map_err(|_| ViewError::Chain)?);
                }
                None => {
                    let request = Self::finish_proposal_request(
                        round,
                        config,
                        parent,
                        attach_parent,
                        proposals,
                    )?;
                    return Ok(Drive::done(processed, Some(request)));
                }
            }
        }
        Ok(Drive::yielded(budget, None))
    }

    /// Returns the cumulative count of verified headers admitted after this leader sealed its
    /// proposal, while that proposal's view was still current.
    pub(crate) const fn headers_after_seal(&self) -> u64 {
        self.metrics.headers_after_seal
    }

    /// Returns the cumulative count of header-triggered proposal-pass restarts.
    pub(crate) const fn header_restarts(&self) -> u64 {
        self.metrics.header_restarts
    }

    /// How many times one view's proposal pass may restart on header admissions.
    ///
    /// Each restart re-walks the pass from scratch under the same core credits, so the cap
    /// guarantees a seal after bounded work even under a sustained header stream; headers
    /// arriving past the cap are referenced by whatever the walk reads when it resumes.
    const HEADER_RESTARTS: u8 = 4;

    /// Reacts to a verified producer header entering chain state.
    ///
    /// An in-flight proposal pass restarts so its next walk can reference the header,
    /// mirroring the restart on reserved DA votes in [`Self::observe_sign_request`], bounded
    /// per view by [`Self::HEADER_RESTARTS`]. A header landing while this node's sealed
    /// proposal for `view` is still current is counted instead: it missed this leader slot
    /// and rides a later proposal.
    pub(crate) fn observe_attested_header(&mut self, view: View) {
        if let Some(RegularSignPass::Proposal {
            view: pass_view, ..
        }) = self.regular_sign_pass
        {
            let consumed = if self.pass_restarts.view == pass_view {
                self.pass_restarts.count
            } else {
                0
            };
            if consumed < Self::HEADER_RESTARTS {
                self.pass_restarts = PassRestarts {
                    view: pass_view,
                    count: consumed + 1,
                };
                self.metrics.header_restarts = self.metrics.header_restarts.saturating_add(1);
                self.regular_sign_pass = None;
            }
            return;
        }
        if self
            .entry(view)
            .is_some_and(|entry| entry.slot.proposal.is_some())
        {
            self.metrics.headers_after_seal = self.metrics.headers_after_seal.saturating_add(1);
        }
    }

    /// Returns whether a vote pass for `view` is in flight.
    pub(crate) fn regular_vote_in_progress(&self, view: View) -> bool {
        matches!(
            self.regular_sign_pass,
            Some(RegularSignPass::Vote { view: pass, .. }) if pass == view
        )
    }

    /// Drains the vote-pass lifecycle events recorded since the last drain.
    pub(crate) fn drain_vote_builds(&mut self) -> VoteBuilds {
        take(&mut self.vote_builds)
    }

    fn begin_regular_sign_pass<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H::Digest>,
        view: View,
        chain: &ChainState<V, D>,
    ) -> Result<Option<RegularSignPass<V, D>>, ViewError> {
        let Some(me) = self.me else {
            return Ok(None);
        };
        if let Some(proposal) = self.valid_proposal(view)? {
            let leader = proposal.block().clone();
            let pass = chain.begin_vote_body_pass(leader);
            return Ok(Some(RegularSignPass::Vote {
                view,
                pass,
                ready: None,
            }));
        }

        let leader = profile.protocol().leader(view);
        if me != leader
            || self
                .entry(view)
                .is_some_and(|entry| entry.slot.proposal.is_some())
        {
            return Ok(None);
        }
        let parent = self
            .select_anchor(view)
            .cloned()
            .ok_or(ViewError::MissingParent)?;
        if !self.gap_is_nullified(parent.view, view) {
            return Ok(None);
        }
        let attach_parent = matches!(parent.proof, ParentProof::Vqc(_))
            && self.forwarded_vqcs.get(&parent.view) != Some(&parent.id);
        Ok(Some(RegularSignPass::Proposal {
            view,
            parent,
            attach_parent,
            proposals: Vec::with_capacity(self.config.chains()),
        }))
    }

    fn finish_proposal_request(
        round: Round,
        config: CodecConfig,
        parent: &ParentRecord<V, D>,
        attach_parent: bool,
        proposals: &[ChainProposal<V, D>],
    ) -> Result<SignRequest<V, D>, ViewError> {
        let parent_proof = match &parent.proof {
            ParentProof::Genesis => ProposalParent::Genesis,
            ParentProof::Vqc(certificate) => {
                ProposalParent::Exact(Arc::new(certificate.get().clone()))
            }
        };
        let block = LeaderBlock::new(
            round,
            parent.id,
            parent.child_history()?,
            proposals.to_vec(),
            config,
        )
        .map_err(|_| ViewError::Proposal)?;
        Ok(SignRequest::LeaderBlock(ProposalRequest::new(
            block,
            parent_proof,
            attach_parent,
        )))
    }

    /// Returns the no-vote and nullify requests owed once `view` timed out without a valid
    /// proposal.
    pub(crate) fn timeout_requests(&self, view: View) -> Option<Arc<[SignRequest<V, D>]>> {
        self.me?;
        if !matches!(self.timeout_cutoff(view), Some(TimeoutCutoff::Timeout))
            || !self.can_vote(view)
        {
            return None;
        }
        let round = Round::new(self.epoch, view);
        Some(Arc::from([
            SignRequest::NoVote { round },
            SignRequest::Nullify { round },
        ]))
    }

    /// Returns the vote frozen when `view` timed out while holding a valid proposal, if this node
    /// can still cast it.
    pub(crate) fn cutoff_vote(&self, view: View) -> Option<SignRequest<V, D>> {
        if !self.can_vote(view) {
            return None;
        }
        let TimeoutCutoff::Vote(request) = self.timeout_cutoff(view)? else {
            return None;
        };
        Some(SignRequest::Vote(request.clone()))
    }

    /// Returns the choice this node froze when `view`'s timer fired, if it has fired.
    pub(crate) fn timeout_cutoff(&self, view: View) -> Option<&TimeoutCutoff<D>> {
        self.entry(view)?.timeout.as_ref()
    }

    /// Returns a nullify request once enough signers opposed this node's vote in `view`.
    pub(crate) fn post_vote_nullify(&self, view: View) -> Option<SignRequest<V, D>> {
        self.me?;
        let entry = self.entry(view)?;
        if !entry.slot.has_voted() || entry.slot.nullified() {
            return None;
        }
        if entry.post_vote_evidence.len() < self.config.designation_quorum() {
            return None;
        }
        Some(SignRequest::Nullify {
            round: Round::new(self.epoch, view),
        })
    }

    /// Freezes the timeout cutoff of `view` when its timer fires.
    pub(crate) fn fire_timer<H: Hasher<Digest = D>>(
        &mut self,
        view: View,
        chain: &ChainState<V, D>,
    ) -> Result<(), ViewError> {
        if self.timeout_cutoff(view).is_some() || !self.can_vote(view) {
            return Ok(());
        }
        let cutoff = match (self.me, self.valid_proposal(view)?) {
            (Some(_), Some(proposal)) => TimeoutCutoff::Vote(
                chain
                    .vote_body::<H>(proposal.block())
                    .map_err(|_| ViewError::Chain)?,
            ),
            _ => TimeoutCutoff::Timeout,
        };
        self.entry_mut(view).timeout = Some(cutoff);
        Ok(())
    }

    fn valid_proposal(&self, view: View) -> Result<Option<&SignedLeaderBlock<V, D>>, ViewError> {
        let Some(records) = self.entry(view).map(|entry| &entry.proposals) else {
            return Ok(None);
        };
        let Some((_, record)) = records.first() else {
            return Ok(None);
        };
        // This node votes directly only when it holds exactly one proposal for the view. Proposals
        // are ordered by observation, and verification may complete out of order, so a proposal
        // still awaiting verification could turn out to be an equivocation: wait for it.
        if self
            .claims
            .first_cohort(Claim::new(view, ClaimKind::Proposal))
            .is_some()
        {
            return Ok(None);
        }
        if records.len() > 1 {
            return Ok(None);
        }
        let proposal = record.value.get();
        let block = proposal.block();
        let Some(parent) = self.parents.get(&block.parent()) else {
            return Ok(None);
        };
        if parent.view >= view
            || !self.gap_is_nullified(parent.view, view)
            || !self.proposal_extends(block, parent)?
        {
            return Ok(None);
        }
        Ok(Some(proposal))
    }

    fn proposal_extends(
        &self,
        block: &LeaderBlock<V, D>,
        parent: &ParentRecord<V, D>,
    ) -> Result<bool, ViewError> {
        if block.proposals().len() != parent.tips.blocks().len() {
            return Ok(false);
        }
        if parent.child_history()? != block.history() {
            return Ok(false);
        }
        for (proposal, tip) in block.proposals().iter().zip(parent.tips.blocks()) {
            match proposal.anchor() {
                Anchor::Tip(actual) if actual == tip => {}
                Anchor::Certificate(certificate)
                    if certificate.header().chain() == tip.chain()
                        && certificate.header().height() > tip.height()
                        && certificate.epoch() == self.epoch => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Returns whether every view strictly between `parent` and `child` was nullified.
    ///
    /// A proposal may only skip views that provably could not have finalized. Retirement drops the
    /// live nullification records, so a retired view is answered by the forwarded set instead: a
    /// machine may only leave a view whose exit proof it durably forwarded, which makes that set a
    /// complete witness for every view this node has passed.
    pub(crate) fn gap_is_nullified(&self, parent: View, child: View) -> bool {
        self.first_missing_nullification(parent, child).is_none()
    }

    fn has_nullification(&self, view: View) -> bool {
        view > self.proposal_anchor_view && view <= self.proposal_nullified_through
            || self
                .entry(view)
                .is_some_and(|entry| !entry.nullification.records.is_empty())
            || self.forwarded_nullifications.contains(&view)
    }

    /// Returns the lowest unresolved skipped view required by a proposal parent.
    ///
    /// Incoming proposals always participate. The selected local anchor participates only when the
    /// caller can propose in this view, which avoids speculative resolver work on followers.
    pub(crate) fn missing_nullification(
        &self,
        child: View,
        include_local_anchor: bool,
    ) -> Option<View> {
        let proposal = self
            .entry(child)
            .into_iter()
            .flat_map(|entry| entry.proposals.iter())
            .filter_map(|(_, record)| self.parents.get(&record.value.get().block().parent()))
            .filter(|parent| matches!(parent.proof, ParentProof::Vqc(_)))
            .filter_map(|parent| self.first_missing_nullification(parent.view, child))
            .min();
        let local = include_local_anchor
            .then(|| self.select_anchor(child))
            .flatten()
            .filter(|parent| matches!(parent.proof, ParentProof::Vqc(_)))
            .and_then(|parent| self.first_missing_nullification(parent.view, child));
        proposal.into_iter().chain(local).min()
    }

    fn first_missing_nullification(&self, parent: View, child: View) -> Option<View> {
        // A parent at the last representable view precedes no child, so it is its own gap.
        let Some(first) = parent.get().checked_add(1) else {
            return Some(parent);
        };
        (first..child.get())
            .map(View::new)
            .find(|view| !self.has_nullification(*view))
    }

    fn select_anchor(&self, view: View) -> Option<&ParentRecord<V, D>> {
        let (_, ids) = self.parents_by_view.range(..view).next_back()?;
        ids.iter()
            .filter_map(|id| self.parents.get(id))
            .min_by(|left, right| {
                right.messages.cmp(&left.messages).then_with(|| {
                    left.canonical
                        .cmp(&right.canonical)
                        .then_with(|| left.id.cmp(&right.id))
                })
            })
    }
}
