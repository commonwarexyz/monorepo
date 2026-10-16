//! The per-view protocol handlers (CS Alg. 2) and the view layer's timers.
//!
//! One quantum of the view drive runs, in order:
//!
//! 1. Propose, when this node leads the view and has not proposed ([`Machine::propose`]).
//! 2. Declarations: rule (i) for the current tag; before the view's final vote, `tquorum` and
//!    rules (ii) and (iii).
//! 3. Before the view's final vote: vote for the view's valid leader block; then, with a leader
//!    block voted for, the final vote once the trigger holds; without one, a leaderless final vote
//!    declaring every chain at the grace when the view's emission state is undefined
//!    (optimisation (A)) or at once when optimisation (B) skipped the leader at entry, else a
//!    leaderless final vote at the grace once the trigger holds.
//! 4. Continuous votes: the vote for the leader block, or the pre-vote of the next tag after the
//!    final vote, whenever its content changed and `eta` passed since the last vote.
//! 5. The deadlines that wake the drive again: the grace and rules (i) and (ii) on
//!    [`TimerFamily::View`], `t_max` on [`TimerFamily::Liveness`], and the next vote on
//!    [`TimerFamily::Update`].
//!
//! A vote for a leader block and every final vote are sent at once; only repeated votes wait for
//! `eta`. Every final vote is followed by `AfterFinal`: the next tag's declarations start empty,
//! and only rule (i) adds to them until this node enters the next view. The V-QC store runs handler
//! 9 through [`Machine::finish_view`], and the pool drive checks rule (v) whenever a vote of the
//! current view is read.

use crate::{
    Epochable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::Capabilities,
            input::{Now, StepError, TimerFamily},
            reducer::{
                components::{WorkResult, WorkStatus},
                machine::Machine,
            },
            scheduler::ProtocolComponent,
            view::{declare::DeclarationRule, proposal::HeldVqc},
        },
        types::LeaderBlock,
    },
    types::{Participant, Round, View},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Runs one quantum of the view handlers at `now`.
    pub(in crate::multimmit::machine) fn drive_view(
        &mut self,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        if !matches!(self.profile.role(), Role::Validator(_)) {
            return Ok((WorkStatus::Complete, Capabilities::new()));
        }
        if let Some(result) = self.propose() {
            return result;
        }
        let state = &self.components.view.state;
        let (view, timers, entered_at, skip_leader) = (
            state.view,
            state.timers,
            state.entered_at,
            state.skip_leader,
        );
        let elapsed = now.saturating_since(entered_at);
        self.declare_stopped(&timers, now);
        if !self.final_sent(view) {
            self.note_quorum(now);
            self.declare_late(now);
            self.declare_bound(&timers, now, elapsed);
            let sent = match self.notarised(view) {
                Some(block) if self.trigger() => Some(self.send_vote(block, now)?),
                Some(_) => None,
                None => {
                    if let Some((block, base)) = self.valid_proposal(view) {
                        self.set_notarised_base(view, base);
                        let sent = self.send_vote(block, now)?;
                        if sent.0 == WorkStatus::Complete {
                            self.components.view.timing.narrow();
                        }
                        Some(sent)
                    } else if skip_leader
                        || (elapsed >= timers.grace && !self.emission_defined(view))
                    {
                        self.declare_all(
                            if skip_leader {
                                DeclarationRule::SilentLeader
                            } else {
                                DeclarationRule::Grace
                            },
                            now,
                        );
                        Some(self.send(None, true, now)?)
                    } else if elapsed >= timers.grace && self.trigger() {
                        Some(self.send(None, true, now)?)
                    } else {
                        None
                    }
                }
            };
            if let Some((status, capabilities)) = sent {
                return Ok((requeue(status), capabilities));
            }
        }
        let (status, mut capabilities) = self.send_changed(now)?;
        if status != WorkStatus::Complete {
            return Ok((status, capabilities));
        }
        capabilities.extend(self.arm_view_timers(now));
        Ok((status, capabilities))
    }

    /// Applies rule (v) to the current view at `now`: when this node has not sent its final vote
    /// and the first binding votes split a chain, every chain is declared and the view drive woken.
    pub(in crate::multimmit::machine) fn drive_pool(
        &mut self,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        let view = self.components.view.state.view;
        if matches!(self.profile.role(), Role::Validator(_))
            && !self.final_sent(view)
            && self.split(view)
            && self.declare_all(DeclarationRule::Split, now)
        {
            self.wake(ProtocolComponent::View);
        }
        Ok((WorkStatus::Complete, Capabilities::new()))
    }

    /// Runs handler 9 for a V-QC of the current view held with its chain, whose parent is
    /// `parent` and which designates the leader block above `parent` when `designates`.
    ///
    /// Unless this node already sent its final vote for the view, it declares every chain (rule
    /// (iv)) and sends it now: for the leader block it voted for; else for the designated leader
    /// block `(v, H(parent), C(parent))`, which it builds itself and needs no copy of; else
    /// leaderless. Returns [`WorkStatus::Complete`] once the final vote is reserved, and
    /// [`WorkStatus::Blocked`] when persistence lacks capacity, in which case the caller tries
    /// again after an acknowledgement and enters the next view only after the final vote.
    pub(in crate::multimmit::machine) fn finish_view(
        &mut self,
        parent: &HeldVqc<H::Digest>,
        designates: bool,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        let view = self.components.view.state.view;
        if self.final_sent(view) {
            return Ok((WorkStatus::Complete, Capabilities::new()));
        }
        self.declare_all(DeclarationRule::ViewChange, now);
        match self.notarised(view) {
            Some(block) => self.send_vote(block, now),
            None if designates => {
                let block = LeaderBlock::new(
                    Round::new(self.profile.protocol().epoch(), view),
                    parent.id,
                    parent.history,
                )
                .map_err(|_| StepError::ViewInvariant)?;
                self.set_notarised_base(view, Arc::clone(&parent.tips));
                self.send_vote(block.digest::<H>(), now)
            }
            None => self.send(None, true, now),
        }
    }

    /// Records that `sender` was heard from at `now`: an authenticated message of it arrived.
    pub(in crate::multimmit::machine) fn note_heard(&mut self, sender: Participant, now: Now) {
        if let Some(heard) = self.components.view.heard.get_mut(usize::from(sender)) {
            *heard = now;
        }
    }

    /// Returns whether the emission state of `view` is defined: its base `beta_v` is known.
    ///
    /// View one's base is the genesis tips. Emission records later bases durably, in view order.
    pub(in crate::multimmit::machine) fn emission_defined(&self, view: View) -> bool {
        view <= self.defined_through()
    }

    /// Returns whether `view`'s leader appears crashed at `now`: it was last heard from more than
    /// `silence` (`t_quiet`) ago while `n - f` validators, this node included, were heard from
    /// within it.
    pub(in crate::multimmit::machine) fn leader_silent(
        &self,
        view: View,
        silence: u64,
        now: Now,
    ) -> bool {
        let own = match self.profile.role() {
            Role::Validator(own) => Some(own),
            Role::Observer => None,
        };
        let leader = self.profile.protocol().leader(view);
        let heard = &self.components.view.heard;
        let recent = |participant: Participant| {
            Some(participant) == own
                || heard
                    .get(usize::from(participant))
                    .is_some_and(|at| now.saturating_since(*at) <= silence)
        };
        let audible = (0..heard.len())
            .filter(|index| recent(Participant::from_usize(*index)))
            .count();
        !recent(leader) && audible >= self.profile.codec().view_quorum()
    }

    /// Sends this node's vote for the leader block `block` of the current view, final when the
    /// trigger holds.
    fn send_vote(&mut self, block: H::Digest, now: Now) -> WorkResult<V, H::Digest> {
        let final_ = self.trigger();
        self.send(Some(block), final_, now)
    }

    /// Sends this node's vote of the current tag for `leader`, carrying the tag's declarations,
    /// and records why the view ended after a final vote.
    ///
    /// Before its final vote for the current view this node's tag is the view itself: it enters a
    /// view only after its final vote for the view before.
    fn send(
        &mut self,
        leader: Option<H::Digest>,
        final_: bool,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        let tag = self.vote_tag();
        self.declarations();
        let content =
            self.endorsed_content(tag, leader, final_, &self.components.view.declarations)?;
        let (status, capabilities) = self.send_update(content, now)?;
        if status != WorkStatus::Complete {
            return Ok((status, capabilities));
        }
        self.components.view.last_vote = now;
        if final_ {
            self.record_view_end(self.components.view.state.entered_at, now);
        }
        Ok((status, capabilities))
    }

    /// Sends the vote of the current tag when its content changed since the tag's latest update
    /// (update zero before any) and `eta` passed since the last vote, returning
    /// [`WorkStatus::Requeue`] after a send; arms the update deadline when only `eta` is missing.
    ///
    /// The vote is the vote for the leader block this node voted for in the current view until its
    /// final vote, and the pre-vote of the next tag after it.
    fn send_changed(&mut self, now: Now) -> WorkResult<V, H::Digest> {
        let tag = self.vote_tag();
        let leader = if tag == self.components.view.state.view {
            self.notarised(tag)
        } else {
            None
        };
        self.declarations();
        let content =
            self.endorsed_content(tag, leader, false, &self.components.view.declarations)?;
        if self.repeats_last(&content) {
            return Ok((
                WorkStatus::Complete,
                self.rearm(TimerFamily::Update, None).into_iter().collect(),
            ));
        }
        let due = self
            .components
            .view
            .last_vote
            .saturating_add(self.components.view.timing.vote_interval());
        if now < due {
            return Ok((
                WorkStatus::Complete,
                self.rearm(TimerFamily::Update, Some(due))
                    .into_iter()
                    .collect(),
            ));
        }
        self.send(leader, false, now)
            .map(|(status, capabilities)| (requeue(status), capabilities))
    }

    /// Arms the deadlines at which the current view's handlers may act next: the grace and rules
    /// (i) and (ii) on [`TimerFamily::View`], `t_max` on [`TimerFamily::Liveness`], each
    /// only while it can still change a vote.
    fn arm_view_timers(&mut self, now: Now) -> Capabilities<V, H::Digest> {
        let state = &self.components.view.state;
        let (view, timers, entered_at) = (state.view, state.timers, state.entered_at);
        let open = !self.final_sent(view);
        let grace = (open && self.notarised(view).is_none())
            .then(|| entered_at.saturating_add(timers.grace));
        let tag = self.vote_tag();
        let base = self.sender_base(tag);
        // The latest sign of life of the chain silent the longest among those neither declared
        // nor capped; none once every chain is.
        let silent_since = self
            .profile
            .codec()
            .chain_ids()
            .filter(|chain| !self.finished(*chain, base))
            .map(|chain| self.components.chain.last_life(chain))
            .min();
        let stopped = silent_since.map(|life| life.saturating_add(timers.stop));
        let late = self.late_at().filter(|_| open && silent_since.is_some());
        let deadline = grace
            .into_iter()
            .chain(stopped)
            .chain(late)
            .filter(|at| *at > now)
            .min();
        let bound = open
            .then(|| entered_at.saturating_add(timers.max))
            .filter(|at| *at > now);
        self.arm_before(TimerFamily::View, deadline)
            .into_iter()
            .chain(self.arm_before(TimerFamily::Liveness, bound))
            .collect()
    }
}

/// Returns the status of a drive quantum that did `status`'s work: a completed send leaves more
/// handlers to evaluate.
const fn requeue(status: WorkStatus) -> WorkStatus {
    match status {
        WorkStatus::Complete => WorkStatus::Requeue,
        other => other,
    }
}
