//! The view layer: this node's votes and its progress through views.
//!
//! - [`endorse`] computes what this node's votes endorse and sends them as vote updates.
//! - [`declare`] keeps the declarations of the current vote tag and the final-vote trigger.
//! - [`proposal`] proposes as a view's leader and decides which leader blocks are valid.
//! - [`timing`] measures the network delay and derives each view's timers from it.
//! - [`handlers`] runs the per-view protocol: proposing, voting for a leader block, the final vote
//!   and the late final vote at a view change, continuous votes, and the timers.
//! - [`vqc`] holds V-QCs with their parent chain and the facts they fix, forwards new V-QCs, and
//!   ends a view on its V-QC; [`assemble`] assembles this node's V-QC of the current view.
//! - [`anchor`] re-roots a node further behind than its peers' retention at a finalization
//!   certificate.
//!
//! # State
//!
//! The durable state owns every fact a signature depends on: the current view, this node's leader
//! block per view, the leader block it voted for per view (`notarised`, write-once), and per vote
//! tag the watermark of its votes, which fixes its declarations and its final vote. The view layer
//! reads those (`proposed`, `notarised`, and `final_sent` are projections of them) and keeps only
//! volatile state: when the view was entered and its timers, the V-QC it was entered on, `tquorum`,
//! the leader blocks received, the declarations not yet carried by a vote, the delay estimator and
//! the grace, and when each validator was last heard from. A restart rebuilds it from durable state
//! and treats the restart as the view's entry.
//!
//! # Seam with the V-QC store
//!
//! The V-QC store answers [`Machine::held_vqc`] (which V-QCs are held with their chain, with their
//! commitments and tips), calls [`Machine::finish_view`] when a V-QC of the current view is held
//! with its chain, and [`Machine::enter_view`] once it staged the entry into the next view.
//! A restart rebuilds the store before the view layer, so the V-QC the current view was entered on
//! is held when the layer is restored, unless its chain must be retrieved first.

pub(crate) mod anchor;
pub(crate) mod assemble;
pub(crate) mod declare;
pub(crate) mod endorse;
pub(crate) mod handlers;
pub(crate) mod proposal;
pub(crate) mod timing;
pub(crate) mod vqc;

use self::{
    declare::{DeclarationContexts, DeclarationCounts, Declarations, ViewEnds},
    proposal::{HeldVqc, Proposal},
    timing::{DeltaEstimator, Timing, ViewTimers},
};
use crate::{
    Viewable as _,
    multimmit::{
        config::Profile,
        machine::{
            input::{Now, StepError},
            reducer::machine::Machine,
            scheduler::ProtocolComponent,
        },
        types::{Artifact, ChainId},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// The current view's volatile state, fixed when the view is entered.
pub(crate) struct ViewState<D: Digest> {
    /// The current view `v`.
    view: View,
    /// When the view was entered; `T` is measured from it.
    entered_at: Now,
    /// The view's timers.
    timers: ViewTimers,
    /// The V-QC of the previous view this node entered on, once held with its chain.
    parent: Option<HeldVqc<D>>,
    /// Whether optimisation (B) skipped the view's leader at entry.
    skip_leader: bool,
    /// `tquorum`: when all but `f` chains were first capped or declared in the view, before this
    /// node's final vote for it.
    quorum_at: Option<Now>,
}

/// The view layer's volatile state.
pub(crate) struct ViewLayer<D: Digest> {
    state: ViewState<D>,
    /// The declarations of the current vote tag, including those no vote carried yet.
    declarations: Declarations<D>,
    /// The leader blocks received for views `[v - 1, v + 1]`.
    proposals: BTreeMap<View, Proposal<D>>,
    timing: Timing,
    /// Per validator, when its latest authenticated message was received (`heard`).
    heard: Vec<Now>,
    /// When this node last reserved a vote update (`lastvote`).
    last_vote: Now,
    /// The latest view whose valid proposal widened the grace.
    widened: View,
    /// The chains declared final per rule since the process started.
    declared: DeclarationCounts,
    /// `declared` when this node's previous final vote was sent.
    tag_declared: DeclarationCounts,
    /// What this node knew about each chain it declared final, since the process started.
    contexts: DeclarationContexts,
    /// Why each view this node sent a final vote for ended, since the process started.
    ends: ViewEnds,
}

impl<D: Digest> ViewLayer<D> {
    /// Returns the layer of a node that entered `view` at `now` on `parent`, having heard from
    /// every validator and last voted at `now`.
    ///
    /// Treating the start as a vote keeps the vote interval across a restart, whose last update
    /// time is unknown.
    pub(crate) fn new(
        profile: &Profile<D>,
        view: View,
        parent: Option<HeldVqc<D>>,
        now: Now,
    ) -> Self {
        let mut timing = Timing::new(profile);
        let chains = profile.codec().chains();
        Self {
            state: ViewState {
                view,
                entered_at: now,
                timers: timing.timers(),
                parent,
                skip_leader: false,
                quorum_at: None,
            },
            // No vote is tagged view zero, so the first use loads the current tag's watermark.
            declarations: Declarations::new(View::zero(), chains),
            proposals: BTreeMap::new(),
            timing,
            heard: vec![now; profile.codec().participants()],
            last_vote: now,
            widened: View::zero(),
            declared: DeclarationCounts::default(),
            tag_declared: DeclarationCounts::default(),
            contexts: DeclarationContexts::default(),
            ends: ViewEnds::default(),
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Rebuilds the view layer from durable state at `now`, as if the current view were entered
    /// at `now`, and wakes it.
    ///
    /// The V-QC the view was entered on is its durable exit proof of the previous view, when it is
    /// held with its chain, or the retention root when the previous view is the retired one (the
    /// node anchored there). This node's own leader blocks of the views it reads are recorded
    /// again.
    pub(in crate::multimmit::machine) fn restore_view(&mut self, now: Now) {
        let state = &self.durable.state;
        let view = state.view;
        let parent = match view.previous() {
            Some(previous) if !previous.is_zero() => {
                match state.exits.get(&previous).map(AsRef::as_ref) {
                    Some(Artifact::Vqc(certificate)) => self.held_vqc(&certificate.id::<H>()),
                    Some(_) => None,
                    None => state
                        .root
                        .as_ref()
                        .filter(|_| state.retired_view == previous)
                        .and_then(|root| self.held_vqc(&root.vqc)),
                }
            }
            _ => Some(HeldVqc::genesis(self.profile.protocol().genesis())),
        };
        self.components.view = ViewLayer::new(&self.profile, view, parent, now);
        let own = self
            .durable
            .state
            .local
            .values()
            .filter_map(|artifact| match artifact.as_ref() {
                Artifact::LeaderBlock(block) if block.view().next() >= view => {
                    Some(block.block().clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for block in &own {
            self.record_proposal(block);
        }
        self.wake(ProtocolComponent::View);
    }

    /// Enters the current durable view at `now` on `parent`, the V-QC of the previous view it
    /// was entered with, held with its chain.
    ///
    /// The V-QC store calls this once it staged the entry. The view's timers are fixed now, and
    /// optimisation (B) is decided: when the emission state of the view is undefined, the view's
    /// leader has been silent for `t_quiet`, and `n - f` validators were heard from within
    /// `t_quiet`, this node ends the view at once with a leaderless final vote declaring every
    /// chain.
    ///
    /// # Errors
    ///
    /// Returns [`StepError::ViewInvariant`] unless `parent` is of the view before the current one.
    pub(in crate::multimmit::machine) fn enter_view(
        &mut self,
        parent: HeldVqc<H::Digest>,
        now: Now,
    ) -> Result<(), StepError> {
        let view = self.durable.state.view;
        if parent.view.next() != view {
            return Err(StepError::ViewInvariant);
        }
        let timers = self.components.view.timing.timers();
        let skip_leader =
            !self.emission_defined(view) && self.leader_silent(view, timers.quiet, now);
        let layer = &mut self.components.view;
        layer.state = ViewState {
            view,
            entered_at: now,
            timers,
            parent: Some(parent),
            skip_leader,
            quorum_at: None,
        };
        let previous = view.previous().unwrap_or(view);
        layer.proposals = layer.proposals.split_off(&previous);
        self.wake(ProtocolComponent::View);
        Ok(())
    }

    /// Returns whether this node proposed in `view`: it reserved its leader block.
    pub(in crate::multimmit::machine) fn proposed(&self, view: View) -> bool {
        self.durable.state.leader_blocks.contains_key(&view)
    }

    /// Returns the leader block this node voted for in `view`, if any.
    pub(in crate::multimmit::machine) fn notarised(&self, view: View) -> Option<H::Digest> {
        self.durable.state.notarised.get(&view).copied()
    }

    /// Returns whether this node sent its final vote for `view`.
    pub(in crate::multimmit::machine) fn final_sent(&self, view: View) -> bool {
        self.durable.state.last_final.0 >= view
    }

    /// Returns the delay estimator, which the chain layer feeds with this node's own blocks.
    pub(in crate::multimmit::machine) fn delay_estimator(&mut self) -> &mut dyn DeltaEstimator {
        self.components.view.timing.estimator()
    }

    /// Records that this node accepted the next height of `chain` at `now`, a sample of the
    /// production interval the view timers derive from.
    pub(in crate::multimmit::machine) fn note_acceptance(&mut self, chain: ChainId, now: Now) {
        self.components.view.timing.cadence().accepted(chain, now);
    }

    /// Returns the production estimator.
    #[cfg(test)]
    pub(in crate::multimmit::machine) const fn production_cadence(
        &mut self,
    ) -> &mut timing::Cadence {
        self.components.view.timing.cadence()
    }

    /// Returns the timers fixed when the current view was entered (or the node started).
    pub(in crate::multimmit::machine) const fn current_timers(&self) -> ViewTimers {
        self.components.view.state.timers
    }

    /// Returns the chains declared final per rule since the process started.
    pub(in crate::multimmit::machine) const fn declaration_counts(&self) -> DeclarationCounts {
        self.components.view.declared
    }

    /// Returns what this node knew about each chain it declared final, since the process started.
    pub(in crate::multimmit::machine) const fn declaration_contexts(&self) -> DeclarationContexts {
        self.components.view.contexts
    }

    /// Returns why each view this node sent a final vote for ended, since the process started.
    pub(in crate::multimmit::machine) const fn view_ends(&self) -> ViewEnds {
        self.components.view.ends
    }
}
