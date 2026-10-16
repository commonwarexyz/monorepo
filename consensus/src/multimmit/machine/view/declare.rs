//! Declarations: the chains this node declares final for a view tag, and the final-vote trigger.
//!
//! A vote tagged `v` endorses a declared chain `i` only up to `decl(i)`, the accepted tip's height
//! when `i` was first declared for `v`. A declaration is never withdrawn and never moves, so every
//! vote of the tag endorses the chain at the declared block, which the declaration keeps: later
//! votes need no ancestry below the accepted tip, which retention may drop. The durable vote
//! watermark records both once a vote carries them. The declarations of a tag start empty when the
//! final vote of the tag before is sent (this node's votes are then pre-votes of the new tag), and
//! chains are added by these rules:
//!
//! | rule | when | chains |
//! |---|---|---|
//! | (i) stopped | from the previous final vote on: no sign of life for `D_stop` | each such chain not capped |
//! | (ii) late | in the view, before its final vote: `t_late` after `tquorum` | each chain neither capped nor declared |
//! | (iii) bound | in the view, before its final vote: `T >= t_max` | each chain not capped |
//! | (iv) view change | a V-QC of the view arrives before its final vote | every chain |
//! | (v) split | in the view, before its final vote: first binding votes split a chain | every chain |
//!
//! Optimisations (A) and (B) also declare every chain, before a leaderless final vote.
//!
//! # Late chains
//!
//! Rule (ii) is the only rule that compares chains. `tquorum` is the time at which all but `f`
//! chains were first capped or declared at this node after it entered the view; it is volatile,
//! unset at entry (a restart counts as entry), and never set once the view's final vote is sent.
//! Chains, not validators, are counted: every correct producer builds a block every `theta`, so
//! the chains that keep pace cap within a fraction of `t_late` of one another, and a chain still
//! neither capped nor declared `t_late` after them has fallen behind. It is declared at its
//! current tip, which other validators may read a block apart; rule (v) and the next leader block
//! resolve that at the cost of one pin. With at most `f` chains there is no chain known to keep
//! pace, and rule (iii) alone bounds the view.
//!
//! # Capped
//!
//! This node's tip on chain `i` is capped once it is at least `N` above the base it votes
//! against: the base of the leader block it voted for in the view (`base(l) = Tips(Q')`), or the
//! tips of its latest final vote otherwise. The pool measures other validators' tips against its
//! own base (`beta_v`, else `base(l)`, else the same final tips), so the two sides may disagree on
//! a chain; a vote binds its sender on a capped chain either way.
//!
//! # Trigger
//!
//! The final-vote trigger holds when every chain is declared or capped. The final vote is then
//! sent for the leader block this node voted for, or, `t_grace` after entry, as a leaderless final
//! vote. Rule (iii) makes the trigger hold `t_max` after entry whatever the producers do.

use super::timing::ViewTimers;
use crate::{
    multimmit::{
        machine::{durability::VoteWatermark, input::Now, reducer::machine::Machine},
        types::{BlockRef, ChainId, ChainSet},
    },
    types::{Height, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

/// The chains declared final for one view tag, each with the accepted tip it was declared at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Declarations<D: Digest> {
    tag: View,
    set: ChainSet,
    /// Per chain, the accepted tip when the chain was declared.
    at: Vec<Option<BlockRef<D>>>,
}

impl<D: Digest> Declarations<D> {
    /// Returns the empty declarations of `tag` over `chains` chains.
    pub(crate) fn new(tag: View, chains: usize) -> Self {
        Self {
            tag,
            set: ChainSet::empty(chains),
            at: vec![None; chains],
        }
    }

    /// Returns the declarations of `tag` this node's votes carried, as its watermark records them.
    ///
    /// The watermark's tip on a declared chain is the declaration: the first vote declaring the
    /// chain endorsed it at `decl`, and later tips of the tag neither fall nor pass `decl`.
    pub(crate) fn recorded(tag: View, watermark: Option<&VoteWatermark<D>>, chains: usize) -> Self {
        let mut declarations = Self::new(tag, chains);
        if let Some(watermark) = watermark {
            for chain in watermark.declared.iter() {
                declarations.declare(chain, watermark.tips[chain.index()]);
            }
        }
        declarations
    }

    /// Returns the declared view tag.
    pub(crate) const fn tag(&self) -> View {
        self.tag
    }

    /// Returns the declared chains.
    pub(crate) const fn set(&self) -> &ChainSet {
        &self.set
    }

    /// Returns the accepted tip `chain` was declared at, if it is declared.
    pub(crate) fn at(&self, chain: ChainId) -> Option<BlockRef<D>> {
        self.at[chain.index()]
    }

    /// Declares `chain` at the accepted tip `at` unless it is declared already, and returns
    /// whether it was added.
    pub(crate) fn declare(&mut self, chain: ChainId, at: BlockRef<D>) -> bool {
        if !self.set.insert(chain) {
            return false;
        }
        self.at[chain.index()] = Some(at);
        true
    }
}

/// The rule that declared a chain final, for telemetry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeclarationRule {
    /// Rule (i): no sign of life for `D_stop`.
    Stopped,
    /// Rule (ii): still neither capped nor declared `t_late` after all but `f` chains were.
    Late,
    /// Rule (iii): `t_max` passed in the view.
    Bound,
    /// Rule (iv): a V-QC of the view arrived before this node's final vote.
    ViewChange,
    /// Rule (v): first binding votes split a chain.
    Split,
    /// Optimisation (A): the grace passed without a valid proposal.
    Grace,
    /// Optimisation (B): the view's leader was silent at entry.
    SilentLeader,
}

impl DeclarationRule {
    /// The number of rules.
    pub(crate) const COUNT: usize = 7;
}

/// Cumulative counts of chains declared final, per [`DeclarationRule`], since the process
/// started.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclarationCounts([u64; DeclarationRule::COUNT]);

impl DeclarationCounts {
    /// Returns the chains `rule` declared.
    pub const fn get(&self, rule: DeclarationRule) -> u64 {
        self.0[rule as usize]
    }

    const fn add(&mut self, rule: DeclarationRule, chains: u64) {
        self.0[rule as usize] = self.0[rule as usize].saturating_add(chains);
    }

    /// Returns how many chains every rule declared since `earlier`, and how many of them rule
    /// (iii) declared.
    fn since(&self, earlier: &Self) -> (u64, u64) {
        let total = self
            .0
            .iter()
            .zip(earlier.0)
            .map(|(now, before)| now.saturating_sub(before))
            .sum();
        let bound = self.get(DeclarationRule::Bound) - earlier.get(DeclarationRule::Bound);
        (total, bound)
    }
}

/// What this node knew about a chain when it declared the chain final, for telemetry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeclarationContext {
    /// This node's tip on the chain was capped against the base its votes are capped against.
    pub(crate) capped: bool,
    /// No sign of life had arrived from the chain for `D_stop`.
    pub(crate) silent: bool,
    /// The acceptance bounds held back a header of the chain that was otherwise ready.
    pub(crate) held_back: bool,
}

impl DeclarationContext {
    /// The number of distinct contexts.
    const COUNT: usize = 8;

    /// Every context, in index order.
    pub(crate) const ALL: [Self; Self::COUNT] = {
        let mut all = [Self {
            capped: false,
            silent: false,
            held_back: false,
        }; Self::COUNT];
        let mut index = 0;
        while index < Self::COUNT {
            all[index] = Self {
                capped: index & 4 != 0,
                silent: index & 2 != 0,
                held_back: index & 1 != 0,
            };
            index += 1;
        }
        all
    };

    const fn index(self) -> usize {
        (self.capped as usize) << 2 | (self.silent as usize) << 1 | self.held_back as usize
    }
}

/// Cumulative counts of chains declared final, per [`DeclarationRule`] and
/// [`DeclarationContext`], and the summed time since each declared chain's latest sign of life,
/// since the process started.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeclarationContexts {
    counts: [[u64; DeclarationContext::COUNT]; DeclarationRule::COUNT],
    silence_millis: [u64; DeclarationRule::COUNT],
}

impl DeclarationContexts {
    /// Returns the chains `rule` declared in `context`.
    pub(crate) const fn get(&self, rule: DeclarationRule, context: DeclarationContext) -> u64 {
        self.counts[rule as usize][context.index()]
    }

    /// Returns the summed milliseconds from each chain's latest sign of life to its declaration
    /// by `rule`.
    pub(crate) const fn silence_millis(&self, rule: DeclarationRule) -> u64 {
        self.silence_millis[rule as usize]
    }

    /// Records one chain `rule` declared in `context`, `silence` milliseconds after its latest
    /// sign of life.
    const fn record(&mut self, rule: DeclarationRule, context: DeclarationContext, silence: u64) {
        let count = &mut self.counts[rule as usize][context.index()];
        *count = count.saturating_add(1);
        let millis = &mut self.silence_millis[rule as usize];
        *millis = millis.saturating_add(silence);
    }
}

/// Why this node's final vote for a view was sent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ViewEnd {
    /// Every chain filled its window; no chain was declared.
    Count,
    /// `t_max` passed and rule (iii) declared the chains that had not filled their window.
    Bound,
    /// Another declaration rule declared at least one chain.
    Declared,
}

/// Cumulative counts of the views this node sent its final vote for, per [`ViewEnd`], and their
/// total length from entry to final vote, since the process started.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewEnds {
    count: u64,
    bound: u64,
    declared: u64,
    millis: u64,
}

impl ViewEnds {
    /// Returns the views that ended for `reason`.
    pub const fn get(&self, reason: ViewEnd) -> u64 {
        match reason {
            ViewEnd::Count => self.count,
            ViewEnd::Bound => self.bound,
            ViewEnd::Declared => self.declared,
        }
    }

    /// Returns the views this node sent its final vote for.
    pub const fn total(&self) -> u64 {
        self.count + self.bound + self.declared
    }

    /// Returns the summed time from entering each of those views to its final vote, in
    /// milliseconds.
    pub const fn total_millis(&self) -> u64 {
        self.millis
    }

    /// Records a view that ended for `reason` after `millis`.
    const fn record(&mut self, reason: ViewEnd, millis: u64) {
        match reason {
            ViewEnd::Count => self.count += 1,
            ViewEnd::Bound => self.bound += 1,
            ViewEnd::Declared => self.declared += 1,
        }
        self.millis = self.millis.saturating_add(millis);
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the tag of this node's next vote: the view after its latest final vote.
    pub(in crate::multimmit::machine) const fn vote_tag(&self) -> View {
        self.durable.state.last_final.0.next()
    }

    /// Returns the declarations of the current vote tag, starting them from the tag's watermark
    /// once the tag moved on.
    pub(in crate::multimmit::machine) fn declarations(&mut self) -> &mut Declarations<H::Digest> {
        let tag = self.vote_tag();
        if self.components.view.declarations.tag() != tag {
            self.components.view.declarations = Declarations::recorded(
                tag,
                self.durable.state.watermark.get(&tag),
                self.profile.codec().chains(),
            );
        }
        &mut self.components.view.declarations
    }

    /// Returns the base this node's tips are capped against in its votes tagged `tag`: the base
    /// of the leader block it votes for in `tag`, recorded before its first vote for it, else the
    /// tips of its latest final vote.
    pub(in crate::multimmit::machine) fn sender_base(&self, tag: View) -> &[BlockRef<H::Digest>] {
        self.notarised_base(tag)
            .unwrap_or(&self.durable.state.last_final.1)
    }

    /// Returns whether this node's accepted tip on `chain` is capped: at least `N` above
    /// `base`'s height on that chain.
    pub(in crate::multimmit::machine) fn capped(
        &self,
        chain: ChainId,
        base: &[BlockRef<H::Digest>],
    ) -> bool {
        let cap = u64::from(self.profile.codec().window().cap());
        self.components.chain.tip(chain).height().get()
            >= base[chain.index()].height().get().saturating_add(cap)
    }

    /// Declares every chain `select` picks that is not declared yet, at its accepted tip, counts
    /// them under `rule` with what this node knew about each at `now`, and returns whether any
    /// was added.
    fn declare_where(
        &mut self,
        rule: DeclarationRule,
        now: Now,
        mut select: impl FnMut(&Self, ChainId) -> bool,
    ) -> bool {
        self.declarations();
        let tag = self.vote_tag();
        let stop = self.current_timers().stop;
        let chains = self
            .profile
            .codec()
            .chain_ids()
            .filter(|chain| {
                self.components.view.declarations.at(*chain).is_none() && select(self, *chain)
            })
            .map(|chain| {
                let layer = &self.components.chain;
                let silence = now.saturating_since(layer.last_life(chain));
                let context = DeclarationContext {
                    capped: self.capped(chain, self.sender_base(tag)),
                    silent: silence >= stop,
                    held_back: layer.held_back(chain),
                };
                (chain, layer.tip(chain), context, silence)
            })
            .collect::<Vec<_>>();
        let view = &mut self.components.view;
        let mut added = 0;
        for (chain, tip, context, silence) in chains {
            if view.declarations.declare(chain, tip) {
                added += 1;
                view.contexts.record(rule, context, silence);
            }
        }
        view.declared.add(rule, added);
        added > 0
    }

    /// Declares every chain not declared yet under `rule`: rules (iv) and (v), and optimisations
    /// (A) and (B), at `now`.
    pub(in crate::multimmit::machine) fn declare_all(
        &mut self,
        rule: DeclarationRule,
        now: Now,
    ) -> bool {
        self.declare_where(rule, now, |_, _| true)
    }

    /// Applies rule (i) to the current tag at `now`: a chain not capped from which no sign of
    /// life arrived for `D_stop`.
    pub(in crate::multimmit::machine) fn declare_stopped(
        &mut self,
        timers: &ViewTimers,
        now: Now,
    ) -> bool {
        let tag = self.vote_tag();
        self.declare_where(DeclarationRule::Stopped, now, |machine, chain| {
            let layer = &machine.components.chain;
            now.saturating_since(layer.last_life(chain)) >= timers.stop
                && !machine.capped(chain, machine.sender_base(tag))
        })
    }

    /// Applies rule (iii) to the current view at `now`, `elapsed` after its entry: once
    /// `t_max` passed, every chain not capped.
    pub(in crate::multimmit::machine) fn declare_bound(
        &mut self,
        timers: &ViewTimers,
        now: Now,
        elapsed: u64,
    ) -> bool {
        if elapsed < timers.max {
            return false;
        }
        let tag = self.vote_tag();
        self.declare_where(DeclarationRule::Bound, now, |machine, chain| {
            !machine.capped(chain, machine.sender_base(tag))
        })
    }

    /// Returns how many chains rule (ii) waits for: all but `f`, or `None` when that leaves
    /// none.
    fn late_quorum(&self) -> Option<usize> {
        let codec = self.profile.codec();
        codec
            .chains()
            .checked_sub(codec.max_faults())
            .filter(|chains| *chains > 0)
    }

    /// Returns whether `chain` is declared for the current tag or capped against `base`.
    pub(in crate::multimmit::machine) fn finished(
        &self,
        chain: ChainId,
        base: &[BlockRef<H::Digest>],
    ) -> bool {
        self.components.view.declarations.at(chain).is_some() || self.capped(chain, base)
    }

    /// Records `tquorum` at `now` for the current view, unless it is recorded already: the first
    /// time all but `f` chains are capped or declared before this node's final vote for the view.
    pub(in crate::multimmit::machine) fn note_quorum(&mut self, now: Now) {
        let state = &self.components.view.state;
        if state.quorum_at.is_some() || self.final_sent(state.view) {
            return;
        }
        let Some(quorum) = self.late_quorum() else {
            return;
        };
        self.declarations();
        let base = self.sender_base(self.vote_tag());
        let finished = self
            .profile
            .codec()
            .chain_ids()
            .filter(|chain| self.finished(*chain, base))
            .count();
        if finished >= quorum {
            self.components.view.state.quorum_at = Some(now);
        }
    }

    /// Returns when rule (ii) applies to the current view: `t_late` after `tquorum`, once that
    /// is recorded.
    pub(in crate::multimmit::machine) fn late_at(&self) -> Option<Now> {
        let state = &self.components.view.state;
        state
            .quorum_at
            .map(|at| at.saturating_add(state.timers.late))
    }

    /// Applies rule (ii) to the current view at `now`: once `t_late` passed since `tquorum`,
    /// every chain neither capped nor declared.
    pub(in crate::multimmit::machine) fn declare_late(&mut self, now: Now) -> bool {
        if self.late_at().is_none_or(|at| now < at) {
            return false;
        }
        let tag = self.vote_tag();
        self.declare_where(DeclarationRule::Late, now, |machine, chain| {
            !machine.capped(chain, machine.sender_base(tag))
        })
    }

    /// Records why this node's final vote for the current view, entered at `entered_at`, was
    /// sent at `now`: by the declarations made since the previous final vote.
    pub(in crate::multimmit::machine) fn record_view_end(&mut self, entered_at: Now, now: Now) {
        let view = &mut self.components.view;
        let (declared, bound) = view.declared.since(&view.tag_declared);
        let reason = if bound > 0 {
            ViewEnd::Bound
        } else if declared > 0 {
            ViewEnd::Declared
        } else {
            ViewEnd::Count
        };
        view.ends.record(reason, now.saturating_since(entered_at));
        view.tag_declared = view.declared;
    }

    /// Returns whether rule (v) applies to `view`: on some chain, more than `f` validators'
    /// first binding votes tagged `view` end at one block, and more than `f` but fewer than
    /// `n - f` end at one higher block.
    ///
    /// The chain's tip in the view's V-QCs then depends on which V-QC the next leader block names,
    /// so ending the view at once brings that leader block forward.
    ///
    /// Tips are compared within the window: every tip at or above the window end, `N` above the
    /// view's base `beta_v` (or, until `beta_v` is resolved, the base this node's own votes are
    /// capped against), counts as the window's last block, which it endorses. Senders whose tips
    /// differ only beyond the window agree on the chain's tip in every V-QC of the view, so their
    /// disagreement is no split.
    pub(in crate::multimmit::machine) fn split(&self, view: View) -> bool {
        let codec = self.profile.codec();
        let faults = codec.max_faults();
        let quorum = codec.view_quorum();
        let cap = u64::from(codec.window().cap());
        let base = self.base_of(view).unwrap_or_else(|| self.sender_base(view));
        let mut tips = Vec::new();
        for chain in codec.chain_ids() {
            let end = Height::new(base[chain.index()].height().get().saturating_add(cap));
            tips.clear();
            // A tip at the window end or above is keyed by the end alone.
            tips.extend(self.first_binding(view, chain).iter().map(|(_, tip)| {
                if tip.height() >= end {
                    (end, None)
                } else {
                    (tip.height(), Some(*tip))
                }
            }));
            tips.sort_unstable();
            // The lowest height of a block ending more than f first binding votes, below the run.
            let mut heavy: Option<Height> = None;
            for run in tips.chunk_by(|left, right| left == right) {
                let height = run[0].0;
                let count = run.len();
                if count > faults && count < quorum && heavy.is_some_and(|heavy| heavy < height) {
                    return true;
                }
                if count > faults && heavy.is_none() {
                    heavy = Some(height);
                }
            }
        }
        false
    }

    /// Returns whether the final-vote trigger holds for the current tag: every chain is declared
    /// or capped.
    pub(in crate::multimmit::machine) fn trigger(&mut self) -> bool {
        let tag = self.vote_tag();
        self.declarations();
        let base = self.sender_base(tag);
        self.profile
            .codec()
            .chain_ids()
            .all(|chain| self.finished(chain, base))
    }
}
