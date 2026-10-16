//! What this node's votes endorse, and the vote updates that send them.
//!
//! # Endorsed tips
//!
//! A correct vote tagged `v` endorses, on every chain `i`, the local accepted path up to
//! `lim_i`: the accepted tip's height, limited at `decl(i)` when `i` is declared final for the
//! view, where `decl(i)` is the accepted tip's height when `i` was first declared in `v`. The
//! durable watermark of the tag records `decl`; a chain declared by the vote being formed takes
//! the current tip's height. Every tip lies on the accepted path, so successive votes of a tag
//! extend each other and a declared chain never moves past its declaration.
//!
//! # Updates
//!
//! A vote is sent as the next update `k` of its tag (from one), naming every chain whose tip
//! differs from the tip of this node's update `k - 1` or `k - 2` of the tag, so one lost update is
//! covered by the next. A final vote names every chain: a reader that lost two earlier updates of
//! the tag still reads it, and with it the next tag's first updates, which fall back on it. Update
//! zero (standing in for `k - 1` at `k = 1` and `k - 2` at `k <= 2`) is this node's final vote of
//! view `v - 1` (every genesis object in view one). When the durable state holds no final vote of
//! `v - 1`, or the contents of earlier updates of the tag were lost with a restart, the missing
//! update matches nothing and every chain is named. Each named chain carries the payload hashes of
//! the blocks above its tip in update `k - 2`, at most `delta_max` (all `delta_max` when update
//! `k - 1` or `k - 2` is unknown), so a reader holding the sender's tip of either update rebuilds
//! every header in between: one lost update costs no fetch. A vote's tips never fall below the
//! previous update's, so the stretch covers update `k - 1` too, and a chain whose tip stood still
//! since update `k - 2` carries none.
//!
//! Before reserving an update the acceptances it may endorse are staged, so the journal makes them
//! durable before the update's record. The reservation advances the tag's durable watermark, and
//! the pool reads the vote at once: this node's own votes count like any other.
//!
//! # Serving
//!
//! Peers fetch this node's vote of a tag by sender and tag. Once an update's record is durable,
//! the resolver serves it in the form naming every chain, each with the payload hashes of the last
//! `delta_max` blocks ending at its tip, replacing the tag's earlier updates: a reader that missed
//! any number of earlier updates reads it alone, and skipping them only delays its reading. A
//! restart serves again the latest signed update of each tag, which its publication still holds.

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::Role,
        machine::{
            chain::is_capacity,
            durability::{DurableEffect, SignRequest, UpdateRequest},
            input::{Now, StepError},
            pool::Recent,
            reducer::{
                components::{WorkResult, WorkStatus},
                machine::Machine,
            },
            view::declare::Declarations,
        },
        types::{
            Artifact, Attestation, BlockRef, ChainChange, Endorsement, VoteContent, VoteUpdate,
        },
    },
    types::{Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// This node's latest updates per view tag. Volatile: after a restart the next update of a tag
/// names every chain.
pub(crate) struct Sender<D: Digest> {
    /// Per tag, the last two updates reserved.
    sent: BTreeMap<View, Recent<D>>,
}

impl<D: Digest> Sender<D> {
    pub(crate) const fn new() -> Self {
        Self {
            sent: BTreeMap::new(),
        }
    }

    /// Returns the content of the reserved update `seq` of `view`, if it is one of the last two.
    fn content(&self, view: View, seq: u32) -> Option<&Arc<VoteContent<D>>> {
        self.sent.get(&view)?.content(seq)
    }

    /// Returns the content of the latest update reserved for `view`.
    pub(crate) fn latest(&self, view: View) -> Option<&Arc<VoteContent<D>>> {
        self.sent.get(&view)?.latest()
    }

    fn record(&mut self, seq: u32, content: Arc<VoteContent<D>>) {
        self.sent
            .entry(content.view())
            .or_insert_with(Recent::new)
            .record(seq, content);
    }

    /// Forgets the updates of tags `view` and earlier.
    pub(crate) fn retire_through(&mut self, view: View) {
        self.sent = self.sent.split_off(&view.next());
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the content of this node's vote tagged `view`: the leader block it votes for, if
    /// any, whether it is final, the chains `declared` declares final, and on every chain the
    /// accepted path's block at `lim_i`.
    ///
    /// A declared chain is endorsed at the block it was declared at, which the accepted tip never
    /// falls below; the tag's watermark records it once a vote carried the declaration.
    pub(in crate::multimmit::machine) fn endorsed_content(
        &self,
        view: View,
        leader: Option<H::Digest>,
        final_: bool,
        declared: &Declarations<H::Digest>,
    ) -> Result<VoteContent<H::Digest>, StepError> {
        let layer = &self.components.chain;
        let recorded = self.durable.state.watermark.get(&view);
        let tips = self
            .profile
            .codec()
            .chain_ids()
            .map(|chain| {
                let tip = layer.tip(chain);
                let Some(at) = declared.at(chain) else {
                    return Ok(tip);
                };
                let at = recorded
                    .filter(|watermark| watermark.declared.contains(chain))
                    .map_or(at, |watermark| watermark.tips[chain.index()]);
                if at.height() > tip.height() {
                    return Err(StepError::ChainInvariant);
                }
                Ok(at)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let endorsement = Endorsement::new(declared.set().clone(), tips, self.profile.codec())
            .map_err(|_| StepError::ViewInvariant)?;
        VoteContent::new(
            Round::new(self.profile.protocol().epoch(), view),
            leader,
            final_,
            endorsement,
        )
        .map_err(|_| StepError::ViewInvariant)
    }

    /// Returns the content of the latest update this node reserved for `view` since it started.
    pub(in crate::multimmit::machine) fn last_sent(
        &self,
        view: View,
    ) -> Option<&Arc<VoteContent<H::Digest>>> {
        self.components.sender.latest(view)
    }

    /// Returns whether `content` repeats this node's latest update of its tag, or, before any,
    /// update zero: a pre-vote endorsing the update-zero tips and declaring nothing.
    pub(in crate::multimmit::machine) fn repeats_last(
        &self,
        content: &VoteContent<H::Digest>,
    ) -> bool {
        let view = content.view();
        self.last_sent(view).map_or_else(
            || {
                content.leader().is_none()
                    && !content.is_final()
                    && content.declared().is_empty()
                    && self.sent_tips(view, 0) == Some(content.tips())
            },
            |last| last.as_ref() == content,
        )
    }

    /// Reserves `content` as this node's next vote update of its tag, after staging the
    /// acceptances it may endorse, and reads it into the pool at `now`.
    ///
    /// Returns [`WorkStatus::Blocked`] without reserving when persistence or the outbox lacks
    /// capacity; an acknowledgement frees it. The durable watermark refuses content that lowers a
    /// tip, leaves the accepted path, drops a declaration, changes the leader, or follows the tag's
    /// final vote.
    pub(in crate::multimmit::machine) fn send_update(
        &mut self,
        content: VoteContent<H::Digest>,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        let Role::Validator(own) = self.profile.role() else {
            return Err(StepError::UnauthorizedEffect);
        };
        match self.flush_acceptances() {
            Ok(()) => {}
            Err(error) if is_capacity(&error) => {
                return Ok((WorkStatus::Blocked, Vec::new()));
            }
            Err(error) => return Err(error),
        }
        let view = content.view();
        let seq = self
            .durable
            .state
            .watermark
            .get(&view)
            .map_or(1, |watermark| watermark.seq + 1);
        let changes = self.update_changes(&content, seq)?;
        let content = Arc::new(content);
        let request = UpdateRequest::new(content.as_ref().clone(), seq, changes);
        let capabilities =
            match self.reserve_effect(DurableEffect::sign(SignRequest::Update(request))) {
                Ok(capabilities) => capabilities,
                Err(error) if is_capacity(&error) => {
                    return Ok((WorkStatus::Blocked, Vec::new()));
                }
                Err(error) => return Err(error),
            };
        self.components.sender.record(seq, Arc::clone(&content));
        self.read_vote(own, seq, content, now, now);
        Ok((WorkStatus::Complete, capabilities))
    }

    /// Returns the tips of this node's update `seq` of `view`, or `None` when they are unknown.
    /// Update zero is the final vote of the previous view, which a node that anchored at `view`
    /// never signed.
    fn sent_tips(&self, view: View, seq: u32) -> Option<&[BlockRef<H::Digest>]> {
        if seq > 0 {
            return self
                .components
                .sender
                .content(view, seq)
                .map(|content| content.tips());
        }
        if view == View::new(1) {
            return Some(self.profile.protocol().genesis().tips());
        }
        let state = &self.durable.state;
        let (last, tips) = &state.last_final;
        (last.next() == view && state.anchored_tag != Some(view)).then_some(tips.as_slice())
    }

    /// Returns the changes of update `seq` carrying `content`: every chain whose tip differs
    /// from update `seq - 1` or `seq - 2`, or every chain in a final vote, with the payload hashes
    /// of the path ending at it.
    fn update_changes(
        &self,
        content: &VoteContent<H::Digest>,
        seq: u32,
    ) -> Result<Vec<ChainChange<H::Digest>>, StepError> {
        let view = content.view();
        self.changes_since(
            content,
            self.sent_tips(view, seq - 1),
            self.sent_tips(view, seq.saturating_sub(2)),
        )
    }

    /// Returns the changes carrying `content` after updates with tips `previous` and `before`:
    /// every chain whose tip differs from either, or every chain in a final vote or when either is
    /// unknown, with the payload hashes of the path ending at it.
    fn changes_since(
        &self,
        content: &VoteContent<H::Digest>,
        previous: Option<&[BlockRef<H::Digest>]>,
        before: Option<&[BlockRef<H::Digest>]>,
    ) -> Result<Vec<ChainChange<H::Digest>>, StepError> {
        let delta_max = u64::from(self.profile.codec().window().delta_max());
        let headers = &self.components.chain.headers;
        let mut changes = Vec::new();
        for (index, tip) in content.tips().iter().enumerate() {
            let unchanged =
                |tips: Option<&[BlockRef<H::Digest>]>| tips.is_some_and(|tips| tips[index] == *tip);
            if !content.is_final() && unchanged(previous) && unchanged(before) {
                continue;
            }
            let advance = |tips: Option<&[BlockRef<H::Digest>]>| {
                tips.map_or(delta_max, |tips| {
                    tip.height()
                        .get()
                        .saturating_sub(tips[index].height().get())
                })
            };
            let count = advance(previous)
                .max(advance(before))
                .min(delta_max)
                .min(tip.height().get());
            let mut payloads = Vec::new();
            let mut block = *tip;
            while (payloads.len() as u64) < count {
                let Some(entry) = headers.get(&block) else {
                    break;
                };
                payloads.push(entry.header.body_digest());
                block = entry.header.parent_ref();
            }
            payloads.reverse();
            changes.push(
                ChainChange::new(*tip, payloads, self.profile.codec())
                    .map_err(|_| StepError::ViewInvariant)?,
            );
        }
        Ok(changes)
    }

    /// Returns this node's update `seq` of `content`, signed by `attestation`, in the form naming
    /// every chain, which peers fetching this node's vote of the tag read without its earlier
    /// updates.
    pub(in crate::multimmit::machine) fn complete_update(
        &self,
        content: &VoteContent<H::Digest>,
        seq: u32,
        attestation: &Attestation<V>,
    ) -> Result<VoteUpdate<V, H::Digest>, StepError> {
        VoteUpdate::new(
            content.round(),
            content.leader(),
            content.is_final(),
            content.declared().clone(),
            seq,
            self.changes_since(content, None, None)?,
            attestation.clone(),
            self.profile.codec(),
        )
        .map_err(|_| StepError::ViewInvariant)
    }

    /// Returns this node's latest signed update of every view tag the pool reads, in the form
    /// naming every chain, for the resolver to serve after a restart.
    ///
    /// The latest signed update of a tag carries the tag's watermark, and its publication stays
    /// queued until a later update supersedes it or the tag retires.
    pub(crate) fn served_votes(&self) -> Vec<Artifact<V, H::Digest>> {
        let state = &self.durable.state;
        let (low, high) = self.vote_tags();
        state
            .outbox
            .values()
            .flat_map(|entry| entry.publication().artifacts())
            .filter_map(|artifact| {
                let Artifact::Update(update) = artifact.as_ref() else {
                    return None;
                };
                let view = update.view();
                let watermark = state.watermark.get(&view).filter(|watermark| {
                    view >= low && view <= high && watermark.seq == update.seq()
                })?;
                let content = update.content(&watermark.tips, self.profile.codec()).ok()?;
                self.complete_update(&content, update.seq(), update.attestation())
                    .ok()
                    .map(Artifact::Update)
            })
            .collect()
    }
}
