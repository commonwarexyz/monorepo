//! The vote pool: reading vote updates, and the votes this node has read.
//!
//! A validator sends its growing vote for a view tag as numbered updates, each naming only the
//! chains whose tips changed since one of its two previous updates of the tag. Per sender and tag
//! the pool keeps the highest sequence number read and the contents of the last two updates read,
//! and reads updates in sequence order:
//!
//! 1. Rebuild. A chain an update omits takes its tip from the sender's update `k - 1` if read,
//!    else `k - 2`. For `k <= 2` the sender's final vote of the previous view stands in for the
//!    missing update zero (every chain's genesis object in view one). An update naming every chain
//!    needs no predecessor, which is how a sender resumes after a restart. An update whose
//!    predecessor is unread is parked unverified on the sender's vote of the tag, which is
//!    requested: peers answer with the sender's latest update of the tag naming every chain.
//!    Reading any update of the tag wakes the parked ones, and those it supersedes are dropped.
//!    Verification covers the rebuilt content, so a wrong rebuild fails it.
//! 2. Resolve. Each changed tip must name a linked header: one whose held ancestry reaches an
//!    accepted header, the chain's origin, or the store's floor. The update's payload hashes
//!    rebuild the headers below its tip from a held ancestor, which the chain layer then holds; a
//!    tip still unknown or not yet linked is fetched from peers one missing header at a time while
//!    the update waits, on whichever branch it lies. A tip the chain layer can never hold (outside
//!    the held band, or a foreign copy of the local producer's chain) is read unresolved: the vote
//!    endorses nothing on that chain.
//! 3. Read. The vote is interpreted once, at its first read, and never again: it endorses the
//!    held path below each tip, which feeds the per-header endorser sets (and through them `h*`
//!    and adoption), and its tips on the chains it binds are recorded if it is the sender's first
//!    binding vote there.
//!
//! Updates are read only for tags within `[v - W_back, v + 2]` of the current view `v`, at most
//! `pending_updates_per_sender` unread updates are retained per sender (the newest beyond is
//! refused, unless it names every chain and a parked update of the sender waits for its vote of the
//! tag: it needs no predecessor and, once read, supersedes those parked updates), and an update at
//! or below the sender's last read sequence number, or after its final vote, is refused.
//!
//! Skipping a sender's intermediate updates of a tag only delays what the pool reads: within a tag
//! a correct sender's votes extend each other, and each vote is interpreted at its first read.
//!
//! [`counts`] derives the view-level facts the view and emission layers read from the pool, and
//! [`lqc`] aggregates the signed votes for a finalized leader block into an L-QC.

pub(crate) mod counts;
pub(crate) mod lqc;

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        algebra::{Path, binding},
        config::Role,
        machine::{
            input::{Now, Rejection, StepError},
            reducer::{components::Precheck, machine::Machine},
            resolution::RetrievalKey,
            scheduler::ProtocolComponent,
            view::endorse::Sender,
        },
        types::{ArtifactId, BlockRef, ChainChange, ChainId, Endorsement, VoteContent, VoteUpdate},
    },
    types::{Attributable as _, Height, Participant, Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::bitmap::BitMap;
use std::{collections::BTreeMap, sync::Arc};

/// The sequence numbers and contents of one sender's last two updates of a view tag, newest
/// first.
pub(crate) struct Recent<D: Digest>([Option<(u32, Arc<VoteContent<D>>)>; 2]);

impl<D: Digest> Recent<D> {
    pub(crate) const fn new() -> Self {
        Self([None, None])
    }

    /// Returns the content of update `seq`, if it is one of the two.
    pub(crate) fn content(&self, seq: u32) -> Option<&Arc<VoteContent<D>>> {
        self.0
            .iter()
            .flatten()
            .find_map(|(recorded, content)| (*recorded == seq).then_some(content))
    }

    /// Returns the content of the newest update.
    pub(crate) fn latest(&self) -> Option<&Arc<VoteContent<D>>> {
        self.0[0].as_ref().map(|(_, content)| content)
    }

    /// Records update `seq` as the newest.
    pub(crate) fn record(&mut self, seq: u32, content: Arc<VoteContent<D>>) {
        self.0[1] = self.0[0].take();
        self.0[0] = Some((seq, content));
    }
}

/// One sender's reading state for one view tag.
struct Reader<D: Digest> {
    /// The highest sequence number read, zero before any.
    read: u32,
    /// The last two updates read.
    last: Recent<D>,
    /// Per chain, the tip of the first vote read that binds the sender there; empty until one
    /// does.
    first_binding: Vec<Option<BlockRef<D>>>,
}

impl<D: Digest> Reader<D> {
    const fn new() -> Self {
        Self {
            read: 0,
            last: Recent::new(),
            first_binding: Vec::new(),
        }
    }

    /// Returns whether `seq` is new: above the last read and not after a final vote.
    fn admits(&self, seq: u32) -> bool {
        seq > self.read && self.last.latest().is_none_or(|content| !content.is_final())
    }

    fn record(&mut self, seq: u32, content: Arc<VoteContent<D>>) {
        self.read = seq;
        self.last.record(seq, content);
    }
}

/// What the pool read in one view tag.
struct Tag<D: Digest> {
    /// Per leader block, the senders of a read vote for it.
    leaders: BTreeMap<D, BitMap>,
    /// The senders whose final vote was read, in read order.
    finals: Vec<Participant>,
    /// Per chain, every sender's first binding tip, in read order; empty until a vote binds.
    bindings: Vec<Vec<(Participant, BlockRef<D>)>>,
}

/// The pool's volatile state, rebuilt from the own vote watermarks on start; peers' votes return
/// as they are received again.
pub(crate) struct Pool<D: Digest> {
    participants: usize,
    readers: BTreeMap<(View, Participant), Reader<D>>,
    tags: BTreeMap<View, Tag<D>>,
    /// Per view, the base of the leader block this node voted for, which the view layer supplies.
    notarised_bases: BTreeMap<View, Arc<[BlockRef<D>]>>,
    /// The highest view tag whose votes were forgotten.
    retired: View,
}

impl<D: Digest> Pool<D> {
    /// Creates an empty pool for `participants` validators.
    pub(crate) const fn new(participants: usize) -> Self {
        Self {
            participants,
            readers: BTreeMap::new(),
            tags: BTreeMap::new(),
            notarised_bases: BTreeMap::new(),
            retired: View::zero(),
        }
    }

    fn reader(&self, view: View, sender: Participant) -> Option<&Reader<D>> {
        self.readers.get(&(view, sender))
    }
}

/// How far a changed tip of a verified update resolves.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TipStatus<D: Digest> {
    /// The tip names a linked header, a genesis object, or a height below the held floor.
    Held,
    /// The tip names a header the chain layer can never hold; the vote is read unresolved there.
    Unresolvable,
    /// The tip's path down to a linked header lacks this header, which a peer can supply.
    Missing(BlockRef<D>),
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the lowest and highest view tag the pool reads.
    pub(in crate::multimmit::machine) fn vote_tags(&self) -> (View, View) {
        let view = self.durable.state.view;
        let low = view.saturating_sub(self.profile.tuning().vote_window);
        (
            low.max(View::new(1)),
            View::new(view.get().saturating_add(2)),
        )
    }

    /// Checks that the pool reads update `seq` of `sender` for `view`: its tag lies in the
    /// window and it is newer than every update of the tag read from `sender`.
    fn readable(&self, view: View, sender: Participant, seq: u32) -> Result<(), Rejection> {
        let (low, high) = self.vote_tags();
        if view < low || view > high {
            return Err(Rejection::TagWindow);
        }
        if self
            .components
            .pool
            .reader(view, sender)
            .is_some_and(|reader| !reader.admits(seq))
        {
            return Err(Rejection::Superseded);
        }
        Ok(())
    }

    /// Checks an observed vote update and rebuilds its signed content, or names the sender's vote
    /// it must wait for. A `parked` update already counts toward its sender's bound, and one
    /// naming every chain that a parked update of the sender waits for is not held to it.
    ///
    /// An update the pool no longer reads is refused, unless its content rebuilds from the
    /// sender's read updates and equivocates with the sender's greatest vote of the tag seen: it
    /// is then verified as evidence, and never read.
    pub(in crate::multimmit::machine) fn precheck_update(
        &self,
        update: &VoteUpdate<V, H::Digest>,
        parked: bool,
    ) -> Result<Precheck<H::Digest>, Rejection> {
        let sender = update.signer();
        let superseded = match self.readable(update.view(), sender, update.seq()) {
            Ok(()) => false,
            Err(Rejection::Superseded) => true,
            Err(rejection) => return Err(rejection),
        };
        let complete = update.changes().len() == self.profile.codec().chains();
        let awaited = complete
            && self.store.has_waiters(&RetrievalKey::Update {
                signer: sender,
                view: update.view(),
            });
        if !parked
            && !awaited
            && self.store.pending_updates(sender)
                >= self.profile.tuning().pending_updates_per_sender.get()
        {
            return Err(Rejection::PendingUpdatesFull);
        }
        let tips = if complete {
            update.changes().iter().map(ChainChange::tip).collect()
        } else {
            let mut tips = match self.predecessor(update) {
                Ok(tips) => tips.to_vec(),
                Err(_) if superseded => return Err(Rejection::Superseded),
                // The pool never reads an update below its window, so one rebuilt from it waits
                // forever.
                Err(key) if key.view().is_some_and(|view| view < self.vote_tags().0) => {
                    return Err(Rejection::TagWindow);
                }
                Err(key) => return Ok(Precheck::Park(key)),
            };
            for change in update.changes() {
                tips[change.chain().index()] = change.tip();
            }
            tips
        };
        let endorsement = Endorsement::new(update.declared().clone(), tips, self.profile.codec())
            .map_err(|_| Rejection::Context)?;
        let content = VoteContent::new(
            update.round(),
            update.leader(),
            update.is_final(),
            endorsement,
        )
        .map_err(|_| Rejection::Context)?;
        if superseded && !self.components.accountability.conflicts(sender, &content) {
            return Err(Rejection::Superseded);
        }
        Ok(Precheck::Verify(Some(Arc::new(content))))
    }

    /// Returns the tips an update's omitted chains take, or the key of the sender's vote it waits
    /// for.
    fn predecessor(
        &self,
        update: &VoteUpdate<V, H::Digest>,
    ) -> Result<&[BlockRef<H::Digest>], RetrievalKey<H::Digest>> {
        let view = update.view();
        let sender = update.signer();
        let seq = update.seq();
        let pool = &self.components.pool;
        let read = pool.reader(view, sender).and_then(|reader| {
            reader
                .last
                .content(seq - 1)
                .or_else(|| reader.last.content(seq.saturating_sub(2)))
        });
        if let Some(content) = read {
            return Ok(content.tips());
        }
        if seq > 2 {
            return Err(RetrievalKey::Update {
                signer: sender,
                view,
            });
        }
        let Some(previous) = view.previous().filter(|previous| !previous.is_zero()) else {
            return Ok(self.profile.protocol().genesis().tips());
        };
        match pool
            .reader(previous, sender)
            .and_then(|reader| reader.last.latest())
        {
            Some(content) if content.is_final() => Ok(content.tips()),
            _ => Err(RetrievalKey::Update {
                signer: sender,
                view: previous,
            }),
        }
    }

    /// Holds the headers a verified update's payload hashes rebuild, and returns the header the
    /// first changed tip still missing names.
    pub(in crate::multimmit::machine) fn update_dependency(
        &mut self,
        update: &VoteUpdate<V, H::Digest>,
    ) -> Option<RetrievalKey<H::Digest>> {
        if self
            .readable(update.view(), update.signer(), update.seq())
            .is_err()
        {
            return None;
        }
        let previous = self
            .components
            .pool
            .reader(update.view(), update.signer())
            .and_then(|reader| reader.last.latest())
            .cloned();
        let mut missing = None;
        for change in update.changes() {
            let hint = previous
                .as_ref()
                .map(|content| content.tips()[change.chain().index()]);
            if let TipStatus::Missing(block) = self.resolve_tip(change, hint)
                && missing.is_none()
            {
                missing = Some(RetrievalKey::Header {
                    chain: block.chain(),
                    digest: block.digest(),
                });
            }
        }
        missing
    }

    /// Resolves one changed tip, rebuilding and holding the headers its payload hashes name.
    ///
    /// A tip held but not linked names the first header missing below it: the parent of the
    /// lowest header held on its path. A branch is so fetched one header at a time, at most
    /// `D + 2N` deep, wherever it forks from the accepted path.
    fn resolve_tip(
        &mut self,
        change: &ChainChange<H::Digest>,
        hint: Option<BlockRef<H::Digest>>,
    ) -> TipStatus<H::Digest> {
        let tip = change.tip();
        let chain = tip.chain();
        if tip.height().is_zero() {
            return if tip == self.profile.protocol().genesis().tips()[chain.index()] {
                TipStatus::Held
            } else {
                TipStatus::Unresolvable
            };
        }
        let layer = &self.components.chain;
        if tip.height() <= layer.headers.floor(chain) {
            return TipStatus::Held;
        }
        if layer.headers.get(&tip).is_none() {
            self.rebuild_path(change, hint);
        }
        let layer = &self.components.chain;
        let mut missing = tip;
        while let Some(entry) = layer.headers.get(&missing) {
            if entry.linked {
                return TipStatus::Held;
            }
            missing = entry.header.parent_ref();
        }
        if layer.resolvable(chain, missing.height()) {
            TipStatus::Missing(missing)
        } else {
            TipStatus::Unresolvable
        }
    }

    /// Rebuilds the headers below `change`'s tip from its payload hashes and holds them, lowest
    /// first.
    ///
    /// A path of `j` payload hashes starts above a held object `j` below the tip. The sender's
    /// previous tip `hint` is tried first, then every held header from the tip's height down,
    /// each costing one hash per rebuilt header: at most `(n + 1) * m * (m + 1) / 2` hashes for
    /// `m` payload hashes.
    fn rebuild_path(&mut self, change: &ChainChange<H::Digest>, hint: Option<BlockRef<H::Digest>>) {
        let tip = change.tip();
        let payloads = change.payloads();
        let chain = tip.chain();
        let lowest = tip.height().get().saturating_sub(payloads.len() as u64);
        let genesis = self.profile.protocol().genesis().tips()[chain.index()];
        let headers = &self.components.chain.headers;
        let candidates = hint
            .filter(|hint| hint.chain() == chain && hint.height().get() >= lowest)
            .into_iter()
            .chain((lowest..tip.height().get()).rev().flat_map(|height| {
                let held = headers
                    .at(chain, Height::new(height))
                    .iter()
                    .map(|entry| entry.block());
                (height == 0).then_some(genesis).into_iter().chain(held)
            }))
            .filter(|from| from.height() < tip.height())
            .collect::<Vec<_>>();
        let epoch = self.profile.protocol().epoch();
        for from in candidates {
            let skip = (from.height().get() - lowest) as usize;
            let Ok(path) = Path::resolve::<H>(epoch, from, &payloads[skip..], &tip) else {
                continue;
            };
            for (header, block) in path.rebuilt() {
                if !self.hold_rebuilt(header, block.digest()) {
                    break;
                }
            }
            return;
        }
    }

    /// Reads an authenticated vote update whose changed tips resolved, accounts for it as its
    /// sender's statement, and drops its store entry: the pool keeps its content. The update is
    /// read at `now` and was received at `received`. Returns whether it was read; an update the
    /// pool no longer reads is evidence only.
    pub(in crate::multimmit::machine) fn read_update(
        &mut self,
        id: ArtifactId<H::Digest>,
        update: &VoteUpdate<V, H::Digest>,
        content: Option<&Arc<VoteContent<H::Digest>>>,
        now: Now,
        received: Now,
    ) -> bool {
        self.store.remove(&id);
        let Some(content) = content else {
            return false;
        };
        let sender = update.signer();
        self.account_vote(sender, content);
        let read = self.readable(update.view(), sender, update.seq()).is_ok();
        if read {
            self.read_vote(sender, update.seq(), Arc::clone(content), now, received);
        }
        read
    }

    /// Interprets `sender`'s vote `seq` with `content`, read at `now` and received at
    /// `received`, once and for good: every held tip endorses its held path, and every chain the
    /// vote binds records its tip unless an earlier vote of the tag already bound the sender
    /// there.
    pub(in crate::multimmit::machine) fn read_vote(
        &mut self,
        sender: Participant,
        seq: u32,
        content: Arc<VoteContent<H::Digest>>,
        now: Now,
        received: Now,
    ) {
        let view = content.view();
        for tip in content.tips() {
            if self
                .components
                .chain
                .headers
                .get(tip)
                .is_some_and(|entry| entry.linked)
            {
                self.note_endorsement(sender, view, *tip, now, received);
            }
        }
        let base = self.base_of(view).map(<[_]>::to_vec);
        let cap = self.profile.codec().window().cap();
        let pool = &mut self.components.pool;
        let participants = pool.participants;
        let reader = pool
            .readers
            .entry((view, sender))
            .or_insert_with(Reader::new);
        let tag = pool.tags.entry(view).or_insert_with(|| Tag {
            leaders: BTreeMap::new(),
            finals: Vec::new(),
            bindings: Vec::new(),
        });
        for (index, tip) in content.tips().iter().enumerate() {
            let binds = binding(
                &content,
                ChainId::new(index as u32),
                base.as_ref().map(|base| &base[index]),
                cap,
            );
            if reader.first_binding.get(index).is_some_and(Option::is_some) || !binds {
                continue;
            }
            if reader.first_binding.is_empty() {
                reader.first_binding = vec![None; content.tips().len()];
            }
            reader.first_binding[index] = Some(*tip);
            if tag.bindings.is_empty() {
                tag.bindings = vec![Vec::new(); content.tips().len()];
            }
            tag.bindings[index].push((sender, *tip));
        }
        if let Some(leader) = content.leader() {
            tag.leaders
                .entry(leader)
                .or_insert_with(|| BitMap::zeroes(participants as u64))
                .set(u64::from(sender.get()), true);
        }
        if content.is_final() {
            tag.finals.push(sender);
        }
        let final_ = content.is_final();
        reader.record(seq, content);
        self.wake(ProtocolComponent::Emission);
        if view == self.durable.state.view {
            self.wake(ProtocolComponent::Pool);
            if final_ {
                self.wake(ProtocolComponent::Forwarding);
            }
        }
    }

    /// Reads the final votes a V-QC records, which its aggregate signature vouches for, as votes
    /// of their senders read at `now` and received with the V-QC at `received`. The forwarding
    /// drive then wakes each sender's updates that waited for an update of the tag, such as the
    /// next tag's first updates (the `k <= 2` default).
    ///
    /// A sender's final vote is skipped when the pool already read one of the tag from it, when the
    /// sender is this node (its own votes are read as it reserves them), or when the tag lies
    /// outside the window the pool reads.
    pub(in crate::multimmit::machine) fn read_certified_finals(
        &mut self,
        contents: &[(Participant, VoteContent<H::Digest>)],
        now: Now,
        received: Now,
    ) {
        let Some(view) = contents.first().map(|(_, content)| content.view()) else {
            return;
        };
        let (low, high) = self.vote_tags();
        if view < low || view > high {
            return;
        }
        let own = match self.profile.role() {
            Role::Validator(own) => Some(own),
            Role::Observer => None,
        };
        for (sender, content) in contents {
            let content = Arc::new(content.clone());
            self.account_vote(*sender, &content);
            let reader = self.components.pool.reader(view, *sender);
            if Some(*sender) == own
                || reader.is_some_and(|reader| {
                    reader.last.latest().is_some_and(|latest| latest.is_final())
                })
            {
                continue;
            }
            let seq = reader.map_or(0, |reader| reader.read);
            self.read_vote(*sender, seq, content, now, received);
            let key = RetrievalKey::Update {
                signer: *sender,
                view,
            };
            self.components.vqcs.available.push(key..=key);
        }
    }

    /// Returns the base of the leader block this node voted for in `view`, once recorded.
    pub(in crate::multimmit::machine) fn notarised_base(
        &self,
        view: View,
    ) -> Option<&[BlockRef<H::Digest>]> {
        self.components
            .pool
            .notarised_bases
            .get(&view)
            .map(AsRef::as_ref)
    }

    /// Records `base`, the base of the leader block this node voted for in `view`, against which
    /// this node caps its own tips in `view`.
    pub(in crate::multimmit::machine) fn set_notarised_base(
        &mut self,
        view: View,
        base: Arc<[BlockRef<H::Digest>]>,
    ) {
        self.components.pool.notarised_bases.insert(view, base);
    }

    /// Forgets every vote tagged `view` or earlier, and folds their endorsements of held headers
    /// into one partition, once no count reads a view at or below it.
    pub(in crate::multimmit::machine) fn retire_votes_through(&mut self, view: View) {
        let pool = &mut self.components.pool;
        if view <= pool.retired {
            return;
        }
        pool.retired = view;
        let next = view.next();
        pool.readers = pool.readers.split_off(&(next, Participant::new(0)));
        pool.tags = pool.tags.split_off(&next);
        pool.notarised_bases = pool.notarised_bases.split_off(&next);
        self.components.sender.retire_through(view);
        self.components.chain.headers.merge_tags_through(view);
    }

    /// Rebuilds the pool and the update sender at `now` from durable state: this node's latest
    /// vote of every view tag the pool reads, as its watermark records it.
    ///
    /// A watermark's tips extend every earlier vote of its tag along the accepted path, so the
    /// latest vote endorses everything the earlier ones did. Peers' votes return as they are
    /// received again.
    pub(in crate::multimmit::machine) fn restore_votes(
        &mut self,
        now: Now,
    ) -> Result<(), StepError> {
        self.components.pool = Pool::new(self.profile.codec().participants());
        self.components.sender = Sender::new();
        let Role::Validator(own) = self.profile.role() else {
            return Ok(());
        };
        let (low, high) = self.vote_tags();
        let state = &self.durable.state;
        let votes = state
            .watermark
            .range(low..=high)
            .map(|(view, watermark)| {
                let content = match &watermark.final_content {
                    Some(content) => content.clone(),
                    None => VoteContent::new(
                        Round::new(self.profile.protocol().epoch(), *view),
                        state.notarised.get(view).copied(),
                        false,
                        Endorsement::new(
                            watermark.declared.clone(),
                            watermark.tips.clone(),
                            self.profile.codec(),
                        )
                        .map_err(|_| StepError::ViewInvariant)?,
                    )
                    .map_err(|_| StepError::ViewInvariant)?,
                };
                Ok((watermark.seq, Arc::new(content)))
            })
            .collect::<Result<Vec<_>, StepError>>()?;
        for (seq, content) in votes {
            self.read_vote(own, seq, content, now, now);
        }
        Ok(())
    }
}
