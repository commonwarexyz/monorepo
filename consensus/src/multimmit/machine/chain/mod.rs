//! The chain layer: producer headers, their acceptance, and the local producer.
//!
//! Per producer chain the layer holds the headers this node knows ([`headers`]), the path it has
//! accepted, the height quorum `h*` (the greatest height whose block `n - 2f` validators endorse),
//! and the times of the latest acceptance and sign of life that declaration rule (i) reads.
//!
//! - [`accept`] decides acceptance: in full once a header's body verified, or by adoption once
//!   `alpha` validators endorse it, each only on the accepted parent, within `D` of `h*`, and
//!   within `D + N` of the chain's final height.
//!   Acceptances wait in a pending list until [`Machine::flush_acceptances`] stages them, which
//!   must happen before any vote update that could endorse them is reserved.
//! - [`validation`] asks the chain planes for the application's verdict on buffered headers.
//! - [`producer`] builds, custodies, and signs this node's own blocks.
//!
//! The vote layer feeds the layer through [`Machine::hold_rebuilt`] (headers rebuilt from payload
//! hashes) and [`Machine::note_endorsement`] (the endorsed tip of one read vote on one chain);
//! `h*` and adoption follow from those endorsements.

pub(crate) mod accept;
pub(crate) mod headers;
pub(crate) mod producer;
pub(crate) mod validation;

use self::{
    accept::Refusals,
    headers::{HeaderEntry, HeaderStore, Marked, Signed, Thresholds},
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Role},
        machine::{
            capability::Capabilities,
            durability::Acceptance,
            input::{Now, Rejection, StepError},
            reducer::machine::Machine,
            resolution::RetrievalKey,
            scheduler::ProtocolComponent,
        },
        types::{
            Activity, Artifact, ArtifactId, BlockRef, ChainId, SignedTransactionBlock,
            TransactionBlockHeader,
        },
    },
    types::{Attributable as _, Height, Participant, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeSet, sync::Arc};

/// The bounds the chain layer enforces, fixed for the epoch.
#[derive(Copy, Clone, Debug)]
struct Bounds {
    /// The flow bound `D`: a header is accepted at most this far above `h*`.
    flow: u64,
    /// `D + N`: a header is accepted at most this far above its chain's final height.
    final_lead: u64,
    /// The tip lead `D + 2N`: headers are held at most this far above `h*`, and producer-signed
    /// headers are buffered at most this far above the accepted tip.
    lead: u64,
    /// Producer-signed headers buffered per height above the accepted tip.
    branches: usize,
    /// The endorsers that make a header adoptable (`alpha`).
    adoption: usize,
    /// The local producer's chain, whose headers only the local producer accepts.
    own: Option<ChainId>,
}

/// The chain layer's volatile state.
///
/// The accepted path is rebuilt from durable state on start; endorsements, and with them `h*`,
/// return as the vote layer reads retained votes again.
pub(crate) struct ChainLayer<V: Variant, D: Digest> {
    bounds: Bounds,
    /// Held headers and their endorsers.
    pub(crate) headers: HeaderStore<V, D>,
    /// Per chain, the accepted tip, including acceptances not yet staged.
    tips: Vec<BlockRef<D>>,
    /// Acceptances not yet staged, in acceptance order (lowest height first per chain).
    pending: Vec<Acceptance<V, D>>,
    /// Per chain, the height quorum `h*`. Never decreases.
    quorum: Vec<Height>,
    /// Per chain, the greatest height known final.
    finalized: Vec<Height>,
    /// Per chain, the time of the latest sign of life (`lastlife`): an acceptance, or the first
    /// read of a vote endorsing a header this node has not accepted.
    last_life: Vec<Now>,
    /// Chains whose next height may have become acceptable.
    dirty: BTreeSet<ChainId>,
    /// Per chain, the greatest height whose ready header a bound refused.
    refused: Vec<Height>,
    /// The ready headers the bounds refused, each counted once.
    refusals: Refusals,
}

impl<V: Variant, D: Digest> ChainLayer<V, D> {
    /// Creates the layer of an epoch whose chains sit at `origin`, one block per chain: their
    /// genesis objects, or the base of the view this node anchored at. Each origin is finalized,
    /// so `h*` and the final height start there, at time `now`.
    pub(crate) fn new(profile: &Profile<D>, origin: &[BlockRef<D>], now: Now) -> Self {
        let codec = profile.codec();
        let genesis = profile.protocol().genesis().tips();
        let participants = codec.participants();
        let own = match profile.role() {
            Role::Validator(participant) => profile.protocol().producer_chain(participant),
            Role::Observer => None,
        };
        Self {
            bounds: Bounds {
                flow: u64::from(codec.window().flow()),
                final_lead: u64::from(codec.window().flow()) + u64::from(codec.window().cap()),
                lead: profile.height_window(),
                branches: profile.tuning().pending_branches_per_height.get(),
                adoption: codec.adoption_quorum(),
                own,
            },
            // One header per endorsing validator's path, and the producer's own.
            headers: HeaderStore::new(
                origin,
                participants,
                participants + 1,
                Thresholds {
                    quorum: codec.height_quorum(),
                    adoption: codec.adoption_quorum(),
                    confirmation: codec.view_quorum(),
                },
            ),
            tips: origin.to_vec(),
            pending: Vec::new(),
            quorum: origin.iter().map(|tip| tip.height()).collect(),
            finalized: origin.iter().map(|tip| tip.height()).collect(),
            last_life: vec![now; genesis.len()],
            dirty: BTreeSet::new(),
            refused: origin.iter().map(|tip| tip.height()).collect(),
            refusals: Refusals::default(),
        }
    }

    /// Returns `chain`'s accepted tip, including acceptances not yet staged.
    pub(crate) fn tip(&self, chain: ChainId) -> BlockRef<D> {
        self.tips[chain.index()]
    }

    /// Returns `chain`'s height quorum `h*`.
    pub(crate) fn quorum(&self, chain: ChainId) -> Height {
        self.quorum[chain.index()]
    }

    /// Returns the greatest height of `chain` known final.
    pub(crate) fn finalized(&self, chain: ChainId) -> Height {
        self.finalized[chain.index()]
    }

    /// Returns whether this node's acceptance bounds admit building `height` of `chain`: at most
    /// `D` above the greater of `h*` and the final height (the flow bound), and at most `D + N`
    /// above the final height. A producer builds only what its peers accept, so a block beyond
    /// either bound would be refused by every correct validator.
    pub(crate) fn admits_production(&self, chain: ChainId, height: Height) -> bool {
        let finalized = self.finalized(chain).get();
        let top = self.quorum(chain).get().max(finalized);
        height.get() <= top.saturating_add(self.bounds.flow)
            && height.get() <= finalized.saturating_add(self.bounds.final_lead)
            && (std::env::var("EXP_B").is_err() || height.get() <= finalized.saturating_add(self.bounds.final_lead - self.bounds.flow))
    }

    /// Raises each chain's final height to its block in `tips`, one per chain in chain order, and
    /// marks for acceptance every chain whose next height the raise admits: its flow bound, counted
    /// from the greater of `h*` and the final height, rose, or its finality bound held it. Returns
    /// whether any chain was marked.
    fn finalize(&mut self, tips: &[BlockRef<D>]) -> bool {
        let mut raised = false;
        for (index, tip) in tips.iter().enumerate() {
            let finalized = self.finalized[index];
            if tip.height() <= finalized {
                continue;
            }
            self.finalized[index] = tip.height();
            let top = self.quorum[index].max(finalized);
            let lead = self.tips[index]
                .height()
                .get()
                .saturating_sub(finalized.get());
            let held = lead >= self.bounds.final_lead;
            if tip.height() > top || held {
                self.dirty.insert(tip.chain());
                raised = true;
            }
        }
        raised
    }

    /// Returns the time of `chain`'s latest sign of life.
    pub(crate) fn last_life(&self, chain: ChainId) -> Now {
        self.last_life[chain.index()]
    }

    /// Returns whether the last acceptance pass over `chain` found its next header ready but
    /// refused by the flow or finality bound.
    pub(crate) fn held_back(&self, chain: ChainId) -> bool {
        self.refused[chain.index()] == self.tip(chain).height().next()
    }

    /// Returns the acceptances not yet staged.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> &[Acceptance<V, D>] {
        &self.pending
    }

    /// Checks that a header of `chain` at `height` lies within the held band: above the floor and
    /// at most `D + 2N` above the greater of `h*` and the final height, on any branch.
    fn holdable(&self, chain: ChainId, height: Height) -> bool {
        let top = self.quorum(chain).max(self.finalized(chain));
        height > self.headers.floor(chain)
            && height.get() <= top.get().saturating_add(self.bounds.lead)
    }

    /// Checks that a header of `chain` at `height` may be held to resolve a vote's tip: within the
    /// held band on another producer's chain. A correct node's own chain has one branch at every
    /// correct voter, so a peer's copy of it never resolves anything.
    pub(crate) fn resolvable(&self, chain: ChainId, height: Height) -> bool {
        Some(chain) != self.bounds.own && self.holdable(chain, height)
    }

    /// Checks that a peer's producer-signed header of `chain` at `height` could be buffered for
    /// acceptance: resolvable, above the accepted tip, and within the tip lead of the tip.
    fn bufferable(&self, chain: ChainId, height: Height) -> bool {
        let tip = self.tip(chain).height().get();
        height.get() > tip
            && height.get() <= tip.saturating_add(self.bounds.lead)
            && self.resolvable(chain, height)
    }

    /// Checks that a producer-signed header `header` with digest `digest` may be buffered for
    /// acceptance: on another producer's chain, above the accepted tip, within the tip lead of
    /// both the tip and `h*`, with room among its height's buffered branches and held headers.
    fn admits_signed(
        &self,
        header: &TransactionBlockHeader<D>,
        digest: &D,
    ) -> Result<(), Rejection> {
        let chain = header.chain();
        let height = header.height();
        if !self.bufferable(chain, height) {
            return Err(Rejection::TipLead);
        }
        let entries = self.headers.at(chain, height);
        if let Some(held) = entries.iter().find(|entry| entry.digest == *digest) {
            return if held.signed.is_none() {
                Ok(())
            } else {
                Err(Rejection::HeightFull)
            };
        }
        let buffered = entries
            .iter()
            .filter(|entry| entry.signed.is_some() && !entry.accepted)
            .count();
        if buffered >= self.bounds.branches || !self.headers.has_room(chain, height, true) {
            return Err(Rejection::HeightFull);
        }
        Ok(())
    }

    /// Checks that an authenticated header `header` with digest `digest` that cannot be buffered
    /// for acceptance may still be held to resolve votes: resolvable, not held, with room at its
    /// height.
    fn admits_resolution(
        &self,
        header: &TransactionBlockHeader<D>,
        digest: &D,
    ) -> Result<(), Rejection> {
        let chain = header.chain();
        let height = header.height();
        if !self.resolvable(chain, height) {
            return Err(Rejection::TipLead);
        }
        if self
            .headers
            .get(&BlockRef::new(chain, height, *digest))
            .is_some()
            || !self.headers.has_room(chain, height, false)
        {
            return Err(Rejection::HeightFull);
        }
        Ok(())
    }

    /// Records the thresholds a marking pass on `chain` crossed, and returns whether `h*` rose.
    fn absorb(&mut self, chain: ChainId, marked: Marked) -> bool {
        if marked.adoptable {
            self.dirty.insert(chain);
        }
        let Some(height) = marked.quorum else {
            return false;
        };
        let quorum = &mut self.quorum[chain.index()];
        if height <= *quorum {
            return false;
        }
        *quorum = height;
        self.dirty.insert(chain);
        true
    }

    /// Holds the accepted header `acceptance` with digest `digest` as the new tip of its chain,
    /// at time `now`.
    fn extend(&mut self, acceptance: &Acceptance<V, D>, digest: D, now: Now) {
        let header = acceptance.header();
        let chain = header.chain();
        let block = BlockRef::new(chain, header.height(), digest);
        if self.headers.get(&block).is_some() {
            self.headers.accept(&block);
        } else {
            let mut entry = HeaderEntry::new(header.clone(), digest, self.headers.participants());
            entry.signed = acceptance.signed().map(|block| Signed {
                block: Arc::clone(block),
                artifact: None,
            });
            entry.accepted = true;
            // The accepted path extends the previous tip, which the store holds, so the new tip
            // inherits no endorsements and is held whatever its height holds.
            let _ = self.headers.insert(entry);
        }
        self.tips[chain.index()] = block;
        self.last_life[chain.index()] = now;
    }
}

/// Returns whether `error` reports capacity an acknowledgement or retirement frees.
pub(crate) const fn is_capacity(error: &StepError) -> bool {
    matches!(
        error,
        StepError::PersistenceCapacity
            | StepError::OutboxFull
            | StepError::LocalArtifactReservation
    )
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the chain layer.
    #[cfg(test)]
    pub(in crate::multimmit::machine) const fn chain_layer(&self) -> &ChainLayer<V, H::Digest> {
        &self.components.chain
    }

    /// Raises each chain's final height to its block in `tips`, one per chain in chain order,
    /// wakes acceptance when that lifted a chain's flow bound, and wakes the producer when it
    /// lifted the own chain's final height, which bounds how far ahead the producer builds.
    pub(in crate::multimmit::machine) fn finalize_chains(&mut self, tips: &[BlockRef<H::Digest>]) {
        let own = self.components.chain.bounds.own;
        let before = own.map(|chain| self.components.chain.finalized(chain));
        if self.components.chain.finalize(tips) {
            self.wake(ProtocolComponent::Chain);
        }
        if own.map(|chain| self.components.chain.finalized(chain)) != before {
            self.wake(ProtocolComponent::Producer);
        }
    }

    /// Checks the chain-layer bounds of an observed producer header before it is verified.
    ///
    /// A header that cannot be buffered for acceptance is still verified when a vote waits for it
    /// and it can be held to resolve that vote, or when its height is full but it would prove its
    /// producer equivocated: another producer-signed header is held at its height.
    pub(in crate::multimmit::machine) fn precheck_header(
        &self,
        block: &SignedTransactionBlock<V, H::Digest>,
    ) -> Result<(), Rejection> {
        let header = block.header();
        let digest = header.digest::<H>();
        let layer = &self.components.chain;
        match layer.admits_signed(header, &digest) {
            Err(Rejection::HeightFull) if self.header_equivocates(header, &digest) => Ok(()),
            Err(rejection) if self.awaited(header, &digest) => layer
                .admits_resolution(header, &digest)
                .map_err(|_| rejection),
            Err(rejection) => Err(rejection),
            Ok(()) => Ok(()),
        }
    }

    /// Returns whether a stored artifact waits for `header`, with digest `digest`, to resolve a
    /// tip. Only such headers are held off the acceptance buffer, so a producer cannot make
    /// others verify and hold headers nobody names.
    fn awaited(&self, header: &TransactionBlockHeader<H::Digest>, digest: &H::Digest) -> bool {
        self.store.has_waiters(&RetrievalKey::Header {
            chain: header.chain(),
            digest: *digest,
        })
    }

    /// Returns whether another producer-signed header than `digest` is held at `header`'s height,
    /// from a producer not yet proven faulty.
    fn header_equivocates(
        &self,
        header: &TransactionBlockHeader<H::Digest>,
        digest: &H::Digest,
    ) -> bool {
        self.components
            .chain
            .headers
            .at(header.chain(), header.height())
            .iter()
            .any(|entry| entry.digest != *digest && entry.signed.is_some())
            && self
                .profile
                .protocol()
                .producer(header.chain())
                .is_some_and(|producer| !self.quarantined(producer))
    }

    /// Buffers an authenticated producer header for acceptance and asks its chain plane to
    /// validate it, or else holds it, without its signed copy, to resolve votes naming it. It is
    /// refused when the bounds moved since its precheck.
    pub(in crate::multimmit::machine) fn receive_header(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Artifact<V, H::Digest>,
    ) -> Capabilities<V, H::Digest> {
        let Artifact::TransactionBlock(block) = artifact else {
            return Capabilities::new();
        };
        let header = block.header();
        let digest = header.digest::<H>();
        let chain = header.chain();
        if self.header_equivocates(header, &digest) {
            self.account_equivocation(block.signer());
        }
        if self
            .components
            .chain
            .admits_signed(header, &digest)
            .is_err()
        {
            self.store.remove(&id);
            if self.awaited(header, &digest)
                && self
                    .components
                    .chain
                    .admits_resolution(header, &digest)
                    .is_ok()
            {
                self.hold_resolution(header.clone(), digest);
            }
            return Capabilities::new();
        }
        let signed = Signed {
            block: Arc::new(block.clone()),
            artifact: Some(id),
        };
        let layer = &mut self.components.chain;
        let reference = BlockRef::new(chain, header.height(), digest);
        if let Some(entry) = layer.headers.get_mut(&reference) {
            entry.signed = Some(signed);
        } else {
            let mut entry = HeaderEntry::new(header.clone(), digest, layer.headers.participants());
            entry.signed = Some(signed);
            let Some(inserted) = layer.headers.insert(entry) else {
                self.store.remove(&id);
                return Capabilities::new();
            };
            for evicted in &inserted.evicted {
                self.store.remove(evicted);
            }
            self.absorb_marked(chain, inserted.marked);
        }
        self.request_validation(reference).into_iter().collect()
    }

    /// Holds `header` with digest `digest`, which admission checked, to resolve the votes naming it
    /// or a descendant, wherever its parent is.
    fn hold_resolution(&mut self, header: TransactionBlockHeader<H::Digest>, digest: H::Digest) {
        let chain = header.chain();
        let layer = &mut self.components.chain;
        let entry = HeaderEntry::new(header, digest, layer.headers.participants());
        let Some(inserted) = layer.headers.insert(entry) else {
            return;
        };
        for evicted in &inserted.evicted {
            self.store.remove(evicted);
        }
        self.absorb_marked(chain, inserted.marked);
    }

    /// Hashes `header` and holds it as [`Self::hold_rebuilt`] does.
    #[cfg(test)]
    pub(in crate::multimmit::machine) fn hold_header(
        &mut self,
        header: TransactionBlockHeader<H::Digest>,
    ) -> bool {
        let digest = header.digest::<H>();
        self.hold_rebuilt(&header, digest)
    }

    /// Holds `header` of digest `digest`, rebuilt from payload hashes a vote or certificate names,
    /// and returns whether it is held. The rebuild computed the digest, so holding hashes nothing.
    ///
    /// A header is held only within the held band, on a held parent (or the chain's origin, or the
    /// floor), and while its height has room.
    pub(in crate::multimmit::machine) fn hold_rebuilt(
        &mut self,
        header: &TransactionBlockHeader<H::Digest>,
        digest: H::Digest,
    ) -> bool {
        let chain = header.chain();
        let layer = &mut self.components.chain;
        if chain.index() >= self.profile.codec().chains()
            || header.epoch() != self.profile.protocol().epoch()
            || !layer.holdable(chain, header.height())
            || !layer.headers.links(header)
        {
            return false;
        }
        if layer
            .headers
            .get(&BlockRef::new(chain, header.height(), digest))
            .is_some()
        {
            return true;
        }
        let entry = HeaderEntry::new(header.clone(), digest, layer.headers.participants());
        let Some(inserted) = layer.headers.insert(entry) else {
            return false;
        };
        for evicted in &inserted.evicted {
            self.store.remove(evicted);
        }
        self.absorb_marked(chain, inserted.marked);
        true
    }

    /// Records that a vote of `signer` tagged `tag`, read at `now` and received at `received`,
    /// endorses the held header `tip` and so its held ancestors.
    ///
    /// A vote endorsing a header this node has not accepted is a sign of life of its chain. An
    /// endorsement that lifts a header to `n - 2f` endorsers raises `h*`, and one that lifts an
    /// unaccepted header to `alpha` endorsers makes it a candidate for adoption. An own header that
    /// reaches `n - f` endorsers completes a round-trip sample of the delay estimator.
    ///
    /// The sample ends at `received`, so it measures the network and not this node's backlog of
    /// unread votes. The sign of life is dated `now`: silence is judged from what this node has
    /// read, and a backlog must not make a live chain look stopped.
    pub(in crate::multimmit::machine) fn note_endorsement(
        &mut self,
        signer: Participant,
        tag: View,
        tip: BlockRef<H::Digest>,
        now: Now,
        received: Now,
    ) {
        let chain = tip.chain();
        let layer = &mut self.components.chain;
        let Some(entry) = layer.headers.get(&tip) else {
            return;
        };
        if !entry.accepted {
            layer.last_life[chain.index()] = now;
        }
        let marked = layer.headers.endorse(signer, tag, tip);
        if let Some(height) = marked.confirmed
            && Some(chain) == layer.bounds.own
        {
            self.delay_estimator().confirmed(height, received);
        }
        self.absorb_marked(chain, marked);
    }

    /// Applies the thresholds a marking pass on `chain` crossed, waking the work they enable.
    fn absorb_marked(&mut self, chain: ChainId, marked: Marked) {
        let raised = self.components.chain.absorb(chain, marked);
        if self.components.chain.dirty.contains(&chain) {
            self.wake(ProtocolComponent::Chain);
        }
        if raised && Some(chain) == self.components.chain.bounds.own {
            self.wake(ProtocolComponent::Producer);
        }
    }

    /// Rebuilds the chain layer from durable state at `now`: every chain's origin, the held window
    /// above the heights retention keeps, every chain's accepted path, whose every acceptance is
    /// reported again, then this node's own signed headers that extend its chain's accepted tip,
    /// accepted again because a crash may have lost their acceptance before it was staged. A
    /// signed own header above a header whose signature is still reserved waits in the producer.
    pub(in crate::multimmit::machine) fn restore_chain(
        &mut self,
        now: Now,
    ) -> Result<(), StepError> {
        let state = &self.durable.state;
        let genesis = self.profile.protocol().genesis().tips();
        let mut layer = ChainLayer::new(&self.profile, &state.origin, now);
        for (tip, height) in genesis.iter().zip(state.retained_heights(genesis)) {
            layer
                .headers
                .retain_above(tip.chain(), height.previous().unwrap_or(height));
        }
        let mut reports = Vec::new();
        let grace = self.adoption_grace();
        for acceptance in state.accepted.iter().flat_map(|accepted| accepted.values()) {
            layer.extend(acceptance, acceptance.header().digest::<H>(), now);
            reports.push(Activity::HeaderAccepted {
                header: acceptance.header().clone(),
                adopted: acceptance.adopted().then_some(grace),
            });
        }
        self.components.chain = layer;
        self.report_in_order(reports);
        let Some(own) = self.components.chain.bounds.own else {
            return Ok(());
        };
        let tip = self.components.chain.tip(own).height();
        let mut produced = self
            .durable
            .state
            .local
            .values()
            .filter_map(|artifact| match artifact.as_ref() {
                Artifact::TransactionBlock(block)
                    if block.header().chain() == own && block.header().height() > tip =>
                {
                    Some(Arc::new(block.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        produced.sort_by_key(|block| block.header().height());
        for block in produced {
            if block.header().parent_ref() != self.components.chain.tip(own) {
                break;
            }
            self.accept_own(block, now)?;
        }
        Ok(())
    }
}
