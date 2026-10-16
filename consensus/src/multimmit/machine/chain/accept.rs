//! Acceptance of producer headers and the staging of acceptances.
//!
//! A node accepts a header of chain `i` at height `h` when (i) it accepted nothing at `(i, h)`,
//! (ii) `h = 1` or it accepted the parent, (iii) `h - h*_i <= D`, and (iv) `h - f_i <= D + N`
//! for the chain's greatest height `f_i` known final, and either in full, once the producer
//! signature verified and the application validated the body, or by adoption, once `alpha`
//! validators endorse the header. Each pass walks every chain whose next height may have
//! become acceptable in increasing height, preferring a header accepted in full over one adopted
//! at the same height. A header failing (ii), (iii), or (iv) stays buffered in the header store
//! until its parent is accepted or `h*` or the final height moves; once the accepted tip passes
//! its height its signed copy is dropped.
//!
//! Condition (iv) bounds a chain's accepted lead over its finality. `h*` follows acceptance,
//! not finality: validators endorse what they accept, so under (iii) alone a producer running
//! ahead of finality raises `h*` and with it the next heights validators accept, and the
//! accepted headers durable state keeps above the retained bases grow without bound. A correct
//! producer builds at most `N` plus its slack above the final height it knows, and `D` covers
//! that slack and one more window, so neither (iii) nor (iv) refuses its blocks while the
//! validator's `h*` and final height lag the producer's by at most `N`.
//!
//! A header that is otherwise ready (valid, or adoptable) but refused by (iii) or (iv) is counted
//! once per height in [`Refusals`]: a correct producer's block refused there is a sign that `D`
//! is too small for the lag between producers and validators, and it delays the chain's signs of
//! life at this node.
//!
//! The local producer's chain is accepted only through production: its own signed header is
//! accepted in full by construction, since the body entered custody before the header was signed.
//!
//! Acceptances are staged as [`Change::Accepted`] by [`Machine::flush_acceptances`]. A vote
//! update must not endorse a header whose acceptance a crash could forget, so the update path
//! flushes before it reserves an update; the journal is a prefix order, so the update's record
//! is durable only after the acceptances. The chain drive also flushes at the end of every pass.
//!
//! An adopted header's report carries the current view's delay estimate `delta_hat` as the
//! grace a consumer gives the body to arrive by relay before fetching it: `alpha` endorsers have
//! the body, so it is usually already on its way.

use super::{ChainLayer, is_capacity};
use crate::multimmit::{
    machine::{
        capability::{Capabilities, Capability, ChainCommand},
        durability::{Acceptance, Change, Retained},
        input::{BlockValidity, Now, StepError},
        reducer::{
            components::{WorkResult, WorkStatus},
            machine::Machine,
        },
        scheduler::{Budget, ProtocolComponent},
    },
    types::{Activity, BlockRef, ChainId, SignedTransactionBlock},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{sync::Arc, time::Duration};

/// Cumulative counts of headers whose acceptance a bound refused, each counted once per chain and
/// height, since the process started.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Refusals {
    /// Headers more than `D` above the greater of `h*` and the final height.
    pub(crate) flow: u64,
    /// Headers within `D` of `h*` but more than `D + N` above the final height.
    pub(crate) finality: u64,
}

impl<V: Variant, D: Digest> ChainLayer<V, D> {
    /// Returns the header of `chain` that may be accepted next, and whether it would be adopted,
    /// counting a ready header the bounds refuse.
    ///
    /// The flow bound counts from the greater of `h*` and the final height: `h*` is flow control
    /// only, and a final height is endorsed by at least `n - 4f` correct validators. The
    /// finality bound counts from the final height alone.
    fn candidate(&mut self, chain: ChainId) -> Option<(BlockRef<D>, bool)> {
        if Some(chain) == self.bounds.own {
            return None;
        }
        let tip = self.tip(chain);
        let height = tip.height().next();
        let children = || {
            self.headers
                .at(chain, height)
                .iter()
                .filter(move |entry| entry.header.parent() == tip.digest())
        };
        let ready = children()
            .find(|entry| entry.signed.is_some() && entry.verdict == Some(BlockValidity::Valid))
            .map(|entry| (entry.block(), false))
            .or_else(|| {
                children()
                    .find(|entry| entry.endorsements() >= self.bounds.adoption)
                    .map(|entry| (entry.block(), true))
            })?;
        let finalized = self.finalized(chain);
        let top = self.quorum(chain).max(finalized);
        let refusal = if height.get().saturating_sub(top.get()) > self.bounds.flow {
            &mut self.refusals.flow
        } else if height.get().saturating_sub(finalized.get()) > self.bounds.final_lead {
            &mut self.refusals.finality
        } else {
            return Some(ready);
        };
        let refused = &mut self.refused[chain.index()];
        if height > *refused {
            *refused = height;
            *refusal += 1;
        }
        None
    }

    /// Returns the headers a bound refused since the process started.
    pub(crate) const fn refusals(&self) -> Refusals {
        self.refusals
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the grace an adopted header's report carries: the current view's `delta_hat`.
    pub(super) const fn adoption_grace(&self) -> Duration {
        Duration::from_millis(self.current_timers().delta)
    }

    /// Accepts every acceptable header, within `budget`, then stages the pending acceptances.
    pub(in crate::multimmit::machine) fn drive_chain(
        &mut self,
        budget: &mut Budget,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        let capabilities = self.accept_ready(budget, now);
        let status = if self.components.chain.dirty.is_empty() {
            WorkStatus::Complete
        } else {
            WorkStatus::Requeue
        };
        match self.flush_acceptances() {
            Ok(()) => Ok((status, capabilities)),
            Err(error) if is_capacity(&error) => Ok((WorkStatus::Blocked, capabilities)),
            Err(error) => Err(error),
        }
    }

    /// Accepts headers of the dirty chains in increasing height, one budget unit each, and returns
    /// the new accepted tip heights for the chain planes of the chains it advanced.
    fn accept_ready(&mut self, budget: &mut Budget, now: Now) -> Capabilities<V, H::Digest> {
        let mut capabilities = Capabilities::new();
        while let Some(chain) = self.components.chain.dirty.pop_first() {
            let before = self.components.chain.tip(chain);
            while let Some((block, adopted)) = self.components.chain.candidate(chain) {
                if !budget.try_spend(1) {
                    self.components.chain.dirty.insert(chain);
                    break;
                }
                self.accept(block, adopted, now);
            }
            let tip = self.components.chain.tip(chain);
            if tip != before {
                self.wake(ProtocolComponent::View);
                capabilities.push(Capability::Chain(
                    chain,
                    ChainCommand::Accepted(tip.height()),
                ));
            }
            if budget.remaining() == 0 {
                break;
            }
        }
        capabilities
    }

    /// Accepts the held header `block`, in full or by adoption, at `now`, and releases the
    /// buffered signed copies the new tip makes useless.
    fn accept(&mut self, block: BlockRef<H::Digest>, adopted: bool, now: Now) {
        let layer = &mut self.components.chain;
        let entry = layer
            .headers
            .get_mut(&block)
            .expect("an acceptance candidate is held");
        let acceptance = if adopted {
            Acceptance::Adopted(entry.header.clone())
        } else {
            let signed = entry
                .signed
                .as_ref()
                .expect("a header accepted in full is signed");
            Acceptance::Full(Arc::clone(&signed.block))
        };
        let mut released = entry
            .signed
            .as_mut()
            .and_then(|signed| signed.artifact.take())
            .into_iter()
            .collect::<Vec<_>>();
        layer.extend(&acceptance, block.digest(), now);
        layer.pending.push(acceptance);
        released.extend(
            layer
                .headers
                .release_signed_through(block.chain(), block.height()),
        );
        for id in released {
            self.store.remove(&id);
        }
        self.note_acceptance(block.chain(), now);
    }

    /// Accepts this node's own signed header `block` in full at `now`.
    ///
    /// The header must extend its chain's accepted tip: the producer signs one header per height,
    /// each on the previous one, and builds only once the previous one is accepted.
    pub(in crate::multimmit::machine) fn accept_own(
        &mut self,
        block: Arc<SignedTransactionBlock<V, H::Digest>>,
        now: Now,
    ) -> Result<(), StepError> {
        let layer = &mut self.components.chain;
        let header = block.header();
        if Some(header.chain()) != layer.bounds.own
            || header.parent_ref() != layer.tip(header.chain())
        {
            return Err(StepError::ChainInvariant);
        }
        let (chain, digest) = (header.chain(), header.digest::<H>());
        let acceptance = Acceptance::Full(block);
        layer.extend(&acceptance, digest, now);
        layer.pending.push(acceptance);
        self.note_acceptance(chain, now);
        self.wake(ProtocolComponent::Chain);
        self.wake(ProtocolComponent::View);
        Ok(())
    }

    /// Stages every pending acceptance and reports each once its record is durable.
    ///
    /// The update path calls this before it reserves a vote update, so the update's record
    /// follows the acceptances it may endorse. Fails without staging the remainder when the
    /// pipeline or the artifact cache has no room.
    pub(in crate::multimmit::machine) fn flush_acceptances(&mut self) -> Result<(), StepError> {
        // One event holds at most every chain's tip-lead window, the journal's decoding bound.
        let window = usize::try_from(self.profile.height_window()).unwrap_or(usize::MAX);
        let limit = self.profile.codec().chains().saturating_mul(window).max(1);
        while !self.components.chain.pending.is_empty() {
            let pending = &self.components.chain.pending;
            let blocks = pending[..pending.len().min(limit)].to_vec();
            let ids = blocks
                .iter()
                .filter_map(Acceptance::signed)
                .map(|block| Retained::<V, H::Digest>::Header(block).id::<H>())
                .collect::<Vec<_>>();
            if self
                .durable
                .occupancy_after(&ids, &[], 0, 0)
                .is_none_or(|occupancy| occupancy > self.profile.resources().max_cached_artifacts())
            {
                return Err(StepError::LocalArtifactReservation);
            }
            let count = blocks.len();
            let emitted = self.reserve_change(Change::Accepted { blocks })?;
            debug_assert!(emitted.is_empty(), "acceptances release nothing");
            let grace = self.adoption_grace();
            let reports = self
                .components
                .chain
                .pending
                .drain(..count)
                .map(|acceptance| Activity::HeaderAccepted {
                    header: acceptance.header().clone(),
                    adopted: acceptance.adopted().then_some(grace),
                })
                .collect::<Vec<_>>();
            self.report_when_durable(reports);
        }
        Ok(())
    }
}
