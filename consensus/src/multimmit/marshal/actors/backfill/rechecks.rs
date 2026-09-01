//! Local custody rechecks run before any network fetch.

use super::{Error, waiter::Resolved};
use crate::multimmit::{
    marshal::{
        actors::catalog,
        bodies::Bodies,
        wire::{BackfillKey, MAX_SEGMENT_ITEMS},
    },
    types::{BlockRef, Body},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::futures::{AbortablePool, Aborter};
use futures::future::Aborted;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    future::Future,
    sync::Arc,
};

/// A finished local recheck of one key.
pub(super) struct RecheckCompletion<H: Hasher, V: Variant, B: Body<H>> {
    pub key: BackfillKey<H::Digest>,
    /// The locally held value, if any.
    pub result: Result<Option<Resolved<H, V, B>>, Error>,
}

/// Progress of one key's recheck.
enum RecheckState {
    /// Waiting for a free recheck slot.
    Queued,
    /// Running; dropping the aborter cancels it.
    Active(Aborter),
}

/// One recheck per key, at most `max_active` running at once, the rest queued in order.
pub(super) struct Rechecks<H: Hasher, V: Variant, B: Body<H>> {
    states: BTreeMap<BackfillKey<H::Digest>, RecheckState>,
    queued: VecDeque<BackfillKey<H::Digest>>,
    active: AbortablePool<'static, RecheckCompletion<H, V, B>>,
    max_active: usize,
}

impl<H: Hasher, V: Variant, B: Body<H>> Rechecks<H, V, B> {
    pub(super) fn new(max_active: usize) -> Self {
        Self {
            states: BTreeMap::new(),
            queued: VecDeque::new(),
            active: AbortablePool::default(),
            max_active,
        }
    }

    /// Returns whether a recheck of `key` is queued or running.
    pub(super) fn contains(&self, key: &BackfillKey<H::Digest>) -> bool {
        self.states.contains_key(key)
    }

    /// Queues a recheck of `key`, returning `false` if one is already queued or running.
    pub(super) fn queue(&mut self, key: BackfillKey<H::Digest>) -> bool {
        let Entry::Vacant(entry) = self.states.entry(key) else {
            return false;
        };
        entry.insert(RecheckState::Queued);
        self.queued.push_back(key);
        true
    }

    /// Cancels the recheck of `key`, if any.
    pub(super) fn cancel(&mut self, key: &BackfillKey<H::Digest>) {
        match self.states.remove(key) {
            Some(RecheckState::Queued) => self.queued.retain(|queued| queued != key),
            Some(RecheckState::Active(aborter)) => drop(aborter),
            None => {}
        }
    }

    /// Pops the next queued key when a recheck slot is free.
    pub(super) fn next_queued(&mut self) -> Option<BackfillKey<H::Digest>> {
        if self.active.len() >= self.max_active {
            return None;
        }
        self.queued.pop_front()
    }

    /// Runs `recheck` for `key`, which [`Self::next_queued`] returned.
    pub(super) fn start(
        &mut self,
        key: BackfillKey<H::Digest>,
        recheck: impl Future<Output = RecheckCompletion<H, V, B>> + Send + 'static,
    ) {
        let aborter = self.active.push(recheck);
        *self
            .states
            .get_mut(&key)
            .expect("a started recheck was queued") = RecheckState::Active(aborter);
    }

    /// Records that the recheck of `key` finished, returning `false` if it was not running.
    pub(super) fn finish(&mut self, key: &BackfillKey<H::Digest>) -> bool {
        matches!(self.states.remove(key), Some(RecheckState::Active(_)))
    }

    /// Returns the number of running rechecks.
    pub(super) fn active(&self) -> usize {
        self.active.len()
    }

    /// Returns the number of queued rechecks.
    pub(super) fn queued(&self) -> usize {
        self.queued.len()
    }

    /// Resolves to the next finished or canceled recheck.
    pub(super) async fn next_completed(&mut self) -> Result<RecheckCompletion<H, V, B>, Aborted> {
        self.active.next_completed().await
    }
}

/// Returns the value for `key` that local custody already holds, if any.
///
/// A range recheck returns the held prefix of `references`, which must be the range's exact
/// references.
pub(super) async fn local_value<H, V, B>(
    catalog: catalog::Mailbox<H, V, B>,
    bodies: Bodies<H, V, B>,
    key: BackfillKey<H::Digest>,
    references: Option<Arc<Vec<BlockRef<H::Digest>>>>,
    max_value_bytes: usize,
) -> Result<Option<Resolved<H, V, B>>, Error>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    match key {
        BackfillKey::LqcById { id } => {
            Ok(catalog.lqc(id).await?.map(|proof| Resolved::Lqc(id, proof)))
        }
        BackfillKey::TipRecord { commitment } => Ok(catalog
            .history(commitment)
            .await?
            .map(|record| Resolved::History(commitment, Arc::new(vec![record])))),
        BackfillKey::ProducerBlock { chain, digest } => Ok(bodies
            .block_by_digest(chain, digest)
            .await?
            .map(|block| Resolved::Block(block.reference(), block))),
        BackfillKey::ProducerBlocks { .. } => {
            let Some(references) = references else {
                return Err(Error::Invalid("range recheck is missing exact references"));
            };
            let values = bodies.blocks(references.as_ref().clone()).await?;
            if values.len() != references.len() {
                return Err(Error::Invalid(
                    "local producer body range has invalid cardinality",
                ));
            }
            let mut blocks = Vec::new();
            for (reference, block) in references.iter().zip(values) {
                let Some(block) = block else {
                    break;
                };
                if block.reference() != *reference {
                    return Err(Error::Invalid(
                        "local producer body does not match its range coordinate",
                    ));
                }
                blocks.push(block);
            }
            Ok((!blocks.is_empty()).then(|| Resolved::Blocks(key, Arc::new(blocks))))
        }
        BackfillKey::ProducerHeaders { head } => {
            let headers = catalog
                .header_segments(vec![(head, MAX_SEGMENT_ITEMS)], max_value_bytes)
                .await?
                .pop()
                .unwrap_or_default();
            Ok((!headers.is_empty()).then(|| Resolved::Headers(head, Arc::new(headers))))
        }
    }
}
