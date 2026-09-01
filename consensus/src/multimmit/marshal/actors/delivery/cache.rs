//! A byte-bounded prefix of committed outputs waiting to be reported.

use super::batch::{DeliveryOutput, DurableBatch};
use crate::multimmit::{
    marshal::{storage::catalog::StoredRef, types::OutputIndex},
    types::{Body, TransactionBlock},
};
use commonware_cryptography::Hasher;
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};

/// Committed outputs from published batches, kept in output order within a byte bound.
pub(super) struct DeliveryCache<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    outputs: VecDeque<DeliveryOutput<H, B>>,
    bytes: u64,
    max_bytes: u64,
}

impl<H, B> DeliveryCache<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(super) fn new(max_bytes: NonZeroUsize) -> Self {
        Self {
            outputs: VecDeque::new(),
            bytes: 0,
            max_bytes: u64::try_from(max_bytes.get()).unwrap_or(u64::MAX),
        }
    }

    /// Appends the batch's outputs at or after `next`, then evicts the newest outputs until the
    /// cache fits its bound.
    pub(super) fn insert(&mut self, batch: DurableBatch<H, B>, next: OutputIndex) {
        for output in batch.outputs {
            let index = output.stored().index;
            if index < next
                || self
                    .outputs
                    .back()
                    .is_some_and(|retained| index <= retained.stored().index)
            {
                continue;
            }
            self.bytes = self.bytes.saturating_add(output.retained_bytes());
            self.outputs.push_back(output);
        }
        while self.bytes > self.max_bytes {
            let output = self
                .outputs
                .pop_back()
                .expect("a delivery output exists while over its byte bound");
            self.bytes = self.bytes.saturating_sub(output.retained_bytes());
        }
    }

    fn discard_before(&mut self, index: OutputIndex) {
        while self
            .outputs
            .front()
            .is_some_and(|output| output.stored().index < index)
        {
            let output = self
                .outputs
                .pop_front()
                .expect("a stale delivery output is available");
            self.bytes = self.bytes.saturating_sub(output.retained_bytes());
        }
    }

    /// Takes the body of output `index` if the cache holds it.
    pub(super) fn take_hot(&mut self, index: OutputIndex) -> Option<Arc<TransactionBlock<H, B>>> {
        self.discard_before(index);
        match self.outputs.front()? {
            DeliveryOutput::Hot(output) if output.stored.index == index => {}
            _ => return None,
        }
        let output = self
            .outputs
            .pop_front()
            .expect("the requested delivery output is available");
        self.bytes = self.bytes.saturating_sub(output.retained_bytes());
        let DeliveryOutput::Hot(output) = output else {
            unreachable!("the requested delivery output is hot");
        };
        Some(output.block)
    }

    /// Takes consecutive descriptors from `index`, up to `max_items` whose bodies encode within
    /// `max_bytes` (one larger body is taken alone).
    pub(super) fn take_refs(
        &mut self,
        index: OutputIndex,
        max_items: NonZeroUsize,
        max_bytes: NonZeroUsize,
    ) -> Vec<StoredRef<H::Digest>> {
        self.discard_before(index);
        let mut next = index;
        let mut encoded_bytes = 0u64;
        let max_bytes = u64::try_from(max_bytes.get()).unwrap_or(u64::MAX);
        let mut refs = Vec::new();
        while refs.len() < max_items.get() {
            let Some(DeliveryOutput::Descriptor(stored)) = self.outputs.front() else {
                break;
            };
            if stored.index != next {
                break;
            }
            if !refs.is_empty()
                && encoded_bytes
                    .checked_add(stored.encoded_len)
                    .is_none_or(|total| total > max_bytes)
            {
                break;
            }
            let output = self
                .outputs
                .pop_front()
                .expect("the requested delivery descriptor is available");
            self.bytes = self.bytes.saturating_sub(output.retained_bytes());
            let stored = *output.stored();
            encoded_bytes = encoded_bytes.saturating_add(stored.encoded_len);
            refs.push(stored);
            let Some(following) = next.next() else {
                break;
            };
            next = following;
        }
        refs
    }

    /// Returns how many outputs from `index` may be read before the next cached output, at most
    /// `max`.
    pub(super) fn cold_prefix(&self, index: OutputIndex, max: NonZeroUsize) -> NonZeroUsize {
        let Some(output) = self.outputs.front() else {
            return max;
        };
        debug_assert!(output.stored().index > index);
        let distance = output.stored().index.get().saturating_sub(index.get());
        let distance = usize::try_from(distance).unwrap_or(usize::MAX);
        NonZeroUsize::new(max.get().min(distance)).expect("the next hot output follows the cursor")
    }

    pub(super) fn clear(&mut self) {
        self.outputs.clear();
        self.bytes = 0;
    }
}
