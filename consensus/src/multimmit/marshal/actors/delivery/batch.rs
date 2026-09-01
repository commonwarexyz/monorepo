//! Committed outputs handed to delivery, and the hot-byte budget they draw from.
//!
//! A batch carries one entry per output it can afford: a descriptor naming the committed row, or
//! the row with its body so delivery need not read it back. Descriptors and bodies are charged
//! against one hot-byte budget.

use crate::multimmit::{
    marshal::{storage::catalog::StoredRef, types::OutputIndex},
    types::{Body, TransactionBlock},
};
use commonware_cryptography::{Digest, Hasher};
use std::{mem::size_of, sync::Arc};

/// Bytes one output descriptor charges.
pub(crate) fn descriptor_bytes<D: Digest>() -> u64 {
    u64::try_from(size_of::<StoredRef<D>>()).unwrap_or(u64::MAX)
}

/// Bytes one output of `encoded_len` charges with its body.
pub(crate) fn body_bytes<D: Digest>(encoded_len: u64) -> u64 {
    encoded_len.max(descriptor_bytes::<D>())
}

/// A committed output with its body in memory.
pub(crate) struct HotOutput<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// The committed row.
    pub(crate) stored: StoredRef<H::Digest>,
    /// The row's block.
    pub(crate) block: Arc<TransactionBlock<H, B>>,
}

impl<H, B> Clone for HotOutput<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            stored: self.stored,
            block: Arc::clone(&self.block),
        }
    }
}

/// One committed output handed to delivery.
pub(crate) enum DeliveryOutput<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// The row alone; delivery reads the body from custody.
    Descriptor(StoredRef<H::Digest>),
    /// The row with its body.
    Hot(HotOutput<H, B>),
}

impl<H, B> DeliveryOutput<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Returns the committed row.
    pub(crate) const fn stored(&self) -> &StoredRef<H::Digest> {
        match self {
            Self::Descriptor(stored) => stored,
            Self::Hot(output) => &output.stored,
        }
    }

    /// Returns the hot-byte budget this output charges.
    pub(crate) fn retained_bytes(&self) -> u64 {
        match self {
            Self::Descriptor(_) => descriptor_bytes::<H::Digest>(),
            Self::Hot(output) => body_bytes::<H::Digest>(output.stored.encoded_len),
        }
    }
}

/// Outputs that became deliverable with one published checkpoint.
///
/// A batch only saves reads: delivery reads the catalog whenever a batch is dropped under
/// pressure or lost across a restart.
pub(crate) struct DurableBatch<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(crate) floor_generation: u64,
    /// Highest committed output the batch's checkpoint names.
    pub(crate) committed: OutputIndex,
    /// A prefix of the committed outputs, in output order.
    pub(crate) outputs: Vec<DeliveryOutput<H, B>>,
    /// Hot bytes still available to outputs coalesced into this batch.
    remaining_bytes: u64,
}

impl<H, B> DurableBatch<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Starts a batch whose outputs may charge at most `max_bytes`.
    pub(crate) const fn builder(
        floor_generation: u64,
        committed: OutputIndex,
        max_bytes: u64,
    ) -> DurableBatchBuilder<H, B> {
        DurableBatchBuilder {
            floor_generation,
            committed,
            outputs: Vec::new(),
            bytes: 0,
            max_bytes,
        }
    }

    /// Merges a later batch of the same generation, keeping the newest commit and every later
    /// output that still fits.
    pub(super) fn coalesce(&mut self, next: Self) {
        debug_assert_eq!(self.floor_generation, next.floor_generation);
        self.committed = self.committed.max(next.committed);
        for output in next.outputs {
            if self
                .outputs
                .last()
                .is_some_and(|retained| output.stored().index <= retained.stored().index)
            {
                continue;
            }
            let retained_bytes = output.retained_bytes();
            if retained_bytes > self.remaining_bytes {
                continue;
            }
            self.remaining_bytes -= retained_bytes;
            self.outputs.push(output);
        }
    }
}

/// Assembles a [`DurableBatch`] within its hot-byte budget.
pub(crate) struct DurableBatchBuilder<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    floor_generation: u64,
    committed: OutputIndex,
    outputs: Vec<DeliveryOutput<H, B>>,
    bytes: u64,
    max_bytes: u64,
}

impl<H, B> DurableBatchBuilder<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Appends `output`, or returns it when its charge exceeds the remaining budget.
    pub(crate) fn push(
        &mut self,
        output: DeliveryOutput<H, B>,
    ) -> Result<(), DeliveryOutput<H, B>> {
        let Some(bytes) = self
            .bytes
            .checked_add(output.retained_bytes())
            .filter(|bytes| *bytes <= self.max_bytes)
        else {
            return Err(output);
        };
        self.bytes = bytes;
        self.outputs.push(output);
        Ok(())
    }

    /// Returns the bytes the appended outputs charge.
    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Finishes the batch.
    pub(crate) fn build(self) -> DurableBatch<H, B> {
        DurableBatch {
            floor_generation: self.floor_generation,
            committed: self.committed,
            outputs: self.outputs,
            remaining_bytes: self.max_bytes - self.bytes,
        }
    }
}
