//! Pure validation of peer responses against their backfill keys.

use super::waiter::Resolved;
use crate::{
    Epochable as _,
    multimmit::{
        marshal::wire::{BackfillKey, MAX_SEGMENT_ITEMS},
        types::{
            BlockRef, Body, CodecConfig, Lqc, TipRecord, TransactionBlock, TransactionBlockHeader,
        },
    },
    types::Epoch,
};
use bytes::Bytes;
use commonware_codec::{Decode as _, EncodeSize as _, RangeCfg};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A linked tip-history segment, newest first, shared across waiters.
pub(crate) type SharedHistory<D> = Arc<Vec<Arc<TipRecord<D>>>>;

/// A linked producer-header segment, newest first, shared across waiters.
pub(crate) type SharedHeaders<D> = Arc<Vec<TransactionBlockHeader<D>>>;

/// Consecutive producer blocks, newest first, shared across waiters.
pub(crate) type SharedBlocks<H, B> = Arc<Vec<Arc<TransactionBlock<H, B>>>>;

/// Bounds a peer response must satisfy.
pub(super) struct Limits<C> {
    /// Epoch of every accepted proof, header and block.
    pub epoch: Epoch,
    /// Decode bounds for the epoch.
    pub codec: CodecConfig,
    /// Decode configuration for application bodies.
    pub body: C,
    /// Maximum encoded size of one block.
    pub max_block_bytes: usize,
    /// Maximum size of one resolver value.
    pub max_value_bytes: usize,
}

/// Returns the linked tip-history segment whose newest record has commitment `expected`.
pub(super) fn validate_history_segment<H: Hasher>(
    mut expected: H::Digest,
    records: Vec<TipRecord<H::Digest>>,
) -> Option<SharedHistory<H::Digest>> {
    let mut segment = Vec::with_capacity(records.len());
    for record in records {
        if record.commitment::<H>() != expected {
            return None;
        }
        expected = record.parent();
        segment.push(Arc::new(record));
    }
    Some(Arc::new(segment))
}

/// Returns the linked producer-header segment of `epoch` whose newest header is `expected`.
pub(super) fn validate_header_segment<H: Hasher>(
    epoch: Epoch,
    mut expected: BlockRef<H::Digest>,
    headers: Vec<TransactionBlockHeader<H::Digest>>,
) -> Option<SharedHeaders<H::Digest>> {
    for (position, header) in headers.iter().enumerate() {
        if header.epoch() != epoch
            || header.block_ref::<H>() != expected
            || (expected.height().get() == 1 && position + 1 != headers.len())
        {
            return None;
        }
        expected = header.parent_ref();
    }
    Some(Arc::new(headers))
}

/// Returns the linked block segment of `epoch` whose newest block is `expected`.
pub(super) fn validate_block_segment<H, B>(
    epoch: Epoch,
    mut expected: BlockRef<H::Digest>,
    blocks: Vec<TransactionBlock<H, B>>,
) -> Option<SharedBlocks<H, B>>
where
    H: Hasher,
    B: Body<H>,
{
    let count = blocks.len();
    let mut segment = Vec::with_capacity(count);
    for (position, block) in blocks.into_iter().enumerate() {
        if block.header().epoch() != epoch
            || block.reference() != expected
            || (expected.height().get() == 1 && position + 1 != count)
        {
            return None;
        }
        expected = block.header().parent_ref();
        segment.push(Arc::new(block));
    }
    Some(Arc::new(segment))
}

/// Decodes and validates the peer response `value` for `key`.
///
/// Returns `None` when the value is oversized, malformed, from another epoch, or does not match
/// the key. A returned L-QC is not yet verified.
pub(super) fn decode<H, V, B>(
    limits: &Limits<B::Cfg>,
    key: BackfillKey<H::Digest>,
    value: Bytes,
) -> Option<Resolved<H, V, B>>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    if value.len() > limits.max_value_bytes {
        return None;
    }
    match key {
        BackfillKey::LqcById { id } => {
            let proof = Lqc::<V, H::Digest>::decode_cfg(value, &limits.codec).ok()?;
            (proof.epoch() == limits.epoch && proof.id::<H>() == id)
                .then(|| Resolved::Lqc(id, Arc::new(proof)))
        }
        BackfillKey::TipRecord { commitment } => {
            let records = Vec::<TipRecord<H::Digest>>::decode_cfg(
                value,
                &(RangeCfg::from(1..=MAX_SEGMENT_ITEMS), limits.codec),
            )
            .ok()?;
            validate_history_segment::<H>(commitment, records)
                .map(|segment| Resolved::History(commitment, segment))
        }
        BackfillKey::ProducerHeaders { head } => {
            let headers = Vec::<TransactionBlockHeader<H::Digest>>::decode_cfg(
                value,
                &(RangeCfg::from(1..=MAX_SEGMENT_ITEMS), ()),
            )
            .ok()?;
            validate_header_segment::<H>(limits.epoch, head, headers)
                .map(|segment| Resolved::Headers(head, segment))
        }
        BackfillKey::ProducerBlock { chain, digest } => {
            let block = TransactionBlock::<H, B>::decode_cfg(value, &limits.body).ok()?;
            let reference = block.reference();
            (block.encode_size() <= limits.max_block_bytes
                && block.header().epoch() == limits.epoch
                && reference.chain() == chain
                && reference.digest() == digest)
                .then(|| Resolved::Block(reference, Arc::new(block)))
        }
        BackfillKey::ProducerBlocks { head, max_items } => {
            let blocks = Vec::<TransactionBlock<H, B>>::decode_cfg(
                value,
                &(
                    RangeCfg::from(1..=usize::from(max_items.get())),
                    limits.body.clone(),
                ),
            )
            .ok()?;
            let blocks = validate_block_segment::<H, B>(limits.epoch, head, blocks)?;
            blocks
                .iter()
                .all(|block| block.encode_size() <= limits.max_block_bytes)
                .then(|| Resolved::Blocks(key, blocks))
        }
    }
}
