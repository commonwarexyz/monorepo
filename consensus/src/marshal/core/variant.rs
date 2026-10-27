//! Marshal variant and buffer traits.
//!
//! This module defines the core abstractions that allow the marshal actor to work
//! with different block dissemination strategies:
//!
//! - [`Variant`]: Describes the types used by a marshal variant
//! - [`Buffer`]: Abstracts over block dissemination strategies
//!
//! The [`Variant`] trait expects a 1:1 mapping between the [`Variant::Commitment`] and the
//! block digest, with the commitment being a superset of the digest. The commitment may
//! contain extra information that can be used for optimized retrieval or variant-specific
//! mechanisms, though it is required that the digest can be extracted from the commitment
//! for lookup purposes.

use crate::{Block, simplex::scheme::Scheme, types::Round};
use commonware_codec::{Codec, Error as CodecError, Input, Read};
use commonware_cryptography::{Digest, Digested, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_utils::channel::oneshot;
use std::{future::Future, marker::PhantomData};

/// A block commitment and the evidence available when decoding it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedCommitment<C> {
    /// A locally certified or finalized block commitment, or an ancestor's.
    ///
    /// Decoding reuses its expensive components instead of recomputing them. Notarization
    /// alone is insufficient.
    Trusted(C),
    /// A commitment without certification evidence, whose components decoding recomputes.
    Untrusted(C),
}

/// A marker trait describing the types used by a variant of Marshal.
///
/// Working blocks carry their identity. A [`Variant::Block`] reads its digest and commitment from
/// what it was built with, and [`Variant::into_shared`] yields a [`Digested`] application block,
/// so readers never compute identity themselves. A block's identity is established once, where
/// its raw form enters marshal. The application digests a block it built,
/// [`Variant::decode_block`] a received block, and [`Variant::restore`] or
/// [`Variant::restore_across`] a stored block.
pub trait Variant: Clone + Send + Sync + 'static {
    /// The working block type of marshal, whose digest and consensus commitment are ready.
    ///
    /// Cloning must share the block payload, and conversion to [`Self::StoredBlock`]
    /// must not copy it.
    type Block: Block<Digest = <Self::ApplicationBlock as Digestible>::Digest>
        + Into<Self::StoredBlock>;

    /// The application block type, as decoded from the wire.
    type ApplicationBlock: Block + Codec;

    /// The type of block stored in the archive, as decoded from storage.
    ///
    /// Decoding only parses, so a stored block's identity is reattached from the key it was
    /// stored under by [`Self::restore`], or computed by [`Self::restore_across`] when the key
    /// is unknown.
    type StoredBlock: Block<Digest = <Self::Block as Digestible>::Digest>
        + Codec<Cfg = <Self::ApplicationBlock as Read>::Cfg>;

    /// The [`Digest`] type used by consensus.
    type Commitment: Digest;

    /// Returns the consensus commitment of a block.
    ///
    /// The commitment is what validators sign over during consensus.
    ///
    /// Together with [`Variant::commitment_to_inner`], implementations must satisfy:
    /// `commitment_to_inner(commitment(block)) == block.digest()`.
    fn commitment(block: &Self::Block) -> Self::Commitment;

    /// Extracts the block digest from a consensus commitment.
    ///
    /// For blocks/certificates accepted by marshal in this variant instance, the digest
    /// must uniquely determine the commitment. In other words, there should not be two accepted
    /// commitments with the same inner digest.
    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest;

    /// Returns the parent commitment referenced by `block`.
    fn parent_commitment(block: &Self::Block) -> Self::Commitment;

    /// Returns the parent commitment referenced by a stored block.
    ///
    /// The parent linkage is part of the stored bytes, so walking ancestry through storage does
    /// not restore each block's identity.
    fn stored_parent_commitment(block: &Self::StoredBlock) -> Self::Commitment;

    /// Validates a certificate payload against the active consensus scheme.
    fn check_payload<S>(scheme: &S, payload: Self::Commitment) -> bool
    where
        S: Scheme<Self::Commitment>;

    /// Decodes a [`Self::Block`] received over the wire, failing unless [`Self::commitment`] of
    /// the result equals the commitment in `expected`.
    fn decode_block(
        buf: impl Input,
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        expected: ExpectedCommitment<Self::Commitment>,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Result<Self::Block, CodecError>> + Send;

    /// Restores a working block from its stored form and `digest`, the key it was stored under.
    fn restore(
        stored: Self::StoredBlock,
        digest: <Self::Block as Digestible>::Digest,
    ) -> Self::Block;

    /// Restores a working block from its stored form when the key it was stored under is
    /// unknown, computing any identity the stored form lacks as a job on `strategy`.
    fn restore_across(
        stored: Self::StoredBlock,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Self::Block> + Send;

    /// Converts a working block to the application block without copying the payload.
    fn into_shared(block: Self::Block) -> Digested<Self::ApplicationBlock>;

    /// Reconstructs a working block from an application block and the trusted consensus payload
    /// that commits to it.
    ///
    /// Panics if `payload` does not commit to the block's digest.
    fn from_application_block(
        block: Digested<Self::ApplicationBlock>,
        payload: Self::Commitment,
    ) -> Self::Block;

    /// Returns the largest encoded size of a [`Self::Block`] that holds an application block of at
    /// most `block` encoded bytes, or `None` if the size overflows.
    fn max_block_size(block: usize) -> Option<usize>;

    /// Returns the largest payload that the [`Buffer`] implementation provided with the variant
    /// passes to the network to disseminate application blocks of at most `block` encoded bytes
    /// to a committee of at most `participants`. A custom [`Buffer`] implementation sizes its own
    /// payloads.
    ///
    /// Returns `None` if the size overflows, if `participants` is below the variant's smallest
    /// committee or above its largest, or if any committee size from its smallest up to
    /// `participants` cannot carry such a block.
    fn max_buffer_size(participants: usize, block: usize) -> Option<usize>;
}

/// A buffer for block storage and retrieval, abstracting over different
/// dissemination strategies.
///
/// The trait is generic over a [`Variant`] which provides the block, commitment,
/// and recipient types.
///
/// Lookup operations come in two forms:
/// - By digest: Simple lookup using only the block hash
/// - By commitment: Lookup using the full consensus commitment, which may enable
///   additional retrieval mechanisms depending on the variant
pub trait Buffer<V: Variant>: Clone + Send + Sync + 'static {
    /// The public key type used to identify peers.
    type PublicKey: PublicKey;

    /// Attempt to find a block by its digest.
    ///
    /// Returns `Some(block)` if the block is immediately available in the buffer,
    /// or `None` if it is not currently cached.
    ///
    /// This is a non-blocking lookup that does not trigger network fetches.
    fn find_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> impl Future<Output = Option<V::Block>> + Send;

    /// Attempt to find a block by its commitment.
    ///
    /// Returns `Some(block)` if the block is immediately available in the buffer,
    /// or `None` if it is not currently cached.
    ///
    /// This is a non-blocking lookup that does not trigger network fetches.
    /// Having the full commitment may enable additional retrieval mechanisms
    /// depending on the variant implementation.
    fn find_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> impl Future<Output = Option<V::Block>> + Send;

    /// Subscribe to a block's availability by its digest.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    /// Returns `None` when the buffer cannot provide availability notifications.
    ///
    /// Keep the subscription open while the block may still arrive. Close it only when the buffer
    /// shuts down or can no longer obtain the block from any source.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<V::Block>>;

    /// Subscribe to a block's availability by its commitment.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    /// Returns `None` when the buffer cannot provide availability notifications.
    ///
    /// Having the full commitment may enable additional retrieval mechanisms
    /// depending on the variant implementation.
    ///
    /// Keep the subscription open while the block may still arrive. Close it only when the buffer
    /// shuts down or can no longer obtain the block from any source.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> Option<oneshot::Receiver<V::Block>>;

    /// Send a block to peers.
    fn send(&self, round: Round, block: V::Block, recipients: Recipients<Self::PublicKey>);
}

/// A buffer implementation that never stores, subscribes, or sends blocks.
pub(super) struct NoBuffer<P> {
    _public_key: PhantomData<fn() -> P>,
}

impl<P> NoBuffer<P> {
    pub(super) const fn new() -> Self {
        Self {
            _public_key: PhantomData,
        }
    }
}

impl<P> Clone for NoBuffer<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for NoBuffer<P> {}

impl<V, P> Buffer<V> for NoBuffer<P>
where
    V: Variant,
    P: PublicKey,
{
    type PublicKey = P;

    async fn find_by_digest(&self, _: <V::Block as Digestible>::Digest) -> Option<V::Block> {
        None
    }

    async fn find_by_commitment(&self, _: V::Commitment) -> Option<V::Block> {
        None
    }

    fn subscribe_by_digest(
        &self,
        _: <V::Block as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<V::Block>> {
        None
    }

    fn subscribe_by_commitment(&self, _: V::Commitment) -> Option<oneshot::Receiver<V::Block>> {
        None
    }

    fn send(&self, _: Round, _: V::Block, _: Recipients<Self::PublicKey>) {}
}
