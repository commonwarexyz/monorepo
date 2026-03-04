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

use crate::{types::Round, Block};
use commonware_codec::{Codec, Read};
use commonware_cryptography::{Digest, Digestible};
use commonware_utils::channel::oneshot;
use std::{future::Future, sync::Arc};

/// A marker trait describing the types used by a variant of Marshal.
pub trait Variant: Clone + Send + Sync + 'static {
    /// The working block type of marshal, supporting the consensus commitment.
    ///
    /// Must be convertible to `StoredBlock` via `Into` for archival.
    type Block: Block<Digest = <Self::ApplicationBlock as Digestible>::Digest>
        + Into<Self::StoredBlock>
        + Clone;

    /// The application block type.
    type ApplicationBlock: Block + Clone;

    /// The type of block stored in the archive.
    ///
    /// Must be convertible back to the working block type via `Into`.
    type StoredBlock: Block<Digest = <Self::Block as Digestible>::Digest>
        + Into<Self::Block>
        + Clone
        + Codec<Cfg = <Self::Block as Read>::Cfg>;

    /// The [`Digest`] type used by consensus.
    type Commitment: Digest;

    /// Computes the consensus commitment for a block.
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

    /// Converts a working block to an application block.
    ///
    /// This conversion cannot use `Into` due to orphan rules when `Block` wraps
    /// `ApplicationBlock` (e.g., `CodedBlock<B, C, H> -> B`).
    fn into_inner(block: Self::Block) -> Self::ApplicationBlock;
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
    /// The cached block type held internally by the buffer.
    ///
    /// This allows buffers to use efficient internal representations (e.g., `Arc<Block>`)
    /// while providing conversion to the underlying block type via [`IntoBlock`].
    type CachedBlock: IntoBlock<V::Block>;

    /// Attempt to find a block by its digest.
    ///
    /// Returns `Some(block)` if the block is immediately available in the buffer,
    /// or `None` if it is not currently cached.
    ///
    /// This is a non-blocking lookup that does not trigger network fetches.
    fn find_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> impl Future<Output = Option<Self::CachedBlock>> + Send;

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
    ) -> impl Future<Output = Option<Self::CachedBlock>> + Send;

    /// Subscribe to a block's availability by its digest.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> impl Future<Output = oneshot::Receiver<Self::CachedBlock>> + Send;

    /// Subscribe to a block's availability by its commitment.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    ///
    /// Having the full commitment may enable additional retrieval mechanisms
    /// depending on the variant implementation.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> impl Future<Output = oneshot::Receiver<Self::CachedBlock>> + Send;

    /// Notify the buffer that a block has been finalized.
    ///
    /// This allows the buffer to perform variant-specific cleanup operations.
    fn finalized(&self, commitment: V::Commitment) -> impl Future<Output = ()> + Send;

    /// Broadcast a proposed block to peers.
    ///
    /// This handles the initial dissemination of a newly proposed block.
    fn proposed(&self, round: Round, block: V::Block) -> impl Future<Output = ()> + Send;
}

/// A trait for cached block types that can be converted to the underlying block.
///
/// This trait allows buffer implementations to use efficient internal representations
/// (e.g., `Arc<Block>`) while providing a uniform way to extract the block.
pub trait IntoBlock<B>: Clone + Send {
    /// Convert this cached block into the underlying block type.
    fn into_block(self) -> B;
}

/// Blanket implementation for any cloneable block type.
///
/// This covers the standard variant where `CachedBlock = B`.
impl<B: Clone + Send> IntoBlock<B> for B {
    fn into_block(self) -> B {
        self
    }
}

/// Implementation for `Arc<B>` to support the coding variant.
///
/// Uses `Arc::unwrap_or_clone` to avoid cloning when the refcount is 1.
impl<B: Clone + Send + Sync> IntoBlock<B> for Arc<B> {
    fn into_block(self) -> B {
        Self::unwrap_or_clone(self)
    }
}
