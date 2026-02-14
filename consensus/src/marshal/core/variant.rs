//! Marshal variant and buffer traits.
//!
//! This module defines the core abstractions that allow the marshal actor to work
//! with different block dissemination strategies:
//!
//! - [`Variant`]: Describes the types used by a marshal variant
//! - [`BlockBuffer`]: Abstracts over block dissemination strategies

use crate::{types::Round, CertifiableBlock};
use commonware_codec::{Codec, Read};
use commonware_cryptography::{Digest, Digestible};
use commonware_utils::channel::oneshot;
use std::{future::Future, sync::Arc};

/// A marker trait describing the types used by a variant of Marshal.
pub trait Variant: Clone + Send + Sync + 'static {
    /// The working block type of marshal, supporting the consensus commitment.
    ///
    /// Must be convertible to `StoredBlock` via `Into` for archival.
    type Block: CertifiableBlock<Digest = <Self::ApplicationBlock as Digestible>::Digest>
        + Into<Self::StoredBlock>
        + Clone;

    /// The application block type.
    type ApplicationBlock: CertifiableBlock + Clone;

    /// The type of block stored in the archive.
    ///
    /// Must be convertible back to the working block type via `Into`.
    type StoredBlock: CertifiableBlock<Digest = <Self::Block as Digestible>::Digest>
        + Into<Self::Block>
        + Clone
        + Codec<Cfg = <Self::Block as Read>::Cfg>;

    /// The [`Digest`] type used by consensus.
    type Commitment: Digest;

    /// Computes the consensus commitment for a block.
    ///
    /// The commitment is what validators sign over during consensus.
    fn commitment(block: &Self::Block) -> Self::Commitment;

    /// Extracts the block digest from a consensus commitment.
    fn commitment_to_application(
        commitment: Self::Commitment,
    ) -> <Self::Block as Digestible>::Digest;

    /// Converts a working block to an application block.
    ///
    /// This conversion cannot use `Into` due to orphan rules when `Block` wraps
    /// `ApplicationBlock` (e.g., `CodedBlock<B, C> -> B`).
    fn into_application_block(block: Self::Block) -> Self::ApplicationBlock;
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
pub trait BlockBuffer<V: Variant>: Clone + Send + Sync + 'static {
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
        &mut self,
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
        &mut self,
        commitment: V::Commitment,
    ) -> impl Future<Output = Option<Self::CachedBlock>> + Send;

    /// Subscribe to a block's availability by its digest.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_digest(
        &mut self,
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
        &mut self,
        commitment: V::Commitment,
    ) -> impl Future<Output = oneshot::Receiver<Self::CachedBlock>> + Send;

    /// Notify the buffer that a block has been finalized.
    ///
    /// This allows the buffer to perform variant-specific cleanup operations.
    fn finalized(&mut self, commitment: V::Commitment) -> impl Future<Output = ()> + Send;

    /// Broadcast a proposed block to peers.
    ///
    /// This handles the initial dissemination of a newly proposed block.
    fn proposed(&mut self, round: Round, block: V::Block) -> impl Future<Output = ()> + Send;
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
