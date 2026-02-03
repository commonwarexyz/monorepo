//! Marshal variant and buffer traits.
//!
//! This module defines the core abstractions for unifying the standard and coding
//! marshal implementations:
//!
//! - [`Variant`]: Describes the types used by a marshal variant (standard vs coding)
//! - [`BlockBuffer`]: Abstracts over block dissemination strategies (whole blocks vs shards)

#![allow(dead_code)]

use crate::Block;
use commonware_codec::{Codec, Read};
use commonware_cryptography::{Committable, Digest, Digestible};
use commonware_utils::channel::oneshot;
use std::future::Future;

/// A marker trait describing the types used by a variant of Marshal.
pub trait Variant: Clone + Send + Sync + 'static {
    /// The application block type.
    type ApplicationBlock: Block + Clone;

    /// The working block type of marshal, supporting the consensus commitment.
    type Block: Block<Digest = <Self::ApplicationBlock as Digestible>::Digest>
        + Committable<Commitment = Self::Commitment>
        + Clone;

    /// The type of block stored in the archive.
    type StoredBlock: Block<Digest = <Self::Block as Digestible>::Digest>
        + Clone
        + Codec<Cfg = <Self::Block as Read>::Cfg>;

    /// The [`Digest`] type used by consensus.
    type Commitment: Digest;

    /// The type used for broadcast recipients.
    ///
    /// - Standard: `()` (broadcasts to all peers via the underlying network)
    /// - Coding: `Vec<P>` (specific peers for shard distribution)
    type Recipients: Send;

    /// Extracts the block digest from a consensus commitment.
    fn commitment_to_digest(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest;

    /// Converts a working block to an application block.
    fn unwrap_working(block: Self::Block) -> Self::ApplicationBlock;

    /// Converts an application block to a storage block.
    fn wrap_stored(stored: Self::Block) -> Self::StoredBlock;

    /// Converts a stored block to the application block type.
    fn unwrap_stored(stored: Self::StoredBlock) -> Self::Block;
}

/// A buffer for block storage and retrieval, abstracting over different
/// dissemination strategies.
///
/// This trait unifies the interfaces of:
/// - `buffered::Mailbox` (standard): Broadcasts and caches whole blocks
/// - `shards::Mailbox` (coding): Distributes erasure-coded shards and reconstructs blocks
///
/// The trait is generic over a [`Variant`] which provides the block, commitment,
/// and recipient types.
///
/// Lookup operations come in two forms:
/// - By digest: Simple lookup, no shard reconstruction possible
/// - By commitment: In coding mode, enables shard reconstruction
pub trait BlockBuffer<V: Variant>: Clone + Send + Sync + 'static {
    /// The cached block type held internally by the buffer.
    ///
    /// This allows buffers to use efficient internal representations (e.g., `Arc<Block>`)
    /// while exposing the block via `AsRef`.
    ///
    /// - Standard: `V::Block` (no wrapper needed)
    /// - Coding: `Arc<CodedBlock<B, C>>` for efficient sharing
    type CachedBlock: AsRef<V::Block> + Clone + Send;

    /// Attempt to find a block by its digest.
    ///
    /// Returns `Some(block)` if the block is immediately available in the buffer,
    /// or `None` if it is not currently cached.
    ///
    /// This is a non-blocking lookup that does not trigger network fetches.
    /// In coding mode, this does NOT attempt shard reconstruction since we
    /// don't have the full commitment needed for reconstruction.
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
    /// In coding mode, this MAY attempt shard reconstruction since we have
    /// the full commitment needed for reconstruction.
    ///
    /// In standard mode, commitment equals digest, so this behaves the same
    /// as [`Self::find_by_digest`].
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
    /// In coding mode, having the commitment enables shard reconstruction
    /// to satisfy the subscription.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_commitment(
        &mut self,
        commitment: V::Commitment,
    ) -> impl Future<Output = oneshot::Receiver<Self::CachedBlock>> + Send;

    /// Notify the buffer that a block has been finalized.
    ///
    /// This allows the buffer to perform cleanup operations:
    /// - Standard: No-op (cleanup handled elsewhere)
    /// - Coding: Releases shard storage for the finalized block
    fn finalized(&mut self, commitment: V::Commitment) -> impl Future<Output = ()> + Send;

    /// Broadcast a proposed block to peers.
    ///
    /// This handles the initial dissemination of a newly proposed block:
    /// - Standard: Broadcasts the complete block to all peers (recipients is `()`)
    /// - Coding: Distributes erasure-coded shards to assigned peers (recipients is `Vec<P>`)
    fn broadcast(
        &mut self,
        block: V::Block,
        recipients: V::Recipients,
    ) -> impl Future<Output = ()> + Send;
}
