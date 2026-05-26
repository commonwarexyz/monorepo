//! Variant-agnostic adapter for publishing a block through the variant's
//! local cache (buffered broadcast engine for Standard, shards engine
//! for Coding).
//!
//! The driver calls `publish_via_variant` then
//! [`VariantPublish::locally_available`] to confirm the publish landed
//! before treating the block as locally provided. Both backing engines
//! cache locally-sent messages, so single-validator publication still
//! makes the block discoverable through marshal's variant integration.

use commonware_broadcast::{buffered, Broadcaster as _};
use commonware_codec::Codec;
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::{
    marshal::coding::{shards, types::CodedBlock},
    types::Round,
    CertifiableBlock,
};
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_p2p::Recipients;

/// Adapter trait the marshal fuzz driver calls to push a block into the
/// variant's local cache and verify it is now retrievable. Implemented
/// for `buffered::Mailbox` (standard variant) and `shards::Mailbox`
/// (coding variant).
pub trait VariantPublish<Block: Clone + Send + 'static>: Sync {
    /// Best-effort publish. The implementation may silently drop the
    /// request if the underlying mailbox enqueue fails; the driver
    /// confirms availability via [`Self::locally_available`] before
    /// counting the publish.
    fn publish_via_variant(&self, round: Round, block: &Block);

    /// Whether the variant's local cache currently holds the block.
    /// Used after [`Self::publish_via_variant`] to verify the publish
    /// was accepted before the driver treats the block as provided.
    fn locally_available(&self, block: &Block) -> impl std::future::Future<Output = bool> + Send;
}

impl<P, M> VariantPublish<M> for buffered::Mailbox<P, M>
where
    P: PublicKey,
    M: Codec + Digestible + Clone + Send + 'static,
{
    fn publish_via_variant(&self, _round: Round, block: &M) {
        let _ = self.broadcast(Recipients::All, block.clone());
    }

    async fn locally_available(&self, block: &M) -> bool {
        self.get(block.digest()).await.is_some()
    }
}

impl<B, C, H, P> VariantPublish<CodedBlock<B, C, H>> for shards::Mailbox<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    fn publish_via_variant(&self, round: Round, block: &CodedBlock<B, C, H>) {
        self.proposed(round, block.clone());
    }

    async fn locally_available(&self, block: &CodedBlock<B, C, H>) -> bool {
        self.get(block.commitment()).await.is_some()
    }
}
