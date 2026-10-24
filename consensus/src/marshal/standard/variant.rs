//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

use crate::{
    Block, Heightable,
    marshal::{
        ancestry::BlockProvider,
        core::{Buffer, CommitmentFallback, ExpectedCommitment, Mailbox, Variant},
    },
    simplex::scheme::Scheme as SimplexScheme,
    types::Round,
};
use commonware_broadcast::{Broadcaster as _, buffered};
use commonware_codec::{Codec, Error as CodecError, Input, Read};
use commonware_cryptography::{Digested, Digestible, PublicKey, certificate::Scheme};
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_utils::channel::oneshot;
use std::{future::Future, sync::Arc};

/// The standard variant of Marshal, which broadcasts complete blocks.
///
/// This variant sends the entire block to all peers.
#[derive(Default, Clone, Copy)]
pub struct Standard<B: Block + Codec>(std::marker::PhantomData<B>);

impl<B> Variant for Standard<B>
where
    B: Block + Codec,
{
    type ApplicationBlock = B;
    type Block = Digested<B>;
    type StoredBlock = Arc<B>;
    type Commitment = <B as Digestible>::Digest;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        // Standard variant commitment is exactly the block digest.
        block.digest()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        // Trivial left-inverse: digest == commitment in this variant.
        commitment
    }

    fn parent_commitment(block: &Self::Block) -> Self::Commitment {
        // In standard mode, commitments are digests, so parent commitment is parent digest.
        block.parent()
    }

    fn stored_parent_commitment(block: &Self::StoredBlock) -> Self::Commitment {
        block.parent()
    }

    fn check_payload<S>(_scheme: &S, _payload: Self::Commitment) -> bool
    where
        S: SimplexScheme<Self::Commitment>,
    {
        true
    }

    fn decode_block(
        buf: impl Input,
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        expected: ExpectedCommitment<Self::Commitment>,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Result<Self::Block, CodecError>> + Send {
        let (ExpectedCommitment::Trusted(digest) | ExpectedCommitment::Untrusted(digest)) =
            expected;
        let compute = B::decode_cfg(buf, block_cfg).map(|block| Digested::compute(block, strategy));
        async move {
            let block = compute?.await;
            if block.digest() != digest {
                return Err(CodecError::Invalid("Block", "digest mismatch"));
            }
            Ok(block)
        }
    }

    fn restore(
        stored: Self::StoredBlock,
        digest: <Self::Block as Digestible>::Digest,
    ) -> Self::Block {
        Digested::precomputed(stored, digest)
    }

    fn restore_across(
        stored: Self::StoredBlock,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Self::Block> + Send {
        Digested::compute(stored, strategy)
    }

    fn into_shared(block: Self::Block) -> Digested<Self::ApplicationBlock> {
        block
    }

    fn from_application_block(
        block: Digested<Self::ApplicationBlock>,
        payload: Self::Commitment,
    ) -> Self::Block {
        assert_eq!(block.digest(), payload, "payload does not commit to block");
        block
    }

    fn block_size(block: usize) -> Option<usize> {
        Some(block)
    }

    fn buffer_size(_participants: usize, block: usize) -> Option<usize> {
        // The buffer broadcasts each block whole
        Some(block)
    }
}

impl<B, K> Buffer<Standard<B>> for buffered::Mailbox<K, B>
where
    B: Block + Codec,
    K: PublicKey,
{
    type PublicKey = K;

    async fn find_by_digest(&self, digest: B::Digest) -> Option<Digested<B>> {
        self.get(digest).await
    }

    async fn find_by_commitment(&self, commitment: B::Digest) -> Option<Digested<B>> {
        self.find_by_digest(commitment).await
    }

    fn subscribe_by_digest(&self, digest: B::Digest) -> Option<oneshot::Receiver<Digested<B>>> {
        Some(self.subscribe(digest))
    }

    fn subscribe_by_commitment(
        &self,
        commitment: B::Digest,
    ) -> Option<oneshot::Receiver<Digested<B>>> {
        self.subscribe_by_digest(commitment)
    }

    fn send(&self, _round: Round, block: Digested<B>, recipients: Recipients<K>) {
        self.broadcast(recipients, block);
    }
}

impl<S, B> BlockProvider for Mailbox<S, Standard<B>>
where
    S: Scheme,
    B: Block + Codec,
{
    type Block = B;

    fn subscribe_parent(
        &self,
        block: &Digested<Self::Block>,
    ) -> impl Future<Output = Option<Digested<Self::Block>>> + Send + 'static {
        let receiver = block.height().previous().map(|parent_height| {
            self.subscribe_by_commitment(
                block.parent(),
                CommitmentFallback::FetchByCommitment {
                    height: parent_height,
                },
            )
        });
        async move { receiver?.await.ok() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{marshal::mocks::block::Block as MockBlock, types::Height};
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Digest as _, Hasher as _,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_parallel::Sequential;
    use futures::executor::block_on;

    type TestBlock = MockBlock<Sha256Digest, u64>;
    type TestVariant = Standard<TestBlock>;

    #[test]
    fn decode_block_binds_digest() {
        let block = TestBlock::new::<Sha256>(0, Sha256Digest::EMPTY, Height::new(1), 0);
        let encoded = block.encode();

        for expected in [
            ExpectedCommitment::Trusted(block.digest()),
            ExpectedCommitment::Untrusted(block.digest()),
        ] {
            let decoded = block_on(TestVariant::decode_block(
                encoded.clone(),
                &(),
                expected,
                &Sequential,
            ))
            .unwrap();
            assert_eq!(decoded.inner(), &block);
            assert_eq!(decoded.digest(), block.digest());
        }

        // A digest the bytes do not hash to is rejected, whether or not it is trusted.
        let other = Sha256::hash(&[b"other block"]);
        for expected in [
            ExpectedCommitment::Trusted(other),
            ExpectedCommitment::Untrusted(other),
        ] {
            assert!(
                block_on(TestVariant::decode_block(
                    encoded.clone(),
                    &(),
                    expected,
                    &Sequential
                ))
                .is_err()
            );
        }
    }
}
