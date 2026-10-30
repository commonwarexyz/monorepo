use crate::{
    CertifiableBlock, Heightable,
    marshal::{
        ancestry::BlockProvider,
        coding::{
            shards,
            types::{CodedBlock, Shard, StoredCodedBlock, coding_config_for_participants},
        },
        core::{Buffer, CommitmentFallback, ExpectedCommitment, Mailbox, Variant},
    },
    simplex::{scheme::Scheme as SimplexScheme, types::Context},
    types::{Round, coding::Commitment},
};
use commonware_codec::{Codec, Decode as _, Error as CodecError, Input, Read};
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{
    Committable, Digested, Digestible, Hasher, PublicKey, certificate::Scheme,
};
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_utils::channel::oneshot;
use std::{future::Future, sync::Arc};

/// The coding variant of Marshal, which uses erasure coding for block dissemination.
///
/// This variant distributes blocks as erasure-coded shards, allowing reconstruction
/// from a subset of shards. This reduces bandwidth requirements for block propagation.
pub struct Coding<B, C, H, P>(std::marker::PhantomData<(B, C, H, P)>);

impl<B, C, H, P> Clone for Coding<B, C, H, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B, C, H, P> Copy for Coding<B, C, H, P> {}

impl<B, C, H, P> Variant for Coding<B, C, H, P>
where
    B: CertifiableBlock<Context = Context<Commitment<B, C, H>, P>> + Codec,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type ApplicationBlock = B;
    type Block = Arc<CodedBlock<B, C, H>>;
    type StoredBlock = StoredCodedBlock<B, C, H>;
    type Commitment = Commitment<B, C, H>;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        block.commitment()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        // The inner digest is embedded in the coding commitment.
        commitment.block()
    }

    fn parent_commitment(block: &Self::Block) -> Self::Commitment {
        // Parent commitment is embedded in the consensus context.
        block.context().parent.1
    }

    fn stored_parent_commitment(block: &Self::StoredBlock) -> Self::Commitment {
        block.context().parent.1
    }

    fn check_payload<S>(scheme: &S, payload: Self::Commitment) -> bool
    where
        S: SimplexScheme<Self::Commitment>,
    {
        let n_participants = u16::try_from(scheme.participants().len())
            .expect("scheme must have at most 2^16-1 participants");
        payload.config() == coding_config_for_participants(n_participants)
    }

    fn decode_block(
        buf: impl Input,
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        expected: ExpectedCommitment<Self::Commitment>,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Result<Self::Block, CodecError>> + Send {
        let decoded = <(B, CodingConfig)>::decode_cfg(buf, &(block_cfg.clone(), ()))
            .map(|(inner, config)| CodedBlock::from_decoded(inner, config, expected, strategy));
        async move { decoded?.await.map(Arc::new) }
    }

    fn restore(
        stored: Self::StoredBlock,
        digest: <Self::Block as Digestible>::Digest,
    ) -> Self::Block {
        assert_eq!(
            stored.digest(),
            digest,
            "stored block was keyed by another digest"
        );
        stored.into()
    }

    fn restore_across(
        stored: Self::StoredBlock,
        _strategy: &impl Strategy,
    ) -> impl Future<Output = Self::Block> + Send {
        // The stored commitment carries the block's identity, so nothing is computed.
        std::future::ready(stored.into())
    }

    fn into_shared(block: Self::Block) -> Digested<Self::ApplicationBlock> {
        block.inner_digested()
    }

    fn from_application_block(
        block: Digested<Self::ApplicationBlock>,
        payload: Self::Commitment,
    ) -> Self::Block {
        Arc::new(CodedBlock::precomputed(block, payload))
    }

    fn max_backfill_block_size(application: usize) -> usize {
        CodedBlock::<B, C, H>::max_encode_size(application)
    }

    /// Returns an upper bound on the encoded size of any shard a committee of 4 to `participants`
    /// members codes from a block of at most `application` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `participants` is below 4 or above `u16::MAX`.
    fn max_buffer_payload_size(participants: u32, application: usize) -> usize {
        // The shards engine sends shards coded from the block with its coding configuration.
        let block = CodedBlock::<B, C, H>::max_encode_size(application);

        // A larger committee can split a block into more data shards or prove each shard with a
        // deeper tree, so shard width can shrink or grow with the committee. Coding supports
        // committees of at least 4, so take the widest over every size from 4 to `participants`.
        let participants =
            u16::try_from(participants).expect("committee must have at most u16::MAX members");
        let widest = (4..=participants)
            .map(|n| C::max_shard_size(&coding_config_for_participants(n), block))
            .max()
            .expect("committee must have at least 4 members");

        Shard::<B, C, H>::max_encode_size(widest)
    }
}

impl<B, C, H, P> Buffer<Coding<B, C, H, P>> for shards::Mailbox<B, C, H, P>
where
    B: CertifiableBlock<Context = Context<Commitment<B, C, H>, P>> + Codec,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type PublicKey = P;

    async fn find_by_digest(
        &self,
        digest: <CodedBlock<B, C, H> as Digestible>::Digest,
    ) -> Option<Arc<CodedBlock<B, C, H>>> {
        self.get_by_digest(digest).await
    }

    async fn find_by_commitment(
        &self,
        commitment: Commitment<B, C, H>,
    ) -> Option<Arc<CodedBlock<B, C, H>>> {
        self.get(commitment).await
    }

    fn subscribe_by_digest(
        &self,
        digest: <CodedBlock<B, C, H> as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<Arc<CodedBlock<B, C, H>>>> {
        Some(self.subscribe_by_digest(digest))
    }

    fn subscribe_by_commitment(
        &self,
        commitment: Commitment<B, C, H>,
    ) -> Option<oneshot::Receiver<Arc<CodedBlock<B, C, H>>>> {
        Some(self.subscribe(commitment))
    }

    fn send(&self, round: Round, block: Arc<CodedBlock<B, C, H>>, _recipients: Recipients<P>) {
        // Targeted forwarding is not supported by the coding variant.
        self.proposed_shared(round, block);
    }
}

impl<S, B, C, H, P> BlockProvider for Mailbox<S, Coding<B, C, H, P>>
where
    S: Scheme,
    B: CertifiableBlock<Context = Context<Commitment<B, C, H>, P>> + Codec,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type Block = B;

    fn subscribe_parent(
        &self,
        block: &Digested<Self::Block>,
    ) -> impl Future<Output = Option<Digested<Self::Block>>> + Send + 'static {
        let receiver = block.height().previous().map(|parent_height| {
            self.subscribe_by_commitment(
                block.context().parent.1,
                CommitmentFallback::FetchByCommitment {
                    height: parent_height,
                },
            )
        });
        async move { receiver?.await.ok().map(|block| block.inner_digested()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{
            coding::types::StoredCodedBlock,
            mocks::block::{Block, encode_block},
        },
        types::{Epoch, Height, View},
    };
    use bytes::BufMut;
    use commonware_codec::{Buf, Encode, EncodeSize, Error, Read, Write};
    use commonware_coding::{Config as CodingConfig, ReedSolomon};
    use commonware_cryptography::{
        Digest as _, Digestible, Signer as _,
        ed25519::{PrivateKey, PublicKey},
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::{Sequential, mocks::explore};
    use commonware_utils::{NZU16, test_rng};
    use futures::executor::block_on;

    type TestCommitment = Commitment<NoCloneBlock, ReedSolomon<Sha256>, Sha256>;
    type TestContext = Context<TestCommitment, PublicKey>;
    type InnerBlock = Block<Sha256Digest, TestContext>;
    type TestScheme = ReedSolomon<Sha256>;
    type TestVariant = Coding<NoCloneBlock, TestScheme, Sha256, PublicKey>;

    /// Coding configuration for the coded blocks built by these tests.
    const CONFIG: CodingConfig = CodingConfig {
        minimum_shards: NZU16!(1),
        extra_shards: NZU16!(2),
    };

    struct NoCloneBlock {
        inner: InnerBlock,
    }

    impl Clone for NoCloneBlock {
        fn clone(&self) -> Self {
            panic!("shared block operations must not clone the inner block");
        }
    }

    impl Write for NoCloneBlock {
        fn write(&self, writer: &mut impl BufMut) {
            self.inner.write(writer);
        }
    }

    impl Read for NoCloneBlock {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
            Ok(Self {
                inner: InnerBlock::read_cfg(reader, cfg)?,
            })
        }
    }

    impl EncodeSize for NoCloneBlock {
        fn encode_size(&self) -> usize {
            self.inner.encode_size()
        }
    }

    impl Digestible for NoCloneBlock {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            self.inner.digest()
        }
    }

    impl crate::Heightable for NoCloneBlock {
        fn height(&self) -> Height {
            self.inner.height
        }
    }

    impl crate::Block for NoCloneBlock {
        fn parent(&self) -> Self::Digest {
            self.inner.parent
        }
    }

    impl CertifiableBlock for NoCloneBlock {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.inner.context.clone()
        }
    }

    fn no_clone_block(config: CodingConfig) -> NoCloneBlock {
        let mut rng = test_rng();
        let leader = PrivateKey::random(&mut rng).public_key();
        let parent_commitment = TestCommitment::from((
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            config,
        ));
        let context = Context {
            round: Round::new(Epoch::new(1), View::new(2)),
            leader,
            parent: (View::new(1), parent_commitment),
        };
        let inner = InnerBlock::new::<Sha256>(
            context,
            Sha256::hash(&[b"parent"]),
            Height::new(7),
            1_234_567,
        );
        NoCloneBlock { inner }
    }

    #[test]
    fn max_backfill_block_size_matches_encoding() {
        // Encoding the block with its coding configuration yields what `max_backfill_block_size`
        // reports.
        let block = no_clone_block(CONFIG);
        let size = block.encode_size();
        let coded = encode_block::<NoCloneBlock, TestScheme, Sha256>(block, CONFIG);
        assert_eq!(
            TestVariant::max_backfill_block_size(size),
            coded.encode().len()
        );
    }

    #[test]
    fn storage_conversion_shares_coding_block() {
        let block = no_clone_block(CONFIG);
        let coded = Arc::new(encode_block::<NoCloneBlock, TestScheme, Sha256>(
            block, CONFIG,
        ));
        let expected = coded.commitment();
        let stored: StoredCodedBlock<_, _, _> = coded.clone().into();

        assert_eq!(stored.commitment(), expected);
        assert!(std::ptr::eq(stored.inner(), coded.inner()));

        let recovered = stored.into();
        assert_eq!(TestVariant::commitment(&recovered), expected);
        assert!(Arc::ptr_eq(
            &TestVariant::into_shared(recovered).inner_shared(),
            &coded.inner_shared()
        ));
    }

    #[test]
    fn decode_block_recomputes_untrusted_root() {
        let block = no_clone_block(CONFIG);
        let coded = encode_block::<NoCloneBlock, TestScheme, Sha256>(block, CONFIG);
        let expected = coded.commitment();
        let encoded = coded.encode();
        explore(|strategy| {
            // An untrusted commitment is recomputed, so the decoded block already holds its shards.
            let decoded = block_on(TestVariant::decode_block(
                encoded.clone(),
                &(),
                ExpectedCommitment::Untrusted(expected),
                strategy,
            ))
            .unwrap();
            assert_eq!(TestVariant::commitment(&decoded), expected);
            assert!(decoded.shard(0).is_some());

            // A root that does not encode the block is rejected unless it is trusted.
            let other = TestCommitment::from((
                expected.block(),
                Sha256::hash(&[b"other root"]),
                expected.context(),
                CONFIG,
            ));
            assert!(
                block_on(TestVariant::decode_block(
                    encoded.clone(),
                    &(),
                    ExpectedCommitment::Untrusted(other),
                    strategy,
                ))
                .is_err()
            );
            let trusted = block_on(TestVariant::decode_block(
                encoded.clone(),
                &(),
                ExpectedCommitment::Trusted(other),
                strategy,
            ))
            .unwrap();
            assert_eq!(TestVariant::commitment(&trusted), other);
            assert!(trusted.shard(0).is_none());

            // Bytes after the block are rejected.
            let mut extended = encoded.to_vec();
            extended.push(0);
            assert!(
                block_on(TestVariant::decode_block(
                    extended,
                    &(),
                    ExpectedCommitment::Untrusted(expected),
                    strategy,
                ))
                .is_err()
            );

            // Every shape must decode to the same commitments.
            (
                TestVariant::commitment(&decoded),
                TestVariant::commitment(&trusted),
            )
        });
    }

    #[test]
    fn decode_block_binds_context_digest() {
        let block = no_clone_block(CONFIG);
        let coded = encode_block::<NoCloneBlock, TestScheme, Sha256>(block, CONFIG);
        let expected = coded.commitment();
        let encoded = coded.encode();

        // Only the context digest differs, which only the full-commitment comparison can see.
        let other = TestCommitment::from((
            expected.block(),
            expected.root(),
            Sha256::hash(&[b"other context"]),
            CONFIG,
        ));
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
