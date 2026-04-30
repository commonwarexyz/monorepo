//! Core reshare [Application] implementation.

use crate::{
    application::{genesis_block, Block},
    dkg, BLOCKS_PER_EPOCH,
};
use commonware_consensus::{
    marshal::{
        ancestry::{AncestorStream, BlockProvider},
        core::Mailbox as MarshalMailbox,
        standard::Standard,
    },
    simplex::types::Context,
    types::{Epoch, Epocher, FixedEpocher, Round, View},
    Heightable, VerifyingApplication,
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, certificate::Scheme, Committable, Digest, Hasher,
    Signer,
};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::StreamExt;
use rand::Rng;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Application<E, S, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    dkg: dkg::Mailbox<H, C, V>,
    marshal: MarshalMailbox<S, Standard<Block<H, C, V>>>,
    _marker: PhantomData<(E, S)>,
}

impl<E, S, H, C, V> Application<E, S, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    pub const fn new(
        dkg: dkg::Mailbox<H, C, V>,
        marshal: MarshalMailbox<S, Standard<Block<H, C, V>>>,
    ) -> Self {
        Self {
            dkg,
            marshal,
            _marker: PhantomData,
        }
    }
}

impl<E, S, H, C, V> commonware_consensus::Application<E> for Application<E, S, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Context = Context<H::Digest, C::PublicKey>;
    type SigningScheme = S;
    type Block = Block<H, C, V>;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Block {
        if !epoch.is_zero() {
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            let previous = epoch
                .previous()
                .expect("nonzero epoch must have predecessor");
            let boundary_height = epocher
                .last(previous)
                .expect("epoch boundary height must be supported");
            return self
                .marshal
                .get_block(boundary_height)
                .await
                .expect("epoch boundary block must be available in marshal");
        }

        // Create a genesis context with the requested epoch, view 0, and empty parent.
        // Use a deterministic leader from seed 0 so all validators agree on genesis.
        let genesis_context = Context {
            round: Round::new(epoch, View::zero()),
            leader: C::from_seed(0).public_key(),
            parent: (View::zero(), <H::Digest as Digest>::EMPTY),
        };
        genesis_block::<H, C, V>(genesis_context)
    }

    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        (_, context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
    ) -> Option<Self::Block> {
        // Fetch the parent block from the ancestry stream.
        let parent_block = ancestry.next().await?;
        let parent_commitment = parent_block.commitment();

        // Ask the DKG actor for a result to include
        //
        // This approach does allow duplicate commitments to be proposed, but
        // the arbiter handles this by choosing the first commitment it sees
        // from any given dealer.
        let reshare = self.dkg.act().await;

        // Create a new block with the consensus context
        Some(Block::new(
            context,
            parent_commitment,
            parent_block.height().next(),
            reshare,
        ))
    }
}

impl<E, S, H, C, V> VerifyingApplication<E> for Application<E, S, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _: (E, Self::Context),
        _: AncestorStream<A, Self::Block>,
    ) -> bool {
        // We wrap this application with `Marshaled`, which handles ancestry
        // verification (parent commitment and height contiguity).
        //
        // You could opt to verify the deal_outcome in the block here (both that it is valid
        // and that the dealer is the proposer) but we opt to only process deal data after the
        // block has been finalized to keep verification as fast as possible. The downside
        // of this approach is that invalid data can be included in the canonical chain (which
        // makes certificates over finalized blocks less useful because the verifier must still
        // check the block contents).
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{EdScheme, Provider};
    use commonware_consensus::{
        marshal::{
            self,
            core::{Actor as MarshalActor, Buffer},
            resolver::handler,
        },
        simplex::types::Finalization,
        types::{Height, ViewDelta},
        Application as ConsensusApplication, Reporter,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig,
        certificate::Scheme as CertificateScheme,
        ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
        Digest, Digestible, Signer,
    };
    use commonware_p2p::Recipients;
    use commonware_parallel::Sequential;
    use commonware_resolver::Resolver;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        channel::{mpsc, oneshot},
        vec::NonEmptyVec,
        NZUsize, NZU16, NZU32, NZU64,
    };
    use std::{num::NonZeroU16, time::Duration};

    type TestBlock = Block<Sha256, ed25519::PrivateKey, MinSig>;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1_024);

    #[derive(Clone)]
    struct NoopBuffer;

    impl Buffer<Standard<TestBlock>> for NoopBuffer {
        type PublicKey = ed25519::PublicKey;
        type CachedBlock = TestBlock;

        async fn find_by_digest(&self, _digest: Sha256Digest) -> Option<Self::CachedBlock> {
            None
        }

        async fn find_by_commitment(&self, _commitment: Sha256Digest) -> Option<Self::CachedBlock> {
            None
        }

        async fn subscribe_by_digest(
            &self,
            _digest: Sha256Digest,
        ) -> oneshot::Receiver<Self::CachedBlock> {
            let (_tx, rx) = oneshot::channel();
            rx
        }

        async fn subscribe_by_commitment(
            &self,
            _commitment: Sha256Digest,
        ) -> oneshot::Receiver<Self::CachedBlock> {
            let (_tx, rx) = oneshot::channel();
            rx
        }

        async fn finalized(&self, _commitment: Sha256Digest) {}

        async fn send(
            &self,
            _round: Round,
            _block: TestBlock,
            _recipients: Recipients<Self::PublicKey>,
        ) {
        }
    }

    #[derive(Clone)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        type Key = handler::Request<Sha256Digest>;
        type PublicKey = ed25519::PublicKey;

        async fn fetch(&mut self, _key: Self::Key) {}

        async fn fetch_all(&mut self, _keys: Vec<Self::Key>) {}

        async fn fetch_targeted(
            &mut self,
            _key: Self::Key,
            _targets: NonEmptyVec<Self::PublicKey>,
        ) {
        }

        async fn fetch_all_targeted(
            &mut self,
            _requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
        ) {
        }

        async fn cancel(&mut self, _key: Self::Key) {}

        async fn clear(&mut self) {}

        async fn retain(&mut self, _predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {}
    }

    #[derive(Clone)]
    struct NoopReporter;

    impl Reporter for NoopReporter {
        type Activity = marshal::Update<TestBlock>;

        async fn report(&mut self, _activity: Self::Activity) {}
    }

    fn archive_config<C>(
        prefix: &str,
        page_cache: CacheRef,
        codec_config: C,
    ) -> immutable::Config<C> {
        immutable::Config {
            metadata_partition: format!("{prefix}-metadata"),
            freezer_table_partition: format!("{prefix}-freezer-table"),
            freezer_table_initial_size: 16,
            freezer_table_resize_frequency: 4,
            freezer_table_resize_chunk_size: 4,
            freezer_key_partition: format!("{prefix}-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{prefix}-freezer-value"),
            freezer_value_target_size: 1_024 * 1_024,
            freezer_value_compression: None,
            ordinal_partition: format!("{prefix}-ordinal"),
            items_per_section: NZU64!(16),
            codec_config,
            replay_buffer: NZUsize!(1_024),
            freezer_key_write_buffer: NZUsize!(1_024),
            freezer_value_write_buffer: NZUsize!(1_024),
            ordinal_write_buffer: NZUsize!(1_024),
        }
    }

    #[test]
    fn genesis_for_nonzero_epoch_returns_boundary_block_from_marshal() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(16));
            let finalizations_by_height: immutable::Archive<
                _,
                Sha256Digest,
                Finalization<EdScheme, Sha256Digest>,
            > = immutable::Archive::init(
                context.with_label("finalizations_by_height"),
                archive_config(
                    "finalizations-by-height",
                    page_cache.clone(),
                    EdScheme::certificate_codec_config_unbounded(),
                ),
            )
            .await
            .expect("failed to init finalizations archive");
            let finalized_blocks: immutable::Archive<_, Sha256Digest, TestBlock> =
                immutable::Archive::init(
                    context.with_label("finalized_blocks"),
                    archive_config("finalized-blocks", page_cache.clone(), NZU32!(1)),
                )
                .await
                .expect("failed to init blocks archive");

            let signer = ed25519::PrivateKey::from_seed(1);
            let provider = Provider::<EdScheme, ed25519::PrivateKey>::new(
                b"test".to_vec(),
                signer.clone(),
                None,
            );
            let (marshal_actor, marshal, _) = MarshalActor::init(
                context.with_label("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                    partition_prefix: "test-marshal".to_string(),
                    mailbox_size: 16,
                    view_retention_timeout: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(16),
                    page_cache,
                    replay_buffer: NZUsize!(1_024),
                    key_write_buffer: NZUsize!(1_024),
                    value_write_buffer: NZUsize!(1_024),
                    block_codec_config: NZU32!(1),
                    max_repair: NZUsize!(4),
                    max_pending_acks: NZUsize!(4),
                    strategy: Sequential,
                },
            )
            .await;
            let (_resolver_tx, resolver_rx) = mpsc::channel(16);
            let marshal_handle =
                marshal_actor.start(NoopReporter, NoopBuffer, (resolver_rx, NoopResolver));

            let epoch = Epoch::new(1);
            let boundary_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(epoch.previous().unwrap())
                .unwrap();
            let genesis_context = Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader: signer.public_key(),
                parent: (View::zero(), <Sha256Digest as Digest>::EMPTY),
            };
            let genesis = genesis_block::<Sha256, ed25519::PrivateKey, MinSig>(genesis_context);
            let boundary_context = Context {
                round: Round::new(Epoch::zero(), View::new(boundary_height.get())),
                leader: signer.public_key(),
                parent: (View::zero(), genesis.digest()),
            };
            let boundary =
                TestBlock::new(boundary_context, genesis.digest(), boundary_height, None);
            let boundary_digest = boundary.digest();
            marshal.set_floor(boundary).await;
            assert_eq!(
                marshal
                    .get_block(boundary_height)
                    .await
                    .expect("boundary must be in marshal")
                    .digest(),
                boundary_digest
            );

            let (dkg_sender, _dkg_receiver) = mpsc::channel(1);
            let mut application = Application::<
                deterministic::Context,
                EdScheme,
                Sha256,
                ed25519::PrivateKey,
                MinSig,
            >::new(dkg::Mailbox::new(dkg_sender), marshal.clone());

            let epoch_zero: TestBlock =
                ConsensusApplication::genesis(&mut application, Epoch::zero()).await;
            assert_eq!(epoch_zero.height(), Height::zero());

            let epoch_one: TestBlock = ConsensusApplication::genesis(&mut application, epoch).await;
            assert_eq!(epoch_one.height(), boundary_height);
            assert_eq!(epoch_one.digest(), boundary_digest);

            marshal_handle.abort();
        });
    }
}
