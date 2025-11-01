//! Core reshare [Application] implementation.

use crate::{
    application::{genesis_block, Block},
    dkg,
};
use commonware_consensus::{
    marshal::ingress::mailbox::AncestorStream,
    simplex::{signing_scheme::Scheme, types::Context},
    Block as _, VerifyingApplication,
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, Committable, Digestible, Hasher, Signer,
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
    pub fn new(dkg: dkg::Mailbox<H, C, V>) -> Self {
        Self {
            dkg,
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
    type Block = Block<H, C, V>;
    type SigningScheme = S;
    type Context = Context<H::Digest, C::PublicKey>;

    async fn genesis(&mut self) -> Self::Block {
        genesis_block::<H, C, V>()
    }

    async fn build(
        &mut self,
        _r_context: E,
        _context: Self::Context,
        mut ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
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

        // Create a new block
        Some(Block::new(
            parent_commitment,
            parent_block.height() + 1,
            reshare,
        ))
    }

    async fn finalize(&mut self, _: Self::Block) {
        // no-op: the reshare application does not process finalized blocks
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
    async fn verify(&mut self, _: E, parent: Self::Block, block: Self::Block) -> bool {
        block.height() == parent.height() + 1 && block.parent() == parent.digest()
    }
}
