//! Core reshare [Application] implementation.

use crate::{
    application::{genesis_block, Block},
    dkg,
};
use commonware_consensus::{simplex::types::Context, Block as _, VerifyingApplication};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, Committable, Digestible, Hasher, Signer,
};
use commonware_runtime::{Clock, Metrics, Spawner};
use rand::Rng;
use std::{marker::PhantomData, time::Duration};

#[derive(Clone)]
pub struct Application<E, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    dkg: dkg::Mailbox<H, C, V>,
    _marker: PhantomData<E>,
}

impl<E, H, C, V> Application<E, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
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

impl<E, H, C, V> commonware_consensus::Application<E> for Application<E, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Block = Block<H, C, V>;
    type Context = Context<H::Digest, C::PublicKey>;

    async fn genesis(&mut self) -> Self::Block {
        genesis_block::<H, C, V>()
    }

    async fn build(
        &mut self,
        context: E,
        parent_commitment: <Self::Block as Committable>::Commitment,
        parent_block: Self::Block,
    ) -> Self::Block {
        // Ask the DKG actor for a result to include
        //
        // This approach does allow duplicate commitments to be proposed, but
        // the arbiter handles this by choosing the first commitment it sees
        // from any given dealer.
        let mut dkg_mailbox = self.dkg.clone();
        let reshare = context
            .timeout(
                Duration::from_millis(5),
                async move { dkg_mailbox.act().await },
            )
            .await
            .ok()
            .flatten();

        // Create a new block
        Block::new(parent_commitment, parent_block.height() + 1, reshare)
    }

    async fn finalize(&mut self, _: Self::Block) {
        // no-op: the reshare application does not process finalized blocks
    }
}

impl<E, H, C, V> VerifyingApplication<E> for Application<E, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    async fn verify(&mut self, _: E, parent: Self::Block, block: Self::Block) -> bool {
        block.height() == parent.height() + 1 && block.parent() == parent.digest()
    }
}
