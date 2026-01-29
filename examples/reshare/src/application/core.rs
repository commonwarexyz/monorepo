//! Core reshare [Application] implementation.

use crate::{
    application::{genesis_block, Block},
    dkg,
};
use commonware_consensus::{
    marshal::ingress::mailbox::AncestorStream,
    simplex::types::Context,
    types::{Epoch, Round, View},
    Heightable, VerifyingApplication,
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, certificate::Scheme, Committable, Digest, Hasher,
    Signer,
};
use commonware_runtime::{Metrics, Spawner, Timer};
use futures::StreamExt;
use rand::Rng;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Application<E, S, H, C, V>
where
    E: Rng + Spawner + Metrics + Timer,
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
    E: Rng + Spawner + Metrics + Timer,
    S: Scheme,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    pub const fn new(dkg: dkg::Mailbox<H, C, V>) -> Self {
        Self {
            dkg,
            _marker: PhantomData,
        }
    }
}

impl<E, S, H, C, V> commonware_consensus::Application<E> for Application<E, S, H, C, V>
where
    E: Rng + Spawner + Metrics + Timer,
    S: Scheme,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Context = Context<H::Digest, C::PublicKey>;
    type SigningScheme = S;
    type Block = Block<H, C, V>;

    async fn genesis(&mut self) -> Self::Block {
        // Create a genesis context with epoch 0, view 0, and empty parent.
        // Use a deterministic leader from seed 0 so all validators agree on genesis.
        let genesis_context = Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader: C::from_seed(0).public_key(),
            parent: (View::zero(), <H::Digest as Digest>::EMPTY),
        };
        genesis_block::<H, C, V>(genesis_context)
    }

    async fn propose(
        &mut self,
        (_, context): (E, Self::Context),
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
    E: Rng + Spawner + Metrics + Timer,
    S: Scheme,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    async fn verify(
        &mut self,
        _: (E, Self::Context),
        _: AncestorStream<Self::SigningScheme, Self::Block>,
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
