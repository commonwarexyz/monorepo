//! Block-building automaton for the multi-node marshal liveness model.
//!
//! Plays the simplex [`Automaton`](commonware_consensus::Automaton) /
//! [`Relay`](commonware_consensus::Relay) role (via the marshal
//! [`Deferred`](commonware_consensus::marshal::standard::Deferred) or
//! [`Marshaled`](commonware_consensus::marshal::coding::Marshaled) wrapper) for
//! a live engine whose `reporter` is marshal. On `propose` it reads the parent
//! from the supplied ancestry and emits a contiguous child block
//! (`height = parent + 1`) that embeds the consensus context verbatim, so a
//! peer's wrapper accepts it (it checks `block.context() == context`). `verify`
//! always accepts; ancestry and parent-linkage checks are enforced by the
//! wrapper itself.
//!
//! Generic over the context type `C` so the same builder serves both variants:
//! standard uses `Context<Digest, K>`, coding uses `Context<Commitment, K>`.

use commonware_codec::Codec;
use commonware_consensus::{
    marshal::{
        ancestry::Ancestry,
        mocks::{block::Block, harness::S},
    },
    Application, Epochable, Heightable,
};
use commonware_cryptography::{sha256::Digest as Sha256Digest, Digestible, Sha256};
use commonware_runtime::deterministic;
use futures::StreamExt;
use std::marker::PhantomData;

/// Honest block-building application, generic over the consensus context type.
pub struct BlockBuilderApp<C>(PhantomData<fn() -> C>);

impl<C> Default for BlockBuilderApp<C> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C> Clone for BlockBuilderApp<C> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<C> Application<deterministic::Context> for BlockBuilderApp<C>
where
    C: Codec<Cfg = ()> + Epochable + Clone + PartialEq + Send + Sync + 'static,
{
    type SigningScheme = S;
    type Context = C;
    type Block = Block<Sha256Digest, C>;

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        let (_, consensus_context) = context;
        // The first ancestor is the parent (highest height); the wrapper seeds
        // the stream with the parent it already fetched for this round.
        let parent = ancestry.next().await?;
        let height = parent.height().next();
        Some(Block::<Sha256Digest, C>::new::<Sha256>(
            consensus_context,
            parent.digest(),
            height,
            height.get(),
        ))
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        true
    }
}
