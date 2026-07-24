//! Block-building automaton for the multi-node marshal liveness model.
//!
//! Plays the simplex [`Automaton`](commonware_consensus::Automaton) /
//! [`Relay`](commonware_consensus::Relay) role (via the marshal
//! [`Deferred`](commonware_consensus::marshal::standard::Deferred) or
//! [`Marshaled`](commonware_consensus::marshal::coding::Marshaled) wrapper) for
//! a live engine whose `reporter` is marshal. On `propose` it reads the parent
//! from the supplied ancestry and emits a contiguous child block
//! (`height = parent + 1`) that embeds the consensus context verbatim. `verify`
//! eventually accepts, with an optional per-view delay used to exercise
//! certification timeouts; ancestry, context, and parent-linkage checks are
//! enforced by the wrapper itself.
//!
//! Generic over the context type `C` so the same builder serves both variants:
//! standard uses `Context<Digest, K>`, coding uses `Context<Commitment, K>`.

use commonware_codec::Codec;
use commonware_consensus::{
    Application, Epochable, Heightable, Viewable,
    marshal::{
        ancestry::Ancestry,
        mocks::{block::Block, harness::S as DefaultSigningScheme},
    },
    types::View,
};
use commonware_cryptography::{
    Digestible, Sha256, certificate::Scheme, sha256::Digest as Sha256Digest,
};
use commonware_runtime::{Clock as _, deterministic};
use futures::StreamExt;
use std::{marker::PhantomData, time::Duration};

/// Honest block-building application, generic over the consensus context type.
pub struct BlockBuilderApp<C, S = DefaultSigningScheme> {
    verification_delay: Option<(View, Duration)>,
    _marker: PhantomData<fn() -> (C, S)>,
}

impl<C, S> Default for BlockBuilderApp<C, S> {
    fn default() -> Self {
        Self {
            verification_delay: None,
            _marker: PhantomData,
        }
    }
}

impl<C, S> Clone for BlockBuilderApp<C, S> {
    fn clone(&self) -> Self {
        Self {
            verification_delay: self.verification_delay,
            _marker: PhantomData,
        }
    }
}

impl<C, S> BlockBuilderApp<C, S> {
    /// Delay verification at `view`, then return the normal successful verdict.
    pub const fn with_verification_delay(view: View, delay: Duration) -> Self {
        Self {
            verification_delay: Some((view, delay)),
            _marker: PhantomData,
        }
    }
}

impl<C, S> Application<deterministic::Context> for BlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Epochable + Viewable + Clone + PartialEq + Send + Sync + 'static,
    S: Scheme,
{
    type SigningScheme = S;
    type Context = C;
    type Block = Block<Sha256Digest, C>;
    type Input = ();

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        _input: Self::Input,
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
        context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let (runtime, consensus) = context;
        if let Some((view, delay)) = self.verification_delay
            && consensus.view() == view
        {
            runtime.sleep(delay).await;
        }
        true
    }
}
