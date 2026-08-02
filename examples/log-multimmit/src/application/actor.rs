use commonware_actor::Feedback;
use commonware_consensus::{Automaton, Heightable, Relay, multimmit::types::Context};
use commonware_cryptography::{Hasher, ed25519};
use commonware_utils::channel::oneshot;
use core::future::ready;
use std::{future::Future, marker::PhantomData};
use tracing::info;

/// A deterministic mock application for one Multimmit producer chain.
///
/// Its proposal policy is to immediately return a commitment for every request from consensus.
pub struct Application<H: Hasher> {
    seed: u64,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> Clone for Application<H> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            _hasher: PhantomData,
        }
    }
}

impl<H: Hasher> Application<H> {
    /// Creates a deterministic mock application from `seed`.
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            _hasher: PhantomData,
        }
    }
}

impl<H: Hasher> Automaton for Application<H> {
    type Context = Context<H::Digest>;
    type Digest = H::Digest;

    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        let chain = context.chain().get();
        let height = context.height().get();
        let seed_bytes = self.seed.to_be_bytes();
        let chain_bytes = chain.to_be_bytes();
        let height_bytes = height.to_be_bytes();
        let parent = context.parent();
        let commitment = H::hash(&[
            b"log-multimmit",
            &seed_bytes,
            &chain_bytes,
            &height_bytes,
            parent.as_ref(),
        ]);

        info!(chain, height, ?commitment, "produced");

        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(commitment);
        ready(receiver)
    }

    fn verify(
        &mut self,
        _context: Self::Context,
        _payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        // This body-free example reports every canonical commitment as available and valid.
        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(true);
        ready(receiver)
    }
}

impl<H: Hasher> Relay for Application<H> {
    type Digest = H::Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = ();

    fn broadcast(&mut self, _payload: Self::Digest, (): Self::Plan) -> Feedback {
        Feedback::Ok
    }
}
