use crate::{
    ordered_broadcast::types::Context, types::Epoch, Automaton as A, RetryableAutomaton as RA,
};
use bytes::Bytes;
use commonware_cryptography::{sha256, Hasher, PublicKey, Sha256};
use futures::channel::oneshot;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
use tracing::trace;

/// A mock automaton that simulates first broadcast failures.
///
/// This automaton "drops" the first propose for each digest, only making the
/// payload available for verification after `repropose()` is called. This tests
/// that the engine correctly triggers repropose when initial broadcasts fail.
#[derive(Clone)]
pub struct DropFirstAutomaton<P: PublicKey> {
    delivered: Arc<Mutex<HashSet<sha256::Digest>>>,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: PublicKey> DropFirstAutomaton<P> {
    pub fn new() -> Self {
        Self {
            delivered: Arc::new(Mutex::new(HashSet::new())),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: PublicKey> Default for DropFirstAutomaton<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PublicKey> A for DropFirstAutomaton<P> {
    type Context = Context<P>;
    type Digest = sha256::Digest;

    async fn genesis(&mut self, _epoch: Epoch) -> Self::Digest {
        unimplemented!()
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();

        let Self::Context { sequencer, height } = context;
        let payload = Bytes::from(format!("hello world, {sequencer} {height}"));
        let mut hasher = Sha256::default();
        hasher.update(&payload);
        let digest = hasher.finalize();

        trace!(?digest, "propose (dropping first broadcast)");

        sender.send(digest).unwrap();
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();

        let delivered = self.delivered.lock().unwrap().contains(&payload);
        trace!(?context, ?payload, delivered, "verify");

        sender.send(delivered).unwrap();
        receiver
    }
}

impl<P: PublicKey> RA for DropFirstAutomaton<P> {
    async fn repropose(&mut self, payload: Self::Digest) {
        trace!(?payload, "repropose (delivering payload)");
        self.delivered.lock().unwrap().insert(payload);
    }
}
