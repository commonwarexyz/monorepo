use super::super::Context;
use crate::{Automaton as A, Relay as R};
use bytes::Bytes;
use commonware_cryptography::{sha256, Hasher, Sha256};
use commonware_utils::Array;
use futures::channel::oneshot;
use tracing::trace;

#[derive(Clone)]
pub struct Automaton<P: Array> {
    invalid_when: fn(u64) -> bool,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: Array> Automaton<P> {
    pub fn new(invalid_when: fn(u64) -> bool) -> Self {
        Self {
            invalid_when,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: Array> A for Automaton<P> {
    type Context = Context<P>;
    type Digest = sha256::Digest;

    async fn genesis(&mut self) -> Self::Digest {
        unimplemented!()
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();

        let Self::Context { sequencer, height } = context;
        let payload = Bytes::from(format!("hello world, {} {}", sequencer, height));
        let mut hasher = Sha256::default();
        hasher.update(&payload);

        // Inject an invalid digest by updating with the payload again.
        if (self.invalid_when)(height) {
            hasher.update(&payload);
        }

        let digest = hasher.finalize();
        sender.send(digest).unwrap();

        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        trace!(?context, ?payload, "verify");
        let (sender, receiver) = oneshot::channel();
        // Always say the payload is valid.
        sender.send(true).unwrap();
        receiver
    }
}

impl<P: Array> R for Automaton<P> {
    type Digest = sha256::Digest;
    async fn broadcast(&mut self, payload: Self::Digest) {
        trace!(?payload, "broadcast");
    }
}
