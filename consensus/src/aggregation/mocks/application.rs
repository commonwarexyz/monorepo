use crate::{aggregation::types::Index, Automaton as A};
use commonware_cryptography::{sha256, Hasher, Sha256};
use futures::channel::oneshot;
use tracing::trace;

#[derive(Clone)]
pub struct Application {
    invalid_when: fn(u64) -> bool,
}

impl Application {
    pub fn new(invalid_when: fn(u64) -> bool) -> Self {
        Self { invalid_when }
    }
}

impl A for Application {
    type Context = Index;
    type Digest = sha256::Digest;

    async fn genesis(&mut self) -> Self::Digest {
        let mut hasher = Sha256::default();
        hasher.update(b"genesis");
        hasher.finalize()
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();

        let payload = format!("data for index {}", context);
        let mut hasher = Sha256::default();
        hasher.update(payload.as_bytes());

        // Inject an invalid digest by updating with the payload again.
        if (self.invalid_when)(context) {
            hasher.update(payload.as_bytes());
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

        // Compute the expected valid digest
        let expected_payload = format!("data for index {}", context);
        let mut hasher = Sha256::default();
        hasher.update(expected_payload.as_bytes());
        let expected_digest = hasher.finalize();

        // Return true only if the payload matches the expected digest
        let is_valid = payload == expected_digest;
        sender.send(is_valid).unwrap();
        receiver
    }
}
