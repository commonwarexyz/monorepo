use crate::{aggregation::types::Index, Automaton as A};
use commonware_cryptography::{hash, sha256, Hasher, Sha256};
use futures::channel::oneshot;
use tracing::trace;

#[derive(Clone, Debug)]
pub enum Strategy {
    Correct,
    Incorrect,
}

#[derive(Clone)]
pub struct Application {
    strategy: Strategy,
}

impl Application {
    pub fn new(strategy: Strategy) -> Self {
        Self { strategy }
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

        let digest = match self.strategy {
            Strategy::Correct => {
                let payload = format!("data for index {context}");
                hash(payload.as_bytes())
            }
            Strategy::Incorrect => {
                let conflicting_payload = format!("conflicting_data for index {context}");
                hash(conflicting_payload.as_bytes())
            }
        };

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
        let expected_payload = format!("data for index {context}");
        let mut hasher = Sha256::default();
        hasher.update(expected_payload.as_bytes());
        let expected_digest = hasher.finalize();

        // Return true only if the payload matches the expected digest
        sender.send(payload == expected_digest).unwrap();
        receiver
    }
}
