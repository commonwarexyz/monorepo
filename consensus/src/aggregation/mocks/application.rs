use crate::{aggregation::types::Index, Automaton as A};
use commonware_cryptography::{sha256, Hasher, Sha256};
use futures::channel::oneshot;
use rand::{thread_rng, Rng};
use tracing::trace;

#[derive(Clone, Debug)]
pub enum ByzantineStrategy {
    None,
    DoubleHash,
    RandomDigest,
    WrongPrefix,
    ConflictingContent,
}

#[derive(Clone)]
pub struct Application {
    invalid_when: fn(u64) -> bool,
    byzantine_strategy: ByzantineStrategy,
}

impl Application {
    pub fn honest() -> Self {
        Self {
            invalid_when: |_| false,
            byzantine_strategy: ByzantineStrategy::None,
        }
    }

    pub fn byzantine(invalid_when: fn(u64) -> bool, byzantine_strategy: ByzantineStrategy) -> Self {
        Self {
            invalid_when,
            byzantine_strategy,
        }
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

        let payload = format!("data for index {context}");
        let mut hasher = Sha256::default();
        hasher.update(payload.as_bytes());

        let digest = if (self.invalid_when)(context) {
            match self.byzantine_strategy {
                ByzantineStrategy::None => hasher.finalize(),
                ByzantineStrategy::DoubleHash => {
                    hasher.update(payload.as_bytes());
                    hasher.finalize()
                }
                ByzantineStrategy::RandomDigest => {
                    let mut random_bytes = [0u8; 32];
                    thread_rng().fill(&mut random_bytes);
                    sha256::Digest::from(random_bytes)
                }
                ByzantineStrategy::WrongPrefix => {
                    let mut hasher = Sha256::default();
                    hasher.update(b"wrong_prefix");
                    hasher.update(payload.as_bytes());
                    hasher.finalize()
                }
                ByzantineStrategy::ConflictingContent => {
                    let conflicting_payload = format!("conflicting_data for index {context}");
                    let mut hasher = Sha256::default();
                    hasher.update(conflicting_payload.as_bytes());
                    hasher.finalize()
                }
            }
        } else {
            hasher.finalize()
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
        let is_valid = payload == expected_digest;
        sender.send(is_valid).unwrap();
        receiver
    }
}
