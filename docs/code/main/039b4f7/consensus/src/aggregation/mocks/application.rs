use crate::{aggregation::types::Index, types::Epoch, Automaton as A};
use commonware_cryptography::{Hasher, Sha256};
use futures::channel::oneshot;
use tracing::trace;

#[derive(Clone, Debug)]
pub enum Strategy {
    Correct,
    Incorrect,
    Skip { index: u64 },
}

#[derive(Clone)]
pub struct Application {
    strategy: Strategy,
}

impl Application {
    pub fn new(strategy: Strategy) -> Self {
        Self { strategy }
    }

    fn correct_message(context: Index) -> <Sha256 as Hasher>::Digest {
        let payload = format!("data for index {context}");
        Sha256::hash(payload.as_bytes())
    }
}

impl A for Application {
    type Context = Index;
    type Digest = <Sha256 as Hasher>::Digest;

    async fn genesis(&mut self, _epoch: Epoch) -> Self::Digest {
        let mut hasher = Sha256::default();
        hasher.update(b"genesis");
        hasher.finalize()
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();

        let digest = match &self.strategy {
            Strategy::Correct => Self::correct_message(context),
            Strategy::Incorrect => {
                let conflicting_payload = format!("conflicting_data for index {context}");
                Sha256::hash(conflicting_payload.as_bytes())
            }
            Strategy::Skip { index } => {
                if context == *index {
                    // Receiver will be canceled (sender dropped)
                    return receiver;
                }
                Self::correct_message(context)
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

        // Return true only if the payload matches the expected digest
        let expected_payload = Self::correct_message(context);
        sender.send(payload == expected_payload).unwrap();
        receiver
    }
}
