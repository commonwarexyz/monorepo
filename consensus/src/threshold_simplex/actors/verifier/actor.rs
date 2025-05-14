use super::{Config, Mailbox, Message};
use crate::{
    threshold_simplex::{
        actors::voter,
        types::{PartialVerifier, View, Viewable},
    },
    ThresholdSupervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{poly, variant::Variant},
    Digest, Scheme,
};
use commonware_runtime::{Handle, Metrics, Spawner};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::histogram::Histogram;
use std::{collections::BTreeMap, marker::PhantomData};
use tracing::{trace, warn};

async fn recv_batch<T, F>(rx: &mut mpsc::Receiver<T>, block: bool, mut f: F) -> bool
where
    F: FnMut(T),
{
    if block {
        match rx.next().await {
            Some(first) => {
                f(first);
                while let Ok(Some(item)) = rx.try_next() {
                    f(item);
                }
                true // processed at least one item
            }
            None => false, // channel closed
        }
    } else {
        while let Ok(Some(item)) = rx.try_next() {
            f(item);
        }
        true
    }
}

pub struct Actor<
    E: Spawner + Metrics,
    C: Scheme,
    V: Variant,
    D: Digest,
    S: ThresholdSupervisor<
        Index = View,
        Identity = poly::Public<V>,
        PublicKey = C::PublicKey,
        Public = V::Public,
    >,
> {
    context: E,
    supervisor: S,

    namespace: Vec<u8>,

    mailbox_receiver: mpsc::Receiver<Message<V, D>>,

    batch_size: Histogram,

    _phantom: PhantomData<C>,
}

impl<
        E: Spawner + Metrics,
        C: Scheme,
        V: Variant,
        D: Digest,
        S: ThresholdSupervisor<
            Index = View,
            Identity = poly::Public<V>,
            PublicKey = C::PublicKey,
            Public = V::Public,
        >,
    > Actor<E, C, V, D, S>
{
    pub fn new(context: E, cfg: Config<S>) -> (Self, Mailbox<V, D>) {
        let batch_size =
            Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0].into_iter());
        context.register(
            "batch_size",
            "number of messages in a partial signature verification batch",
            batch_size.clone(),
        );
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                supervisor: cfg.supervisor,

                namespace: cfg.namespace,

                mailbox_receiver: receiver,

                batch_size,

                _phantom: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(mut self, consensus: voter::Mailbox<V, D>) -> Handle<()> {
        self.context.spawn_ref()(self.run(consensus))
    }

    pub async fn run(mut self, mut consensus: voter::Mailbox<V, D>) {
        // Initialize view data structures
        let mut latest: View = 0;
        let mut oldest: View = 0;
        let mut work: BTreeMap<u64, PartialVerifier<V, D>> = BTreeMap::new();

        loop {
            // Read at least one message (if there doesn't already exist a backlog)
            if !recv_batch(
                &mut self.mailbox_receiver,
                work.is_empty(),
                |message| match message {
                    Message::Update {
                        latest: new_latest,
                        oldest: new_oldest,
                    } => {
                        latest = new_latest;
                        oldest = new_oldest;
                    }
                    Message::Message(message) => {
                        work.entry(message.view()).or_default().add(message);
                    }
                },
            )
            .await
            {
                return;
            }

            // If work is still empty, continue (could happen if just got Update)
            if work.is_empty() {
                continue;
            }

            // Select some verifier (preferring the current view) without removing it initially
            let view = if work.contains_key(&latest) {
                latest
            } else {
                *work.keys().next_back().unwrap()
            };
            let verifier = work.get_mut(&view).unwrap();

            // Verify messages
            let identity = self.supervisor.identity(view).unwrap();
            let (voters, failed) = verifier.verify(&self.namespace, identity);
            let batch = voters.len() + failed.len();
            trace!(view, batch, "batch verified messages");
            self.batch_size.observe(batch as f64);

            // Send messages
            for msg in voters {
                consensus.voter(msg).await;
            }

            // Block invalid signers
            if !failed.is_empty() {
                let participants = self.supervisor.participants(view).unwrap();
                for invalid in failed {
                    let signer = participants[invalid as usize].clone();
                    warn!(?signer, "blocking peer");
                }
            }

            // Drop any old verifiers
            work.retain(|view, _| *view >= oldest);
        }
    }
}
