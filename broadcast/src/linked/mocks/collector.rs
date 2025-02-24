use crate::{linked::prover::Prover, Collector as Z, Proof};
use commonware_cryptography::{bls12381::primitives::group, Scheme};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
};
use tracing::error;

enum Message<C: Scheme, D: Array> {
    Acknowledged(Proof, D),
    GetTip(C::PublicKey, oneshot::Sender<Option<u64>>),
    GetContiguousTip(C::PublicKey, oneshot::Sender<Option<u64>>),
    Get(C::PublicKey, u64, oneshot::Sender<Option<D>>),
}

pub struct Collector<C: Scheme, D: Array> {
    mailbox: mpsc::Receiver<Message<C, D>>,

    // Application namespace
    namespace: Vec<u8>,

    // Public key of the group
    public: group::Public,

    // All known digests
    digests: HashMap<C::PublicKey, BTreeMap<u64, D>>,

    // Highest contiguous known height for each sequencer
    contiguous: HashMap<C::PublicKey, u64>,

    // Highest known height for each sequencer
    highest: HashMap<C::PublicKey, u64>,
}

impl<C: Scheme, D: Array> Collector<C, D> {
    pub fn new(namespace: &[u8], public: group::Public) -> (Self, Mailbox<C, D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Collector {
                mailbox: receiver,
                namespace: namespace.to_vec(),
                public,
                digests: HashMap::new(),
                contiguous: HashMap::new(),
                highest: HashMap::new(),
            },
            Mailbox { sender },
        )
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Acknowledged(proof, payload) => {
                    // Check proof.
                    // The prover checks the validity of the threshold signature when deserializing
                    let prover = Prover::<C, D>::new(&self.namespace, self.public);
                    let context = match prover.deserialize_threshold(proof) {
                        Some((context, _payload, _epoch, _threshold)) => context,
                        None => {
                            error!("invalid proof");
                            continue;
                        }
                    };

                    // Update the collector
                    let digests = self.digests.entry(context.sequencer.clone()).or_default();
                    digests.insert(context.height, payload);

                    // Update the highest height
                    let highest = self.highest.get(&context.sequencer).copied().unwrap_or(0);
                    self.highest
                        .insert(context.sequencer.clone(), max(highest, context.height));

                    // Update the highest contiguous height
                    let highest = self.contiguous.get(&context.sequencer);
                    if (highest.is_none() && context.height == 0)
                        || (highest.is_some() && context.height == highest.unwrap() + 1)
                    {
                        let mut contiguous = context.height;
                        while digests.contains_key(&(contiguous + 1)) {
                            contiguous += 1;
                        }
                        self.contiguous.insert(context.sequencer, contiguous);
                    }
                }
                Message::GetTip(sequencer, sender) => {
                    let hi = self.highest.get(&sequencer).copied();
                    sender.send(hi).unwrap();
                }
                Message::GetContiguousTip(sequencer, sender) => {
                    let contiguous = self.contiguous.get(&sequencer).copied();
                    sender.send(contiguous).unwrap();
                }
                Message::Get(sequencer, height, sender) => {
                    let digest = self
                        .digests
                        .get(&sequencer)
                        .and_then(|map| map.get(&height))
                        .cloned();
                    sender.send(digest).unwrap();
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<C: Scheme, D: Array> {
    sender: mpsc::Sender<Message<C, D>>,
}

impl<C: Scheme, D: Array> Z for Mailbox<C, D> {
    type Digest = D;
    async fn acknowledged(&mut self, proof: Proof, payload: Self::Digest) {
        self.sender
            .send(Message::Acknowledged(proof, payload))
            .await
            .expect("Failed to send acknowledged");
    }
}

impl<C: Scheme, D: Array> Mailbox<C, D> {
    pub async fn get_tip(&mut self, sequencer: C::PublicKey) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get_contiguous_tip(&mut self, sequencer: C::PublicKey) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetContiguousTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, sequencer: C::PublicKey, height: u64) -> Option<D> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get(sequencer, height, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
