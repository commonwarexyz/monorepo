use crate::{linked::Context, Collector as Z, Proof};
use commonware_cryptography::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
};

enum Message<D: Array, P: Array> {
    Acknowledged(Context<P>, D, Proof),
    GetTip(P, oneshot::Sender<Option<u64>>),
    GetContiguousTip(P, oneshot::Sender<Option<u64>>),
    Get(P, u64, oneshot::Sender<Option<D>>),
}

pub struct Collector<D: Array, P: Array> {
    mailbox: mpsc::Receiver<Message<D, P>>,

    // All known digests
    digests: HashMap<P, BTreeMap<u64, D>>,

    // Highest contiguous known height for each sequencer
    contiguous: HashMap<P, u64>,

    // Highest known height for each sequencer
    highest: HashMap<P, u64>,
}

impl<D: Array, P: Array> Collector<D, P> {
    pub fn new() -> (Self, Mailbox<D, P>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Collector {
                mailbox: receiver,
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
                Message::Acknowledged(context, payload, _proof) => {
                    // TODO: check proof

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
pub struct Mailbox<D: Array, P: Array> {
    sender: mpsc::Sender<Message<D, P>>,
}

impl<D: Array, P: Array> Z for Mailbox<D, P> {
    type Context = Context<P>;
    type Digest = D;
    async fn acknowledged(&mut self, context: Self::Context, payload: Self::Digest, proof: Proof) {
        self.sender
            .send(Message::Acknowledged(context, payload, proof))
            .await
            .expect("Failed to send acknowledged");
    }
}

impl<D: Array, P: Array> Mailbox<D, P> {
    pub async fn get_tip(&mut self, sequencer: P) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get_contiguous_tip(&mut self, sequencer: P) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetContiguousTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, sequencer: P, height: u64) -> Option<D> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get(sequencer, height, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
