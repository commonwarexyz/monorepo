use crate::{linked::Context, Collector as Z, Proof};
use commonware_cryptography::{Digest, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
};

enum Message<D: Digest> {
    Acknowledged(Context, D, Proof),
    GetTip(PublicKey, oneshot::Sender<Option<u64>>),
    GetContiguousTip(PublicKey, oneshot::Sender<Option<u64>>),
    Get(PublicKey, u64, oneshot::Sender<Option<D>>),
}

pub struct Collector<D: Digest> {
    mailbox: mpsc::Receiver<Message<D>>,

    // All known digests
    digests: HashMap<PublicKey, BTreeMap<u64, D>>,

    // Highest contiguous known height for each sequencer
    contiguous: HashMap<PublicKey, u64>,

    // Highest known height for each sequencer
    highest: HashMap<PublicKey, u64>,
}

impl<D: Digest> Collector<D> {
    pub fn new() -> (Self, Mailbox<D>) {
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
pub struct Mailbox<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: Digest> Z for Mailbox<D> {
    type Context = Context;
    type Digest = D;
    async fn acknowledged(&mut self, context: Self::Context, payload: Self::Digest, proof: Proof) {
        self.sender
            .send(Message::Acknowledged(context, payload, proof))
            .await
            .expect("Failed to send acknowledged");
    }
}

impl<D: Digest> Mailbox<D> {
    pub async fn get_tip(&mut self, sequencer: PublicKey) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get_contiguous_tip(&mut self, sequencer: PublicKey) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetContiguousTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, sequencer: PublicKey, height: u64) -> Option<D> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get(sequencer, height, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
