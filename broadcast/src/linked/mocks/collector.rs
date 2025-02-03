use crate::{linked::Context, Collector as Z, Proof};
use commonware_cryptography::{Digest, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::collections::{BTreeMap, HashMap};

enum Message<D: Digest> {
    Acknowledged(Context, D, Proof),
    GetTip(PublicKey, oneshot::Sender<Option<u64>>),
    Get(PublicKey, u64, oneshot::Sender<Option<D>>),
}

pub struct Collector<D: Digest> {
    mailbox: mpsc::Receiver<Message<D>>,

    // All known digests
    map: HashMap<PublicKey, BTreeMap<u64, D>>,

    // Highest contiguous known height for each sequencer
    hi: HashMap<PublicKey, u64>,
}

impl<D: Digest> Collector<D> {
    pub fn new() -> (Self, Mailbox<D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Collector {
                mailbox: receiver,
                map: HashMap::new(),
                hi: HashMap::new(),
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
                    let map = self.map.entry(context.sequencer.clone()).or_default();
                    map.insert(context.height, payload);

                    // Update the highest contiguous height
                    let hi = self.hi.get(&context.sequencer);
                    if (hi.is_none() && context.height == 0)
                        || (hi.is_some() && context.height == hi.unwrap() + 1)
                    {
                        let mut new_hi = context.height;
                        while map.contains_key(&(new_hi + 1)) {
                            new_hi += 1;
                        }
                        self.hi.insert(context.sequencer, new_hi);
                    }
                }
                Message::GetTip(sequencer, sender) => {
                    let tip = self.hi.get(&sequencer).copied();
                    sender.send(tip).unwrap();
                }
                Message::Get(sequencer, height, sender) => {
                    let digest = self
                        .map
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

    pub async fn get(&mut self, sequencer: PublicKey, height: u64) -> Option<D> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get(sequencer, height, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
