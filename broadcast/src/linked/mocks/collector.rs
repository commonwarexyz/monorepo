use crate::{linked::Context, Collector as Z, Digest, Proof};
use commonware_cryptography::PublicKey;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::collections::{BTreeMap, HashMap};

enum Message {
    Acknowledged(Context, Digest, Proof),
    GetTip(PublicKey, oneshot::Sender<Option<u64>>),
    Get(PublicKey, u64, oneshot::Sender<Option<Digest>>),
}

pub struct Collector {
    mailbox: mpsc::Receiver<Message>,

    // All known digests
    map: HashMap<PublicKey, BTreeMap<u64, Digest>>,

    // Highest contiguous known height for each sequencer
    hi: HashMap<PublicKey, u64>,
}

impl Collector {
    pub fn new() -> (Self, Mailbox) {
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
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Z for Mailbox {
    type Context = Context;
    async fn acknowledged(&mut self, context: Self::Context, payload: Digest, proof: Proof) {
        self.sender
            .send(Message::Acknowledged(context, payload, proof))
            .await
            .expect("Failed to send acknowledged");
    }
}

impl Mailbox {
    pub async fn get_tip(&mut self, sequencer: PublicKey) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, sequencer: PublicKey, height: u64) -> Option<Digest> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get(sequencer, height, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
