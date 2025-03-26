use crate::{
    ordered_broadcast::{prover::Prover, Epoch},
    Committer as Z, Proof,
};
use commonware_cryptography::{bls12381::primitives::group, Digest, Scheme};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::collections::{btree_map::Entry, BTreeMap, HashMap};

enum Message<C: Scheme, D: Digest> {
    Acknowledged(Proof, D),
    GetTip(C::PublicKey, oneshot::Sender<Option<(u64, Epoch)>>),
    GetContiguousTip(C::PublicKey, oneshot::Sender<Option<u64>>),
    Get(C::PublicKey, u64, oneshot::Sender<Option<(D, Epoch)>>),
}

pub struct Committer<C: Scheme, D: Digest> {
    mailbox: mpsc::Receiver<Message<C, D>>,

    // Application namespace
    namespace: Vec<u8>,

    // Public key of the group
    public: group::Public,

    // All known digests
    digests: HashMap<C::PublicKey, BTreeMap<u64, (D, Epoch)>>,

    // Highest contiguous known height for each sequencer
    contiguous: HashMap<C::PublicKey, u64>,

    // Highest known height (and epoch) for each sequencer
    highest: HashMap<C::PublicKey, (u64, Epoch)>,
}

impl<C: Scheme, D: Digest> Committer<C, D> {
    pub fn new(namespace: &[u8], public: group::Public) -> (Self, Mailbox<C, D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Committer {
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
        let prover = Prover::<C, D>::new(&self.namespace, self.public);
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Acknowledged(proof, payload) => {
                    // Check proof.
                    //
                    // The prover checks the validity of the threshold signature when deserializing
                    let (context, _, epoch, _) =
                        prover.deserialize_threshold(proof).expect("Invalid proof");

                    // Update the committer
                    let digests = self.digests.entry(context.sequencer.clone()).or_default();
                    let entry = digests.entry(context.height);
                    match entry {
                        Entry::Occupied(mut entry) => {
                            // It should never be possible to get a conflicting payload
                            let (existing_payload, existing_epoch) = entry.get();
                            assert_eq!(*existing_payload, payload);

                            // We may hear about a commitment again, however, this should
                            // only occur if the epoch has changed.
                            assert_ne!(*existing_epoch, epoch);
                            if epoch > *existing_epoch {
                                entry.insert((payload, epoch));
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert((payload, epoch));
                        }
                    }

                    // Update the highest height
                    let highest = self
                        .highest
                        .get(&context.sequencer)
                        .copied()
                        .unwrap_or((0, 0));
                    if context.height > highest.0 {
                        self.highest
                            .insert(context.sequencer.clone(), (context.height, epoch));
                    }

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
pub struct Mailbox<C: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<C, D>>,
}

impl<C: Scheme, D: Digest> Z for Mailbox<C, D> {
    type Digest = D;
    async fn finalized(&mut self, proof: Proof, payload: Self::Digest) {
        self.sender
            .send(Message::Acknowledged(proof, payload))
            .await
            .expect("Failed to send acknowledged");
    }

    async fn prepared(&mut self, _proof: Proof, _payload: Self::Digest) {
        unimplemented!()
    }
}

impl<C: Scheme, D: Digest> Mailbox<C, D> {
    pub async fn get_tip(&mut self, sequencer: C::PublicKey) -> Option<(u64, Epoch)> {
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

    pub async fn get(&mut self, sequencer: C::PublicKey, height: u64) -> Option<(D, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get(sequencer, height, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
