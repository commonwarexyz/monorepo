use crate::{
    aggregation::types::{Ack, Activity, Epoch, Index, Item},
    Reporter as Z,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::{poly, variant::Variant},
    Digest,
};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::collections::{btree_map::Entry, BTreeMap, HashSet};

#[allow(clippy::large_enum_variant)]
enum Message<V: Variant, D: Digest> {
    Ack(Ack<V, D>),
    Recovered(Item<D>, V::Signature),
    Tip(Index),
    GetTip(oneshot::Sender<Option<(Index, Epoch)>>),
    GetContiguousTip(oneshot::Sender<Option<Index>>),
    Get(Index, oneshot::Sender<Option<(D, Epoch)>>),
}

pub struct Reporter<V: Variant, D: Digest> {
    mailbox: mpsc::Receiver<Message<V, D>>,

    // Application namespace
    namespace: Vec<u8>,

    // Polynomial public key of the group
    public: poly::Public<V>,

    // Received acks (for validation)
    acks: HashSet<(Index, Epoch)>,

    // All known digests
    digests: BTreeMap<Index, (D, Epoch)>,

    // Highest contiguous known height
    contiguous: Option<Index>,

    // Highest known height (and epoch)
    highest: Option<(Index, Epoch)>,

    // Current epoch (tracked from acks)
    current_epoch: Epoch,
}

impl<V: Variant, D: Digest> Reporter<V, D> {
    pub fn new(namespace: &[u8], public: poly::Public<V>) -> (Self, Mailbox<V, D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Reporter {
                mailbox: receiver,
                namespace: namespace.to_vec(),
                public,
                acks: HashSet::new(),
                digests: BTreeMap::new(),
                contiguous: None,
                highest: None,
                current_epoch: 111, // Initialize with the expected epoch
            },
            Mailbox { sender },
        )
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Ack(ack) => {
                    // Verify properly constructed (not needed in production)
                    if !ack.verify(&self.namespace, &self.public) {
                        panic!("Invalid ack signature");
                    }

                    // Test encoding/decoding
                    let encoded = ack.encode();
                    Ack::<V, D>::decode(encoded).unwrap();

                    // Update current epoch from ack
                    self.current_epoch = ack.epoch;

                    // Store the ack
                    self.acks.insert((ack.item.index, ack.epoch));
                }
                Message::Recovered(item, signature) => {
                    tracing::debug!(
                        index = item.index,
                        current_epoch = self.current_epoch,
                        "Reporter received Recovered activity"
                    );
                    // Verify threshold signature
                    use commonware_cryptography::bls12381::primitives::{ops, poly};
                    let mut ack_namespace = self.namespace.clone();
                    ack_namespace.extend_from_slice(b"_AGG_ACK");
                    let threshold_public = poly::public::<V>(&self.public);
                    let verification_result = ops::verify_message::<V>(
                        threshold_public,
                        Some(&ack_namespace),
                        &item.encode(),
                        &signature,
                    );
                    if verification_result.is_err() {
                        panic!(
                            "Invalid threshold signature for item at index {}: {:?}",
                            item.index,
                            verification_result.err()
                        );
                    }

                    // Test encoding/decoding
                    let encoded = item.encode();
                    Item::<D>::decode(encoded).unwrap();
                    let encoded = signature.encode();
                    V::Signature::decode(encoded).unwrap();

                    // Update the reporter
                    let entry = self.digests.entry(item.index);
                    match entry {
                        Entry::Occupied(mut entry) => {
                            // It should never be possible to get a conflicting payload
                            let (existing_payload, _existing_epoch) = entry.get();
                            assert_eq!(*existing_payload, item.digest);

                            // We may hear about a commitment again, however, this should
                            // only occur if the epoch has changed.
                            // For now, we'll allow the same epoch to be overwritten
                            entry.insert((item.digest, self.current_epoch));
                        }
                        Entry::Vacant(entry) => {
                            entry.insert((item.digest, self.current_epoch));
                        }
                    }

                    // Update the highest height
                    if self.highest.is_none_or(|(h, _)| item.index > h) {
                        self.highest = Some((item.index, self.current_epoch));
                    }

                    // Update the highest contiguous height
                    let mut next_contiguous = self.contiguous.map(|c| c + 1).unwrap_or(0);
                    while self.digests.contains_key(&next_contiguous) {
                        next_contiguous += 1;
                    }
                    if next_contiguous > 0 {
                        self.contiguous = Some(next_contiguous.checked_sub(1).unwrap());
                    }
                }
                Message::Tip(index) => {
                    // Update our view of the tip
                    if self.highest.is_none_or(|(h, _)| index > h) {
                        self.highest = Some((index, self.current_epoch));
                    }

                    // Update the contiguous tip if necessary;
                    // An individual validator may have missed constructing a signature, but a
                    // majority of the rest of the network has constructed a signature.
                    if self.contiguous.is_none_or(|c| index > c) {
                        self.contiguous = Some(index);
                    }
                }
                Message::GetTip(sender) => {
                    sender.send(self.highest).unwrap();
                }
                Message::GetContiguousTip(sender) => {
                    sender.send(self.contiguous).unwrap();
                }
                Message::Get(index, sender) => {
                    let digest = self.digests.get(&index).cloned();
                    sender.send(digest).unwrap();
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<V: Variant, D: Digest> {
    sender: mpsc::Sender<Message<V, D>>,
}

impl<V: Variant, D: Digest> Z for Mailbox<V, D> {
    type Activity = Activity<V, D>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Activity::Ack(ack) => {
                self.sender
                    .send(Message::Ack(ack))
                    .await
                    .expect("Failed to send ack");
            }
            Activity::Recovered(item, signature) => {
                self.sender
                    .send(Message::Recovered(item, signature))
                    .await
                    .expect("Failed to send recovered signature");
            }
            Activity::Tip(index) => {
                self.sender
                    .send(Message::Tip(index))
                    .await
                    .expect("Failed to send tip");
            }
        }
    }
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    pub async fn get_tip(&mut self) -> Option<(Index, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(Message::GetTip(sender)).await.unwrap();
        receiver.await.unwrap()
    }

    pub async fn get_contiguous_tip(&mut self) -> Option<Index> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetContiguousTip(sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, index: Index) -> Option<(D, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(Message::Get(index, sender)).await.unwrap();
        receiver.await.unwrap()
    }
}
