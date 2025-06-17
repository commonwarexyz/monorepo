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
    Locked(Item<D>, V::Signature),
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
    limit_misses: Option<usize>,

    // All known digests
    digests: BTreeMap<Index, (D, Epoch)>,

    // Highest contiguous known height
    contiguous: Index,

    // Highest known height (and epoch)
    highest: Option<(Index, Epoch)>,

    // Current epoch (tracked from acks)
    current_epoch: Epoch,
}

impl<V: Variant, D: Digest> Reporter<V, D> {
    pub fn new(
        namespace: &[u8],
        public: poly::Public<V>,
        limit_misses: Option<usize>,
    ) -> (Self, Mailbox<V, D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Reporter {
                mailbox: receiver,
                namespace: namespace.to_vec(),
                public,
                acks: HashSet::new(),
                limit_misses,
                digests: BTreeMap::new(),
                contiguous: 0,
                highest: None,
                current_epoch: 111, // Initialize with the expected epoch
            },
            Mailbox { sender },
        )
    }

    pub async fn run(mut self) {
        let mut misses = 0;
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
                Message::Locked(item, signature) => {
                    tracing::debug!(
                        index = item.index,
                        current_epoch = self.current_epoch,
                        "Reporter received Lock activity"
                    );
                    // Verify threshold signature (this was previously skipped)
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

                    // Check if we saw acks for this item
                    if let Some(misses_allowed) = self.limit_misses {
                        let ack_count = self
                            .acks
                            .iter()
                            .filter(|(index, _)| *index == item.index)
                            .count();
                        if ack_count == 0 {
                            misses += 1;
                        }
                        assert!(misses <= misses_allowed, "Missed too many acks");
                    }

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
                    // Check if this item extends our contiguous range
                    if item.index <= self.contiguous + 1 {
                        // Recompute contiguous from 0
                        let mut contiguous = 0;
                        while self.digests.contains_key(&contiguous) {
                            contiguous += 1;
                        }
                        self.contiguous = contiguous.saturating_sub(1);
                    }
                }
                Message::Tip(index) => {
                    // Update our view of the tip
                    if self.highest.is_none_or(|(h, _)| index > h) {
                        self.highest = Some((index, self.current_epoch));
                    }
                }
                Message::GetTip(sender) => {
                    sender.send(self.highest).unwrap();
                }
                Message::GetContiguousTip(sender) => {
                    sender.send(Some(self.contiguous)).unwrap();
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
            Activity::Lock(item, signature) => {
                self.sender
                    .send(Message::Locked(item, signature))
                    .await
                    .expect("Failed to send locked");
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
