use crate::{
    aggregation::{
        scheme,
        types::{Ack, Activity, Certificate, Index},
    },
    types::Epoch,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Digest};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use rand::{CryptoRng, Rng};
use std::collections::{btree_map::Entry, BTreeMap, HashSet};

#[allow(clippy::large_enum_variant)]
enum Message<S: Scheme, D: Digest> {
    Ack(Ack<S, D>),
    Certified(Certificate<S, D>),
    Tip(Index),
    GetTip(oneshot::Sender<Option<(Index, Epoch)>>),
    GetContiguousTip(oneshot::Sender<Option<Index>>),
    Get(Index, oneshot::Sender<Option<(D, Epoch)>>),
}

pub struct Reporter<R: Rng + CryptoRng, S: Scheme, D: Digest> {
    mailbox: mpsc::Receiver<Message<S, D>>,

    // RNG used for signature verification with scheme.
    rng: R,

    // Application namespace
    namespace: Vec<u8>,

    // Signing scheme for verification
    scheme: S,

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

impl<R, S, D> Reporter<R, S, D>
where
    R: Rng + CryptoRng,
    S: scheme::Scheme<D>,
    D: Digest,
{
    pub fn new(rng: R, namespace: &[u8], scheme: S) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Self {
                mailbox: receiver,
                rng,
                namespace: namespace.to_vec(),
                scheme,
                acks: HashSet::new(),
                digests: BTreeMap::new(),
                contiguous: None,
                highest: None,
                current_epoch: Epoch::new(111), // Initialize with the expected epoch
            },
            Mailbox { sender },
        )
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Ack(ack) => {
                    // Verify properly constructed (not needed in production)
                    assert!(ack.verify(&self.scheme, &self.namespace));

                    // Test encoding/decoding
                    let encoded = ack.encode();
                    Ack::<S, D>::decode(encoded).unwrap();

                    // Update current epoch from ack
                    self.current_epoch = ack.epoch;

                    // Store the ack
                    self.acks.insert((ack.item.index, ack.epoch));
                }
                Message::Certified(certificate) => {
                    // Verify certificate
                    assert!(certificate.verify(&mut self.rng, &self.scheme, &self.namespace));

                    // Test encoding/decoding
                    let encoded = certificate.encode();
                    let cfg = self.scheme.certificate_codec_config();
                    Certificate::<S, D>::decode_cfg(encoded, &cfg).unwrap();

                    // Update the reporter
                    let entry = self.digests.entry(certificate.item.index);
                    match entry {
                        Entry::Occupied(mut entry) => {
                            // It should never be possible to get a conflicting payload
                            let (existing_payload, _existing_epoch) = entry.get();
                            assert_eq!(*existing_payload, certificate.item.digest);

                            // We may hear about a commitment again, however, this should
                            // only occur if the epoch has changed.
                            // For now, we'll allow the same epoch to be overwritten
                            entry.insert((certificate.item.digest, self.current_epoch));
                        }
                        Entry::Vacant(entry) => {
                            entry.insert((certificate.item.digest, self.current_epoch));
                        }
                    }

                    // Update the highest height
                    if self.highest.is_none_or(|(h, _)| certificate.item.index > h) {
                        self.highest = Some((certificate.item.index, self.current_epoch));
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
                    if self.highest.is_none_or(|(h, _)| index > h) {
                        self.highest = Some((index, self.current_epoch));
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
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S, D> crate::Reporter for Mailbox<S, D>
where
    S: Scheme,
    D: Digest,
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Activity::Ack(ack) => {
                self.sender
                    .send(Message::Ack(ack))
                    .await
                    .expect("Failed to send ack");
            }
            Activity::Certified(certificate) => {
                self.sender
                    .send(Message::Certified(certificate))
                    .await
                    .expect("Failed to send certified signature");
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

impl<S, D> Mailbox<S, D>
where
    S: Scheme,
    D: Digest,
{
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
