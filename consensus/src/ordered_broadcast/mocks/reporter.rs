use crate::{
    ordered_broadcast::{
        scheme,
        types::{Activity, Chunk, Lock, Proposal},
    },
    types::Epoch,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use rand::{CryptoRng, Rng};
use std::collections::{btree_map::Entry, BTreeMap, HashMap, HashSet};

#[allow(clippy::large_enum_variant)]
enum Message<C: PublicKey, S: Scheme, D: Digest> {
    Proposal(Proposal<C, D>),
    Locked(Lock<C, S, D>),
    GetTip(C, oneshot::Sender<Option<(u64, Epoch)>>),
    GetContiguousTip(C, oneshot::Sender<Option<u64>>),
    Get(C, u64, oneshot::Sender<Option<(D, Epoch)>>),
}

pub struct Reporter<R: Rng + CryptoRng, C: PublicKey, S: Scheme, D: Digest> {
    mailbox: mpsc::Receiver<Message<C, S, D>>,

    // RNG used for signature verification with scheme.
    rng: R,

    // Application namespace
    namespace: Vec<u8>,

    // Scheme for verification
    scheme: S,

    // Notified proposals
    proposals: HashSet<Chunk<C, D>>,
    limit_misses: Option<usize>,

    // All known digests
    digests: HashMap<C, BTreeMap<u64, (D, Epoch)>>,

    // Highest contiguous known height for each sequencer
    contiguous: HashMap<C, u64>,

    // Highest known height (and epoch) for each sequencer
    highest: HashMap<C, (u64, Epoch)>,
}

impl<R, C, S, D> Reporter<R, C, S, D>
where
    R: Rng + CryptoRng,
    C: PublicKey,
    S: Scheme,
    D: Digest,
{
    pub fn new(
        rng: R,
        namespace: &[u8],
        scheme: S,
        limit_misses: Option<usize>,
    ) -> (Self, Mailbox<C, S, D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Self {
                rng,
                mailbox: receiver,
                namespace: namespace.to_vec(),
                scheme,
                proposals: HashSet::new(),
                limit_misses,
                digests: HashMap::new(),
                contiguous: HashMap::new(),
                highest: HashMap::new(),
            },
            Mailbox { sender },
        )
    }

    pub async fn run(mut self)
    where
        S: scheme::Scheme<C, D>,
    {
        let mut misses = 0;
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Proposal(proposal) => {
                    // Verify properly constructed (not needed in production)
                    if !proposal.verify(&self.namespace) {
                        panic!("Invalid proof");
                    }

                    // Test encoding/decoding
                    let encoded = proposal.encode();
                    Proposal::<C, D>::decode(encoded).unwrap();

                    // Store the proposal
                    self.proposals.insert(proposal.chunk);
                }
                Message::Locked(lock) => {
                    // Verify properly constructed (not needed in production)
                    if !lock.verify(&mut self.rng, &self.namespace, &self.scheme) {
                        panic!("Invalid proof");
                    }

                    // Test encoding/decoding
                    let encoded = lock.encode();
                    Lock::<C, S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                        .unwrap();

                    // Check if the proposal is known
                    if let Some(misses_allowed) = self.limit_misses {
                        if !self.proposals.contains(&lock.chunk) {
                            misses += 1;
                        }
                        assert!(misses <= misses_allowed, "Missed too many proposals");
                    }

                    // Update the reporter
                    let chunk = lock.chunk;
                    let digests = self.digests.entry(chunk.sequencer.clone()).or_default();
                    let entry = digests.entry(chunk.height);
                    match entry {
                        Entry::Occupied(mut entry) => {
                            // It should never be possible to get a conflicting payload
                            let (existing_payload, existing_epoch) = entry.get();
                            assert_eq!(*existing_payload, chunk.payload);

                            // We may hear about a commitment again, however, this should
                            // only occur if the epoch has changed.
                            assert_ne!(*existing_epoch, lock.epoch);
                            if lock.epoch > *existing_epoch {
                                entry.insert((chunk.payload, lock.epoch));
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert((chunk.payload, lock.epoch));
                        }
                    }

                    // Update the highest height
                    let highest = self
                        .highest
                        .get(&chunk.sequencer)
                        .copied()
                        .unwrap_or((0, Epoch::zero()));
                    if chunk.height > highest.0 {
                        self.highest
                            .insert(chunk.sequencer.clone(), (chunk.height, lock.epoch));
                    }

                    // Update the highest contiguous height
                    let highest = self.contiguous.get(&chunk.sequencer);
                    if (highest.is_none() && chunk.height == 0)
                        || (highest.is_some() && chunk.height == highest.unwrap() + 1)
                    {
                        let mut contiguous = chunk.height;
                        while digests.contains_key(&(contiguous + 1)) {
                            contiguous += 1;
                        }
                        self.contiguous.insert(chunk.sequencer, contiguous);
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
pub struct Mailbox<C: PublicKey, S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<C, S, D>>,
}

impl<C: PublicKey, S: Scheme, D: Digest> crate::Reporter for Mailbox<C, S, D> {
    type Activity = Activity<C, S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Activity::Tip(proposal) => {
                self.sender
                    .send(Message::Proposal(proposal))
                    .await
                    .expect("Failed to send proposal");
            }
            Activity::Lock(lock) => {
                self.sender
                    .send(Message::Locked(lock))
                    .await
                    .expect("Failed to send locked");
            }
        }
    }
}

impl<C: PublicKey, S: Scheme, D: Digest> Mailbox<C, S, D> {
    pub async fn get_tip(&mut self, sequencer: C) -> Option<(u64, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get_contiguous_tip(&mut self, sequencer: C) -> Option<u64> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::GetContiguousTip(sequencer, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn get(&mut self, sequencer: C, height: u64) -> Option<(D, Epoch)> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get(sequencer, height, sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
