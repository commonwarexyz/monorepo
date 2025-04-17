use crate::{
    ordered_broadcast::types::{Activity, Chunk, Epoch, Lock, Proposal},
    Reporter as Z,
};
use commonware_cryptography::{bls12381::primitives::group, Digest, Verifier};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::collections::{btree_map::Entry, BTreeMap, HashMap, HashSet};

#[allow(clippy::large_enum_variant)]
enum Message<C: Verifier, D: Digest> {
    Proposal(Proposal<C, D>),
    Locked(Lock<C::PublicKey, D>),
    GetTip(C::PublicKey, oneshot::Sender<Option<(u64, Epoch)>>),
    GetContiguousTip(C::PublicKey, oneshot::Sender<Option<u64>>),
    Get(C::PublicKey, u64, oneshot::Sender<Option<(D, Epoch)>>),
}

pub struct Reporter<C: Verifier, D: Digest> {
    mailbox: mpsc::Receiver<Message<C, D>>,

    // Application namespace
    namespace: Vec<u8>,

    // Public key of the group
    public: group::Public,

    // Notified proposals
    proposals: HashSet<Chunk<C::PublicKey, D>>,
    limit_misses: Option<usize>,

    // All known digests
    digests: HashMap<C::PublicKey, BTreeMap<u64, (D, Epoch)>>,

    // Highest contiguous known height for each sequencer
    contiguous: HashMap<C::PublicKey, u64>,

    // Highest known height (and epoch) for each sequencer
    highest: HashMap<C::PublicKey, (u64, Epoch)>,
}

impl<C: Verifier, D: Digest> Reporter<C, D> {
    pub fn new(
        namespace: &[u8],
        public: group::Public,
        limit_misses: Option<usize>,
    ) -> (Self, Mailbox<C, D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Reporter {
                mailbox: receiver,
                namespace: namespace.to_vec(),
                public,
                proposals: HashSet::new(),
                limit_misses,
                digests: HashMap::new(),
                contiguous: HashMap::new(),
                highest: HashMap::new(),
            },
            Mailbox { sender },
        )
    }

    pub async fn run(mut self) {
        let mut misses = 0;
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Proposal(proposal) => {
                    // Verify properly constructed (not needed in production)
                    if !proposal.verify(&self.namespace) {
                        panic!("Invalid proof");
                    }

                    // Store the proposal
                    self.proposals.insert(proposal.chunk);
                }
                Message::Locked(lock) => {
                    // Verify properly constructed (not needed in production)
                    if !lock.verify(&self.namespace, &self.public) {
                        panic!("Invalid proof");
                    }

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
                        .unwrap_or((0, 0));
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
pub struct Mailbox<C: Verifier, D: Digest> {
    sender: mpsc::Sender<Message<C, D>>,
}

impl<C: Verifier, D: Digest> Z for Mailbox<C, D> {
    type Activity = Activity<C, D>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Activity::Proposal(proposal) => {
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

impl<C: Verifier, D: Digest> Mailbox<C, D> {
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
