//! Backfill missing proposals seen in consensus.

use super::{utils::proposal_digest, wire};
use crate::{Application, Hash, Height, Payload, View, HASH_LENGTH};
use commonware_cryptography::PublicKey;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock, Spawner};
use commonware_utils::{hash, hex};
use core::panic;
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
};
use futures::{SinkExt, StreamExt};
use prost::Message as _;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, warn};

pub enum Message {
    Propose {
        response: oneshot::Sender<Option<(Hash, Height, Hash, Payload)>>,
    },
    Parse {
        parent: Hash,
        height: Height,
        payload: Payload,
        response: oneshot::Sender<Option<Hash>>,
    },
    Verify {
        hash: Hash,
        proposal: wire::Proposal,
        response: oneshot::Sender<bool>,
    },
    Notarized {
        proposal: Proposal,
    },
    Finalized {
        proposal: Proposal,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn propose(&mut self) -> Option<(Hash, Height, Hash, Payload)> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { response: sender })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn parse(&mut self, parent: Hash, height: Height, payload: Payload) -> Option<Hash> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Parse {
                parent,
                height,
                payload,
                response: sender,
            })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn verify(&mut self, hash: Hash, proposal: wire::Proposal) -> bool {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify {
                hash,
                proposal,
                response: sender,
            })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn notarized(&mut self, proposal: Proposal) {
        self.sender
            .send(Message::Notarized { proposal })
            .await
            .unwrap();
    }

    pub async fn finalized(&mut self, proposal: Proposal) {
        self.sender
            .send(Message::Finalized { proposal })
            .await
            .unwrap();
    }
}

#[derive(Clone)]
pub enum Proposal {
    Reference(View, Height, Hash),
    Populated(Hash, wire::Proposal),
}

#[derive(Clone)]
enum Knowledge {
    Notarized(BTreeMap<View, Hash>), // priotize building off of earliest view (avoid wasting work)
    Finalized(Hash),
}

pub struct Orchestrator<E: Clock + Rng + Spawner, A: Application> {
    runtime: E,
    application: A,

    fetch_timeout: Duration,
    max_fetch_count: u64,
    max_fetch_size: usize,

    mailbox_receiver: mpsc::Receiver<Message>,

    validators: BTreeMap<View, Vec<PublicKey>>,

    knowledge: HashMap<Height, Knowledge>,
    blocks: HashMap<Hash, wire::Proposal>,

    // Track verifications
    //
    // We never verify the same block twice.
    verified: HashMap<Height, HashSet<Hash>>,

    // Track notarization/finalization
    last_notarized: Height,
    last_finalized: Height,

    // Fetch missing proposals
    missing: HashMap<Hash, Height>,
    missing_sender: mpsc::Sender<(Height, Hash)>,
    missing_receiver: mpsc::Receiver<(Height, Hash)>,

    // Track last notifications
    //
    // We only increase this once we notify of finalization at some height.
    // It is not guaranteed that we will notify every notarization (may just be finalizes).
    notarizations_sent: HashMap<Height, HashSet<Hash>>,
    last_notified: Height,
}

// Sender/Receiver here are different than one used in consensus (separate rate limits and compression settings).
impl<E: Clock + Rng + Spawner, A: Application> Orchestrator<E, A> {
    pub fn new(
        runtime: E,
        mut application: A,
        fetch_timeout: Duration,
        max_fetch_count: u64,
        max_fetch_size: usize,
        validators: BTreeMap<View, Vec<PublicKey>>,
    ) -> (Self, Mailbox) {
        // Create genesis block and store it
        let mut verified = HashMap::new();
        let mut knowledge = HashMap::new();
        let mut blocks = HashMap::new();
        let genesis = application.genesis();
        verified.insert(0, HashSet::from([genesis.0.clone()]));
        knowledge.insert(0, Knowledge::Finalized(genesis.0.clone()));

        blocks.insert(
            genesis.0.clone(),
            wire::Proposal {
                view: 0,
                height: 0,
                parent: Hash::new(),
                payload: genesis.1,
                signature: None,
            },
        );

        // Initialize mailbox
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1024);
        let (missing_sender, missing_receiver) = mpsc::channel(1024);
        (
            Self {
                runtime,
                application,

                fetch_timeout,
                max_fetch_count,
                max_fetch_size,

                mailbox_receiver,

                validators,

                knowledge,
                blocks,

                verified,

                last_notarized: 0,
                last_finalized: 0,

                missing: HashMap::new(),
                missing_sender,
                missing_receiver,

                notarizations_sent: HashMap::new(),
                last_notified: 0,
            },
            Mailbox::new(mailbox_sender),
        )
    }

    async fn register_missing(&mut self, height: Height, hash: Hash) {
        // Check if we have the proposal
        if self.blocks.contains_key(&hash) {
            return;
        }

        // Check if have already registered
        if self.missing.contains_key(&hash) {
            return;
        }
        self.missing.insert(hash.clone(), height);
        debug!(height, parent = hex(&hash), "registered missing proposal");

        // Enqueue missing proposal for fetching
        self.missing_sender.send((height, hash)).await.unwrap();
    }

    fn resolve(&mut self, proposal: Proposal) -> Option<(Height, Hash)> {
        // Parse proposal
        let (hash, proposal) = match proposal {
            Proposal::Reference(_, height, hash) => {
                if self.blocks.contains_key(&hash) {
                    return None;
                }
                return Some((height, hash));
            }
            Proposal::Populated(hash, proposal) => (hash, proposal),
        };

        // If already resolved, do nothing.
        if self.blocks.contains_key(&hash) {
            return None;
        }

        // Remove from missing
        if self.missing.remove(&hash).is_some() {
            debug!(
                height = proposal.height,
                hash = hex(&hash),
                "resolved missing proposal"
            );
        }

        // Record what we learned
        match self.knowledge.entry(proposal.height) {
            Entry::Vacant(e) => {
                if proposal.height > self.last_finalized {
                    let mut seen = BTreeMap::new();
                    seen.insert(proposal.view, hash.clone());
                    e.insert(Knowledge::Notarized(seen));
                } else {
                    e.insert(Knowledge::Finalized(hash.clone()));
                }
            }
            Entry::Occupied(_) => {}
        }

        // Store proposal
        let height = proposal.height;
        let parent = proposal.parent.clone();
        self.blocks.insert(hash, proposal);

        // Check if parent is missing
        if self.blocks.contains_key(&parent) {
            return None;
        }
        Some((height - 1, parent))
    }

    fn notify(&mut self) {
        // Notify application of all finalized proposals
        let mut next = self.last_notified + 1;
        loop {
            // Get info
            let knowledge = match self.knowledge.get(&next).cloned() {
                Some(knowledge) => knowledge,
                None => {
                    // No more blocks to notify
                    return;
                }
            };

            // Send event
            match knowledge {
                Knowledge::Notarized(hashes) => {
                    // Send fulfilled unsent notarizations
                    for (_, hash) in hashes {
                        let already_notified = self
                            .notarizations_sent
                            .get(&next)
                            .map_or(false, |notifications| notifications.contains(&hash));
                        if already_notified {
                            continue;
                        }
                        let proposal = match self.blocks.get(&hash) {
                            Some(proposal) => proposal,
                            None => {
                                continue;
                            }
                        };
                        if !self.verify(hash.clone(), proposal.clone()) {
                            debug!(
                                height = next,
                                hash = hex(&hash),
                                "failed to verify notarized proposal"
                            );
                            continue;
                        }
                        self.notarizations_sent
                            .entry(next)
                            .or_default()
                            .insert(hash.clone());
                        self.application.notarized(hash.clone());
                    }
                }
                Knowledge::Finalized(hash) => {
                    let proposal = match self.blocks.get(&hash) {
                        Some(proposal) => proposal,
                        None => {
                            debug!(
                                height = next,
                                hash = hex(&hash),
                                "missing finalized proposal, exiting backfill"
                            );
                            return;
                        }
                    };
                    if !self.verify(hash.clone(), proposal.clone()) {
                        debug!(
                            height = next,
                            hash = hex(&hash),
                            "failed to verify finalized proposal"
                        );
                        return;
                    }
                    self.verified.remove(&(next - 1)); // parent of finalized must be accessible
                    self.notarizations_sent.remove(&next);
                    self.last_notified = next;
                    self.application.finalized(hash.clone());
                }
            }

            // Update next
            next += 1;
        }
    }

    // TODO: no guarantee this approach will ensure we load off verified
    fn best_parent(&self) -> Option<(Hash, Height)> {
        // Find highest block that we have notified the application of
        let mut next = self.last_notarized;
        loop {
            match self.knowledge.get(&next) {
                Some(Knowledge::Notarized(hashes)) => {
                    // Find earliest view that we also sent notification for
                    for (_, hash) in hashes.iter() {
                        if let Some(notifications) = self.notarizations_sent.get(&next) {
                            if notifications.contains(hash) {
                                return Some((hash.clone(), self.blocks.get(hash).unwrap().height));
                            }
                        }
                    }
                }
                Some(Knowledge::Finalized(hash)) => {
                    if self.last_notified >= next {
                        return Some((hash.clone(), self.blocks.get(hash).unwrap().height));
                    }
                }
                None => return None,
            }

            // Update next
            if next == 0 {
                return None;
            }
            next -= 1;
        }
    }

    pub fn propose(&mut self) -> Option<(Hash, Height, Hash, Payload)> {
        // If don't have ancestry to last notarized block fulfilled, do nothing.
        let parent = match self.best_parent() {
            Some(parent) => parent,
            None => {
                return None;
            }
        };

        // Propose block
        let height = parent.1 + 1;
        let payload = match self.application.propose(parent.0.clone(), height) {
            Some(payload) => payload,
            None => {
                return None;
            }
        };

        let payload_hash = self
            .application
            .parse(parent.0.clone(), height, payload.clone())
            .unwrap();

        // Generate proposal
        Some((parent.0, height, payload_hash, payload))
    }

    pub fn parse(&self, parent: Hash, height: Height, payload: Payload) -> Option<Hash> {
        self.application.parse(parent, height, payload)
    }

    fn valid_ancestry(&self, proposal: &wire::Proposal) -> bool {
        // Check if we have the parent
        let parent = self.blocks.get(&proposal.parent);
        if parent.is_none() {
            debug!(
                height = proposal.height,
                parent_hash = hex(&proposal.parent),
                "missing parent"
            );
            return false;
        }
        let parent = parent.unwrap();

        // Check if parent has been verified
        if let Some(hashes) = self.verified.get(&parent.height) {
            if hashes.contains(&proposal.parent) {
                return true;
            }
        }
        debug!(
            height = proposal.height,
            parent_hash = hex(&proposal.parent),
            "parent not verified"
        );
        false
    }

    pub fn verify(&mut self, hash: Hash, proposal: wire::Proposal) -> bool {
        // If already verified, do nothing
        if self
            .verified
            .get(&proposal.height)
            .map_or(false, |hashes| hashes.contains(&hash))
        {
            return true;
        }

        // If don't have ancestry yet, do nothing.
        if !self.valid_ancestry(&proposal) {
            // If we return false here, don't vote but don't discard the proposal (as may eventually still be finalized).
            debug!(
                height = proposal.height,
                parent_hash = hex(&proposal.parent),
                "invalid ancestry"
            );
            return false;
        }

        // Verify payload
        if self.application.verify(
            proposal.parent.clone(),
            proposal.height,
            proposal.payload.clone(),
            hash.clone(),
        ) {
            debug!(
                height = proposal.height,
                hash = hex(&hash),
                "verified proposal"
            );
            // Record verification
            let entry = self.verified.entry(proposal.height).or_default();
            entry.insert(hash);
            return true;
        }
        false
    }

    pub async fn notarized(&mut self, proposal: Proposal) {
        // Extract height and hash
        let (view, height, hash) = match &proposal {
            Proposal::Reference(view, height, hash) => (*view, *height, hash.clone()),
            Proposal::Populated(hash, proposal) => (proposal.view, proposal.height, hash.clone()),
        };

        // Set last notarized
        if height > self.last_notarized {
            self.last_notarized = height;
        }

        // Insert lock if doesn't already exist
        let previous = self.knowledge.get_mut(&height);
        match previous {
            Some(Knowledge::Notarized(seen)) => {
                if let Some(old_hash) = seen.get(&view) {
                    if *old_hash != hash {
                        panic!("notarized block hash mismatch");
                    }
                    return;
                }
                seen.insert(view, hash.clone());
            }
            Some(Knowledge::Finalized(_)) => {
                // Already finalized, do nothing
                return;
            }
            None => {
                let mut seen = BTreeMap::new();
                seen.insert(view, hash.clone());
                self.knowledge.insert(height, Knowledge::Notarized(seen));
            }
        }

        // Mark as seen
        if let Some((height, hash)) = self.resolve(proposal) {
            self.register_missing(height, hash).await;
        }

        // Notify application
        self.notify();
    }

    pub async fn finalized(&mut self, proposal: Proposal) {
        // Extract height and hash
        let (height, mut hash) = match &proposal {
            Proposal::Reference(_, height, hash) => (*height, hash.clone()),
            Proposal::Populated(hash, proposal) => (proposal.height, hash.clone()),
        };

        // Set last finalized
        if height > self.last_finalized {
            self.last_finalized = height;
        }

        // Finalize all locks we have that are ancestors of this block
        let mut next = height;
        loop {
            let previous = self.knowledge.get_mut(&next);
            match previous {
                Some(Knowledge::Notarized(hashes)) => {
                    // Remove unnecessary proposals from memory
                    for (_, old_hash) in hashes.iter() {
                        if old_hash != &hash {
                            self.blocks.remove(old_hash);
                            debug!(
                                height,
                                hash = hex(old_hash),
                                "removing unnecessary proposal"
                            );
                        }
                    }

                    // Store finalized block record
                    self.knowledge
                        .insert(height, Knowledge::Finalized(hash.clone()));

                    // Update value of hash to be parent of this block
                    if let Some(parent) = self.blocks.get(&hash) {
                        hash = parent.parent.clone();
                    } else {
                        // If we don't know the parent, we can't finalize any ancestors
                        break;
                    }
                }
                Some(Knowledge::Finalized(seen)) => {
                    if *seen != hash {
                        panic!("finalized block hash mismatch");
                    }
                    break;
                }
                None => {
                    self.knowledge
                        .insert(next, Knowledge::Finalized(hash.clone()));

                    // Attempt to keep recursing backwards until hit a finalized block or 0
                    if let Some(parent) = self.blocks.get(&hash) {
                        hash = parent.parent.clone();
                    } else {
                        break;
                    }
                }
            }

            // Update next
            if next == 0 {
                break;
            }
            next -= 1;
        }

        // Mark as seen
        if let Some((height, hash)) = self.resolve(proposal) {
            self.register_missing(height, hash).await;
        }

        // Notify application
        self.notify();
    }

    fn get_next_missing(&mut self) -> Option<(Height, Hash)> {
        loop {
            // See if we have any missing proposals
            let (height, hash) = match self.missing_receiver.try_next() {
                Ok(res) => res.unwrap(),
                Err(_) => return None,
            };

            // Check if still unfulfilled
            if self.blocks.contains_key(&hash) {
                continue;
            }

            // Return missing proposal
            return Some((height, hash));
        }
    }

    async fn send_request(
        &mut self,
        height: Height,
        hash: Hash,
        sender: &mut impl Sender,
    ) -> PublicKey {
        // Get validators from highest view we know about
        let (view, validators) = self
            .validators
            .range(..=self.last_notarized)
            .next_back()
            .expect("validators do not cover range of allowed views");

        // Select random validator to fetch from
        let validator = validators.choose(&mut self.runtime).unwrap().clone();

        // Compute missing blocks from hash
        let mut parents = 0;
        loop {
            // Check to see if we are already at root
            let target = height - parents;
            if target == 1 || parents + 1 == self.max_fetch_count {
                break;
            }

            // Check to see if we know anything about the height
            if let Some(knowledge) = self.knowledge.get(&target) {
                match knowledge {
                    Knowledge::Notarized(_) => {
                        // We only want to batch fill finalized data
                        break;
                    }
                    Knowledge::Finalized(hash) => {
                        if self.blocks.contains_key(hash) {
                            // We have a block and no longer need to fetch its parent
                            break;
                        }
                    }
                }
            }

            // If we have no knowledge of a height, we need to fetch it
            parents += 1;
        }

        // Send the request
        debug!(
            height,
            hash = hex(&hash),
            peer = hex(&validator),
            parents,
            validator_view = view,
            "requesting missing proposal"
        );
        let msg = wire::Backfill {
            payload: Some(wire::backfill::Payload::Request(wire::Request {
                hash,
                parents,
            })),
        }
        .encode_to_vec()
        .into();

        // Send message
        sender
            .send(Recipients::One(validator.clone()), msg, true)
            .await
            .unwrap();
        validator
    }

    // This is a pretty basic backfiller (in that it only attempts to resolve one missing
    // proposal at a time). In `tbd`, this will operate very differently because we can
    // verify the integrity of any proposal we receive at an index by the threshold signature.
    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        let mut outstanding_task = None;
        loop {
            // Ensure task has not been resolved
            if let Some((_, ref height, ref hash, _)) = outstanding_task {
                if self.blocks.contains_key(hash) {
                    debug!(
                        height,
                        hash = hex(hash),
                        "unexpeted resolution of missing proposal out of backfill"
                    );
                    outstanding_task = None;
                }
            }

            // Look for next task if nothing
            if outstanding_task.is_none() {
                let missing = self.get_next_missing();
                if let Some((height, hash)) = missing {
                    // Check if already have
                    if self.blocks.contains_key(&hash) {
                        continue;
                    }

                    // Send request
                    let validator = self.send_request(height, hash.clone(), &mut sender).await;

                    // Set timeout
                    debug!(
                        height,
                        hash = hex(&hash),
                        peer = hex(&validator),
                        "requesting missing proposal"
                    );
                    outstanding_task = Some((
                        validator,
                        height,
                        hash,
                        self.runtime.current() + self.fetch_timeout,
                    ));
                }
            };

            // Avoid arbitrarily long sleep
            let missing_timeout = if let Some((_, _, _, ref deadline)) = outstanding_task {
                Either::Left(self.runtime.sleep_until(*deadline))
            } else {
                Either::Right(futures::future::pending())
            };

            // Wait for an event
            select! {
                _task_timeout = missing_timeout => {
                    // Send request again
                    let (_, height, hash, _)= outstanding_task.take().unwrap();
                    let validator = self.send_request(height, hash.clone(), &mut sender).await;

                    // Reset timeout
                    outstanding_task = Some((validator, height, hash, self.runtime.current() + self.fetch_timeout));
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Propose { response } => {
                            let proposal = self.propose();
                            response.send(proposal).unwrap();
                        }
                        Message::Parse { parent, height, payload, response } => {
                            let hash = self.parse(parent, height, payload);
                            response.send(hash).unwrap();
                        }
                        Message::Verify { hash, proposal, response } => {
                            // If proposal height is already finalized, fail
                            //
                            // We will only verify old proposals via notify loop.
                            if proposal.height <= self.last_finalized {
                                debug!(
                                    height = proposal.height,
                                    finalized = self.last_finalized,
                                    "already finalized"
                                );
                                response.send(false).unwrap();
                                continue;
                            }

                            // Attempt to verify proposal
                            response.send(self.verify(hash, proposal)).unwrap();
                        }
                        Message::Notarized { proposal } => self.notarized(proposal).await,
                        Message::Finalized { proposal } => self.finalized(proposal).await,
                    };
                },
                network = receiver.recv() => {
                    let (s, msg) = network.unwrap();
                    let msg = match wire::Backfill::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, sender = hex(&s), "failed to decode message");
                            continue;
                        }
                    };
                    let payload = match msg.payload {
                        Some(payload) => payload,
                        None => {
                            warn!(sender = hex(&s), "message missing payload");
                            continue;
                        }
                    };
                    match payload {
                        wire::backfill::Payload::Request(request) => {
                            // Confirm request is valid
                            if request.hash.len() != HASH_LENGTH {
                                warn!(sender = hex(&s), "invalid request hash size");
                                continue;
                            }

                            // Populate as many proposals as we can
                            let mut proposal_bytes = 0; // TODO: add a buffer
                            let mut proposals = Vec::new();
                            let mut cursor = request.hash.clone();
                            loop {
                                // Check to see if we have proposal
                                let proposal = match self.blocks.get(&cursor).cloned() {
                                    Some(proposal) => proposal,
                                    None => {
                                        break;
                                    }
                                };

                                // If we don't have any more space, stop
                                proposal_bytes += proposal.encoded_len();
                                if proposal_bytes > self.max_fetch_size {
                                    debug!(
                                        requested = request.parents + 1,
                                        found = proposals.len(),
                                        peer = hex(&s),
                                        "reached max response size",
                                    );
                                    break;
                                }

                                // If we do have space, add to proposals
                                cursor = proposal.parent.clone();
                                proposals.push(proposal);

                                // If we have all parents requested, stop gathering more
                                let fetched = proposals.len() as u64;
                                if fetched == request.parents + 1 || fetched == self.max_fetch_count {
                                    break;
                                }
                            }

                            // Send messages
                            debug!(hash = hex(&request.hash), requested = request.parents + 1, found = proposals.len(), peer = hex(&s), "responding to backfill request");
                            let msg = match proposals.len() {
                                0 => wire::Backfill {
                                    payload: Some(wire::backfill::Payload::Missing(wire::Missing {
                                        hash: request.hash,
                                    })),
                                },
                                _ => wire::Backfill {
                                    payload: Some(wire::backfill::Payload::Resolution(wire::Resolution {
                                        proposals,
                                    })),
                                },
                            };
                            sender.send(Recipients::One(s), msg.encode_to_vec().into(), false).await.unwrap();
                        }
                        wire::backfill::Payload::Missing(missing) => {
                            if missing.hash.len() != HASH_LENGTH {
                                warn!(sender = hex(&s), "invalid missing hash size");
                                continue;
                            }
                            if let Some(ref outstanding) = outstanding_task {
                                let hash = outstanding.2.clone();
                                if outstanding.0 == s && hash == missing.hash {
                                    debug!(hash = hex(&missing.hash), peer = hex(&s), "peer missing proposal");

                                    // Send request again
                                    let validator = self.send_request(outstanding.1, hash.clone(), &mut sender).await;

                                    // Reset timeout
                                    outstanding_task = Some((validator, outstanding.1, hash, self.runtime.current() + Duration::from_secs(1)));
                                }
                            }
                        }
                        wire::backfill::Payload::Resolution(resolution) => {
                            // Parse proposals
                            let mut next = None;
                            for proposal in resolution.proposals {
                                if proposal.parent.len() != HASH_LENGTH {
                                    warn!(sender = hex(&s), "invalid proposal parent hash size");
                                    break;
                                }
                                let payload_hash = match self.application.parse(proposal.parent.clone(), proposal.height, proposal.payload.clone()) {
                                    Some(payload_hash) => payload_hash,
                                    None => {
                                        warn!(sender = hex(&s), "unable to parse notarized/finalized payload");
                                        break;
                                    }
                                };
                                let incoming_hash = hash(&proposal_digest(
                                    proposal.view,
                                    proposal.height,
                                    &proposal.parent,
                                    &payload_hash,
                                ));

                                // Ensure this is the block we want
                                if let Some((height, ref hash)) = next {
                                    if proposal.height != height || incoming_hash != hash {
                                        warn!(sender = hex(&s), "received invalid batch proposal");
                                        break;
                                    }
                                }

                                // Record the proposal
                                let height = proposal.height;
                                debug!(height, hash = hex(&incoming_hash), peer = hex(&s), "received proposal via backfill");
                                let proposal = Proposal::Populated(incoming_hash.clone(), proposal.clone());
                                next = self.resolve(proposal);

                                // Remove outstanding task if we were waiting on this
                                //
                                // Note, we don't care if we are sent the proposal from someone unexpected (although
                                // this is unexpected).
                                if let Some(ref outstanding) = outstanding_task {
                                    if outstanding.2 == incoming_hash {
                                        debug!(height = outstanding.1, hash = hex(&incoming_hash), peer = hex(&s), "resolved missing proposal via backfill");
                                        outstanding_task = None;
                                    }
                                }

                                // Notify application if we can
                                self.notify();

                                // Stop processing if we don't need anything else
                                if next.is_none() {
                                    break;
                                }
                            }

                            // Notify missing if next is not none
                            if let Some((height, hash)) = next {
                                // By waiting to register missing until the end, we avoid a bunch of unnecessary
                                // backfill request additions.
                                self.register_missing(height, hash).await;
                            }
                        }
                    }
                },
            }
        }
    }
}
