//! Backfill missing proposals seen in consensus.

use super::{
    voter::{hash, proposal_digest},
    wire,
};
use crate::{Application, Hash, Height, Payload, View};
use commonware_cryptography::{utils::hex, PublicKey};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock, Spawner};
use core::panic;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use prost::Message as _;
use rand::seq::SliceRandom;
use rand::Rng;
use std::time::Duration;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::SystemTime,
};
use tracing::{debug, warn};

pub enum Message {
    Propose {
        response: oneshot::Sender<Option<((Hash, wire::Proposal), (Hash, Payload))>>,
    },
    Parse {
        payload: Payload,
        response: oneshot::Sender<Option<Hash>>,
    },
    Verify {
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

    pub async fn propose(&mut self) -> Option<((Hash, wire::Proposal), (Hash, Payload))> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { response: sender })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn parse(&mut self, payload: Payload) -> Option<Hash> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Parse {
                payload,
                response: sender,
            })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn verify(&mut self, proposal: wire::Proposal) -> bool {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify {
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

// TODO: change name from `Lock` to something else (only finalization is really a lock)
enum Lock {
    Notarized(BTreeMap<View, Hash>), // priotize building off of earliest view (avoid wasting work)
    Finalized(Hash),
}

pub struct Orchestrator<E: Clock + Rng + Spawner, A: Application> {
    runtime: E,
    application: A,

    mailbox_receiver: mpsc::Receiver<Message>,

    validators: Vec<PublicKey>,

    locked: HashMap<Height, Lock>,
    blocks: HashMap<Hash, wire::Proposal>,

    // Track notarization/finalization
    last_notarized: Height,
    last_finalized: Height,

    // Fetch missing proposals
    missing_sender: mpsc::Sender<Hash>,
    missing_receiver: mpsc::Receiver<Hash>,

    // Track last notifications
    //
    // We only increase this once we notify of finalization at some height.
    // It is not guaranteed that we will notify every notarization (may just be finalizes).
    notarizations_sent: HashMap<Height, HashSet<Hash>>,
    last_notified: Height,
}

// Sender/Receiver here are different than one used in consensus (separate rate limits and compression settings).
impl<E: Clock + Rng + Spawner, A: Application> Orchestrator<E, A> {
    pub fn new(runtime: E, application: A, mut validators: Vec<PublicKey>) -> (Self, Mailbox) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1024);
        let (missing_sender, missing_receiver) = mpsc::channel(1024);
        validators.sort();
        (
            Self {
                runtime,
                application,

                mailbox_receiver,

                validators,

                locked: HashMap::new(),
                blocks: HashMap::new(),

                last_notarized: 0,
                last_finalized: 0,

                missing_sender,
                missing_receiver,

                notarizations_sent: HashMap::new(),
                last_notified: 0,
            },
            Mailbox::new(mailbox_sender),
        )
    }

    // TODO: base this off of notarized/finalized (don't want to build index until finalized data, could
    // have a separate index for notarized blocks by view and another for finalized blocks by height)
    async fn resolve(&mut self, hash: Hash, proposal: wire::Proposal) {
        // If already resolved, do nothing.
        if self.blocks.contains_key(&hash) {
            return;
        }

        // Record what we know
        if self.locked.get(&proposal.height).is_none() {
            if proposal.height < self.last_finalized {
                let mut seen = BTreeMap::new();
                seen.insert(proposal.view, hash.clone());
                self.locked.insert(proposal.height, Lock::Notarized(seen));
            } else {
                self.locked
                    .insert(proposal.height, Lock::Finalized(hash.clone()));
            }
        }

        // Store proposal
        let parent = proposal.parent.clone();
        self.blocks.insert(hash, proposal);

        // Check if we are missing the parent
        if parent.len() > 0 && !self.blocks.contains_key(&parent) {
            self.missing_sender.send(parent).await.unwrap();
            return;
        }
    }

    fn notify(&mut self) {
        // Notify application of all finalized proposals
        let mut next = self.last_notified;
        loop {
            // Get lock info
            let lock = match self.locked.get(&next) {
                Some(lock) => lock,
                None => {
                    // No more blocks to notify
                    return;
                }
            };

            // Send event
            match lock {
                Lock::Notarized(hashes) => {
                    // Send fulfilled unsent notarizations
                    let notifications = self.notarizations_sent.entry(next).or_default();
                    for (_, hash) in hashes.iter() {
                        if notifications.contains(hash) {
                            continue;
                        }
                        let proposal = match self.blocks.get(hash) {
                            Some(proposal) => proposal,
                            None => continue,
                        };
                        notifications.insert(hash.clone());
                        self.application.notarized(proposal.payload.clone());
                    }
                }
                Lock::Finalized(hash) => {
                    // Send finalized blocks as soon as we have them
                    let proposal = match self.blocks.get(hash) {
                        Some(proposal) => proposal,
                        None => {
                            return;
                        }
                    };
                    self.application.finalized(proposal.payload.clone());
                    self.notarizations_sent.remove(&self.last_notified);
                    self.last_notified += 1;
                }
            }

            // Update next
            next += 1;
        }
    }

    async fn seen(&mut self, proposal: Proposal) {
        match proposal {
            Proposal::Reference(_, _, hash) => {
                // Check to see if we have the proposal
                if self.blocks.contains_key(&hash) {
                    return;
                }

                // Record that we are missing the view
                self.missing_sender.send(hash.clone()).await.unwrap();
            }
            Proposal::Populated(hash, proposal) => self.resolve(hash, proposal).await,
        }
    }

    // This is a pretty basic backfiller (in that it only attempts to resolve one missing
    // proposal at a time). In `tbd`, this will operate very differently because we can
    // verify the integrity of any proposal we receive at an index by the threshold signature.
    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        let mut outstanding_task = (None, SystemTime::UNIX_EPOCH + Duration::MAX);
        loop {
            // Check to see if we should add a task
            if outstanding_task.0.is_none() {
                let missing = self.missing_receiver.try_next();
                if let Ok(res) = missing {
                    let request = res.unwrap();

                    // Select random validator to fetch from
                    let validator = self.validators.choose(&mut self.runtime).unwrap().clone();

                    // Send the request
                    let msg = wire::Request {
                        hash: request.clone(),
                    }
                    .encode_to_vec()
                    .into();

                    // Send message
                    sender
                        .send(Recipients::One(validator.clone()), msg, true)
                        .await
                        .unwrap();

                    // Set timeout
                    outstanding_task = (
                        Some(request),
                        self.runtime.current() + Duration::from_secs(1),
                    );
                }
            }

            // Wait for an event
            select! {
                _task_timeout = self.runtime.sleep_until(outstanding_task.1) => {
                    // Request from another random validator
                    let validator = self.validators.choose(&mut self.runtime).unwrap().clone();

                    // Send the request
                    let request = outstanding_task.0.unwrap();
                    let msg = wire::Request {
                        hash: request.clone(),
                    }
                    .encode_to_vec()
                    .into();

                    // Send message
                    sender
                        .send(Recipients::One(validator.clone()), msg, true)
                        .await
                        .unwrap();

                    // Reset timeout
                    outstanding_task = (Some(request), self.runtime.current() + Duration::from_secs(1));
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Propose { response } => {
                            let proposal = match self.propose() {
                                Some(proposal) => proposal,
                                None => {
                                    response.send(None).unwrap();
                                    continue;
                                }
                            };
                            response.send(Some(proposal)).unwrap();
                        }
                        Message::Parse { payload, response } => {
                            let hash = self.application.parse(payload);
                            response.send(hash).unwrap();
                        }
                        Message::Verify { proposal, response } => {
                            let valid = self.verify(proposal);
                            response.send(valid).unwrap();
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
                            let proposal = self.blocks.get(&request.hash).cloned();
                            let msg = wire::Resolution {
                                proposal,
                            }.encode_to_vec().into();
                            sender.send(Recipients::One(s), msg, false).await.unwrap();
                        }
                        wire::backfill::Payload::Resolution(resolution) => {
                            // Parse proposal
                            let proposal = match resolution.proposal {
                                Some(proposal) => proposal,
                                None => {
                                    warn!(sender = hex(&s), "resolution missing proposal");
                                    continue;
                                }
                            };
                            let payload_hash = match self.application.parse(proposal.payload.clone()) {
                                Some(payload_hash) => payload_hash,
                                None => {
                                    warn!(sender = hex(&s), "unable to parse notarized/finalized payload");
                                    continue;
                                }
                            };
                            let incoming_hash = hash(proposal_digest(
                                proposal.view,
                                proposal.height,
                                proposal.parent.clone(),
                                payload_hash,
                            ));

                            // Check if we were expecting this hash
                            //
                            // It is ok if we get something we don't need, we may have gotten
                            // what we need from a variety of other places.
                            match self.locked.get(&proposal.height) {
                                Some(Lock::Notarized(seen)) => {
                                    let entry = seen.get(&proposal.view);
                                    if entry.is_none() {
                                        warn!(
                                            sender = hex(&s),
                                            height = proposal.height,
                                            "unexpected block hash on resolution"
                                        );
                                        continue;
                                    }
                                    if entry.unwrap() != &incoming_hash {
                                        warn!(
                                            sender = hex(&s),
                                            height = proposal.height,
                                            "unexpected block hash on resolution"
                                        );
                                        continue;
                                    }
                                }
                                Some(Lock::Finalized(expected)) => {
                                    if incoming_hash != *expected {
                                        warn!(
                                            sender = hex(&s),
                                            height = proposal.height,
                                            "unexpected block hash on resolution"
                                        );
                                        continue;
                                    }
                                }
                                None => {
                                    warn!(
                                        sender = hex(&s),
                                        height = proposal.height,
                                        "unexpected block hash"
                                    );
                                    continue;
                                }
                            }

                            // Check to see if we already have this proposal
                            if self.blocks.contains_key(&incoming_hash) {
                                debug!(
                                    sender = hex(&s),
                                    height = proposal.height,
                                    "block already resolved"
                                );
                                continue;
                            }

                            // Record the proposal
                            self.resolve(incoming_hash.clone(), proposal).await;

                            // Notify application if we can
                            self.notify();

                            // If incoming hash was our task, exit the loop
                            if let Some(request) = outstanding_task.0 {
                                debug!(
                                    request = hex(&request),
                                    sender = hex(&s),
                                    "backfill resolution"
                                );
                                outstanding_task = (None, SystemTime::UNIX_EPOCH + Duration::MAX);
                            }
                        }
                    }
                },
            }
        }
    }

    fn best_parent(&self) -> Option<(Hash, wire::Proposal)> {
        // Find highest block that we have notified the application of
        let mut next = self.last_notarized;
        loop {
            match self.locked.get(&next) {
                Some(Lock::Notarized(hashes)) => {
                    // Find earliest view that we also sent notification for
                    for (_, hash) in hashes.iter() {
                        if let Some(notifications) = self.notarizations_sent.get(&next) {
                            if notifications.contains(hash) {
                                return Some((
                                    hash.clone(),
                                    self.blocks.get(hash).unwrap().clone(),
                                ));
                            }
                        }
                    }
                }
                Some(Lock::Finalized(hash)) => {
                    if self.last_notified >= next {
                        return Some((hash.clone(), self.blocks.get(hash).unwrap().clone()));
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

    // Simplified application functions
    pub fn propose(&mut self) -> Option<((Hash, wire::Proposal), (Hash, Payload))> {
        // If don't have ancestry to last notarized block fulfilled, do nothing.
        let parent = match self.best_parent() {
            Some(parent) => parent,
            None => {
                return None;
            }
        };

        // Propose block
        //
        // TODO: provide more info to application
        let payload = match self.application.propose(parent.1.payload.clone()) {
            Some(payload) => payload,
            None => {
                return None;
            }
        };

        let payload_hash = self.application.parse(payload.clone()).unwrap();

        // Generate proposal
        Some((parent, (payload_hash, payload)))
    }

    pub fn parse(&self, payload: Payload) -> Option<Hash> {
        self.application.parse(payload)
    }

    fn valid_ancestry(&self, proposal: &wire::Proposal) -> bool {
        // Check if we have the parent
        if !self.blocks.contains_key(&proposal.parent) {
            return false;
        }

        // If proposal height is already finalized, fail
        if proposal.height <= self.last_finalized {
            return false;
        }

        // Get parent
        let parent = match self.blocks.get(&proposal.parent) {
            Some(parent) => parent,
            None => return false,
        };

        // Check if parent is notarized or finalized and that the application
        // has been notified of the parent (ancestry is processed)
        match self.locked.get(&parent.height) {
            Some(Lock::Notarized(hashes)) => {
                if !hashes.contains_key(&parent.view) {
                    return false;
                }
                let notifications = match self.notarizations_sent.get(&parent.height) {
                    Some(notifications) => notifications,
                    None => return false,
                };
                notifications.contains(&parent.parent)
            }
            Some(Lock::Finalized(hash)) => {
                if parent.parent != *hash {
                    return false;
                }
                self.last_notified >= parent.height
            }
            None => false,
        }
    }

    pub fn verify(&self, proposal: wire::Proposal) -> bool {
        // If don't have ancestry yet, do nothing.
        if !self.valid_ancestry(&proposal) {
            // If we return false here, don't vote but don't discard the proposal (as may eventually still be finalized).
            return false;
        }

        // Verify payload
        self.application.verify(proposal.payload.clone())
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
        //
        // TODO: treat notarizations in consecutive views as a finalization and recuse backwards
        let previous = self.locked.get_mut(&height);
        match previous {
            Some(Lock::Notarized(seen)) => {
                if let Some(old_hash) = seen.get(&view) {
                    if *old_hash != hash {
                        panic!("notarized block hash mismatch");
                    }
                    return;
                }
                seen.insert(view, hash.clone());
            }
            Some(Lock::Finalized(_)) => {
                // Already finalized, do nothing
                return;
            }
            None => {
                let mut seen = BTreeMap::new();
                seen.insert(view, hash.clone());
                self.locked.insert(height, Lock::Notarized(seen));
            }
        }

        // Mark as seen
        self.seen(proposal).await;

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
            let previous = self.locked.get_mut(&next);
            match previous {
                Some(Lock::Notarized(hashes)) => {
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
                    self.locked.insert(height, Lock::Finalized(hash.clone()));

                    // Update value of hash to be parent of this block
                    if let Some(parent) = self.blocks.get(&hash) {
                        hash = parent.parent.clone();
                    } else {
                        // If we don't know the parent, we can't finalize any ancestors
                        break;
                    }
                }
                Some(Lock::Finalized(seen)) => {
                    if *seen != hash {
                        panic!("finalized block hash mismatch");
                    }
                    break;
                }
                None => {
                    self.locked.insert(next, Lock::Finalized(hash.clone()));

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
        // TODO: call application recursively
        self.seen(proposal).await;

        // Notify application
        self.notify();
    }
}
