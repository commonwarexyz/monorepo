//! Resolve actions requested by consensus.

use super::{Config, Mailbox, Message};
use crate::{
    authority::{
        actors::{voter, Proposal},
        encoder::{proposal_digest, proposal_namespace},
        wire,
    },
    Application, Context, Finalizer, Hash, Hasher, Height, Payload, Supervisor, View,
};
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::hex;
use core::panic;
use futures::{channel::mpsc, future::Either};
use futures::{SinkExt, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use prost::Message as _;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, trace, warn};

#[derive(Clone)]
enum Knowledge {
    Notarized(BTreeMap<View, Hash>), // priotize building off of earliest view (avoid wasting work)
    Finalized(Hash),
}

pub struct Actor<
    E: Clock + GClock + Rng + Spawner,
    C: Scheme,
    H: Hasher,
    A: Application + Supervisor + Finalizer,
> {
    runtime: E,
    crypto: C,
    hasher: H,
    application: A,

    proposal_namespace: Vec<u8>,

    fetch_timeout: Duration,
    max_fetch_count: u64,
    max_fetch_size: usize,
    fetch_rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,

    mailbox_receiver: mpsc::Receiver<Message>,

    null_notarizations: BTreeSet<View>,
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
impl<
        E: Clock + GClock + Rng + Spawner,
        C: Scheme,
        H: Hasher,
        A: Application + Supervisor + Finalizer,
    > Actor<E, C, H, A>
{
    pub fn new(runtime: E, mut cfg: Config<C, H, A>) -> (Self, Mailbox) {
        // Create genesis block and store it
        let mut verified = HashMap::new();
        let mut knowledge = HashMap::new();
        let mut blocks = HashMap::new();
        let genesis = cfg.application.genesis();
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

        // Initialize rate limiter
        let fetch_rate_limiter = RateLimiter::hashmap_with_clock(cfg.fetch_rate_per_peer, &runtime);

        // Initialize mailbox
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1024);
        let (missing_sender, missing_receiver) = mpsc::channel(1024);
        (
            Self {
                runtime,
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                application: cfg.application,

                proposal_namespace: proposal_namespace(&cfg.namespace),

                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_rate_limiter,

                mailbox_receiver,

                null_notarizations: BTreeSet::new(),
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

    // TODO: remove duplicatred code
    fn leader(&self, view: View) -> Option<PublicKey> {
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => return None,
        };
        Some(validators[view as usize % validators.len()].clone())
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
            Proposal::Null(_) => panic!("null proposal cannot be resolved"),
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
        if proposal.height > self.last_finalized {
            // Add to notarized if not finalized
            match self.knowledge.get_mut(&proposal.height) {
                Some(Knowledge::Notarized(seen)) => {
                    seen.insert(proposal.view, hash.clone());
                }
                None => {
                    let mut seen = BTreeMap::new();
                    seen.insert(proposal.view, hash.clone());
                    self.knowledge
                        .insert(proposal.height, Knowledge::Notarized(seen));
                }
                _ => {}
            }
        } else {
            // TODO: clean this up

            // Insert as final (in case it doesn't exist)
            let mut start = (proposal.height, hash.clone());
            if let Some(Knowledge::Finalized(_)) = self.knowledge.get(&proposal.height) {
                debug!("overriding backfill start to parent");
                start = (proposal.height - 1, proposal.parent.clone());
            }

            // Finalize this block and all blocks we have that are ancestors of this block
            self.backfill_finalization(start.0, start.1);
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

    async fn notify(&mut self) {
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
            trace!(height = next, "attempting application notification");

            // Send event
            match knowledge {
                Knowledge::Notarized(hashes) => {
                    // Only send notarization if greater than our latest knowledge
                    // of the finalizaed tip
                    //
                    // We may still only have notarization knowledge at this height because
                    // we have not been able to resolve blocks from the accepted tip
                    // to this height yet.
                    if self.last_finalized >= next {
                        trace!(
                            height = next,
                            last_finalized = self.last_finalized,
                            "skipping notarization notification because behind finalization"
                        );
                        return;
                    }

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
                        let proposal_view = proposal.view;
                        if !self.verify(hash.clone(), proposal.clone()).await {
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
                        self.application
                            .notarized(proposal_view, hash.clone())
                            .await;
                    }
                    trace!(height = next, "notified application notarization");
                }
                Knowledge::Finalized(hash) => {
                    // Send finalized proposal
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
                    let proposal_view = proposal.view;
                    if !self.verify(hash.clone(), proposal.clone()).await {
                        debug!(
                            height = next,
                            hash = hex(&hash),
                            "failed to verify finalized proposal"
                        );
                        return;
                    };
                    self.verified.remove(&(next - 1)); // parent of finalized must be accessible
                    self.notarizations_sent.remove(&next);
                    self.last_notified = next;
                    self.application
                        .finalized(proposal_view, hash.clone())
                        .await;
                    trace!(height = next, "notified application finalization");
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

    pub async fn propose(
        &mut self,
        view: View,
        proposer: PublicKey,
    ) -> Option<(Hash, Height, Hash, Payload)> {
        // If don't have ancestry to last notarized block fulfilled, do nothing.
        let parent = match self.best_parent() {
            Some(parent) => parent,
            None => {
                return None;
            }
        };

        // Propose block
        let context = Context {
            view,
            parent: parent.0.clone(),
            height: parent.1 + 1,
            proposer,
        };
        let height = parent.1 + 1;
        let payload = match self.application.propose(context).await {
            Some(payload) => payload,
            None => {
                return None;
            }
        };

        // Compute payload hash
        let payload_hash = match self.application.parse(payload.clone()).await {
            Some(hash) => hash,
            None => {
                return None;
            }
        };

        // Generate proposal
        Some((parent.0, height, payload, payload_hash))
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

        // TODO: add condition to ensure we can't skip a proposal notarization unless there is a null block notarization?
        // if building at height 5 (view 10), need to ensure there are null notarizations to parent (height 4, view V) -> if there are
        // not null notarizations, it is possible those intermediate views could be finalized
        if self.last_finalized < proposal.height {
            // TODO: remove all of this jank/spread out logic around when we verify ancestry during backfill vs at tip
            //
            // We broadcast any notarizations we see for a view, so everyone should be able to recover even at tip (as long
            // as we have not finalized past the view)?
            for view in (parent.view + 1)..proposal.view {
                if !self.null_notarizations.contains(&view) {
                    debug!(
                        height = proposal.height,
                        view,
                        proposal_view = proposal.view,
                        parent_view = parent.view,
                        "missing null notarization"
                    );
                    return false;
                } else {
                    trace!(
                        height = proposal.height,
                        view,
                        proposal_view = proposal.view,
                        parent_view = parent.view,
                        "depending on null notarization"
                    );
                }
            }
        }

        // Check if parent has been verified
        if let Some(hashes) = self.verified.get(&parent.height) {
            if hashes.contains(&proposal.parent) {
                trace!(
                    height = proposal.height,
                    parent_hash = hex(&proposal.parent),
                    proposal_view = proposal.view,
                    parent_view = parent.view,
                    "ancestry verified"
                );
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

    pub async fn verify(&mut self, hash: Hash, proposal: wire::Proposal) -> bool {
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
            trace!(
                height = proposal.height,
                parent_hash = hex(&proposal.parent),
                "invalid ancestry"
            );
            return false;
        }

        // Verify payload
        let context = Context {
            view: proposal.view,
            parent: proposal.parent.clone(),
            height: proposal.height,
            proposer: proposal.signature.clone().unwrap().public_key.clone(),
        };
        if !self
            .application
            .verify(context, proposal.payload.clone(), hash.clone())
            .await
        {
            return false;
        }

        // Record verification
        let entry = self.verified.entry(proposal.height).or_default();
        entry.insert(hash);
        true
    }

    pub async fn notarized(&mut self, proposal: Proposal) {
        // Extract height and hash
        let (view, height, hash) = match &proposal {
            Proposal::Reference(view, height, hash) => (*view, *height, hash.clone()),
            Proposal::Populated(hash, proposal) => (proposal.view, proposal.height, hash.clone()),
            Proposal::Null(view) => {
                // TODO: write up explanation for why we don't set last_notarized here (which
                // is really just used to select the best parent for building)
                self.null_notarizations.insert(*view);
                return;
            }
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
        self.notify().await;
    }

    fn backfill_finalization(&mut self, height: Height, mut block: Hash) {
        trace!(height, hash = hex(&block), "backfilling finalizations");
        let mut next = height;
        loop {
            let previous = self.knowledge.get_mut(&next);
            match previous {
                Some(Knowledge::Notarized(hashes)) => {
                    // Remove unnecessary proposals from memory
                    for (_, old_hash) in hashes.iter() {
                        if old_hash != &block {
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
                        .insert(next, Knowledge::Finalized(block.clone()));

                    // Update value of hash to be parent of this block
                    if let Some(parent) = self.blocks.get(&block) {
                        block = parent.parent.clone();
                    } else {
                        // If we don't know the parent, we can't finalize any ancestors
                        trace!(
                            next = height - 1,
                            hash = hex(&block),
                            reason = "missing parent",
                            "exiting backfill"
                        );
                        break;
                    }
                }
                Some(Knowledge::Finalized(seen)) => {
                    if *seen != block {
                        panic!(
                            "finalized block hash mismatch at height {}: expected={}, found={}",
                            next,
                            hex(seen),
                            hex(&block)
                        );
                    }
                    break;
                }
                None => {
                    self.knowledge
                        .insert(next, Knowledge::Finalized(block.clone()));

                    // Attempt to keep recursing backwards until hit a finalized block or 0
                    if let Some(parent) = self.blocks.get(&block) {
                        block = parent.parent.clone();
                    } else {
                        trace!(
                            next = height - 1,
                            hash = hex(&block),
                            reason = "missing parent",
                            "exiting backfill"
                        );
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
    }

    pub async fn finalized(&mut self, proposal: Proposal) {
        // Extract height and hash
        let (view, height, hash) = match &proposal {
            Proposal::Reference(view, height, hash) => (*view, *height, hash.clone()),
            Proposal::Populated(hash, proposal) => (proposal.view, proposal.height, hash.clone()),
            Proposal::Null(_) => panic!("null proposal cannot be finalized"),
        };

        // Set last finalized
        if height > self.last_finalized {
            self.last_finalized = height;
        }

        // Prune all null notarizations below this view
        while let Some(null_view) = self.null_notarizations.iter().next().cloned() {
            if null_view > view {
                break;
            }
            self.null_notarizations.remove(&null_view);
            debug!(view = null_view, "pruned null notarization");
        }

        // Finalize this block and all blocks we have that are ancestors of this block
        self.backfill_finalization(height, hash);

        // Mark as seen
        if let Some((height, hash)) = self.resolve(proposal) {
            self.register_missing(height, hash).await;
        }

        // Notify application
        self.notify().await;
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
                        // If this height is less than the finalized
                        // tip but it is still a notarization, we should
                        // fetch it.
                        if target <= self.last_finalized {
                            trace!(
                                height,
                                target,
                                last_finalized = self.last_finalized,
                                "requesting gap block"
                            );
                            continue;
                        }

                        // We only want to batch fill finalized data.
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
        let msg: Bytes = wire::Backfill {
            payload: Some(wire::backfill::Payload::Request(wire::Request {
                hash: hash.clone(),
                parents,
            })),
        }
        .encode_to_vec()
        .into();

        // Get validators from highest view we know about
        let validators = self.application.participants(self.last_notarized).unwrap();

        // Generate a shuffle
        let mut validator_indices = (0..validators.len()).collect::<Vec<_>>();
        validator_indices.shuffle(&mut self.runtime);

        // Minimize footprint of rate limiter
        self.fetch_rate_limiter.shrink_to_fit();

        // Loop until we send a message
        let mut index = 0;
        loop {
            // Check if we have exhausted all validators
            if index == validators.len() {
                warn!(
                    height,
                    last_notarized = self.last_notarized,
                    "failed to send request to any validator"
                );

                // Avoid busy looping when disconnected
                self.runtime.sleep(self.fetch_timeout).await;
                index = 0;
            }

            // Select random validator to fetch from
            let validator = validators[validator_indices[index]].clone();
            if validator == self.crypto.public_key() {
                index += 1;
                continue;
            }

            // Check if rate limit is exceeded
            if self.fetch_rate_limiter.check_key(&validator).is_err() {
                debug!(
                    height,
                    hash = hex(&hash),
                    peer = hex(&validator),
                    "skipping request because rate limited"
                );
                index += 1;
                continue;
            }

            // Send message
            if !sender
                .send(Recipients::One(validator.clone()), msg.clone(), true)
                .await
                .unwrap()
                .is_empty()
            {
                debug!(
                    height,
                    hash = hex(&hash),
                    peer = hex(&validator),
                    parents,
                    last_notarized = self.last_notarized,
                    "requested missing proposal"
                );
                return validator;
            }

            // Try again
            debug!(
                height,
                hash = hex(&hash),
                peer = hex(&validator),
                "failed to send backfill request"
            );
            index += 1;
        }
    }

    pub async fn run(
        mut self,
        voter: &mut voter::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
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
                _ = missing_timeout => {
                    // Send request again
                    let (_, height, hash, _)= outstanding_task.take().unwrap();
                    let validator = self.send_request(height, hash.clone(), &mut sender).await;

                    // Reset timeout
                    outstanding_task = Some((validator, height, hash, self.runtime.current() + self.fetch_timeout));
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Propose { view, proposer } => {
                            let (parent, height, payload, payload_hash)= match self.propose(view, proposer).await{
                                Some(proposal) => proposal,
                                None => {
                                    continue;
                                }
                            };
                            voter.proposal(view, parent, height, payload, payload_hash).await;
                        }
                        Message::Verify { hash, proposal } => {
                            // If proposal height is already finalized, fail
                            //
                            // We will only verify old proposals via notify loop.
                            if proposal.height <= self.last_finalized {
                                debug!(
                                    height = proposal.height,
                                    finalized = self.last_finalized,
                                    "already finalized"
                                );
                                continue;
                            }

                            // Attempt to verify proposal
                            let proposal_view = proposal.view;
                            if !self.verify(hash, proposal).await {
                                continue;
                            }
                            voter.verified(proposal_view).await;
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
                            if !H::validate(&request.hash) {
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
                            if !H::validate(&missing.hash) {
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
                                // Ensure this is the block we want
                                if !H::validate(&proposal.parent) {
                                    warn!(sender = hex(&s), "invalid proposal parent hash size");
                                    break;
                                }
                                let payload_hash = match self.application.parse(proposal.payload.clone()).await {
                                    Some(payload_hash) => payload_hash,
                                    None => {
                                        warn!(sender = hex(&s), "unable to parse notarized/finalized payload");
                                        break;
                                    }
                                };
                                let proposal_digest = proposal_digest(
                                    proposal.view,
                                    proposal.height,
                                    &proposal.parent,
                                    &payload_hash,
                                );
                                self.hasher.update(&proposal_digest);
                                let proposal_hash = self.hasher.finalize();
                                if let Some((height, ref hash)) = next {
                                    if proposal.height != height || proposal_hash != hash {
                                        warn!(sender = hex(&s), "received invalid batch proposal");
                                        break;
                                    }
                                }

                                // Verify leader signature
                                //
                                // TODO: remove duplicate code shared with voter
                                let signature = match &proposal.signature {
                                    Some(signature) => signature,
                                    None => {
                                        warn!(sender = hex(&s), "missing proposal signature");
                                        break;
                                    }
                                };
                                if !C::validate(&signature.public_key) {
                                    warn!(sender = hex(&s), "invalid proposal public key");
                                    break;
                                }
                                let expected_leader = match self.leader(proposal.view) {
                                    Some(leader) => leader,
                                    None => {
                                        debug!(
                                            proposal_leader = hex(&signature.public_key),
                                            reason = "unable to compute leader",
                                            "dropping proposal"
                                        );
                                        break;
                                    }
                                };
                                if expected_leader != signature.public_key {
                                    debug!(
                                        proposal_leader = hex(&signature.public_key),
                                        view_leader = hex(&expected_leader),
                                        reason = "leader mismatch",
                                        "dropping proposal"
                                    );
                                    break;
                                }
                                if !C::verify(
                                    &self.proposal_namespace,
                                    &proposal_digest,
                                    &signature.public_key,
                                    &signature.signature,
                                ) {
                                    warn!(sender = hex(&s), "invalid proposal signature");
                                    break;
                                }


                                // Record the proposal
                                let height = proposal.height;
                                debug!(height, hash = hex(&proposal_hash), peer = hex(&s), "received proposal via backfill");
                                let proposal = Proposal::Populated(proposal_hash.clone(), proposal.clone());
                                next = self.resolve(proposal);

                                // Remove outstanding task if we were waiting on this
                                //
                                // Note, we don't care if we are sent the proposal from someone unexpected (although
                                // this is unexpected).
                                if let Some(ref outstanding) = outstanding_task {
                                    if outstanding.2 == proposal_hash {
                                        debug!(height = outstanding.1, hash = hex(&proposal_hash), peer = hex(&s), "resolved missing proposal via backfill");
                                        outstanding_task = None;
                                    }
                                }

                                // Notify application if we can
                                self.notify().await;

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
