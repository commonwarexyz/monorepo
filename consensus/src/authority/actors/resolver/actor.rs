//! Resolve actions requested by consensus.

use super::{Config, Mailbox, Message};
use crate::{
    authority::{
        actors::{backfiller, voter, Proposal},
        wire, Context, Height, View,
    },
    Automaton, Finalizer, Payload, Supervisor,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::hex;
use core::panic;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use prost::Message as _;
use rand::Rng;
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{debug, trace};

#[derive(Clone)]
enum Knowledge {
    Notarized(BTreeMap<View, Digest>), // priotize building off of earliest view (avoid wasting work)
    Finalized(Digest),
}

pub struct Actor<
    E: Clock + Rng + Spawner,
    A: Automaton<Context = Context> + Supervisor<Index = View> + Finalizer,
> {
    runtime: E,
    application: A,

    max_fetch_count: u64,
    max_fetch_size: usize,

    mailbox_receiver: mpsc::Receiver<Message>,

    knowledge: HashMap<Height, Knowledge>,
    containers: HashMap<Digest, wire::Proposal>,

    // Track verifications
    //
    // We never verify the same container twice.
    verified: HashMap<Height, HashSet<Digest>>,

    // Track notarization/finalization
    last_notarized: Height,
    last_finalized: Height,

    // Track notarizations
    last_finalized_view: View,
    notarizations: BTreeMap<View, (bool, bool)>, // (digest, null)

    // Fetch missing proposals
    missing: HashMap<Digest, Height>,
    missing_sender: mpsc::Sender<(Height, Digest)>,
    missing_receiver: mpsc::Receiver<(Height, Digest)>,

    // Track last notifications
    //
    // We only increase this once we notify of finalization at some height.
    // It is not guaranteed that we will notify every notarization (may just be finalizes).
    notarizations_sent: HashMap<Height, HashSet<Digest>>,
    last_notified: Height,
}

// Sender/Receiver here are different than one used in consensus (separate rate limits and compression settings).
impl<
        E: Clock + Rng + Spawner,
        A: Automaton<Context = Context> + Supervisor<Index = View> + Finalizer,
    > Actor<E, A>
{
    pub fn new(runtime: E, mut cfg: Config<A>) -> (Self, Mailbox) {
        // Create genesis container and store it
        let mut verified = HashMap::new();
        let mut knowledge = HashMap::new();
        let mut containers = HashMap::new();
        let (genesis_payload, genesis_digest) = cfg.application.genesis();
        verified.insert(0, HashSet::from([genesis_digest.clone()]));
        knowledge.insert(0, Knowledge::Finalized(genesis_digest.clone()));

        containers.insert(
            genesis_digest,
            wire::Proposal {
                view: 0,
                height: 0,
                parent: Digest::new(),
                payload: genesis_payload,
                signature: None,
            },
        );

        // Initialize mailbox
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1024);
        let (missing_sender, missing_receiver) = mpsc::channel(1024);
        (
            Self {
                runtime,
                application: cfg.application,

                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,

                mailbox_receiver,

                knowledge,
                containers,

                verified,

                last_notarized: 0,
                last_finalized: 0,

                last_finalized_view: 0,
                notarizations: BTreeMap::new(),

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

    async fn register_missing(&mut self, height: Height, digest: Digest) {
        // Check if we have the proposal
        if self.containers.contains_key(&digest) {
            return;
        }

        // Check if have already registered
        if self.missing.contains_key(&digest) {
            return;
        }
        self.missing.insert(digest.clone(), height);
        debug!(height, parent = hex(&digest), "registered missing proposal");

        // Enqueue missing proposal for fetching
        self.missing_sender.send((height, digest)).await.unwrap();
    }

    fn resolve(&mut self, proposal: Proposal) -> Option<(Height, Digest)> {
        // Parse proposal
        let (digest, proposal) = match proposal {
            Proposal::Reference(_, height, digest) => {
                if self.containers.contains_key(&digest) {
                    return None;
                }
                return Some((height, digest));
            }
            Proposal::Populated(digest, proposal) => (digest, proposal),
            Proposal::Null(_) => panic!("null proposal cannot be resolved"),
        };

        // If already resolved, do nothing.
        if self.containers.contains_key(&digest) {
            return None;
        }

        // Remove from missing
        if self.missing.remove(&digest).is_some() {
            debug!(
                height = proposal.height,
                digest = hex(&digest),
                "resolved missing proposal"
            );
        }

        // Record what we learned
        if proposal.height > self.last_finalized {
            // Add to notarized if not finalized
            match self.knowledge.get_mut(&proposal.height) {
                Some(Knowledge::Notarized(seen)) => {
                    seen.insert(proposal.view, digest.clone());
                }
                None => {
                    let mut seen = BTreeMap::new();
                    seen.insert(proposal.view, digest.clone());
                    self.knowledge
                        .insert(proposal.height, Knowledge::Notarized(seen));
                }
                _ => {}
            }
        } else {
            // TODO: clean this up

            // Insert as final (in case it doesn't exist)
            let mut start = (proposal.height, digest.clone());
            if let Some(Knowledge::Finalized(_)) = self.knowledge.get(&proposal.height) {
                debug!("overriding backfill start to parent");
                start = (proposal.height - 1, proposal.parent.clone());
            }

            // Finalize this container and all containers we have that are ancestors of this container
            self.backfill_finalization(start.0, start.1);
        }

        // Store proposal
        let height = proposal.height;
        let parent = proposal.parent.clone();
        self.containers.insert(digest, proposal);

        // Check if parent is missing
        if self.containers.contains_key(&parent) {
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
                    // No more containers to notify
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
                    // we have not been able to resolve containers from the accepted tip
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
                    for (_, digest) in hashes {
                        let already_notified = self
                            .notarizations_sent
                            .get(&next)
                            .map_or(false, |notifications| notifications.contains(&digest));
                        if already_notified {
                            continue;
                        }
                        let proposal = match self.containers.get(&digest) {
                            Some(proposal) => proposal,
                            None => {
                                continue;
                            }
                        };
                        if !self.verify(digest.clone(), proposal.clone()).await {
                            debug!(
                                height = next,
                                digest = hex(&digest),
                                "failed to verify notarized proposal"
                            );
                            continue;
                        }
                        self.notarizations_sent
                            .entry(next)
                            .or_default()
                            .insert(digest.clone());
                        self.application.prepared(digest).await;
                    }
                    debug!(height = next, "notified application notarization");
                }
                Knowledge::Finalized(digest) => {
                    // Send finalized proposal
                    let proposal = match self.containers.get(&digest) {
                        Some(proposal) => proposal,
                        None => {
                            debug!(
                                height = next,
                                digest = hex(&digest),
                                "missing finalized proposal, exiting backfill"
                            );
                            return;
                        }
                    };
                    // If we already verified this proposal, this function will ensure we don't
                    // notify the application of it again.
                    if !self.verify(digest.clone(), proposal.clone()).await {
                        debug!(
                            height = next,
                            digest = hex(&digest),
                            "failed to verify finalized proposal"
                        );
                        return;
                    };
                    self.verified.remove(&(next - 1)); // parent of finalized must be accessible
                    self.notarizations_sent.remove(&next);
                    self.last_notified = next;
                    self.application.finalized(digest).await;
                    debug!(height = next, "notified application finalization");
                }
            }

            // Update next
            next += 1;
        }
    }

    fn best_parent(&self) -> Option<(Digest, View, Height)> {
        // Find highest container that we have notified the application of
        let mut next = self.last_notarized;
        loop {
            match self.knowledge.get(&next) {
                Some(Knowledge::Notarized(hashes)) => {
                    // Find earliest view that we also sent notification for
                    for (_, digest) in hashes.iter() {
                        if let Some(notifications) = self.notarizations_sent.get(&next) {
                            if notifications.contains(digest) {
                                let container = self.containers.get(digest).unwrap();
                                return Some((digest.clone(), container.view, container.height));
                            }
                        }
                    }
                }
                Some(Knowledge::Finalized(digest)) => {
                    if self.last_notified >= next {
                        let container = self.containers.get(digest).unwrap();
                        return Some((digest.clone(), container.view, container.height));
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
    ) -> Option<(Digest, Height, Digest, Payload)> {
        // If don't have ancestry to last notarized container fulfilled, do nothing.
        let parent = match self.best_parent() {
            Some(parent) => parent,
            None => {
                return None;
            }
        };

        // Ensure we have null notarizations back to best parent container (if not, we may
        // just be missing containers and should try again later)
        let height = parent.2 + 1;
        for gap_view in (parent.1 + 1)..view {
            if !self
                .notarizations
                .get(&gap_view)
                .map_or(false, |(_, null)| *null)
            {
                debug!(
                    height,
                    view,
                    parent_view = parent.1,
                    missing = gap_view,
                    reason = "missing null notarization",
                    "skipping propose"
                );
                return None;
            }
        }

        // Propose container
        let context = Context {
            view,
            parent: parent.0.clone(),
            height,
            proposer,
        };
        let payload = match self.application.propose(context).await {
            Some(payload) => payload,
            None => {
                return None;
            }
        };

        // Compute payload digest
        let payload_digest = match self.application.parse(payload.clone()).await {
            Some(digest) => digest,
            None => {
                return None;
            }
        };

        // Generate proposal
        Some((parent.0, height, payload, payload_digest))
    }

    fn valid_ancestry(&self, proposal: &wire::Proposal) -> bool {
        // Check if we have the parent
        let parent = self.containers.get(&proposal.parent);
        if parent.is_none() {
            debug!(
                height = proposal.height,
                parent_digest = hex(&proposal.parent),
                "missing parent"
            );
            return false;
        }
        let parent = parent.unwrap();

        // TODO: add condition to ensure we can't skip a proposal notarization unless there is a null container notarization?
        // if building at height 5 (view 10), need to ensure there are null notarizations to parent (height 4, view V) -> if there are
        // not null notarizations, it is possible those intermediate views could be finalized
        if self.last_finalized < proposal.height {
            // TODO: remove all of this jank/spread out logic around when we verify ancestry during backfill vs at tip
            //
            // We broadcast any notarizations we see for a view, so everyone should be able to recover even at tip (as long
            // as we have not finalized past the view)?
            for view in (parent.view + 1)..proposal.view {
                if !self
                    .notarizations
                    .get(&view)
                    .map_or(false, |(_, null)| *null)
                {
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
                    parent_digest = hex(&proposal.parent),
                    proposal_view = proposal.view,
                    parent_view = parent.view,
                    "ancestry verified"
                );
                return true;
            }
        }
        debug!(
            height = proposal.height,
            parent_digest = hex(&proposal.parent),
            "parent not verified"
        );
        false
    }

    pub async fn verify(&mut self, digest: Digest, proposal: wire::Proposal) -> bool {
        // If already verified, do nothing
        if self
            .verified
            .get(&proposal.height)
            .map_or(false, |hashes| hashes.contains(&digest))
        {
            return true;
        }

        // If don't have ancestry yet, do nothing.
        if !self.valid_ancestry(&proposal) {
            // If we return false here, don't vote but don't discard the proposal (as may eventually still be finalized).
            trace!(
                height = proposal.height,
                parent_digest = hex(&proposal.parent),
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
            .verify(context, proposal.payload.clone(), digest.clone())
            .await
        {
            return false;
        }

        // Record verification
        let entry = self.verified.entry(proposal.height).or_default();
        entry.insert(digest);
        true
    }

    pub async fn notarized(&mut self, proposal: Proposal) {
        // Extract height and digest
        let (view, height, digest) = match &proposal {
            Proposal::Reference(view, height, digest) => (*view, *height, digest.clone()),
            Proposal::Populated(digest, proposal) => {
                (proposal.view, proposal.height, digest.clone())
            }
            Proposal::Null(view) => {
                // TODO: write up explanation for why we don't set last_notarized here (which
                // is really just used to select the best parent for building)
                let entry = self.notarizations.entry(*view).or_default();
                entry.1 = true;
                return;
            }
        };
        let entry = self.notarizations.entry(view).or_default();
        entry.0 = true;

        // Set last notarized
        if height > self.last_notarized {
            self.last_notarized = height;
        }

        // Insert lock if doesn't already exist
        let previous = self.knowledge.get_mut(&height);
        match previous {
            Some(Knowledge::Notarized(seen)) => {
                if let Some(old_digest) = seen.get(&view) {
                    if *old_digest != digest {
                        panic!("notarized container digest mismatch");
                    }
                    return;
                }
                seen.insert(view, digest.clone());
            }
            Some(Knowledge::Finalized(_)) => {
                // Already finalized, do nothing
                return;
            }
            None => {
                let mut seen = BTreeMap::new();
                seen.insert(view, digest.clone());
                self.knowledge.insert(height, Knowledge::Notarized(seen));
            }
        }

        // Mark as seen
        if let Some((height, digest)) = self.resolve(proposal) {
            self.register_missing(height, digest).await;
        }

        // Notify application
        self.notify().await;
    }

    fn backfill_finalization(&mut self, height: Height, mut container: Digest) {
        trace!(
            height,
            digest = hex(&container),
            "backfilling finalizations"
        );
        let mut next = height;
        loop {
            let previous = self.knowledge.get_mut(&next);
            match previous {
                Some(Knowledge::Notarized(hashes)) => {
                    // Remove unnecessary proposals from memory
                    for (_, old_digest) in hashes.iter() {
                        if old_digest != &container {
                            self.containers.remove(old_digest);
                            debug!(
                                height,
                                digest = hex(old_digest),
                                "removing unnecessary proposal"
                            );
                        }
                    }

                    // Store finalized container record
                    self.knowledge
                        .insert(next, Knowledge::Finalized(container.clone()));

                    // Update value of digest to be parent of this container
                    if let Some(parent) = self.containers.get(&container) {
                        container = parent.parent.clone();
                    } else {
                        // If we don't know the parent, we can't finalize any ancestors
                        trace!(
                            next = height - 1,
                            digest = hex(&container),
                            reason = "missing parent",
                            "exiting backfill"
                        );
                        break;
                    }
                }
                Some(Knowledge::Finalized(seen)) => {
                    if *seen != container {
                        panic!(
                            "finalized container digest mismatch at height {}: expected={}, found={}",
                            next,
                            hex(seen),
                            hex(&container)
                        );
                    }
                    break;
                }
                None => {
                    self.knowledge
                        .insert(next, Knowledge::Finalized(container.clone()));

                    // Attempt to keep recursing backwards until hit a finalized container or 0
                    if let Some(parent) = self.containers.get(&container) {
                        container = parent.parent.clone();
                    } else {
                        trace!(
                            next = height - 1,
                            digest = hex(&container),
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
        // Extract height and digest
        let (view, height, digest) = match &proposal {
            Proposal::Reference(view, height, digest) => (*view, *height, digest.clone()),
            Proposal::Populated(digest, proposal) => {
                (proposal.view, proposal.height, digest.clone())
            }
            Proposal::Null(_) => panic!("null proposal cannot be finalized"),
        };

        // Set last finalized
        if height > self.last_finalized {
            self.last_finalized = height;
        }
        if view > self.last_finalized_view {
            self.last_finalized_view = view;
        }

        // Also update last notarized (if necessary)
        if height > self.last_notarized {
            self.last_notarized = height;
        }

        // Prune all notarizations below this view
        self.notarizations.retain(|k, _| *k > view);

        // Finalize this container and all containers we have that are ancestors of this container
        self.backfill_finalization(height, digest);

        // Mark as seen
        if let Some((height, digest)) = self.resolve(proposal) {
            self.register_missing(height, digest).await;
        }

        // Notify application
        self.notify().await;
    }

    fn get_next_missing_proposal(&mut self) -> Option<(Height, Digest)> {
        loop {
            // See if we have any missing proposals
            let (height, digest) = match self.missing_receiver.try_next() {
                Ok(res) => res.unwrap(),
                Err(_) => return None,
            };

            // Check if still unfulfilled
            if self.containers.contains_key(&digest) {
                continue;
            }

            // Return missing proposal
            return Some((height, digest));
        }
    }

    async fn send_request(&mut self, height: Height) -> Height {
        // Compute missing containers from digest
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
                                "requesting gap container"
                            );
                            continue;
                        }

                        // We only want to batch fill finalized data.
                        break;
                    }
                    Knowledge::Finalized(digest) => {
                        if self.containers.contains_key(digest) {
                            // We have a container and no longer need to fetch its parent
                            break;
                        }
                    }
                }
            }

            // If we have no knowledge of a height, we need to fetch it
            parents += 1;
        }
        parents
    }

    pub async fn run(mut self, mut voter: voter::Mailbox, mut backfiller: backfiller::Mailbox) {
        let mut outstanding_proposal_request: Option<(Height, Digest)> = None;
        let mut outstanding_notarization_request: Option<View> = None;
        loop {
            // Check if proposal request has been resolved and reissue request (if so)
            if let Some((ref height, ref digest)) = outstanding_proposal_request {
                if self.containers.contains_key(digest) {
                    debug!(
                        height,
                        digest = hex(digest),
                        "unexpected resolution of missing proposal out of backfill"
                    );
                    outstanding_proposal_request = None;
                }
            }
            if outstanding_proposal_request.is_none() {
                let missing = self.get_next_missing_proposal();
                if let Some((height, digest)) = missing {
                    // Check if already have
                    if self.containers.contains_key(&digest) {
                        continue;
                    }

                    // Send request
                    let parents = self.send_request(height).await;

                    // Send to backfiller
                    //
                    // This will override any existing request in the backfiller.
                    debug!(height, digest = hex(&digest), "requesting missing proposal");
                    outstanding_proposal_request = Some((height, digest.clone()));
                    backfiller.proposals(digest, parents).await;
                }
            };

            // Check if notarization request has been resolved and reissue request (if so)
            if let Some(ref view) = outstanding_notarization_request {
                if self.notarizations.contains_key(view) {
                    debug!(
                        view = view,
                        "unexpected resolution of missing notarization out of backfill"
                    );
                    outstanding_notarization_request = None;
                }
            }
            if outstanding_notarization_request.is_none() && !self.notarizations.is_empty() {
                // Find first gap and count the number of missing children at the gap (to the highest notarization)
                let max = self
                    .notarizations
                    .last_key_value()
                    .map(|(k, _)| *k)
                    .unwrap();
                let mut start = None;
                let mut children = 0;
                for view in (self.last_finalized_view + 1)..max {
                    if self.notarizations.contains_key(&view) {
                        if start.is_some() {
                            break;
                        }
                        continue;
                    }
                    if start.is_none() {
                        start = Some(view);
                    } else {
                        children += 1;
                    }
                }

                // Send to backfiller
                if let Some(start) = start {
                    debug!(view = start, children, "requesting missing notarizations");
                    outstanding_notarization_request = Some(start);
                    backfiller.notarizations(start, children).await;
                }
            }

            // Wait for an event
            let msg = self.mailbox_receiver.next().await.unwrap();
            match msg {
                Message::Propose { view, proposer } => {
                    let (parent, height, payload, payload_digest) =
                        match self.propose(view, proposer).await {
                            Some(proposal) => proposal,
                            None => {
                                voter.proposal_failed(view).await;
                                continue;
                            }
                        };
                    voter
                        .proposal(view, parent, height, payload, payload_digest)
                        .await;
                }
                Message::Verify {
                    container,
                    proposal,
                } => {
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
                    if !self.verify(container, proposal).await {
                        continue;
                    }
                    voter.verified(proposal_view).await;
                }
                Message::Notarized { proposal } => self.notarized(proposal).await,
                Message::Finalized { proposal } => self.finalized(proposal).await,
                Message::Proposals {
                    digest,
                    parents,
                    recipient,
                    deadline,
                } => {
                    // Populate as many proposals as we can
                    let mut proposal_bytes = 0; // TODO: add a buffer
                    let mut proposals = Vec::new();
                    let mut cursor = digest;
                    let drop = loop {
                        // If we are out of time at start, drop request
                        if deadline < self.runtime.current() {
                            break true;
                        }

                        // Check to see if we have proposal
                        let proposal = match self.containers.get(&cursor).cloned() {
                            Some(proposal) => proposal,
                            None => {
                                break false;
                            }
                        };

                        // If we don't have any more space, stop
                        proposal_bytes += proposal.encoded_len();
                        if proposal_bytes > self.max_fetch_size {
                            debug!(
                                requested = parents + 1,
                                found = proposals.len(),
                                peer = hex(&recipient),
                                "reached max response size",
                            );
                            break false;
                        }

                        // If we do have space, add to proposals
                        cursor = proposal.parent.clone();
                        proposals.push(proposal);

                        // If we have all parents requested, stop gathering more
                        let fetched = proposals.len() as u64;
                        if fetched == parents + 1 || fetched == self.max_fetch_count {
                            break false;
                        }
                    };
                    if drop {
                        debug!(
                            requested = parents + 1,
                            found = proposals.len(),
                            peer = hex(&recipient),
                            "dropping expired backfill request"
                        );
                        continue;
                    }
                    backfiller.filled_proposals(recipient, proposals).await;
                }
                Message::BackfilledProposals { proposals } => {
                    let mut next = None;
                    for (digest, proposal) in proposals {
                        // Ensure this is the container we want
                        let proposal = Proposal::Populated(digest, proposal);
                        next = self.resolve(proposal);

                        // Notify application if we can
                        self.notify().await;

                        // Stop processing if we don't need anything else
                        if next.is_none() {
                            break;
                        }
                    }

                    // Notify missing if next is not none
                    if let Some((height, digest)) = next {
                        // By waiting to register missing until the end, we avoid a bunch of unnecessary
                        // backfill request additions.
                        self.register_missing(height, digest).await;
                    }
                }
                Message::BackfilledNotarizations { notarizations } => {
                    for notarization in notarizations {
                        let notarization = if notarization.digest.is_none() {
                            Proposal::Null(notarization.view)
                        } else {
                            Proposal::Reference(
                                notarization.view,
                                notarization.height.unwrap(),
                                notarization.digest.unwrap(),
                            )
                        };
                        self.notarized(notarization).await;
                    }
                }
            };
        }
    }
}
