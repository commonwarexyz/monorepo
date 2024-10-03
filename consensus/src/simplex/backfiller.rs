//! Backfill missing proposals seen in consensus.

use crate::Application;

use super::{
    store::{hash, proposal_digest},
    wire,
};
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use core::panic;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use prost::Message;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, warn};

type View = u64;
type Height = u64;
type Hash = Bytes; // use fixed size bytes

#[derive(Clone)]
pub enum Proposal {
    Reference(View, Height, Hash),
    Populated(Hash, wire::Proposal),
}

enum Lock {
    Notarized(HashSet<Hash>),
    Finalized(Hash),
}

pub struct Backfiller<E: Clock + Rng, S: Sender, R: Receiver, A: Application> {
    runtime: E,
    sender: S,
    receiver: R,
    application: A,

    validators: Vec<PublicKey>,

    locked: HashMap<Height, Lock>,
    blocks: HashMap<Bytes, wire::Proposal>,

    // Fetch missing proposals
    missing_sender: mpsc::Sender<Hash>,
    missing_receiver: mpsc::Receiver<Hash>,
}

// Sender/Receiver here are different than one used in consensus (separate rate limits and compression settings).
impl<E: Clock + Rng, S: Sender, R: Receiver, A: Application> Backfiller<E, S, R, A> {
    // TODO: base this off of notarized/finalized (don't want to build index until finalized data, could
    // have a separate index for notarized blocks by view and another for finalized blocks by height)
    async fn resolve(&mut self, hash: Hash, proposal: wire::Proposal) {
        // If already resolved, do nothing.
        if self.blocks.contains_key(&hash) {
            return;
        }

        // Record what we know
        let height = proposal.height;
        let parent = proposal.parent.clone();
        self.blocks.insert(hash, proposal);

        // Check if we are missing the parent
        if parent.len() > 0 && !self.blocks.contains_key(&parent) {
            self.missing_sender.send(parent).await.unwrap();
        }

        // Notify application of all resolved proposals
        loop {
            let next = self.last_notified + 1;
            if let Some(hash) = self.index.get(&next) {
                let proposal = self.blocks.get(hash).unwrap();
                // TODO: track what has been notarized vs finalized
                self.application.notarized(proposal.payload.clone());
                self.last_notified = next;
            } else {
                break;
            }
        }
    }

    fn seen(&mut self, proposal: Proposal) {
        match proposal {
            Proposal::Reference(view, height, hash) => {
                // Check to see if we have the proposal
                if self.blocks.contains_key(&hash) {
                    return;
                }

                // Record that we are missing the view
                self.missing.insert(view, hash.clone());
            }
            Proposal::Populated(hash, proposal) => self.resolve(hash, proposal),
        }
    }

    // This is a pretty basic backfiller (in that it only attempts to resolve one missing
    // proposal at a time). In `tbd`, this will operate very differently because we can
    // verify the integrity of any proposal we receive at an index by the threshold signature.
    pub async fn run(&mut self) {
        // TODO: need a separate loop for responding to requests
        loop {
            // Get the next missing proposal
            let request = match self.missing_receiver.next().await {
                Some(request) => request,
                None => {
                    // No more missing proposals (shutdown)
                    return;
                }
            };

            // Select random validator to fetch from
            let validator = self.validators.choose(&mut self.runtime).unwrap().clone();

            // Send the request
            let msg = wire::Request {
                block: request.clone(),
            }
            .encode_to_vec()
            .into();
            if let Err(err) = self
                .sender
                .send(Recipients::One(validator.clone()), msg, true)
                .await
            {
                warn!(
                    ?err,
                    request = hex(&request),
                    validator = hex(&validator),
                    "failed to send backfill request"
                );
                continue;
            }

            // Process responses until deadline or we receive the proposal
            let start = self.runtime.current();
            let deadline = start + Duration::from_secs(1);
            loop {
                let (sender, proposal) = select! {
                    _timeout = self.runtime.sleep_until(deadline) => {
                        warn!(request = hex(&request), validator = hex(&validator), "backfill request timed out");
                        break;
                    },
                    msg = self.receiver.recv() => {
                        // Parse message
                        let (sender, msg) = match msg {
                            Ok(msg) => msg,
                            Err(err) => {
                                warn!(?err, "failed to receive backfill response");
                                return;
                            }
                        };
                        let resolution = match wire::Resolution::decode(msg) {
                            Ok(msg) => msg,
                            Err(err) => {
                                warn!(?err, sender = hex(&sender), "failed to decode resolution message");
                                continue;
                            }
                        };
                        let proposal = match resolution.proposal {
                            Some(proposal) => proposal,
                            None => {
                                warn!(sender = hex(&sender), "resolution missing proposal");
                                continue;
                            }
                        };
                        (sender, proposal)
                    },
                };

                // Generate payload hash
                let payload_hash = self
                    .application
                    .verify(proposal.payload.clone())
                    .expect("unable to verify notarized/finalized payload");
                let proposal_digest = proposal_digest(
                    proposal.view,
                    proposal.height,
                    proposal.parent.clone(),
                    payload_hash,
                );
                let incoming_hash = hash(proposal_digest);

                // Check if we were expecting this hash
                //
                // It is ok if we get something we don't need, we may have gotten
                // what we need from a variety of other places.
                match self.locked.get(&proposal.height) {
                    Some(Lock::Notarized(seen)) => {
                        if !seen.contains(&incoming_hash) {
                            warn!(
                                sender = hex(&sender),
                                height = proposal.height,
                                "unexpected block hash on resolution"
                            );
                            continue;
                        }
                    }
                    Some(Lock::Finalized(expected)) => {
                        if incoming_hash != *expected {
                            warn!(
                                sender = hex(&sender),
                                height = proposal.height,
                                "unexpected block hash on resolution"
                            );
                            continue;
                        }
                    }
                    None => {
                        warn!(
                            sender = hex(&sender),
                            height = proposal.height,
                            "unexpected block hash"
                        );
                        continue;
                    }
                }

                // Check to see if we already have this proposal
                if self.blocks.contains_key(&incoming_hash) {
                    debug!(
                        sender = hex(&sender),
                        height = proposal.height,
                        "block already resolved"
                    );
                    continue;
                }

                // Record the proposal
                self.resolve(incoming_hash.clone(), proposal);

                // If incoming hash was the hash we were expecting, exit the loop
                if incoming_hash == request {
                    debug!(
                        request = hex(&request),
                        sender = hex(&sender),
                        "backfill resolution"
                    );
                    break;
                }
            }
        }
    }

    // Simplified application functions
    pub fn propose(&mut self) -> Option<(Bytes, Bytes)> {
        // If don't have ancestry to last notarized block fulfilled, do nothing.

        // Get latest notarized block
    }

    pub fn verify(&self, payload: Bytes) -> Option<Bytes> {
        // Verify block
    }

    pub fn notarized(&mut self, proposal: Proposal) {
        // Extract height and hash
        let (view, height, hash) = match &proposal {
            Proposal::Reference(view, height, hash) => (*view, *height, hash.clone()),
            Proposal::Populated(hash, proposal) => (proposal.view, proposal.height, hash.clone()),
        };

        // Insert lock if doesn't already exist
        let previous = self.locked.get_mut(&height);
        match previous {
            Some(Lock::Notarized(seen)) => {
                if seen.contains(&hash) {
                    // Already seen this notarization
                    return;
                }
                seen.insert(hash.clone());
            }
            Some(Lock::Finalized(_)) => {
                // Already finalized, do nothing
                return;
            }
            None => {
                let mut seen = HashSet::new();
                seen.insert(hash.clone());
                self.locked.insert(height, Lock::Notarized(seen));
            }
        }

        // Mark as seen
        // TODO: call application based on changes to lock (ensure all blocks eventually have both notarized and finalized called in order)
        self.seen(proposal);
    }

    pub fn finalized(&mut self, proposal: Proposal) {
        // Extract height and hash
        let (view, height, hash) = match &proposal {
            Proposal::Reference(view, height, hash) => (*view, *height, hash.clone()),
            Proposal::Populated(hash, proposal) => (proposal.view, proposal.height, hash.clone()),
        };

        // Insert lock if doesn't already exist
        let previous = self.locked.get_mut(&height);
        match previous {
            Some(Lock::Notarized(hashes)) => {
                // Remove unnecessary proposals from memory
                for old_hash in hashes.iter() {
                    if old_hash != &hash {
                        self.blocks.remove(old_hash);
                        debug!(
                            height,
                            hash = hex(old_hash),
                            "removing unnecessary proposal"
                        );
                    }
                }

                // TODO: need to send notarization for block even if hanven't seen it yet
                self.locked.insert(height, Lock::Finalized(hash.clone()));
            }
            Some(Lock::Finalized(seen)) => {
                if *seen != hash {
                    panic!("finalized block hash mismatch");
                }
                return;
            }
            None => {
                self.locked.insert(height, Lock::Finalized(hash.clone()));
            }
        }

        // Mark as seen
        // TODO: call application recursively
        self.seen(proposal);
    }
}
