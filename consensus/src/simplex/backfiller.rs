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
use prost::Message;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Clone)]
pub enum Proposal {
    Hash(u64, Bytes),
    Downloaded(Bytes, wire::Proposal),
}

enum Lock {
    Notarized(HashSet<Bytes>),
    Finalized(Bytes),
}

pub struct Backfiller<E: Clock + Rng, S: Sender, R: Receiver, A: Application> {
    runtime: E,
    sender: S,
    receiver: R,
    application: A,

    validators: Vec<PublicKey>,

    locked: HashMap<u64, Lock>,

    blocks: HashMap<Bytes, wire::Proposal>,
    index: HashMap<u64, Bytes>,

    missing: BTreeMap<u64, Bytes>,

    last_notified: u64,
}

// Sender/Receiver here are different than one used in consensus (separate rate limits and compression settings).
impl<E: Clock + Rng, S: Sender, R: Receiver, A: Application> Backfiller<E, S, R, A> {
    pub fn get(&self, hash: Bytes) -> Option<wire::Proposal> {
        self.blocks.get(&hash).cloned()
    }

    // TODO: base this off of notarized/finalized (don't want to build index until finalized data, could
    // have a separate index for notarized blocks by view and another for finalized blocks by height)
    fn resolve(&mut self, hash: Bytes, proposal: wire::Proposal) {
        // If resolves missing, remove from missing
        self.missing.remove(&proposal.height);

        // Record what we know
        let height = proposal.height;
        let parent = proposal.parent.clone();
        self.index.insert(proposal.height, hash.clone());
        self.blocks.insert(hash, proposal);

        // Check if we are missing the parent
        if height > 0 && !self.index.contains_key(&(height - 1)) {
            self.missing.insert(height - 1, parent);
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
            Proposal::Hash(height, hash) => {
                // Record that we are missing the height
                self.missing.insert(height, hash.clone());
            }
            Proposal::Downloaded(hash, proposal) => self.resolve(hash, proposal),
        }
    }

    // This is a pretty basic backfiller (in that it only attempts to resolve one missing
    // proposal at a time). In `tbd`, this will operate very differently because we can
    // verify the integrity of any proposal we receive at an index by the threshold signature.
    pub async fn run(&mut self) {
        loop {
            // Get the next missing proposal
            let (height, focus) = match self.missing.iter().next() {
                Some((height, hash)) => (*height, hash.clone()),
                None => {
                    self.runtime.sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Select random validator to fetch from
            let validator = self.validators.choose(&mut self.runtime).unwrap().clone();

            // Make the request
            let request = wire::Request {
                block: focus.clone(),
            }
            .encode_to_vec()
            .into();

            // Send the request
            if let Err(err) = self
                .sender
                .send(Recipients::One(validator.clone()), request, true)
                .await
            {
                warn!(?err, height, "failed to send backfill request");
                continue;
            }

            // Process responses until deadline or we receive the proposal
            let start = self.runtime.current();
            let deadline = start + Duration::from_secs(1);
            loop {
                let (sender, proposal) = select! {
                    _timeout = self.runtime.sleep_until(deadline) => {
                        warn!(validator = hex(&validator), height, "backfill request timed out");
                        break;
                    },
                    msg = self.receiver.recv() => {
                        // Parse message
                        let (sender, msg) = match msg {
                            Ok(msg) => msg,
                            Err(err) => {
                                warn!(?err, height, "failed to receive backfill response");
                                continue;
                            }
                        };
                        let resolution = match wire::Resolution::decode(msg) {
                            Ok(msg) => msg,
                            Err(err) => {
                                warn!(?err, sender = hex(&sender), height, "failed to decode message");
                                continue;
                            }
                        };
                        let proposal = match resolution.proposal {
                            Some(proposal) => proposal,
                            None => {
                                warn!(sender = hex(&sender), height, "resolution missing proposal");
                                continue;
                            }
                        };
                        (sender, proposal)
                    },
                };

                // Handle response
                let expected = match self.missing.get(&height) {
                    Some(expected) => expected,
                    None => {
                        // This could happen if an earlier sender already fulfilled
                        debug!(
                            sender = hex(&sender),
                            height, "unexpected backfill response"
                        );
                        continue;
                    }
                };
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
                if incoming_hash != *expected {
                    warn!(
                        sender = hex(&sender),
                        height, "block hash mismatch on resolution"
                    );
                    // TODO: add validator to blacklist
                    continue;
                }

                // Record the proposal
                self.resolve(incoming_hash.clone(), proposal);

                // If incoming hash was the hash we were expecting, exit the loop
                if incoming_hash == focus {
                    debug!(sender = hex(&sender), height, "backfill resolution");
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
        let (height, hash) = match &proposal {
            Proposal::Hash(height, hash) => (*height, hash.clone()),
            Proposal::Downloaded(hash, proposal) => (proposal.height, hash.clone()),
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
        let (height, hash) = match &proposal {
            Proposal::Hash(height, hash) => (*height, hash.clone()),
            Proposal::Downloaded(hash, proposal) => (proposal.height, hash.clone()),
        };

        // Insert lock if doesn't already exist
        let previous = self.locked.get_mut(&height);
        match previous {
            Some(Lock::Notarized(_)) => {
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
