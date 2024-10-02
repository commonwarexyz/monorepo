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
use prost::Message;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tracing::{debug, warn};

pub enum Proposal {
    Hash(u64, Bytes),
    Downloaded(Bytes, wire::Proposal),
}

pub struct Backfiller<E: Clock + Rng, S: Sender, R: Receiver, A: Application> {
    runtime: E,
    sender: S,
    receiver: R,
    application: A,

    validators: Vec<PublicKey>,

    blocks: HashMap<Bytes, wire::Proposal>,
    index: HashMap<u64, Bytes>,

    missing: BTreeMap<u64, Bytes>,
}

impl<E: Clock + Rng, S: Sender, R: Receiver, A: Application> Backfiller<E, S, R, A> {
    pub fn get(&self, hash: Bytes) -> Option<wire::Proposal> {
        self.blocks.get(&hash).cloned()
    }

    fn seen(&mut self, proposal: Proposal) {
        match proposal {
            Proposal::Hash(height, hash) => {
                // Record that we are missing the height
                self.missing.insert(height, hash.clone());
            }
            Proposal::Downloaded(hash, proposal) => {
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
            }
        }
    }

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
            let validator = self.validators.choose(&mut self.runtime).unwrap();

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
                select! {
                    _timeout = self.runtime.sleep_until(deadline) => {
                        warn!(sender = hex(validator), height, "backfill request timed out");
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

                        // Handle response
                        let expected = match self.missing.get(&height) {
                            Some(expected) => expected,
                            None => {
                                // This could happen if an earlier sender already fulfilled
                                debug!(sender = hex(&sender), height, "unexpected backfill response");
                                continue;
                            }
                        };
                        let payload_hash = self.application.verify(proposal.payload.clone()).expect("unable to verify notarized/finalized payload");
                        let proposal_digest = proposal_digest(proposal.view, proposal.height, proposal.parent.clone(), payload_hash);
                        let incoming_hash = hash(proposal_digest);
                        if incoming_hash != *expected {
                            warn!(sender = hex(&sender), height, "block hash mismatch on resolution");
                            // TODO: add validator to blacklist
                            continue;
                        }

                        // Store the proposal
                        let parent = proposal.parent.clone();
                        self.missing.remove(&height);
                        self.index.insert(height, incoming_hash.clone());
                        self.blocks.insert(incoming_hash.clone(), proposal);

                        // Check to see if parent is stored and add to missing if not
                        if height > 0 && !self.index.contains_key(&(height - 1)) {
                            self.missing.insert(height - 1, parent);
                        }

                        // If incoming hash was the hash we were expecting, exit the loop
                        if incoming_hash == focus {
                            debug!(sender = hex(validator), height, "backfill resolution");
                            break;
                        }
                    },
                }
            }
        }
    }
}
