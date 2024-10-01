use super::{store::Store, wire, Error};
use crate::Application;
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use prost::Message as _;
use std::time::{Duration, SystemTime};
use tracing::debug;

pub struct Engine<E: Clock, C: Scheme, A: Application, S: Sender, R: Receiver> {
    runtime: E,
    crypto: C,
    application: A,

    sender: S,
    receiver: R,

    validators: Vec<PublicKey>,
    store: Store<C, A>,
}

impl<E: Clock, C: Scheme, A: Application, S: Sender, R: Receiver> Engine<E, C, A, S, R> {
    pub fn new(
        runtime: E,
        crypto: C,
        application: A,
        sender: S,
        receiver: R,
        mut validators: Vec<PublicKey>,
    ) -> Self {
        validators.sort();
        Self {
            runtime,
            crypto: crypto.clone(),
            application: application.clone(),
            sender,
            receiver,

            validators: validators.clone(),
            store: Store::new(crypto, application, validators),
        }
    }

    async fn handle_proposal(&mut self, proposal: wire::Proposal) {
        // Store the proposal
        let vote = match self.store.proposal(proposal) {
            Some(vote) => vote,
            None => {
                return;
            }
        };

        // Broadcast the vote
        let msg = wire::Message {
            payload: Some(wire::message::Payload::Vote(vote.clone())),
        };
        let msg = msg.encode_to_vec();
        self.sender
            .send(Recipients::All, msg.into(), true)
            .await
            .unwrap();

        // Handle the vote
        self.handle_vote(vote).await;
    }

    async fn handle_vote(&mut self, vote: wire::Vote) {
        // Store the vote
        let notarization = match self.store.vote(vote) {
            Some(notarization) => notarization,
            None => {
                return;
            }
        };

        // Broadcast the notarization
        let msg = wire::Message {
            payload: Some(wire::message::Payload::Notarization(notarization.clone())),
        };
        let msg = msg.encode_to_vec();
        self.sender
            .send(Recipients::All, msg.into(), true)
            .await
            .unwrap();

        // Handle the notarization
        self.handle_notarization(notarization).await;
    }

    async fn handle_notarization(&mut self, notarization: wire::Notarization) {
        // Store the notarization
        let (notarization, finalize) = self.store.notarization(notarization);

        // Broadcast notarization (ours may be better than what we received)
        if let Some(notarization) = notarization {
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Notarization(notarization.clone())),
            };
            let msg = msg.encode_to_vec();
            self.sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();
        }

        // Broadcast the finalize
        if let Some(finalize) = finalize {
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Finalize(finalize.clone())),
            };
            let msg = msg.encode_to_vec();
            self.sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the finalize
            self.handle_finalize(finalize).await;
        }
    }

    async fn handle_finalize(&mut self, finalize: wire::Finalize) {
        // Store the finalize
        let finalization = match self.store.finalize(finalize) {
            Some(finalization) => finalization,
            None => {
                return;
            }
        };

        // Broadcast the finalization (ours may be better than what we received)
        let msg = wire::Message {
            payload: Some(wire::message::Payload::Finalization(finalization.clone())),
        };
        let msg = msg.encode_to_vec();
        self.sender
            .send(Recipients::All, msg.into(), true)
            .await
            .unwrap();

        // Handle the finalization
        self.handle_finalization(finalization).await;
    }

    async fn handle_finalization(&mut self, finalization: wire::Finalization) {
        // Store the finalization
        self.store.finalization(finalization);
    }

    pub async fn run(mut self) -> Result<(), Error> {
        // Process messages
        loop {
            // Initialize the view
            if !view_initialized {
                // Propose a block if we are the leader
                if leader == self.crypto.public_key() {
                    let payload = self.application.propose();
                    let payload_hash = self
                        .application
                        .verify(payload.clone())
                        .expect("unable to verify our own proposal");
                    // TODO: store propose
                    // TODO: broadcast proposal
                    // TODO: generate vote
                    // TODO: store vote
                    // TODO: broadcast vote
                }

                // Set timeouts
                let now = self.runtime.current();
                leader_deadline = now + Duration::from_secs(1);
                notarization_deadline = now + Duration::from_secs(2);
                view_initialized = true;
            }
            // TODO: set leader and if leader, build a new block off of last notarized parent
            // TODO: do this at the top of the block because we need to send first block out.

            // Wait for something to happen
            select! {
                _timeout_leader = self.runtime.sleep_until(leader_deadline) => {
                    debug!(?view, "leader deadline fired");
                    // TODO: broadcast null vote and stop accepting proposals at this view
                },
                _timeout_notarization = self.runtime.sleep_until(notarization_deadline) => {
                    debug!(?view, "notarization deadline fired");
                    // TODO: broadcast null vote
                },
                msg = self.receiver.recv() => {
                    // Parse message
                    let (sender, msg) = msg.map_err(|_| Error::NetworkClosed)?;
                    let msg = match wire::Message::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            debug!(?err, sender = hex(&sender), "failed to decode message");
                            continue;
                        },
                    };
                    let payload = match msg.payload {
                        Some(payload) => payload,
                        None => {
                            debug!(sender = hex(&sender), "message missing payload");
                            continue;
                        },
                    };

                    // Process message
                    //
                    // While syncing any missing blocks, continue to listen to messages at
                    // tip (immediately vote dummy when entering round).
                    match payload {
                        // TODO: verify signature is from sender
                        wire::message::Payload::Proposal(proposal) => {
                            self.handle_proposal(proposal).await;
                        },
                        wire::message::Payload::Vote(vote) => {
                            self.handle_vote(vote).await;
                        },
                        wire::message::Payload::Notarization(notarization) => {
                            // TODO
                        },
                        wire::message::Payload::Finalize(finalize) => {
                            // TODO
                        },
                        wire::message::Payload::Finalization(finalization) => {
                            // TODO
                        },
                        _ => {
                            debug!(sender = hex(&sender), "unexpected message");
                            continue;
                        },
                    };
                },
            };
        }
    }
}
