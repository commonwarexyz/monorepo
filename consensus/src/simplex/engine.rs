use super::{store::Store, wire, Error};
use crate::Application;
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use prost::Message as _;
use tracing::debug;

pub struct Engine<E: Clock, C: Scheme, A: Application, S: Sender, R: Receiver> {
    runtime: E,
    crypto: C,
    application: A,

    sender: S,
    receiver: R,

    validators: Vec<PublicKey>,
    store: Store<E, C, A>,
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
            runtime: runtime.clone(),
            crypto: crypto.clone(),
            application: application.clone(),
            sender,
            receiver,

            validators: validators.clone(),
            store: Store::new(runtime, crypto, application, validators),
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

    async fn handle_timeout(&mut self) {
        // Trigger the timeout
        let vote = self.store.timeout();

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

    pub async fn run(mut self) -> Result<(), Error> {
        // Process messages
        loop {
            // Attempt to propose a block
            if let Some(proposal) = self.store.propose() {
                // Broadcast the proposal
                let msg = wire::Message {
                    payload: Some(wire::message::Payload::Proposal(proposal.clone())),
                };
                let msg = msg.encode_to_vec();
                self.sender
                    .send(Recipients::All, msg.into(), true)
                    .await
                    .unwrap();

                // Handle the proposal
                self.handle_proposal(proposal).await;
            }

            // Wait for a timeout to fire or for a message to arrive
            let null_timeout = self.store.timeout_deadline();
            select! {
                _timeout = self.runtime.sleep_until(null_timeout) => {
                    self.handle_timeout().await;
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
                            self.handle_notarization(notarization).await;
                        },
                        wire::message::Payload::Finalize(finalize) => {
                            self.handle_finalize(finalize).await;
                        },
                        wire::message::Payload::Finalization(finalization) => {
                            self.handle_finalization(finalization).await;
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
