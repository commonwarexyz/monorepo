use super::{orchestrator::Mailbox, voter::Voter, wire, Error};
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock, Spawner};
use prost::Message as _;
use rand::Rng;
use tracing::debug;

pub struct Engine<E: Clock + Rng + Spawner, C: Scheme> {
    runtime: E,
    crypto: C,

    voter: Voter<E, C>,

    validators: Vec<PublicKey>,
}

impl<E: Clock + Rng + Spawner, C: Scheme> Engine<E, C> {
    pub fn new(runtime: E, crypto: C, mailbox: Mailbox, mut validators: Vec<PublicKey>) -> Self {
        validators.sort();
        Self {
            runtime: runtime.clone(),
            crypto: crypto.clone(),

            voter: Voter::new(runtime, crypto, mailbox, validators.clone()),

            validators: validators.clone(),
        }
    }

    async fn send_view_messages(&mut self, sender: &mut impl Sender, view: u64) {
        // Attempt to vote
        if let Some(vote) = self.voter.construct_vote(view) {
            // Broadcast the vote
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Vote(vote.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the vote
            self.voter.vote(vote);
        };

        // Attempt to notarize
        if let Some(notarization) = self.voter.construct_notarization(view) {
            // Broadcast the notarization
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Notarization(notarization.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the notarization
            self.voter.notarization(notarization);
        };

        // Attempt to finalize
        if let Some(finalize) = self.voter.construct_finalize(view) {
            // Broadcast the finalize
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Finalize(finalize.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the finalize
            self.voter.finalize(finalize);
        };

        // Attempt to finalization
        if let Some(finalization) = self.voter.construct_finalization(view) {
            // Broadcast the finalization
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Finalization(finalization.clone())),
            };
            let msg = msg.encode_to_vec();
            sender
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the finalization
            self.voter.finalization(finalization);
        };
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        // Process messages
        loop {
            // Attempt to propose a block
            if let Some(proposal) = self.voter.propose().await {
                // Broadcast the proposal
                let msg = wire::Message {
                    payload: Some(wire::message::Payload::Proposal(proposal.clone())),
                };
                let msg = msg.encode_to_vec();
                sender
                    .send(Recipients::All, msg.into(), true)
                    .await
                    .unwrap();

                // Handle the proposal
                let proposal_view = proposal.view;
                self.voter.proposal(proposal).await;
                self.send_view_messages(&mut sender, proposal_view).await;
            }

            // Wait for a timeout to fire or for a message to arrive
            let null_timeout = self.voter.timeout_deadline();
            select! {
                _timeout = self.runtime.sleep_until(null_timeout) => {
                    // Trigger the timeout
                    let vote = self.voter.timeout();

                    // Broadcast the vote
                    let msg = wire::Message {
                        payload: Some(wire::message::Payload::Vote(vote.clone())),
                    };
                    let msg = msg.encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Handle the vote
                    let vote_view = vote.view;
                    self.voter.vote(vote);
                    self.send_view_messages(&mut sender, vote_view).await;
                },
                result = receiver.recv() => {
                    // Parse message
                    let (s, msg) = result.unwrap();
                    let msg = match wire::Message::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            debug!(?err, sender = hex(&s), "failed to decode message");
                            continue;
                        }
                    };
                    let payload = match msg.payload {
                        Some(payload) => payload,
                        None => {
                            debug!(sender = hex(&s), "message missing payload");
                            continue;
                        }
                    };

                    // Process message
                    //
                    // While syncing any missing blocks, continue to listen to messages at
                    // tip (immediately vote dummy when entering round).
                    let view;
                    match payload {
                        wire::message::Payload::Proposal(proposal) => {
                            view = proposal.view;
                            self.voter.proposal(proposal).await;
                        }
                        wire::message::Payload::Vote(vote) => {
                            view = vote.view;
                            self.voter.vote(vote);
                        }
                        wire::message::Payload::Notarization(notarization) => {
                            view = notarization.view;
                            self.voter.notarization(notarization);
                        }
                        wire::message::Payload::Finalize(finalize) => {
                            view = finalize.view;
                            self.voter.finalize(finalize);
                        }
                        wire::message::Payload::Finalization(finalization) => {
                            view = finalization.view;
                            self.voter.finalization(finalization);
                        }
                    };

                    // Attempt to send any new view messages
                    self.send_view_messages(&mut sender, view).await;
                },
            };
        }
    }
}
