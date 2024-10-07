use super::{orchestrator::Orchestrator, voter::Voter, wire, Error};
use crate::Application;
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use prost::Message as _;
use rand::Rng;
use tracing::debug;

pub struct Engine<E: Clock + Rng, C: Scheme, A: Application, S: Sender, R: Receiver> {
    runtime: E,
    crypto: C,
    application: A,

    voter: Voter<E, C, A>,
    voter_network: (S, R),

    orchestrator: Orchestrator<E, A>,
    orchestrator_network: (S, R),

    validators: Vec<PublicKey>,
}

impl<E: Clock + Rng, C: Scheme, A: Application, S: Sender, R: Receiver> Engine<E, C, A, S, R> {
    pub fn new(
        runtime: E,
        crypto: C,
        application: A,
        voter_network: (S, R),
        orchestrator_network: (S, R),
        mut validators: Vec<PublicKey>,
    ) -> Self {
        validators.sort();
        let orchestrator =
            Orchestrator::new(runtime.clone(), application.clone(), validators.clone());
        Self {
            runtime: runtime.clone(),
            crypto: crypto.clone(),
            application: application.clone(),

            // TODO: need to communicate with orchestrator in some way? Likely need to move to actor model...
            voter: Voter::new(runtime, crypto, orchestrator, validators.clone()),
            voter_network,

            orchestrator,
            orchestrator_network,

            validators: validators.clone(),
        }
    }

    async fn send_view_messages(&mut self, view: u64) {
        // Attempt to vote
        if let Some(vote) = self.voter.construct_vote(view) {
            // Broadcast the vote
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Vote(vote.clone())),
            };
            let msg = msg.encode_to_vec();
            self.voter_network
                .0
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
            self.voter_network
                .0
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
            self.voter_network
                .0
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
            self.voter_network
                .0
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();

            // Handle the finalization
            self.voter.finalization(finalization);
        };
    }

    pub async fn run(mut self) -> Result<(), Error> {
        // Process messages
        loop {
            // Attempt to propose a block
            if let Some(proposal) = self.voter.propose() {
                // Broadcast the proposal
                let msg = wire::Message {
                    payload: Some(wire::message::Payload::Proposal(proposal.clone())),
                };
                let msg = msg.encode_to_vec();
                self.voter_network
                    .0
                    .send(Recipients::All, msg.into(), true)
                    .await
                    .unwrap();

                // Handle the proposal
                let proposal_view = proposal.view;
                self.voter.proposal(proposal);
                self.send_view_messages(proposal_view).await;
            }

            // Wait for a timeout to fire or for a message to arrive
            let null_timeout = self.voter.timeout_deadline();
            let result = select! {
                _timeout = self.runtime.sleep_until(null_timeout) => {
                    None
                },
                result = self.voter_network.1.recv() => {
                    Some(result.map_err(|_| Error::NetworkClosed)?)
                },
            };
            if result.is_none() {
                // Trigger the timeout
                let vote = self.voter.timeout();

                // Broadcast the vote
                let msg = wire::Message {
                    payload: Some(wire::message::Payload::Vote(vote.clone())),
                };
                let msg = msg.encode_to_vec();
                self.voter_network
                    .0
                    .send(Recipients::All, msg.into(), true)
                    .await
                    .unwrap();

                // Handle the vote
                let vote_view = vote.view;
                self.voter.vote(vote);
                self.send_view_messages(vote_view).await;
                continue;
            }
            let (sender, msg) = result.unwrap();

            // Parse message
            let msg = match wire::Message::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = hex(&sender), "failed to decode message");
                    continue;
                }
            };
            let payload = match msg.payload {
                Some(payload) => payload,
                None => {
                    debug!(sender = hex(&sender), "message missing payload");
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
                    self.voter.proposal(proposal);
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
                _ => {
                    debug!(sender = hex(&sender), "unexpected message");
                    continue;
                }
            };

            // Attempt to send any new view messages
            self.send_view_messages(view).await;
        }
    }
}
