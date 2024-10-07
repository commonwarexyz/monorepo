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

    async fn handle_proposal(&mut self, proposal: wire::Proposal) {
        // Store the proposal
        let proposal_view = proposal.view;
        self.voter.proposal(proposal);

        // Attempt to vote
        let vote = match self.voter.construct_vote(proposal_view) {
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
        self.voter_network
            .0
            .send(Recipients::All, msg.into(), true)
            .await
            .unwrap();

        // Handle the vote
        self.handle_vote(vote).await;
    }

    async fn handle_vote(&mut self, vote: wire::Vote) {
        // Store the vote
        let vote_view = vote.view;
        self.voter.vote(vote);

        // Attempt to notarize
        let notarization = match self.voter.construct_notarization(vote_view) {
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
        self.voter_network
            .0
            .send(Recipients::All, msg.into(), true)
            .await
            .unwrap();

        // Handle the notarization
        self.handle_notarization(notarization).await;
    }

    async fn handle_notarization(&mut self, notarization: wire::Notarization) {
        // Store the notarization
        let notarization_view = notarization.view;
        self.voter.notarization(notarization);

        // Attempt to notarize
        if let Some(notarization) = self.voter.construct_notarization(notarization_view) {
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Notarization(notarization.clone())),
            };
            let msg = msg.encode_to_vec();
            self.voter_network
                .0
                .send(Recipients::All, msg.into(), true)
                .await
                .unwrap();
        };

        // Attempt to finalize
        let finalize = match self.voter.construct_finalize(notarization_view) {
            Some(finalize) => finalize,
            None => {
                return;
            }
        };
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
        self.handle_finalize(finalize).await;
    }

    async fn handle_finalize(&mut self, finalize: wire::Finalize) {
        // Store the finalize
        let finalize_view = finalize.view;
        self.voter.finalize(finalize);

        // Broadcast the finalization (ours may be better than what we received)
        let finalization = match self.voter.construct_finalization(finalize_view) {
            Some(finalization) => finalization,
            None => {
                return;
            }
        };
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
        self.handle_finalization(finalization).await;
    }

    async fn handle_finalization(&mut self, finalization: wire::Finalization) {
        // Store the finalization
        self.voter.finalization(finalization);
    }

    async fn handle_timeout(&mut self) {
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
            //
            // TODO: clean this up (done this way to prevent multiple mutable borrows)
            let null_timeout = self.store.timeout_deadline();
            let result = select! {
                _timeout = self.runtime.sleep_until(null_timeout) => {
                    None
                },
                result = self.receiver.recv() => {
                    Some(result.map_err(|_| Error::NetworkClosed)?)
                },
            };
            if result.is_none() {
                self.handle_timeout().await;
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
            match payload {
                // TODO: verify signature is from sender
                wire::message::Payload::Proposal(proposal) => {
                    self.handle_proposal(proposal).await;
                }
                wire::message::Payload::Vote(vote) => {
                    self.handle_vote(vote).await;
                }
                wire::message::Payload::Notarization(notarization) => {
                    self.handle_notarization(notarization).await;
                }
                wire::message::Payload::Finalize(finalize) => {
                    self.handle_finalize(finalize).await;
                }
                wire::message::Payload::Finalization(finalization) => {
                    self.handle_finalization(finalization).await;
                }
                _ => {
                    debug!(sender = hex(&sender), "unexpected message");
                    continue;
                }
            };
        }
    }
}
