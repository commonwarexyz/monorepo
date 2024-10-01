use super::{manager::Store, wire, Error};
use crate::Application;
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{select, Clock};
use prost::Message as _;
use std::time::{Duration, SystemTime};
use tracing::debug;

pub struct Reactor<E: Clock, C: Scheme, A: Application, S: Sender, R: Receiver> {
    runtime: E,
    crypto: C,
    application: A,

    sender: S,
    receiver: R,

    validators: Vec<PublicKey>,
    store: Store<C, A>,
}

impl<E: Clock, C: Scheme, A: Application, S: Sender, R: Receiver> Reactor<E, C, A, S, R> {
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

    pub async fn run(mut self) -> Result<(), Error> {
        // Initialize the reactor
        let mut view = 0;
        let mut leader = self.validators[0].clone();
        let now = self.runtime.current();
        let mut leader_deadline = now + Duration::from_secs(1);
        let mut notarization_deadline = now + Duration::from_secs(2);
        let mut view_initialized = false;

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
                        wire::message::Payload::Proposal(proposal) => {
                            let vote = self.store.proposal(proposal);
                            // TODO
                        },
                        wire::message::Payload::Vote(vote) => {
                            // TODO
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
