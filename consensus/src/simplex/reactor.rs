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

    view: u64,
    leader: PublicKey,
    leader_deadline: SystemTime,
    notarization_deadline: SystemTime,
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
        let now = runtime.current();
        validators.sort();
        Self {
            runtime,
            crypto: crypto.clone(),
            application: application.clone(),
            sender,
            receiver,

            view: 0,
            leader: validators[0].clone(),
            leader_deadline: now + Duration::from_secs(1),
            notarization_deadline: now + Duration::from_secs(2),
            store: Store::new(crypto, application, validators),
        }
    }

    pub async fn run(mut self) -> Result<(), Error> {
        // Process messages
        loop {
            // TODO: Determine if we should advance to the next view
            let now = self.runtime.current();
            self.leader_deadline = now + Duration::from_secs(1);
            self.notarization_deadline = now + Duration::from_secs(2);
            self.view += 1;
            // TODO: set leader and if leader, build a new block off of last notarized parent
            // TODO: do this at the top of the block because we need to send first block out.

            // Wait for something to happen
            select! {
                _timeout_leader = self.runtime.sleep_until(self.leader_deadline) => {
                    debug!(view = self.view, "leader deadline fired");
                    // TODO
                },
                _timeout_notarization = self.runtime.sleep_until(self.notarization_deadline) => {
                    debug!(view = self.view, "notarization deadline fired");
                    // TODO
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
                    match payload {
                        wire::message::Payload::Proposal(proposal) => {
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
