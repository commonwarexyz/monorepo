use super::{
    config::Config,
    ingress::{Mailbox, Message},
};
use crate::{
    collection::{Endpoint, Originator},
    Receiver, Recipients, Sender,
};
use bytes::Bytes;
use commonware_cryptography::{Committable, Digestible};
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Spawner};
use futures::channel::mpsc;
use std::collections::HashMap;
use tracing::{error, warn};

/// Engine that will disperse messages and collect responses.
pub struct Engine<E: Clock + Spawner, O: Originator, Z: Endpoint> {
    // Configuration
    context: E,
    quorum: usize,

    // Message passing
    originator: O,
    endpoint: Z,
    mailbox: mpsc::Receiver<Message<Z::Message, O::PublicKey>>,

    // State
    responses: HashMap<<Z::Message as Digestible>::Digest, HashMap<O::PublicKey, Bytes>>,
}

impl<E: Clock + Spawner, O: Originator, Z: Endpoint> Engine<E, O, Z> {
    pub fn new(context: E, cfg: Config<O, Z>) -> (Self, Mailbox<Z::Message, O::PublicKey>) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(tx);
        (
            Self {
                context,
                quorum: cfg.quorum,
                originator: cfg.originator,
                endpoint: cfg.endpoint,
                mailbox: rx,
                responses: HashMap::new(),
            },
            mailbox,
        )
    }

    pub fn start(
        mut self,
        request_network: (impl Sender, impl Receiver),
        response_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(request_network, response_network))
    }

    async fn run(
        mut self,
        request_network: (impl Sender, impl Receiver),
        response_network: (impl Sender, impl Receiver),
    ) {
        let (req_tx, req_rx) = request_network;
        let (res_tx, res_rx) = response_network;
        loop {
            select! {
                // Command from the mailbox
                command = self.mailbox.next().await => {
                    match command {
                        Message::Send { message } => {
                            // TODO
                            let result = req_tx.send(message, Recipients::All, false).await;
                        },
                        Message::Peek { id, sender } => {
                            let responses = self.responses.get(&id).cloned().unwrap_or_default();
                            let _ = sender.send(responses);
                        },
                        Message::Cancel { id } => {
                            self.responses.remove(&id);
                        }
                    }
                },

                // Response from an endpoint
                response = res_rx.recv() => {
                    // Error handling
                    let (peer, msg) = match response {
                        Ok(r) => r,
                        Err(err) => {
                            error!(?err, "response receiver failed");
                            break;
                        }
                    };

                    // Decode the message
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            continue;
                        }
                    };

                    // Handle the response
                    let digest = msg.digest();
                    let mut entry = self.responses.entry(digest.clone()).or_default();
                    entry.insert(peer, msg);

                    // Check if we have enough responses
                    if entry.len() >= self.quorum {
                        let responses = self
                            .responses
                            .remove(&digest)
                            .expect("digest not found");
                        self.originator
                            .collected(digest, responses)
                            .await;
                    }
                },

                // Request from an originator
                message = req_rx.recv() => {
                    // Error handling
                    let (peer, msg) = match message {
                        Ok(r) => r,
                        Err(err) => {
                            error!(?err, "request receiver failed");
                            break;
                        }
                    };

                    // Decode the message
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            continue;
                        }
                    };

                    // Handle the request
                    let (tx, rx) = oneshot::channel();
                    self.endpoint.process(peer, msg, tx).await;

                    // Send the response
                    match rx.await {
                        Ok(result) => {
                            let _ = res_tx.send(result, Recipients::One(peer), false).await;
                        }
                        Err(err) => {
                            error!(?err, ?peer, "failed to send response");
                        }
                    }
                }
            }
        }
    }
}
