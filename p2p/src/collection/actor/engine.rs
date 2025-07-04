use super::{
    config::Config,
    ingress::{Mailbox, Message},
};
use crate::{
    collection::{Endpoint, Originator},
    Receiver, Recipients, Sender,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use std::collections::HashMap;
use tracing::{error, warn};

/// Engine that will disperse messages and collect responses.
pub struct Engine<
    E: Clock + Spawner,
    M: Committable + Decode,
    D: Digestible + Decode,
    P: PublicKey,
    O: Originator<PublicKey = P>,
    Z: Endpoint<PublicKey = P, Message = M>,
> {
    // Configuration
    context: E,
    quorum: usize,
    priority_request: bool,
    priority_response: bool,

    // Message passing
    originator: O,
    endpoint: Z,
    mailbox: mpsc::Receiver<Message<Z::Message, O::PublicKey>>,

    // State
    responses: HashMap<D::Digest, HashMap<O::PublicKey, Z::Message>>,
}

impl<
        E: Clock + Spawner,
        M: Committable + Decode,
        D: Digestible + Decode,
        P: PublicKey,
        O: Originator<PublicKey = P>,
        Z: Endpoint<PublicKey = P, Message = M>,
    > Engine<E, M, D, P, O, Z>
{
    pub fn new(context: E, cfg: Config<O, Z>) -> (Self, Mailbox<Z::Message, O::PublicKey>) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(tx);
        (
            Self {
                context,
                quorum: cfg.quorum,
                priority_request: cfg.priority_request,
                priority_response: cfg.priority_response,
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
        request_network: (
            impl Sender<PublicKey = O::PublicKey>,
            impl Receiver<PublicKey = O::PublicKey>,
        ),
        response_network: (
            impl Sender<PublicKey = O::PublicKey>,
            impl Receiver<PublicKey = O::PublicKey>,
        ),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(request_network, response_network))
    }

    async fn run(
        mut self,
        request_network: (
            impl Sender<PublicKey = O::PublicKey>,
            impl Receiver<PublicKey = O::PublicKey>,
        ),
        response_network: (
            impl Sender<PublicKey = O::PublicKey>,
            impl Receiver<PublicKey = O::PublicKey>,
        ),
    ) {
        let (req_tx, req_rx) = request_network;
        let (res_tx, res_rx) = response_network;
        loop {
            select! {
                // Command from the mailbox
                command = self.mailbox.next().await => {
                    match command {
                        Message::Send { message } => {
                            let msg = message.encode();
                            let result = req_tx.send(Recipients::All, message, self.priority_request).await;
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
                    let msg = match D::decode(&msg) {
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
                    let msg = match M::decode(&msg) {
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
                            let _ = res_tx.send(Recipients::One(peer), result, self.priority_response).await;
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
