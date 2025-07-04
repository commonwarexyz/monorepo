use super::{
    config::Config,
    ingress::{Mailbox, Message},
};
use crate::{
    collection::{Endpoint, Originator},
    Receiver, Recipients, Sender,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{Committable, Digest, Digestible, PublicKey};
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
    D: Digest,
    Req: Committable + Digestible<Digest = D> + Decode,
    Res: Digestible<Digest = D> + Encode + Decode,
    P: PublicKey,
    O: Originator<D, PublicKey = P, Response = Res>,
    Z: Endpoint<D, PublicKey = P, Request = Req, Response = Res>,
> {
    // Configuration
    context: E,
    quorum: usize,
    priority_request: bool,
    priority_response: bool,

    // Message passing
    originator: O,
    endpoint: Z,
    mailbox: mpsc::Receiver<Message<D, P, Req, Res>>,

    // State
    responses: HashMap<D, HashMap<O::PublicKey, Res>>,
}

impl<
        E: Clock + Spawner,
        D: Digest,
        Req: Committable + Digestible<Digest = D> + Encode + DecodeExt<()>,
        Res: Digestible<Digest = D> + Encode + DecodeExt<()>,
        P: PublicKey,
        O: Originator<D, PublicKey = P, Response = Res>,
        Z: Endpoint<D, PublicKey = P, Request = Req, Response = Res>,
    > Engine<E, D, Req, Res, P, O, Z>
{
    pub fn new(context: E, cfg: Config<D, O, Z>) -> (Self, Mailbox<D, P, Req, Res>) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox: Mailbox<D, P, Req, Res> = Mailbox::new(tx);
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
        let (mut req_tx, mut req_rx) = request_network;
        let (mut res_tx, mut res_rx) = response_network;
        let mut mailbox = self.mailbox.fuse();
        loop {
            select! {
                // Command from the mailbox
                command = mailbox.next() => {
                    if let Some(command) = command {
                        match command {
                            Message::Send { request } => {
                                let msg = request.encode();
                                let _result = req_tx.send(Recipients::All, msg.into(), self.priority_request).await;
                            },
                            Message::Peek { id, sender } => {
                                let responses = self.responses.get(&id)
                                    .cloned()
                                    .unwrap_or_default();
                                let _ = sender.send(responses);
                            },
                            Message::Cancel { id } => {
                                self.responses.remove(&id);
                            }
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
                    let response = match Res::decode(msg.clone()) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            continue;
                        }
                    };

                    // Handle the response
                    let digest = response.digest();
                    let entry = self.responses.entry(digest).or_default();
                    entry.insert(peer, response);

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
                    let msg = match Req::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            continue;
                        }
                    };

                    // Handle the request
                    let (tx, rx) = oneshot::channel();
                    self.endpoint.process(peer.clone(), msg, tx).await;

                    // Send the response
                    match rx.await {
                        Ok(result) => {
                            let result = result.encode();
                            let _ = res_tx.send(Recipients::One(peer), result.into(), self.priority_response).await;
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
