use super::{
    config::Config,
    ingress::{Mailbox, Message},
};
use crate::p2p::{Endpoint, Originator};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
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
    Rq: Committable + Digestible + DecodeExt<()> + Encode,
    Rs: Committable<Commitment = Rq::Commitment>
        + Digestible<Digest = Rq::Digest>
        + DecodeExt<()>
        + Encode,
    P: PublicKey,
    O: Originator<Response = Rs, PublicKey = P>,
    Z: Endpoint<Request = Rq, Response = Rs, PublicKey = P>,
> {
    // Configuration
    context: E,
    quorum: usize,
    priority_request: bool,
    priority_response: bool,

    // Message passing
    originator: O,
    endpoint: Z,
    mailbox: mpsc::Receiver<Message<P, Rq, Rs>>,

    // State
    responses: HashMap<Rq::Commitment, HashMap<O::PublicKey, Rs>>,
}

impl<
        E: Clock + Spawner,
        Rq: Committable + Digestible + DecodeExt<()> + Encode,
        Rs: Committable<Commitment = Rq::Commitment>
            + Digestible<Digest = Rq::Digest>
            + DecodeExt<()>
            + Encode,
        P: PublicKey,
        O: Originator<Response = Rs, PublicKey = P>,
        Z: Endpoint<Request = Rq, Response = Rs, PublicKey = P>,
    > Engine<E, Rq, Rs, P, O, Z>
{
    pub fn new(context: E, cfg: Config<O, Z>) -> (Self, Mailbox<P, Rq, Rs>) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox: Mailbox<P, Rq, Rs> = Mailbox::new(tx);
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
                            Message::Send { request, recipients, responder } => {
                                let msg = request.commitment().encode();
                                match req_tx.send(recipients, msg.into(), self.priority_request).await {
                                    Ok(recipients) => {
                                        let _ = responder.send(recipients);
                                        self.responses.insert(request.commitment(), HashMap::new());
                                    }
                                    Err(err) => {
                                        error!(?err, "failed to send request");
                                    }
                                }
                            },
                            Message::Peek { commitment, sender } => {
                                // Either send back the responses, or drop the sender to indicate
                                // that responses for the digest are not being awaited
                                if let Some(responses) = self.responses.get(&commitment).cloned() {
                                    let _ = sender.send(responses);
                                }
                            },
                            Message::Cancel { commitment } => {
                                self.responses.remove(&commitment);
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
                    let response = match Rs::decode(msg.clone()) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            continue;
                        }
                    };

                    // Handle the response
                    let commitment = response.commitment();
                    let entry = self.responses.entry(commitment).or_default();
                    entry.insert(peer, response);

                    // Check if we have enough responses
                    if entry.len() >= self.quorum {
                        let responses = self
                            .responses
                            .remove(&commitment)
                            .expect("commitment not found");
                        self.originator
                            .collected(commitment, responses)
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
                    let msg = match Rq::decode(msg) {
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
