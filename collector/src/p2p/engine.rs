use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::p2p::{Handler, Monitor};
use commonware_codec::{Codec, DecodeExt, Encode};
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
    Rq: Committable + Digestible + Codec,
    Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Codec,
    P: PublicKey,
    M: Monitor<Response = Rs, PublicKey = P>,
    H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
> {
    // Configuration
    context: E,
    priority_request: bool,
    request_codec: Rq::Cfg,
    priority_response: bool,
    response_codec: Rs::Cfg,

    // Message passing
    monitor: M,
    handler: H,
    mailbox: mpsc::Receiver<Message<P, Rq>>,

    // State
    responses: HashMap<Rq::Commitment, HashMap<P, Rs>>,
}

impl<
        E: Clock + Spawner,
        Rq: Committable + Digestible + Codec,
        Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Codec,
        P: PublicKey,
        M: Monitor<Response = Rs, PublicKey = P>,
        H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
    > Engine<E, Rq, Rs, P, M, H>
{
    pub fn new(context: E, cfg: Config<M, H, Rq::Cfg, Rs::Cfg>) -> (Self, Mailbox<P, Rq>) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox: Mailbox<P, Rq> = Mailbox::new(tx);
        (
            Self {
                context,
                priority_request: cfg.priority_request,
                request_codec: cfg.request_codec,
                priority_response: cfg.priority_response,
                response_codec: cfg.response_codec,
                monitor: cfg.monitor,
                handler: cfg.handler,
                mailbox: rx,
                responses: HashMap::new(),
            },
            mailbox,
        )
    }

    pub fn start(
        mut self,
        request_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        response_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(request_network, response_network))
    }

    async fn run(
        mut self,
        request_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        response_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
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
                    let response = match Rs::decode_cfg(msg, &self.response_codec) {
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
                    let msg = match Rq::decode_cfg(msg, &self.request_codec) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            continue;
                        }
                    };

                    // Handle the request
                    let (tx, rx) = oneshot::channel();
                    self.handler.process(peer.clone(), msg, tx).await;

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
