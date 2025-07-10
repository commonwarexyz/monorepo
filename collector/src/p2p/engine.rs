use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::p2p::{Handler, Monitor};
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use commonware_utils::futures::Pool;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, warn};

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
    tracked: HashMap<Rq::Commitment, HashSet<P>>,

    // Metrics
    outstanding: Gauge,
    requests: Counter,
    responses: Counter,
}

impl<
        E: Clock + Spawner + Metrics,
        Rq: Committable + Digestible + Codec,
        Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Codec,
        P: PublicKey,
        M: Monitor<Response = Rs, PublicKey = P>,
        H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
    > Engine<E, Rq, Rs, P, M, H>
{
    pub fn new(context: E, cfg: Config<M, H, Rq::Cfg, Rs::Cfg>) -> (Self, Mailbox<P, Rq>) {
        // Create mailbox
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox: Mailbox<P, Rq> = Mailbox::new(tx);

        // Create metrics
        let outstanding = Gauge::default();
        let requests = Counter::default();
        let responses = Counter::default();
        context.register(
            "outstanding",
            "outstanding commitments",
            outstanding.clone(),
        );
        context.register("requests", "processed requests", requests.clone());
        context.register("responses", "sent responses", responses.clone());

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
                tracked: HashMap::new(),
                outstanding,
                requests,
                responses,
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
        (mut req_tx, mut req_rx): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        (mut res_tx, mut res_rx): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let mut processed: Pool<Result<(P, Rs), oneshot::Canceled>> = Pool::default();
        loop {
            select! {
                // Command from the mailbox
                command = self.mailbox.next() => {
                    if let Some(command) = command {
                        match command {
                            Message::Send { request, recipients, responder } => {
                                // Track commitment (if not already tracked)
                                let commitment = request.commitment();
                                self.tracked.entry(commitment).or_default();
                                self.outstanding.set(self.tracked.len() as i64);

                                // Send the request to recipients
                                match req_tx.send(recipients, request.encode().into(), self.priority_request).await {
                                    Ok(recipients) => {
                                        let _ = responder.send(recipients);
                                    }
                                    Err(err) => {
                                        error!(?err, "failed to send request");
                                    }
                                }
                            },
                            Message::Cancel { commitment } => {
                                self.tracked.remove(&commitment);
                                self.outstanding.set(self.tracked.len() as i64);
                            }
                        }
                    }
                },

                // Ready future
                ready = processed.next_completed() => {
                    // Error handling
                    let Ok((peer, reply)) = ready else {
                        continue;
                    };
                    self.responses.inc();

                    // Send the response
                    let reply = reply.encode();
                    let _ = res_tx.send(Recipients::One(peer), reply.into(), self.priority_response).await;
                },

                // Request from an originator
                message = req_rx.recv() => {
                    self.requests.inc();

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
                    processed.push(async move {
                        Ok((peer, rx.await?))
                    });
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
                    let Some(responses) = self.tracked.get_mut(&commitment) else {
                        debug!(?commitment, ?peer, "response for unknown commitment");
                        continue;
                    };
                    if !responses.insert(peer.clone()) {
                        debug!(?commitment, ?peer, "duplicate response");
                        continue;
                    }

                    // Send the response to the monitor
                    self.monitor.collected(peer, response, responses.len()).await;
                },
            }
        }
    }
}
