use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    p2p::{Handler, Monitor},
    Error,
};
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{utils::codec::wrap, Blocker, Receiver, Recipients, Sender};
use commonware_runtime::{
    spawn_cell, telemetry::metrics::status::GaugeExt, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::futures::Pool;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, warn};

/// Engine that will disperse messages and collect responses.
pub struct Engine<E, B, Rq, Rs, P, M, H>
where
    E: Clock + Spawner,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    Rq: Committable + Digestible + Codec,
    Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Codec,
    M: Monitor<Response = Rs, PublicKey = P>,
    H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
{
    // Configuration
    context: ContextCell<E>,
    blocker: B,
    priority_request: bool,
    request_codec: Rq::Cfg,
    priority_response: bool,
    response_codec: Rs::Cfg,

    // Message passing
    monitor: M,
    handler: H,
    mailbox: mpsc::Receiver<Message<P, Rq>>,

    // State
    tracked: HashMap<Rq::Commitment, (HashSet<P>, HashSet<P>)>,

    // Metrics
    outstanding: Gauge,
    requests: Counter,
    responses: Counter,
}

impl<E, B, Rq, Rs, P, M, H> Engine<E, B, Rq, Rs, P, M, H>
where
    E: Clock + Spawner + Metrics,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    Rq: Committable + Digestible + Codec,
    Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Codec,
    M: Monitor<Response = Rs, PublicKey = P>,
    H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
{
    /// Creates a new engine with the given configuration.
    ///
    /// Returns a tuple of the engine and the mailbox for sending messages.
    pub fn new(context: E, cfg: Config<B, M, H, Rq::Cfg, Rs::Cfg>) -> (Self, Mailbox<P, Rq>) {
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
                context: ContextCell::new(context),
                blocker: cfg.blocker,
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

    /// Starts the engine with the given network channels.
    ///
    /// Returns a handle that can be used to wait for the engine to complete.
    pub fn start(
        mut self,
        requests: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        responses: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(requests, responses).await)
    }

    async fn run(
        mut self,
        requests: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        responses: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        // Wrap channels
        let (mut req_tx, mut req_rx) = wrap(self.request_codec, requests.0, requests.1);
        let (mut res_tx, mut res_rx) = wrap(self.response_codec, responses.0, responses.1);

        // Create futures pool
        let mut processed: Pool<Result<(P, Rs), oneshot::Canceled>> = Pool::default();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping engine");
            },
            // Command from the mailbox
            command = self.mailbox.next() => {
                if let Some(command) = command {
                    match command {
                        Message::Send { request, recipients, responder } => {
                            // Track commitment (if not already tracked)
                            let commitment = request.commitment();
                            let entry = self.tracked.entry(commitment).or_insert_with(|| {
                                self.outstanding.inc();
                                (HashSet::new(), HashSet::new())
                            });

                            // Send the request to recipients
                            match req_tx.send(
                                recipients,
                                request,
                                self.priority_request
                            ).await {
                                Ok(recipients) => {
                                    entry.0.extend(recipients.iter().cloned());
                                    let _ = responder.send(Ok(recipients));
                                }
                                Err(err) => {
                                    error!(?err, ?commitment, "failed to send message");
                                    let _ = responder.send(Err(Error::SendFailed(anyhow::anyhow!("{err:?}"))));
                                }
                            }
                        },
                        Message::Cancel { commitment } => {
                            if self.tracked.remove(&commitment).is_none() {
                                debug!(?commitment, "ignoring removal of unknown commitment");
                            }
                            let _ = self.outstanding.try_set(self.tracked.len());
                        }
                    }
                }
            },

            // Response from a handler
            ready = processed.next_completed() => {
                // Error handling
                let Ok((peer, reply)) = ready else {
                    continue;
                };
                self.responses.inc();

                // Send the response
                let _ = res_tx.send(
                    Recipients::One(peer),
                    reply,
                    self.priority_response
                ).await;
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
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(err) => {
                        warn!(?err, ?peer, "blocking peer");
                        self.blocker.block(peer).await;
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

            // Response from a handler
            response = res_rx.recv() => {
                // Error handling
                let (peer, msg) = match response {
                    Ok(r) => r,
                    Err(err) => {
                        error!(?err, "response receiver failed");
                        break;
                    }
                };
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(err) => {
                        warn!(?err, ?peer, "blocking peer");
                        self.blocker.block(peer).await;
                        continue;
                    }
                };

                // Handle the response
                let commitment = msg.commitment();
                let Some(responses) = self.tracked.get_mut(&commitment) else {
                    debug!(?commitment, ?peer, "response for unknown commitment");
                    continue;
                };
                if !responses.0.contains(&peer) {
                    debug!(?commitment, ?peer, "never sent request");
                    continue;
                }
                if !responses.1.insert(peer.clone()) {
                    debug!(?commitment, ?peer, "duplicate response");
                    continue;
                }

                // Send the response to the monitor
                self.monitor.collected(peer, msg, responses.1.len()).await;
            },
        }
    }
}
