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
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::futures::Pool;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error};

/// Engine that will disperse messages and collect responses.
pub struct Engine<E, Rq, Rs, P, M, H>
where
    E: Clock + Spawner,
    P: PublicKey,
    Rq: Committable + Digestible + Codec,
    Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Codec,
    M: Monitor<Response = Rs, PublicKey = P>,
    H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
{
    // Configuration
    context: ContextCell<E>,
    priority_request: bool,
    priority_response: bool,

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

impl<E, Rq, Rs, P, M, H> Engine<E, Rq, Rs, P, M, H>
where
    E: Clock + Spawner + Metrics,
    P: PublicKey,
    Rq: Committable + Digestible + Codec,
    Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Codec,
    M: Monitor<Response = Rs, PublicKey = P>,
    H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
{
    /// Creates a new engine with the given configuration.
    ///
    /// Returns a tuple of the engine and the mailbox for sending messages.
    pub fn new(context: E, cfg: Config<M, H>) -> (Self, Mailbox<P, Rq>) {
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
                priority_request: cfg.priority_request,
                priority_response: cfg.priority_response,
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
        requests: (impl Sender<PublicKey = P, Message = Rq>, impl Receiver<PublicKey = P, Message = Rq>),
        responses: (impl Sender<PublicKey = P, Message = Rs>, impl Receiver<PublicKey = P, Message = Rs>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(requests, responses).await)
    }

    async fn run(
        mut self,
        mut requests: (impl Sender<PublicKey = P, Message = Rq>, impl Receiver<PublicKey = P, Message = Rq>),
        mut responses: (impl Sender<PublicKey = P, Message = Rs>, impl Receiver<PublicKey = P, Message = Rs>),
    ) {
        // Create futures pool
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
                                let entry = self.tracked.entry(commitment).or_insert_with(|| {
                                    self.outstanding.inc();
                                    (HashSet::new(), HashSet::new())
                                });

                                // Send the request to recipients
                                match requests.0.send(
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
                                        let _ = responder.send(Err(Error::SendFailed(err.into())));
                                    }
                                }
                            },
                            Message::Cancel { commitment } => {
                                if self.tracked.remove(&commitment).is_none() {
                                    debug!(?commitment, "ignoring removal of unknown commitment");
                                }
                                self.outstanding.set(self.tracked.len() as i64);
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
                    let _ = responses.0.send(
                        Recipients::One(peer),
                        reply,
                        self.priority_response
                    ).await;
                },

                // Request from an originator
                message = requests.1.recv() => {
                    self.requests.inc();

                    // Error handling
                    let (peer, msg) = match message {
                        Ok(r) => r,
                        Err(err) => {
                            error!(?err, "request receiver failed");
                            break;
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
                response = responses.1.recv() => {
                    // Error handling
                    let (peer, msg) = match response {
                        Ok(r) => r,
                        Err(err) => {
                            error!(?err, "response receiver failed");
                            break;
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
}
