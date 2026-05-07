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
use commonware_p2p::{
    utils::codec::{wrap, WrappedMailboxSender, WrappedReceiver},
    Blocker, MailboxSender, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    channel::{
        actor::{self, ActorInbox, ActorMailbox},
        fallible::OneshotExt,
        oneshot,
    },
    futures::Pool,
};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error};

/// Engine that will disperse messages and collect responses.
pub struct Engine<E, B, Rq, Rs, P, M, H>
where
    E: BufferPooler + Clock + Spawner,
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
    mailbox_sender: ActorMailbox<Message<P, Rq>>,
    mailbox: ActorInbox<Message<P, Rq>>,

    // State
    tracked: HashMap<Rq::Commitment, (HashSet<P>, HashSet<P>)>,

    // Metrics
    outstanding: Gauge,
    requests: Counter,
    responses: Counter,
}

impl<E, B, Rq, Rs, P, M, H> Engine<E, B, Rq, Rs, P, M, H>
where
    E: BufferPooler + Clock + Spawner + Metrics,
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
        let (tx, rx) = actor::channel(cfg.mailbox_size);
        let mailbox: Mailbox<P, Rq> = Mailbox::new(tx.clone());

        // Create metrics
        let outstanding = context.gauge("outstanding", "outstanding commitments");
        let requests = context.counter("requests", "processed requests");
        let responses = context.counter("responses", "sent responses");

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
                mailbox_sender: tx,
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
        responses: (
            impl MailboxSender<PublicKey = P>,
            impl Receiver<PublicKey = P>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(requests, responses))
    }

    async fn run(
        mut self,
        requests: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        responses: (
            impl MailboxSender<PublicKey = P>,
            impl Receiver<PublicKey = P>,
        ),
    ) {
        // Wrap channels
        let (req_tx, mut req_rx) = wrap(
            self.request_codec,
            self.context.network_buffer_pool().clone(),
            requests.0,
            requests.1,
        );
        let res_tx = WrappedMailboxSender::<_, Rs>::new(
            self.context.network_buffer_pool().clone(),
            responses.0,
        );
        let mut res_rx = WrappedReceiver::<_, Rs>::new(
            self.response_codec,
            responses.1,
        );

        // Create futures pool
        let mut processed: Pool<Result<(P, Rs), oneshot::error::RecvError>> = Pool::default();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping engine");
            },
            // Command from the mailbox
            Some(command) = self.mailbox.recv() else continue => {
                match command {
                    Message::Send {
                        request,
                        recipients,
                        responder,
                    } => {
                        // Track commitment (if not already tracked)
                        let commitment = request.commitment();
                        self.tracked.entry(commitment).or_insert_with(|| {
                            self.outstanding.inc();
                            (HashSet::new(), HashSet::new())
                        });

                        let mut sender = req_tx.clone();
                        let mailbox = self.mailbox_sender.clone();
                        let priority = self.priority_request;
                        self.context.child("request_send").spawn(move |_| async move {
                            let result = sender
                                .send(recipients, request, priority)
                                .await
                                .map_err(|err| Error::SendFailed(err.into()));
                            let result = mailbox.enqueue(Message::Sent {
                                commitment,
                                responder,
                                result,
                            });
                            if !result.accepted() {
                                error!(?result, "failed to enqueue send result");
                            }
                        });
                    }
                    Message::Sent {
                        commitment,
                        responder,
                        result,
                    } => {
                        match result {
                            Ok(recipients) => {
                                if let Some(entry) = self.tracked.get_mut(&commitment) {
                                    entry.0.extend(recipients.iter().cloned());
                                }
                                responder.send_lossy(Ok(recipients));
                            }
                            Err(err) => {
                                error!(?err, ?commitment, "failed to send message");
                                if self
                                    .tracked
                                    .get(&commitment)
                                    .is_some_and(|(sent, received)| {
                                        sent.is_empty() && received.is_empty()
                                    })
                                {
                                    self.tracked.remove(&commitment);
                                    let _ = self.outstanding.try_set(self.tracked.len());
                                }
                                responder.send_lossy(Err(err));
                            }
                        }
                    }
                    Message::Cancel { commitment } => {
                        if self.tracked.remove(&commitment).is_none() {
                            debug!(?commitment, "ignoring removal of unknown commitment");
                        }
                        let _ = self.outstanding.try_set(self.tracked.len());
                    }
                }
            },

            // Response from a handler
            Ok((peer, reply)) = processed.next_completed() else continue => {
                self.responses.inc();

                // Send the response
                let result = res_tx.send(Recipients::One(peer), reply, self.priority_response);
                if !result.accepted() {
                    error!(?result, "failed to enqueue response");
                }
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
                        commonware_p2p::block!(self.blocker, peer, ?err, "invalid request");
                        continue;
                    }
                };

                // Handle the request
                let (tx, rx) = oneshot::channel();
                self.handler.process(peer.clone(), msg, tx).await;
                processed.push(async move { Ok((peer, rx.await?)) });
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
                        commonware_p2p::block!(self.blocker, peer, ?err, "invalid response");
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
