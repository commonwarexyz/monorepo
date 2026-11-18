use super::{
    Config,
    ingress::{Mailbox, Message},
    metrics,
};
use crate::{Handler, Monitor};
use commonware_actor::mailbox;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender, utils::codec::wrap};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{GaugeExt, status::Status},
};
use commonware_utils::{channel::oneshot, futures::Pool};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error};

/// Sends requests and collects their responses, and serves the requests of other peers.
pub struct Engine<E, B, Rq, Rs, P, M, H>
where
    E: Clock + Spawner + Metrics,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    Rq: Committable + Codec,
    Rs: Committable<Commitment = Rq::Commitment> + Codec,
    M: Monitor<Response = Rs, PublicKey = P>,
    H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
{
    // Configuration
    context: ContextCell<E>,
    blocker: B,
    priority_requests: bool,
    request_codec_config: Rq::Cfg,
    priority_responses: bool,
    response_codec_config: Rs::Cfg,

    // Message passing
    monitor: M,
    handler: H,
    mailbox: mailbox::Receiver<Message<P, Rq>>,

    // Collections by commitment, each with the peers the commitment was sent to and the peers
    // that have responded
    tracked: HashMap<Rq::Commitment, (HashSet<P>, HashSet<P>)>,

    // Metrics
    metrics: metrics::Metrics,
}

impl<E, B, Rq, Rs, P, M, H> Engine<E, B, Rq, Rs, P, M, H>
where
    E: Clock + Spawner + Metrics,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    Rq: Committable + Codec,
    Rs: Committable<Commitment = Rq::Commitment> + Codec,
    M: Monitor<Response = Rs, PublicKey = P>,
    H: Handler<Request = Rq, Response = Rs, PublicKey = P>,
{
    /// Creates a new engine with the given configuration.
    ///
    /// Returns the engine and the [Mailbox] that enqueues requests and cancellations to it.
    pub fn new(context: E, cfg: Config<B, M, H, Rq::Cfg, Rs::Cfg>) -> (Self, Mailbox<P, Rq>) {
        let (tx, rx) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let metrics = metrics::Metrics::init(&context);

        (
            Self {
                context: ContextCell::new(context),
                blocker: cfg.blocker,
                priority_requests: cfg.priority_requests,
                request_codec_config: cfg.request_codec_config,
                priority_responses: cfg.priority_responses,
                response_codec_config: cfg.response_codec_config,
                monitor: cfg.monitor,
                handler: cfg.handler,
                mailbox: rx,
                tracked: HashMap::new(),
                metrics,
            },
            Mailbox::new(tx),
        )
    }

    /// Starts the engine with the network channels that carry requests and responses.
    ///
    /// `requests` and `responses` must be two different channels, and every peer must assign
    /// them the same way.
    ///
    /// Returns a handle that resolves when the engine stops. The engine stops when its context
    /// is stopped, when either receiver closes, or once every [Mailbox] has been dropped and the
    /// commands already enqueued have been handled. A peer that only serves requests must
    /// therefore keep its [Mailbox].
    pub fn start(
        mut self,
        requests: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        responses: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(requests, responses))
    }

    async fn run(
        mut self,
        requests: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        responses: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        // Wrap channels
        let (mut req_tx, mut req_rx) = wrap(self.request_codec_config, requests.0, requests.1);
        let (mut res_tx, mut res_rx) = wrap(self.response_codec_config, responses.0, responses.1);

        // Requests the handler has neither answered nor declined
        let mut processed: Pool<'_, (P, Result<Rs, oneshot::error::RecvError>)> = Pool::default();
        select_loop! {
            self.context,
            on_start => {
                // Update metrics
                let _ = self.metrics.outstanding.try_set(self.tracked.len());
                let _ = self.metrics.serve_processing.try_set(processed.len());
            },
            on_stopped => {
                debug!("context shutdown, stopping engine");
            },
            // Command from the mailbox
            Some(command) = self.mailbox.recv() else {
                debug!("mailbox closed, stopping engine");
                break;
            } => match command {
                Message::Send {
                    commitment,
                    request,
                    recipients,
                } => {
                    // Collect only from the peers the request was sent to
                    let recipients = req_tx.send(recipients, request, self.priority_requests);
                    if recipients.is_empty() {
                        debug!(?commitment, "request sent to no peers");
                        self.metrics.send.inc(Status::Dropped);
                        continue;
                    }
                    self.metrics.send.inc(Status::Success);
                    let (sent, _) = self.tracked.entry(commitment).or_default();
                    sent.extend(recipients);
                }
                Message::Cancel { commitment } => {
                    if self.tracked.remove(&commitment).is_none() {
                        debug!(?commitment, "ignoring removal of unknown commitment");
                    }
                }
            },

            // Response from the local handler
            (peer, response) = processed.next_completed() => {
                let Ok(response) = response else {
                    self.metrics.serve.inc(Status::Failure);
                    continue;
                };

                // Send the response to the peer that sent the request
                let sent = res_tx.send(
                    Recipients::One(peer.clone()),
                    response,
                    self.priority_responses,
                );
                if sent.is_empty() {
                    debug!(?peer, "response not sent");
                    self.metrics.serve.inc(Status::Dropped);
                    continue;
                }
                self.metrics.serve.inc(Status::Success);
            },

            // Response from a remote handler
            //
            // Responses are polled before requests so that a stream of requests cannot starve
            // this peer's own collections.
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
                        self.metrics.collect.inc(Status::Invalid);
                        commonware_p2p::block!(self.blocker, peer, ?err, "invalid response");
                        continue;
                    }
                };

                // Collect the first response from each peer the commitment was sent to
                let mut status = self.metrics.collect.guard(Status::Dropped);
                let commitment = msg.commitment();
                let Some((sent, responded)) = self.tracked.get_mut(&commitment) else {
                    debug!(?commitment, ?peer, "response for unknown commitment");
                    continue;
                };
                if !sent.contains(&peer) {
                    debug!(?commitment, ?peer, "never sent request");
                    continue;
                }
                if !responded.insert(peer.clone()) {
                    debug!(?commitment, ?peer, "duplicate response");
                    continue;
                }
                status.set(Status::Success);

                // Send the response to the monitor
                self.monitor.collected(peer, msg, responded.len());
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
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(err) => {
                        self.metrics.serve.inc(Status::Invalid);
                        commonware_p2p::block!(self.blocker, peer, ?err, "invalid request");
                        continue;
                    }
                };

                // Handle the request
                let (tx, rx) = oneshot::channel();
                self.handler.process(peer.clone(), msg, tx);
                processed.push(async move { (peer, rx.await) });
            },
        }
    }
}
