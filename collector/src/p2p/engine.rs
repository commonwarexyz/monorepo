use super::{
    Config,
    ingress::{Mailbox, Message},
    wire,
};
use crate::{Handler, Monitor};
use ahash::AHashMap;
use commonware_actor::mailbox;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender, utils::codec::wrap};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{
        Counter, Gauge, GaugeExt, MetricsExt as _,
        status::{self, Status},
    },
};
use commonware_utils::{channel::oneshot, futures::Pool};
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

    // Collections by commitment, each with a responded flag per recipient and how many responded
    tracked: AHashMap<Rq::Commitment, (AHashMap<P, bool>, usize)>,

    // Commitments being collected
    outstanding: Gauge,
    // Received requests being served
    serve_processing: Gauge,
    // Sent requests by status. A request sent to at least one peer is a success and a request
    // sent to none is dropped.
    send: status::Counter,
    // Received responses by status. A collected response is a success and an ignored response is
    // dropped.
    collect: status::Counter,
    // Received requests by status. A request is a success when its response is sent, a failure
    // when the handler declines it, and dropped when its response cannot be sent.
    serve: status::Counter,
    // Received messages that failed to decode
    invalid: Counter,
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
    /// Creates a new engine and the [Mailbox] that enqueues requests and cancellations to it.
    pub fn new(context: E, cfg: Config<B, M, H, Rq::Cfg, Rs::Cfg>) -> (Self, Mailbox<P, Rq>) {
        // Create mailbox
        let (tx, rx) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);

        // Create metrics
        let outstanding = context.gauge("outstanding", "Number of commitments being collected");
        let serve_processing = context.gauge(
            "serve_processing",
            "Number of received requests being served",
        );
        let send = context.family("send", "Number of sent requests by status");
        let collect = context.family("collect", "Number of received responses by status");
        let serve = context.family("serve", "Number of received requests by status");
        let invalid = context.counter(
            "invalid",
            "Number of received messages that failed to decode",
        );

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
                tracked: AHashMap::new(),
                outstanding,
                serve_processing,
                send,
                collect,
                serve,
                invalid,
            },
            Mailbox::new(tx),
        )
    }

    /// Starts the engine and returns a handle that resolves once its context is stopped, the
    /// receiver closes, or every [Mailbox] has been dropped and the commands already enqueued have
    /// been handled. A peer that only serves requests must therefore keep its [Mailbox].
    pub fn start(
        mut self,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(network))
    }

    async fn run(mut self, network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>)) {
        // Wrap channel
        let (mut sender, mut receiver) = wrap::<_, _, wire::Message<Rq, Rs>>(
            (self.request_codec_config, self.response_codec_config),
            network.0,
            network.1,
        );

        // Requests the handler has neither answered nor declined
        let mut processed: Pool<'_, (P, Result<Rs, oneshot::error::RecvError>)> = Pool::default();
        select_loop! {
            self.context,
            on_start => {
                // Update metrics
                let _ = self.outstanding.try_set(self.tracked.len());
                let _ = self.serve_processing.try_set(processed.len());
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
                    let recipients = sender.send(
                        recipients,
                        wire::Message::Request(request),
                        self.priority_requests,
                    );
                    if recipients.is_empty() {
                        debug!(?commitment, "request sent to no peers");
                        self.send.inc(Status::Dropped);
                        continue;
                    }
                    self.send.inc(Status::Success);

                    // A recipient that has already responded stays marked as such
                    let (sent, _) = self
                        .tracked
                        .entry(commitment)
                        .or_insert_with(|| (AHashMap::with_capacity(recipients.len()), 0));
                    for recipient in recipients {
                        sent.entry(recipient).or_insert(false);
                    }
                }
                Message::Cancel { commitment } => {
                    if self.tracked.remove(&commitment).is_none() {
                        debug!(?commitment, "ignoring removal of unknown commitment");
                    }
                }
            },

            // Response from the local handler
            (peer, response) = processed.next_completed() => {
                // A dropped sender means the handler declined the request
                let Ok(response) = response else {
                    self.serve.inc(Status::Failure);
                    continue;
                };

                // Send the response to the peer that sent the request
                let sent = sender.send(
                    Recipients::One(peer.clone()),
                    wire::Message::Response(response),
                    self.priority_responses,
                );
                if sent.is_empty() {
                    debug!(?peer, "response not sent");
                    self.serve.inc(Status::Dropped);
                    continue;
                }
                self.serve.inc(Status::Success);
            },

            // Message from the network
            message = receiver.recv() => {
                // Error handling
                let (peer, msg) = match message {
                    Ok(r) => r,
                    Err(err) => {
                        error!(?err, "receiver failed");
                        break;
                    }
                };
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(err) => {
                        self.invalid.inc();
                        commonware_p2p::block!(self.blocker, peer, ?err, "invalid message");
                        continue;
                    }
                };

                match msg {
                    // Request from an originator
                    wire::Message::Request(request) => {
                        let response = self.handler.process(peer.clone(), request);
                        processed.push(async move { (peer, response.await) });
                    }

                    // Response from a remote handler
                    wire::Message::Response(response) => {
                        // Collect the first response from each peer the commitment was sent to
                        let mut status = self.collect.guard(Status::Dropped);
                        let commitment = response.commitment();
                        let Some((sent, count)) = self.tracked.get_mut(&commitment) else {
                            debug!(?commitment, ?peer, "response for unknown commitment");
                            continue;
                        };
                        let Some(responded) = sent.get_mut(&peer) else {
                            debug!(?commitment, ?peer, "never sent request");
                            continue;
                        };
                        if *responded {
                            debug!(?commitment, ?peer, "duplicate response");
                            continue;
                        }
                        *responded = true;
                        *count += 1;
                        status.set(Status::Success);

                        // Send the response to the monitor
                        self.monitor.collected(peer, response, *count);
                    }
                }
            },
        }
    }
}
