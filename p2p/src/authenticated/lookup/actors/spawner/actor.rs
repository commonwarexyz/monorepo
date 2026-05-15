use super::{ingress::Message, Config};
use crate::authenticated::{
    lookup::{
        actors::{peer, router, tracker},
        metrics,
    },
    Mailbox,
};
use commonware_actor::mailbox;
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{CounterFamily, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Sink, Spawner, Stream,
};
use rand_core::CryptoRngCore;
use std::num::NonZeroUsize;
use tracing::debug;
use tracker::ingress::SenderExt as _;

pub struct Actor<
    E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics,
    Si: Sink,
    St: Stream,
    C: PublicKey,
> {
    context: ContextCell<E>,

    mailbox_size: NonZeroUsize,
    send_batch_size: NonZeroUsize,
    ping_frequency: std::time::Duration,

    receiver: mailbox::Receiver<Message<Si, St, C>>,

    sent_messages: CounterFamily<metrics::Message<C>>,
    received_messages: CounterFamily<metrics::Message<C>>,
    dropped_messages: CounterFamily<metrics::Message<C>>,
    rate_limited: CounterFamily<metrics::Message<C>>,
}

impl<
        E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics,
        Si: Sink,
        St: Stream,
        C: PublicKey,
    > Actor<E, Si, St, C>
{
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message<Si, St, C>>) {
        let sent_messages = context.family("messages_sent", "messages sent");
        let received_messages = context.family("messages_received", "messages received");
        let dropped_messages = context.family(
            "messages_dropped",
            "messages dropped due to full application buffer",
        );
        let rate_limited = context.family("messages_rate_limited", "messages rate limited");
        let (sender, receiver) = Mailbox::new(cfg.mailbox_size);

        (
            Self {
                context: ContextCell::new(context),
                mailbox_size: cfg.mailbox_size,
                send_batch_size: cfg.send_batch_size,
                ping_frequency: cfg.ping_frequency,
                receiver,
                sent_messages,
                received_messages,
                dropped_messages,
                rate_limited,
            },
            sender,
        )
    }

    pub fn start(
        mut self,
        tracker: mailbox::Sender<tracker::Message<C>>,
        router: router::Mailbox<C>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, router))
    }

    async fn run(
        mut self,
        tracker: mailbox::Sender<tracker::Message<C>>,
        router: router::Mailbox<C>,
    ) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping spawner");
            },
            Some(msg) = self.receiver.recv() else {
                debug!("mailbox closed, stopping spawner");
                break;
            } => {
                match msg {
                    Message::Spawn {
                        peer,
                        connection,
                        reservation,
                    } => {
                        // Clone required variables
                        let sent_messages = self.sent_messages.clone();
                        let received_messages = self.received_messages.clone();
                        let dropped_messages = self.dropped_messages.clone();
                        let rate_limited = self.rate_limited.clone();
                        let tracker = tracker.clone();
                        let router = router.clone();

                        // Spawn peer
                        self.context.child("peer").spawn(move |context| async move {
                            // Create peer
                            debug!(?peer, "peer started");
                            let (peer_actor, peer_mailbox, messenger) = peer::Actor::new(
                                context,
                                peer::Config {
                                    ping_frequency: self.ping_frequency,
                                    sent_messages,
                                    received_messages,
                                    dropped_messages,
                                    rate_limited,
                                    mailbox_size: self.mailbox_size,
                                    send_batch_size: self.send_batch_size,
                                },
                            );

                            // Register peer with the router (may fail during shutdown)
                            let Some(channels) = router.ready(peer.clone(), messenger).await else {
                                debug!(?peer, "router shut down during peer setup");
                                return;
                            };

                            // Register peer with tracker
                            tracker.connect(peer.clone(), peer_mailbox);

                            // Run peer
                            let result = peer_actor.run(peer.clone(), connection, channels).await;

                            // Let the router know the peer has exited
                            match result {
                                Ok(()) => debug!(?peer, "peer shutdown gracefully"),
                                Err(e) => debug!(error = ?e, ?peer, "peer shutdown"),
                            }
                            let _ = router.release(peer);
                            // Release the reservation
                            drop(reservation)
                        });
                    }
                }
            },
        }
    }
}
