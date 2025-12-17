use super::{ingress::Message, Config};
use crate::authenticated::{
    lookup::{
        actors::{peer, router, tracker},
        metrics,
    },
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Metrics, Quota, Sink, Spawner, Stream,
};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};
use rand::{CryptoRng, Rng};
use tracing::debug;

pub struct Actor<E: Spawner + Clock + Rng + CryptoRng + Metrics, Si: Sink, St: Stream, C: PublicKey>
{
    context: ContextCell<E>,

    mailbox_size: usize,
    ping_frequency: std::time::Duration,
    allowed_ping_rate: Quota,

    receiver: mpsc::Receiver<Message<Si, St, C>>,

    connections: Gauge,
    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
}

impl<E: Spawner + Clock + Rng + CryptoRng + Metrics, Si: Sink, St: Stream, C: PublicKey>
    Actor<E, Si, St, C>
{
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message<Si, St, C>>) {
        let connections = Gauge::default();
        let sent_messages = Family::<metrics::Message, Counter>::default();
        let received_messages = Family::<metrics::Message, Counter>::default();
        let rate_limited = Family::<metrics::Message, Counter>::default();
        context.register(
            "connections",
            "number of connected peers",
            connections.clone(),
        );
        context.register("messages_sent", "messages sent", sent_messages.clone());
        context.register(
            "messages_received",
            "messages received",
            received_messages.clone(),
        );
        context.register(
            "messages_rate_limited",
            "messages rate limited",
            rate_limited.clone(),
        );
        let (sender, receiver) = Mailbox::new(cfg.mailbox_size);

        (
            Self {
                context: ContextCell::new(context),
                mailbox_size: cfg.mailbox_size,
                ping_frequency: cfg.ping_frequency,
                allowed_ping_rate: cfg.allowed_ping_rate,
                receiver,
                connections,
                sent_messages,
                received_messages,
                rate_limited,
            },
            sender,
        )
    }

    pub fn start(
        mut self,
        tracker: UnboundedMailbox<tracker::Message<C>>,
        router: Mailbox<router::Message<C>>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, router).await)
    }

    async fn run(
        mut self,
        tracker: UnboundedMailbox<tracker::Message<C>>,
        router: Mailbox<router::Message<C>>,
    ) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping spawner");
            },
            msg = self.receiver.next() => {
                let Some(msg) = msg else {
                    debug!("mailbox closed, stopping spawner");
                    break;
                };
                match msg {
                    Message::Spawn {
                        peer,
                        connection,
                        reservation,
                    } => {
                        // Mark peer as connected
                        self.connections.inc();

                        // Clone required variables
                        let connections = self.connections.clone();
                        let sent_messages = self.sent_messages.clone();
                        let received_messages = self.received_messages.clone();
                        let rate_limited = self.rate_limited.clone();
                        let mut tracker = tracker.clone();
                        let mut router = router.clone();

                        // Spawn peer
                        self.context
                            .with_label("peer")
                            .spawn(move |context| async move {
                                // Create peer
                                debug!(?peer, "peer started");
                                let (peer_actor, peer_mailbox, messenger) = peer::Actor::new(
                                    context,
                                    peer::Config {
                                        ping_frequency: self.ping_frequency,
                                        allowed_ping_rate: self.allowed_ping_rate,
                                        sent_messages,
                                        received_messages,
                                        rate_limited,
                                        mailbox_size: self.mailbox_size,
                                    },
                                );

                                // Register peer with the router
                                let channels = router.ready(peer.clone(), messenger).await;

                                // Register peer with tracker
                                tracker.connect(peer.clone(), peer_mailbox);

                                // Run peer
                                let result = peer_actor.run(peer.clone(), connection, channels).await;
                                connections.dec();

                                // Let the router know the peer has exited
                                match result {
                                    Ok(()) => debug!(?peer, "peer shutdown gracefully"),
                                    Err(e) => debug!(error = ?e, ?peer, "peer shutdown"),
                                }
                                router.release(peer).await;
                                // Release the reservation
                                drop(reservation)
                            });
                    }
                }
            }
        }
    }
}
