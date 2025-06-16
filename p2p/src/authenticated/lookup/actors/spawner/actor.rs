use super::{ingress::Message, Config, Mailbox};
use crate::authenticated::lookup::{
    actors::{peer, router, tracker},
    metrics,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Handle, Metrics, Sink, Spawner, Stream};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::ReasonablyRealtime, Quota};
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};
use rand::{CryptoRng, Rng};
use tracing::debug;

pub struct Actor<
    E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + Metrics,
    Si: Sink,
    St: Stream,
    C: PublicKey,
> {
    context: E,

    mailbox_size: usize,
    ping_frequency: std::time::Duration,
    allowed_ping_rate: Quota,

    receiver: mpsc::Receiver<Message<E, Si, St, C>>,

    connections: Gauge,
    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
}

impl<
        E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + Metrics,
        Si: Sink,
        St: Stream,
        C: PublicKey,
    > Actor<E, Si, St, C>
{
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<E, Si, St, C>) {
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
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        (
            Self {
                context,
                mailbox_size: cfg.mailbox_size,
                ping_frequency: cfg.ping_frequency,
                allowed_ping_rate: cfg.allowed_ping_rate,
                receiver,
                connections,
                sent_messages,
                received_messages,
                rate_limited,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        tracker: tracker::Mailbox<E, C>,
        router: router::Mailbox<C>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(tracker, router))
    }

    async fn run(mut self, tracker: tracker::Mailbox<E, C>, router: router::Mailbox<C>) {
        while let Some(msg) = self.receiver.next().await {
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
                    let tracker = tracker.clone();
                    let mut router = router.clone();

                    // Spawn peer
                    self.context
                        .with_label("peer")
                        .spawn(move |context| async move {
                            // Create peer
                            debug!(?peer, "peer started");
                            let (actor, messenger) = peer::Actor::new(
                                context,
                                peer::Config {
                                    ping_frequency: self.ping_frequency,
                                    allowed_ping_rate: self.allowed_ping_rate,
                                    sent_messages,
                                    received_messages,
                                    rate_limited,
                                    mailbox_size: self.mailbox_size,
                                },
                                reservation,
                            );

                            // Register peer with the router
                            let channels = router.ready(peer.clone(), messenger).await;

                            // Run peer
                            let e = actor.run(peer.clone(), connection, tracker, channels).await;
                            connections.dec();

                            // Let the router know the peer has exited
                            debug!(error = ?e, ?peer, "peer shutdown");
                            router.release(peer).await;
                        });
                }
            }
        }
        debug!("supervisor shutdown");
    }
}
