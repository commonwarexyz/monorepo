use super::{ingress::Message, Config};
use crate::authenticated::{
    discovery::{
        actors::{
            peer, router,
            tracker::{self, Metadata},
        },
        metrics,
    },
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Handle, Metrics, Sink, Spawner, Stream};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::ReasonablyRealtime, Quota};
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};
use rand::{CryptoRng, Rng};
use std::time::Duration;
use tracing::debug;

pub struct Actor<
    E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + Metrics,
    Si: Sink,
    St: Stream,
    C: PublicKey,
> {
    context: E,

    mailbox_size: usize,
    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    max_peer_set_size: usize,
    allowed_peers_rate: Quota,
    peer_gossip_max_count: usize,

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
    #[allow(clippy::type_complexity)]
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message<E, Si, St, C>>) {
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
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: cfg.allowed_bit_vec_rate,
                max_peer_set_size: cfg.max_peer_set_size,
                allowed_peers_rate: cfg.allowed_peers_rate,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
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
        tracker: Mailbox<tracker::Message<E, C>>,
        router: Mailbox<router::Message<C>>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(tracker, router))
    }

    async fn run(
        mut self,
        tracker: Mailbox<tracker::Message<E, C>>,
        router: Mailbox<router::Message<C>>,
    ) {
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
                    let mut tracker = tracker.clone();
                    let mut router = router.clone();
                    let is_dialer = matches!(reservation.metadata(), Metadata::Dialer(..));

                    // Spawn peer
                    self.context
                        .with_label("peer")
                        .spawn(move |context| async move {
                            // Create peer
                            debug!(?peer, "peer started");
                            let (peer_actor, peer_mailbox, messenger) = peer::Actor::new(
                                context,
                                peer::Config {
                                    sent_messages,
                                    received_messages,
                                    rate_limited,
                                    mailbox_size: self.mailbox_size,
                                    gossip_bit_vec_frequency: self.gossip_bit_vec_frequency,
                                    allowed_bit_vec_rate: self.allowed_bit_vec_rate,
                                    max_peer_set_size: self.max_peer_set_size,
                                    allowed_peers_rate: self.allowed_peers_rate,
                                    peer_gossip_max_count: self.peer_gossip_max_count,
                                },
                            );

                            // Register peer with the router
                            let channels = router.ready(peer.clone(), messenger).await;

                            // Register peer with tracker
                            tracker.connect(peer.clone(), is_dialer, peer_mailbox).await;

                            // Run peer
                            let e = peer_actor
                                .run(peer.clone(), connection, tracker, channels)
                                .await;
                            connections.dec();

                            // Let the router know the peer has exited
                            debug!(error = ?e, ?peer, "peer shutdown");
                            router.release(peer).await;
                            // Release the reservation
                            drop(reservation);
                        });
                }
            }
        }
        debug!("supervisor shutdown");
    }
}
