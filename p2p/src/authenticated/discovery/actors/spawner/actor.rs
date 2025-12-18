use super::{ingress::Message, Config};
use crate::authenticated::{
    discovery::{
        actors::{
            peer, router,
            tracker::{self, Metadata},
        },
        metrics,
        types::InfoVerifier,
    },
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Sink, Spawner, Stream};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};
use rand::{CryptoRng, Rng};
use std::time::Duration;
use tracing::debug;

pub struct Actor<E: Spawner + Clock + Rng + CryptoRng + Metrics, O: Sink, I: Stream, C: PublicKey> {
    context: ContextCell<E>,

    mailbox_size: usize,
    gossip_bit_vec_frequency: Duration,
    max_peer_set_size: u64,
    peer_gossip_max_count: usize,
    info_verifier: InfoVerifier<C>,

    receiver: mpsc::Receiver<Message<O, I, C>>,

    connections: Gauge,
    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
}

impl<E: Spawner + Clock + Rng + CryptoRng + Metrics, O: Sink, I: Stream, C: PublicKey>
    Actor<E, O, I, C>
{
    #[allow(clippy::type_complexity)]
    pub fn new(context: E, cfg: Config<C>) -> (Self, Mailbox<Message<O, I, C>>) {
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
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                max_peer_set_size: cfg.max_peer_set_size,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                info_verifier: cfg.info_verifier,
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

                        // Spawn peer
                        self.context.with_label("peer").spawn({
                            let connections = self.connections.clone();
                            let sent_messages = self.sent_messages.clone();
                            let received_messages = self.received_messages.clone();
                            let rate_limited = self.rate_limited.clone();
                            let mut tracker = tracker.clone();
                            let mut router = router.clone();
                            let is_dialer = matches!(reservation.metadata(), Metadata::Dialer(..));
                            let info_verifier = self.info_verifier.clone();
                            move |context| async move {
                                // Get greeting from tracker (returns None if not eligible)
                                let Some(greeting) = tracker.connect(peer.clone(), is_dialer).await
                                else {
                                    debug!(?peer, "peer not eligible");
                                    connections.dec();
                                    drop(reservation);
                                    return;
                                };

                                // Create peer
                                debug!(?peer, "peer started");
                                let (peer_actor, messenger) = peer::Actor::new(
                                    context,
                                    peer::Config {
                                        sent_messages,
                                        received_messages,
                                        rate_limited,
                                        mailbox_size: self.mailbox_size,
                                        gossip_bit_vec_frequency: self.gossip_bit_vec_frequency,
                                        max_peer_set_size: self.max_peer_set_size,
                                        peer_gossip_max_count: self.peer_gossip_max_count,
                                        info_verifier,
                                    },
                                );

                                // Register peer with the router
                                let channels = router.ready(peer.clone(), messenger).await;

                                // Run peer (greeting is sent first before main loop)
                                let result = peer_actor
                                    .run(peer.clone(), greeting, connection, tracker, channels)
                                    .await;
                                connections.dec();

                                // Let the router know the peer has exited
                                match result {
                                    Ok(()) => debug!(?peer, "peer shutdown gracefully"),
                                    Err(e) => debug!(error = ?e, ?peer, "peer shutdown"),
                                }
                                router.release(peer).await;
                                // Release the reservation
                                drop(reservation);
                            }
                        });
                    }
                }
            }
        }
    }
}
