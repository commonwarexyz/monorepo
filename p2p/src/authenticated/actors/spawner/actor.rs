use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::authenticated::{
    actors::{peer, router, tracker},
    metrics,
};
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_utils::Array;
use futures::{channel::mpsc, StreamExt};
use governor::{clock::ReasonablyRealtime, Quota};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::{CryptoRng, Rng};
use std::time::Duration;
use tracing::{debug, info};

pub struct Actor<E: Spawner + Clock, Si: Sink, St: Stream, P: Array> {
    runtime: E,

    mailbox_size: usize,
    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,

    receiver: mpsc::Receiver<Message<E, Si, St, P>>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng, Si: Sink, St: Stream, P: Array>
    Actor<E, Si, St, P>
{
    pub fn new(runtime: E, cfg: Config) -> (Self, Mailbox<E, Si, St, P>) {
        let sent_messages = Family::<metrics::Message, Counter>::default();
        let received_messages = Family::<metrics::Message, Counter>::default();
        let rate_limited = Family::<metrics::Message, Counter>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("messages_sent", "messages sent", sent_messages.clone());
            registry.register(
                "messages_received",
                "messages received",
                received_messages.clone(),
            );
            registry.register(
                "messages_rate_limited",
                "messages rate limited",
                rate_limited.clone(),
            );
        }
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        (
            Self {
                runtime,
                mailbox_size: cfg.mailbox_size,
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: cfg.allowed_bit_vec_rate,
                allowed_peers_rate: cfg.allowed_peers_rate,
                receiver,
                sent_messages,
                received_messages,
                rate_limited,
            },
            Mailbox::new(sender),
        )
    }

    pub async fn run(mut self, tracker: tracker::Mailbox<E, P>, router: router::Mailbox<P>) {
        while let Some(msg) = self.receiver.next().await {
            match msg {
                Message::Spawn {
                    peer,
                    connection,
                    reservation,
                } => {
                    // Clone required variables
                    let sent_messages = self.sent_messages.clone();
                    let received_messages = self.received_messages.clone();
                    let rate_limited = self.rate_limited.clone();
                    let tracker = tracker.clone();
                    let mut router = router.clone();

                    // Spawn peer
                    self.runtime.spawn("peer", {
                        let runtime = self.runtime.clone();
                        async move {
                            // Create peer
                            info!(?peer, "peer started");
                            let (actor, messenger) = peer::Actor::new(
                                runtime,
                                peer::Config {
                                    sent_messages,
                                    received_messages,
                                    rate_limited,
                                    mailbox_size: self.mailbox_size,
                                    gossip_bit_vec_frequency: self.gossip_bit_vec_frequency,
                                    allowed_bit_vec_rate: self.allowed_bit_vec_rate,
                                    allowed_peers_rate: self.allowed_peers_rate,
                                },
                                reservation,
                            );

                            // Register peer with the router
                            let channels = router.ready(peer.clone(), messenger).await;

                            // Run peer
                            let e = actor.run(peer.clone(), connection, tracker, channels).await;

                            // Let the router know the peer has exited
                            info!(error = ?e, ?peer, "peer shutdown");
                            router.release(peer).await;
                        }
                    });
                }
            }
        }
        debug!("supervisor shutdown");
    }
}
