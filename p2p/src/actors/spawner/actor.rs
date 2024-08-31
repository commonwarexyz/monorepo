use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    actors::{peer, router, tracker},
    metrics,
};
use commonware_cryptography::{utils::hex, Scheme};
use governor::Quota;
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info};

pub struct Actor<C: Scheme> {
    mailbox_size: usize,
    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,

    receiver: mpsc::Receiver<Message<C>>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
}

impl<C: Scheme> Actor<C> {
    pub fn new(cfg: Config) -> (Self, Mailbox<C>) {
        let sent_messages = Family::<metrics::Message, Counter>::default();
        let received_messages = Family::<metrics::Message, Counter>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("messages_sent", "messages sent", sent_messages.clone());
            registry.register(
                "messages_received",
                "messages received",
                received_messages.clone(),
            );
        }
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        (
            Self {
                mailbox_size: cfg.mailbox_size,
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: cfg.allowed_bit_vec_rate,
                allowed_peers_rate: cfg.allowed_peers_rate,
                receiver,
                sent_messages,
                received_messages,
            },
            Mailbox::new(sender),
        )
    }

    pub async fn run(mut self, tracker: tracker::Mailbox, router: router::Mailbox) {
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                Message::Spawn {
                    peer,
                    connection,
                    reservation,
                } => {
                    // Clone required variables
                    let sent_messages = self.sent_messages.clone();
                    let received_messages = self.received_messages.clone();
                    let tracker = tracker.clone();
                    let router = router.clone();

                    // Record handshake messages
                    //
                    // We define these metrics in the spawner to ensure all recorded peers are in
                    // the same family (if we define the same metric in the peer actor, a duplicate
                    // family will be created for each peer).
                    sent_messages
                        .get_or_create(&metrics::Message::new_handshake(&peer))
                        .inc();
                    received_messages
                        .get_or_create(&metrics::Message::new_handshake(&peer))
                        .inc();

                    // Spawn peer
                    tokio::spawn(async move {
                        // Create peer
                        info!(peer = hex(&peer), "peer started");
                        let (actor, messenger) = peer::Actor::new(
                            peer::Config {
                                sent_messages,
                                received_messages,
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
                        info!(error = ?e, peer=hex(&peer), "peer shutdown");

                        // Let the router know the peer has exited
                        router.release(peer).await;
                    });
                }
            }
        }
        debug!("supervisor shutdown");
    }
}
