use super::{
    ingress::{Mailbox, Message},
    metrics::Metrics,
    Config,
};
use crate::authenticated::actors::{peer, router, tracker};
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Sink, Spawner, Stream};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::ReasonablyRealtime, Quota};
use rand::{CryptoRng, Rng};
use std::time::Duration;
use tracing::{debug, info};

pub struct Actor<
    E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RuntimeMetrics,
    Si: Sink,
    St: Stream,
    C: Scheme,
> {
    context: E,

    mailbox_size: usize,
    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,

    receiver: mpsc::Receiver<Message<E, Si, St, C>>,
    metrics: Metrics,
    peer_metrics: peer::Metrics,
}

impl<
        E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RuntimeMetrics,
        Si: Sink,
        St: Stream,
        C: Scheme,
    > Actor<E, Si, St, C>
{
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<E, Si, St, C>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let metrics = Metrics::init(context.clone());
        let peer_metrics = peer::Metrics::init(context.clone());
        (
            Self {
                context,
                mailbox_size: cfg.mailbox_size,
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: cfg.allowed_bit_vec_rate,
                allowed_peers_rate: cfg.allowed_peers_rate,
                receiver,
                metrics,
                peer_metrics,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        tracker: tracker::Mailbox<E, C>,
        router: router::Mailbox<C::PublicKey>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(tracker, router))
    }

    async fn run(mut self, tracker: tracker::Mailbox<E, C>, router: router::Mailbox<C::PublicKey>) {
        while let Some(msg) = self.receiver.next().await {
            match msg {
                Message::Spawn {
                    peer,
                    connection,
                    reservation,
                } => {
                    // Mark peer as connected
                    self.metrics.connections.inc();

                    // Clone required variables
                    let connections = self.metrics.connections.clone();
                    let tracker = tracker.clone();
                    let mut router = router.clone();
                    let metrics = self.peer_metrics.clone();

                    // Spawn peer
                    self.context
                        .with_label("peer")
                        .spawn(move |context| async move {
                            // Create peer
                            info!(?peer, "peer started");
                            let (actor, messenger) = peer::Actor::new(
                                context,
                                peer::Config {
                                    mailbox_size: self.mailbox_size,
                                    gossip_bit_vec_frequency: self.gossip_bit_vec_frequency,
                                    allowed_bit_vec_rate: self.allowed_bit_vec_rate,
                                    allowed_peers_rate: self.allowed_peers_rate,
                                    metrics,
                                },
                                reservation,
                            );

                            // Register peer with the router
                            let channels = router.ready(peer.clone(), messenger).await;

                            // Run peer
                            let e = actor.run(peer.clone(), connection, tracker, channels).await;
                            connections.dec();

                            // Let the router know the peer has exited
                            info!(error = ?e, ?peer, "peer shutdown");
                            router.release(peer).await;
                        });
                }
            }
        }
        debug!("supervisor shutdown");
    }
}
