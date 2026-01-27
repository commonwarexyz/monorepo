//! Actor responsible for dialing peers and establishing connections.

use crate::{
    authenticated::{
        lookup::{
            actors::{
                spawner,
                tracker::{self, Metadata, Reservation},
            },
            metrics,
        },
        mailbox::UnboundedMailbox,
        Mailbox,
    },
    Ingress,
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Metrics, Network, Resolver, SinkOf, Spawner, StreamOf,
};
use commonware_stream::{dial, Config as StreamConfig};
use commonware_utils::SystemTimeExt;
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::seq::SliceRandom;
use rand_core::CryptoRngCore;
use std::time::Duration;
use tracing::debug;

/// Configuration for the dialer actor.
pub struct Config<C: Signer> {
    /// Configuration for the stream.
    pub stream_cfg: StreamConfig<C>,

    /// The frequency at which to dial a single peer from the queue. This also limits the rate at
    /// which we attempt to dial peers in general.
    pub dial_frequency: Duration,

    /// The frequency at which to refresh the list of dialable peers if there are no more peers in
    /// the queue. This also limits the rate at which any single peer is dialed multiple times.
    ///
    /// This approach attempts to help ensure that the connection rate-limiter is not maxed out for
    /// a single peer by preventing dialing it as fast as possible. This should make it easier for
    /// other peers to dial us.
    pub query_frequency: Duration,

    /// Whether to allow dialing private IP addresses after DNS resolution.
    pub allow_private_ips: bool,
}

/// Actor responsible for dialing peers and establishing outgoing connections.
pub struct Actor<E: Spawner + Clock + Network + Resolver + Metrics, C: Signer> {
    context: ContextCell<E>,

    // ---------- State ----------
    /// The list of peers to dial.
    queue: Vec<C::PublicKey>,

    // ---------- Configuration ----------
    stream_cfg: StreamConfig<C>,
    dial_frequency: Duration,
    query_frequency: Duration,
    allow_private_ips: bool,

    // ---------- Metrics ----------
    /// The number of dial attempts made to each peer.
    attempts: Family<metrics::Peer, Counter>,
}

impl<E: Spawner + Clock + Network + Resolver + CryptoRngCore + Metrics, C: Signer> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>) -> Self {
        let attempts = Family::<metrics::Peer, Counter>::default();
        context.register(
            "attempts",
            "The number of dial attempts made to each peer",
            attempts.clone(),
        );
        Self {
            context: ContextCell::new(context),
            queue: Vec::new(),
            stream_cfg: cfg.stream_cfg,
            dial_frequency: cfg.dial_frequency,
            query_frequency: cfg.query_frequency,
            allow_private_ips: cfg.allow_private_ips,
            attempts,
        }
    }

    /// Dial a peer for which we have a reservation.
    #[allow(clippy::type_complexity)]
    async fn dial_peer(
        &mut self,
        reservation: Reservation<C::PublicKey>,
        ingress: Ingress,
        supervisor: &mut Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        // Extract metadata from the reservation
        let Metadata::Dialer(peer) = reservation.metadata().clone() else {
            unreachable!("unexpected reservation metadata");
        };

        // Increment metrics.
        self.attempts
            .get_or_create(&metrics::Peer::new(&peer))
            .inc();

        // Spawn dialer to connect to peer
        self.context.with_label("dialer").spawn({
            let config = self.stream_cfg.clone();
            let mut supervisor = supervisor.clone();
            let allow_private_ips = self.allow_private_ips;
            move |mut context| async move {
                // Resolve ingress to socket addresses (filtered by private IP policy)
                let addresses: Vec<_> = ingress
                    .resolve_filtered(&context, allow_private_ips)
                    .await
                    .map(Iterator::collect)
                    .unwrap_or_default();
                let Some(&address) = addresses.choose(&mut context) else {
                    debug!(?ingress, "failed to resolve or no valid addresses");
                    return;
                };

                // Attempt to dial peer
                let (sink, stream) = match context.dial(address).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        debug!(?err, "failed to dial peer");
                        return;
                    }
                };
                debug!(?peer, ?address, "dialed peer");

                // Upgrade connection
                let connection = match dial(context, config, peer.clone(), stream, sink).await {
                    Ok(instance) => instance,
                    Err(err) => {
                        debug!(?err, "failed to upgrade connection");
                        return;
                    }
                };
                debug!(?peer, ?address, "upgraded connection");

                // Start peer to handle messages
                supervisor.spawn(connection, reservation).await;
            }
        });
    }

    /// Start the dialer actor.
    #[allow(clippy::type_complexity)]
    pub fn start(
        mut self,
        tracker: UnboundedMailbox<tracker::Message<C::PublicKey>>,
        supervisor: Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, supervisor).await)
    }

    #[allow(clippy::type_complexity)]
    async fn run(
        mut self,
        mut tracker: UnboundedMailbox<tracker::Message<C::PublicKey>>,
        mut supervisor: Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        let mut dial_deadline = self.context.current();
        let mut query_deadline = self.context.current();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping dialer");
            },
            _ = self.context.sleep_until(dial_deadline) => {
                // Update the deadline.
                dial_deadline = dial_deadline.add_jittered(
                    &mut self.context,
                    self.dial_frequency,
                );

                // Pop the queue until we can reserve a peer.
                // If a peer is reserved, attempt to dial it.
                while let Some(peer) = self.queue.pop() {
                    // Attempt to reserve peer.
                    let Some((reservation, ingress)) = tracker.dial(peer).await else {
                        continue;
                    };
                    self.dial_peer(reservation, ingress, &mut supervisor).await;
                    break;
                }
            },
            _ = self.context.sleep_until(query_deadline) => {
                // Update the deadline.
                query_deadline = query_deadline.add_jittered(
                    &mut self.context,
                    self.query_frequency,
                );

                // Only update the queue if it is empty.
                if self.queue.is_empty() {
                    // Query the tracker for dialable peers and shuffle the list to prevent
                    // starvation.
                    self.queue = tracker.dialable().await;
                    self.queue.shuffle(&mut self.context);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::lookup::actors::tracker::{ingress::Releaser, Metadata};
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Clock, Runner};
    use commonware_stream::Config as StreamConfig;
    use futures::StreamExt;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    fn test_stream_config(signing_key: PrivateKey) -> StreamConfig<PrivateKey> {
        StreamConfig {
            signing_key,
            namespace: b"test".to_vec(),
            max_message_size: 1024,
            handshake_timeout: Duration::from_secs(5),
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
        }
    }

    #[test]
    fn test_dialer_dials_one_peer_per_tick() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let dial_frequency = Duration::from_millis(100);

            let dialer_cfg = Config {
                stream_cfg: test_stream_config(signer),
                dial_frequency,
                query_frequency: Duration::from_secs(60),
                allow_private_ips: true,
            };

            let dialer = Actor::new(context.with_label("dialer"), dialer_cfg);

            let (tracker_mailbox, mut tracker_rx) =
                UnboundedMailbox::<tracker::Message<PublicKey>>::new();

            // Create a releaser for reservations
            let (releaser_mailbox, _releaser_rx) =
                UnboundedMailbox::<tracker::Message<PublicKey>>::new();
            let releaser = Releaser::new(releaser_mailbox);

            // Generate 5 peers
            let peers: Vec<PublicKey> = (1..=5)
                .map(|i| PrivateKey::from_seed(i).public_key())
                .collect();

            // Create a supervisor that just drops spawn messages
            let (supervisor, mut supervisor_rx) =
                Mailbox::<spawner::Message<_, _, PublicKey>>::new(100);
            context
                .with_label("supervisor")
                .spawn(|_| async move { while supervisor_rx.next().await.is_some() {} });

            // Start the dialer
            let _handle = dialer.start(tracker_mailbox, supervisor);

            // Handle messages until deadline, counting dial attempts
            let mut dial_count = 0;
            let deadline = context.current() + dial_frequency * 3 + Duration::from_millis(100);
            loop {
                select! {
                    msg = tracker_rx.next() => {
                        match msg {
                            Some(tracker::Message::Dialable { responder }) => {
                                let _ = responder.send(peers.clone());
                            }
                            Some(tracker::Message::Dial { public_key, reservation }) => {
                                dial_count += 1;
                                let metadata = Metadata::Dialer(public_key);
                                let res = tracker::Reservation::new(metadata, releaser.clone());
                                let ingress: Ingress =
                                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8000).into();
                                let _ = reservation.send(Some((res, ingress)));
                            }
                            _ => {}
                        }
                    },
                    _ = context.sleep_until(deadline) => break,
                }
            }

            // Should have dialed ~3 peers (one per tick), not all 5 at once
            assert!(
                dial_count >= 2 && dial_count <= 4,
                "expected 2-4 dial attempts (one per tick), got {}",
                dial_count
            );
        });
    }
}
