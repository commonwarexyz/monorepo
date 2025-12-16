//! Actor responsible for dialing peers and establishing connections.

use crate::authenticated::{
    lookup::{
        actors::{
            spawner,
            tracker::{self, Metadata, Reservation},
        },
        metrics,
    },
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Metrics, Network, SinkOf, Spawner, StreamOf,
};
use commonware_stream::{dial, Config as StreamConfig};
use commonware_utils::SystemTimeExt;
use governor::clock::Clock as GClock;
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::{seq::SliceRandom, CryptoRng, Rng};
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
}

/// Actor responsible for dialing peers and establishing outgoing connections.
pub struct Actor<E: Spawner + Clock + GClock + Network + Metrics, C: Signer> {
    context: ContextCell<E>,

    // ---------- State ----------
    /// The list of peers to dial.
    queue: Vec<C::PublicKey>,

    // ---------- Configuration ----------
    stream_cfg: StreamConfig<C>,
    dial_frequency: Duration,
    query_frequency: Duration,

    // ---------- Metrics ----------
    /// The number of dial attempts made to each peer.
    attempts: Family<metrics::Peer, Counter>,
}

impl<E: Spawner + Clock + GClock + Network + Rng + CryptoRng + Metrics, C: Signer> Actor<E, C> {
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
            attempts,
        }
    }

    /// Dial a peer for which we have a reservation.
    #[allow(clippy::type_complexity)]
    async fn dial_peer(
        &mut self,
        reservation: Reservation<C::PublicKey>,
        supervisor: &mut Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        // Extract metadata from the reservation
        let Metadata::Dialer(peer, address) = reservation.metadata().clone() else {
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
            move |context| async move {
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
                    let Some(reservation) = tracker.dial(peer).await else {
                        continue;
                    };
                    self.dial_peer(reservation, &mut supervisor).await;
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
