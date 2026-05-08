//! Actor responsible for dialing peers and establishing connections.

use crate::authenticated::{
    dialing::Dialable,
    discovery::{
        actors::{
            spawner,
            tracker::{self, Metadata, Reservation},
        },
        metrics,
    },
    Mailbox,
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{CounterFamily, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Resolver, SinkOf, Spawner,
    StreamOf,
};
use commonware_stream::encrypted::{dial, Config as StreamConfig};
use commonware_utils::channel::{actor::{self, ActorInbox, Backpressure, MessagePolicy}, Feedback};
use rand::seq::SliceRandom;
use rand_core::CryptoRngCore;
use std::{
    collections::VecDeque,
    time::{Duration, SystemTime},
};
use tracing::debug;

// Mailbox for the spawner actor.
type SupervisorMailbox<E, C> =
    Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, <C as Signer>::PublicKey>>;

/// Configuration for the dialer actor.
pub struct Config<C: Signer> {
    /// Configuration for the stream.
    pub stream_cfg: StreamConfig<C>,

    /// The frequency at which to dial a single peer from the queue. This also limits the rate at
    /// which we attempt to dial peers in general.
    pub dial_frequency: Duration,

    /// The size of the dialer mailbox.
    pub mailbox_size: usize,

    /// The maximum interval between tracker queries when the queue is empty. This tracks the
    /// configured peer connection cooldown, since that is the soonest any peer could become
    /// reservable again.
    pub peer_connection_cooldown: Duration,

    /// Whether to allow dialing private IP addresses after DNS resolution.
    pub allow_private_ips: bool,
}

/// Actor responsible for dialing peers and establishing outgoing connections.
pub struct Actor<E: Spawner + Clock + Network + Resolver + Metrics, C: Signer> {
    context: ContextCell<E>,

    // ---------- Message-Passing ----------
    mailbox: Mailbox<Message<C::PublicKey>>,
    receiver: ActorInbox<Message<C::PublicKey>>,

    // ---------- State ----------
    /// The list of peers to dial.
    queue: Vec<C::PublicKey>,
    awaiting_dialable: bool,
    awaiting_dial: bool,
    next_query_at: Option<SystemTime>,

    // ---------- Configuration ----------
    stream_cfg: StreamConfig<C>,
    dial_frequency: Duration,
    peer_connection_cooldown: Duration,
    allow_private_ips: bool,

    // ---------- Metrics ----------
    /// The number of dial attempts made to each peer.
    attempts: CounterFamily<metrics::Peer<C::PublicKey>>,
}

impl<
        E: Spawner + BufferPooler + Clock + Network + Resolver + CryptoRngCore + Metrics,
        C: Signer,
    > Actor<E, C>
{
    pub fn new(context: E, cfg: Config<C>) -> Self {
        let attempts = context.family("attempts", "The number of dial attempts made to each peer");
        let (mailbox, receiver) = Mailbox::new(cfg.mailbox_size);
        Self {
            context: ContextCell::new(context),
            mailbox,
            receiver,
            queue: Vec::new(),
            awaiting_dialable: false,
            awaiting_dial: false,
            next_query_at: None,
            stream_cfg: cfg.stream_cfg,
            dial_frequency: cfg.dial_frequency,
            peer_connection_cooldown: cfg.peer_connection_cooldown,
            allow_private_ips: cfg.allow_private_ips,
            attempts,
        }
    }

    fn next_empty_deadline(&self, now: SystemTime) -> SystemTime {
        let min = now + self.dial_frequency;
        let max = (now + self.peer_connection_cooldown).max(min);
        self.next_query_at.unwrap_or(max).clamp(min, max)
    }

    fn request_dialable(&mut self, tracker: &Mailbox<tracker::Message<C::PublicKey>>) {
        if self.awaiting_dialable {
            return;
        }
        self.awaiting_dialable = matches!(
            tracker.request_dialable(self.mailbox.clone()),
            Feedback::Ok | Feedback::Backoff
        );
    }

    fn request_next_dial(&mut self, tracker: &Mailbox<tracker::Message<C::PublicKey>>) -> bool {
        if self.awaiting_dial {
            return true;
        }
        let Some(peer) = self.queue.pop() else {
            return false;
        };
        self.awaiting_dial = matches!(
            tracker.request_dial(peer.clone(), self.mailbox.clone()),
            Feedback::Ok | Feedback::Backoff
        );
        if !self.awaiting_dial {
            self.queue.push(peer);
        }
        self.awaiting_dial
    }

    /// Dial a peer for which we have a reservation.
    fn dial_peer(
        &mut self,
        reservation: Reservation<C::PublicKey>,
        supervisor: &mut SupervisorMailbox<E, C>,
    ) {
        // Extract metadata from the reservation
        let Metadata::Dialer(peer, ingress) = reservation.metadata().clone() else {
            unreachable!("unexpected reservation metadata");
        };

        // Increment metrics.
        self.attempts.get_or_create_by(&peer).inc();

        // Spawn dialer to connect to peer
        self.context.child("dialer").spawn({
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
                debug!(?peer, ?ingress, "dialed peer");

                // Upgrade connection
                let instance = match dial(context, config, peer.clone(), stream, sink).await {
                    Ok(instance) => instance,
                    Err(err) => {
                        debug!(?err, "failed to upgrade connection");
                        return;
                    }
                };
                debug!(?peer, ?ingress, "upgraded connection");

                // Start peer to handle messages
                let _ = supervisor.spawn(instance, reservation);
            }
        });
    }

    /// Start the dialer actor.
    pub fn start(
        mut self,
        tracker: Mailbox<tracker::Message<C::PublicKey>>,
        supervisor: SupervisorMailbox<E, C>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, supervisor))
    }

    async fn run(
        mut self,
        tracker: Mailbox<tracker::Message<C::PublicKey>>,
        mut supervisor: SupervisorMailbox<E, C>,
    ) {
        let mut dial_deadline = self.context.current();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping dialer");
            },
            Some(msg) = self.receiver.recv() else {
                debug!("mailbox closed, stopping dialer");
                break;
            } => {
                let now = self.context.current();
                match msg {
                    Message::Dialable(dialable) => {
                        self.awaiting_dialable = false;
                        self.queue = dialable.peers;
                        self.queue.shuffle(self.context.as_mut());
                        self.next_query_at = dialable.next_query_at;

                        dial_deadline = if self.request_next_dial(&tracker) {
                            now + self.dial_frequency
                        } else {
                            self.next_empty_deadline(now)
                        };
                    }
                    Message::Dial {
                        public_key,
                        reservation,
                    } => {
                        self.awaiting_dial = false;
                        if let Some(reservation) = reservation {
                            self.dial_peer(reservation, &mut supervisor);
                            dial_deadline = now + self.dial_frequency;
                        } else if self.request_next_dial(&tracker) {
                            dial_deadline = now + self.dial_frequency;
                        } else if self.queue.is_empty() {
                            dial_deadline = self.next_empty_deadline(now);
                        } else {
                            debug!(?public_key, "dial reservation unavailable");
                            dial_deadline = now + self.dial_frequency;
                        }
                    }
                }
            },
            _ = self.context.sleep_until(dial_deadline) => {
                // Refill the queue if empty.
                let now = self.context.current();
                if self.queue.is_empty() {
                    self.request_dialable(&tracker);
                }

                // Set next deadline.
                dial_deadline = if self.queue.is_empty() {
                    self.next_empty_deadline(now)
                } else {
                    now + self.dial_frequency
                };

                let _ = self.request_next_dial(&tracker);
            },
        }
    }
}

/// Messages sent to the dialer actor.
#[derive(Debug)]
pub(crate) enum Message<C: PublicKey> {
    /// A refreshed set of dialable peers.
    Dialable(Dialable<C>),
    /// Response to a dial reservation request.
    Dial {
        public_key: C,
        reservation: Option<Reservation<C>>,
    },
}

impl<C: PublicKey> MessagePolicy for Message<C> {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        Backpressure::replace_or_retain(match message {
            Self::Dialable(dialable) => actor::replace_last(
                queue,
                Self::Dialable(dialable),
                |pending| matches!(pending, Self::Dialable(_)),
            ),
            message => Err(message),
        }, queue)
    }
}

impl<C: PublicKey> Mailbox<Message<C>> {
    pub(crate) fn dialable(&self, dialable: Dialable<C>) -> Feedback {
        self.enqueue(Message::Dialable(dialable))
    }

    pub(crate) fn dial(&self, public_key: C, reservation: Option<Reservation<C>>) -> Feedback {
        self.enqueue(Message::Dial {
            public_key,
            reservation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authenticated::{
            dialing::Dialable,
            discovery::actors::tracker::{ingress::Releaser, Metadata},
        },
        Ingress,
    };
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
    use commonware_stream::encrypted::Config as StreamConfig;
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
                mailbox_size: 16,
                peer_connection_cooldown: Duration::from_secs(60),
                allow_private_ips: true,
            };

            let dialer = Actor::new(context.child("dialer"), dialer_cfg);

            let (tracker_mailbox, mut tracker_rx) =
                Mailbox::<tracker::Message<PublicKey>>::new(16);

            // Create a releaser for reservations
            let (releaser_mailbox, _releaser_rx) =
                Mailbox::<tracker::Message<PublicKey>>::new(16);
            let releaser = Releaser::new(releaser_mailbox);

            // Generate 10 peers
            let peers: Vec<PublicKey> = (0..10)
                .map(|i| PrivateKey::from_seed(i).public_key())
                .collect();

            // Create a supervisor that just drops spawn messages
            let (supervisor, mut supervisor_rx) =
                Mailbox::<spawner::Message<_, _, PublicKey>>::new(100);
            context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });

            // Start the dialer
            let _handle = dialer.start(tracker_mailbox, supervisor);

            // Handle messages until deadline, counting dial attempts
            let mut dial_count = 0;
            let deadline = context.current() + dial_frequency * 3;
            loop {
                select! {
                    msg = tracker_rx.recv() => match msg {
                        Some(tracker::Message::DialableForDialer { dialer }) => {
                            let _ = dialer.dialable(Dialable {
                                peers: peers.clone(),
                                next_query_at: Some(context.current()),
                            });
                        }
                        Some(tracker::Message::DialForDialer {
                            public_key,
                            dialer,
                        }) => {
                            dial_count += 1;
                            let ingress: Ingress =
                                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8000).into();
                            let metadata = Metadata::Dialer(public_key.clone(), ingress);
                            let res = tracker::Reservation::new(metadata, releaser.clone());
                            let _ = dialer.dial(public_key, Some(res));
                        }
                        _ => {}
                    },
                    _ = context.sleep_until(deadline) => break,
                }
            }

            // Should have dialed ~3 peers (one per tick), not all 10 at once
            assert!(
                (2..=4).contains(&dial_count),
                "expected 2-4 dial attempts (one per tick), got {}",
                dial_count
            );
        });
    }

    #[test]
    fn test_dialer_uses_tracker_next_query_deadline() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let dial_frequency = Duration::from_millis(500);

            let dialer = Actor::new(
                context.child("dialer"),
                Config {
                    stream_cfg: test_stream_config(signer),
                    dial_frequency,
                mailbox_size: 16,
                    peer_connection_cooldown: dial_frequency,
                    allow_private_ips: true,
                },
            );

            let (tracker_mailbox, mut tracker_rx) =
                Mailbox::<tracker::Message<PublicKey>>::new(16);
            let (supervisor, mut supervisor_rx) =
                Mailbox::<spawner::Message<_, _, PublicKey>>::new(100);
            context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });

            let _handle = dialer.start(tracker_mailbox, supervisor);

            // Tracker reports next_query_at=100ms, which is shorter than
            // dial_frequency=500ms. The dialer should clamp to dial_frequency,
            // so we only get 1 refresh in 350ms instead of 3-4.
            let mut refresh_count = 0;
            let deadline = context.current() + Duration::from_millis(350);
            loop {
                select! {
                    msg = tracker_rx.recv() => {
                        if let Some(tracker::Message::DialableForDialer { dialer }) = msg {
                            refresh_count += 1;
                            let _ = dialer.dialable(Dialable {
                                peers: Vec::new(),
                                next_query_at: Some(context.current() + Duration::from_millis(100)),
                            });
                        }
                    },
                    _ = context.sleep_until(deadline) => break,
                }
            }

            assert_eq!(
                refresh_count, 1,
                "expected 1 refresh (clamped to dial_frequency), got {}",
                refresh_count
            );
        });
    }

    #[test]
    fn test_dialer_drains_queue_at_dial_frequency() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let dial_frequency = Duration::from_millis(100);

            let dialer = Actor::new(
                context.child("dialer"),
                Config {
                    stream_cfg: test_stream_config(signer),
                    dial_frequency,
                mailbox_size: 16,
                    peer_connection_cooldown: Duration::from_secs(60),
                    allow_private_ips: true,
                },
            );

            let (tracker_mailbox, mut tracker_rx) =
                Mailbox::<tracker::Message<PublicKey>>::new(16);

            let (releaser_mailbox, _releaser_rx) =
                Mailbox::<tracker::Message<PublicKey>>::new(16);
            let releaser = Releaser::new(releaser_mailbox);

            let peers: Vec<PublicKey> = (0..3)
                .map(|i| PrivateKey::from_seed(i).public_key())
                .collect();

            let (supervisor, mut supervisor_rx) =
                Mailbox::<spawner::Message<_, _, PublicKey>>::new(100);
            context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });

            let _handle = dialer.start(tracker_mailbox, supervisor);

            let mut dial_count = 0;
            let deadline = context.current() + Duration::from_millis(250);
            loop {
                select! {
                    msg = tracker_rx.recv() => match msg {
                        Some(tracker::Message::DialableForDialer { dialer }) => {
                            let _ = dialer.dialable(Dialable {
                                peers: peers.clone(),
                                next_query_at: None,
                            });
                        }
                        Some(tracker::Message::DialForDialer {
                            public_key,
                            dialer,
                        }) => {
                            dial_count += 1;
                            let ingress: Ingress =
                                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8000).into();
                            let metadata = Metadata::Dialer(public_key.clone(), ingress);
                            let res = tracker::Reservation::new(metadata, releaser.clone());
                            let _ = dialer.dial(public_key, Some(res));
                        }
                        _ => {}
                    },
                    _ = context.sleep_until(deadline) => break,
                }
            }

            assert_eq!(
                dial_count, 3,
                "expected queued peers to drain at dial_frequency, got {} dials",
                dial_count
            );
        });
    }

    #[test]
    fn test_dialer_does_not_panic_when_dial_frequency_exceeds_peer_connection_cooldown() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let dial_frequency = Duration::from_millis(200);

            let dialer = Actor::new(
                context.child("dialer"),
                Config {
                    stream_cfg: test_stream_config(signer),
                    dial_frequency,
                mailbox_size: 16,
                    peer_connection_cooldown: Duration::from_millis(50),
                    allow_private_ips: true,
                },
            );

            let (tracker_mailbox, mut tracker_rx) =
                Mailbox::<tracker::Message<PublicKey>>::new(16);
            let (supervisor, mut supervisor_rx) =
                Mailbox::<spawner::Message<_, _, PublicKey>>::new(100);
            context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });

            let _handle = dialer.start(tracker_mailbox, supervisor);

            let mut refresh_count = 0;
            let deadline = context.current() + Duration::from_millis(350);
            loop {
                select! {
                    msg = tracker_rx.recv() => {
                        if let Some(tracker::Message::DialableForDialer { dialer }) = msg {
                            refresh_count += 1;
                            let _ = dialer.dialable(Dialable {
                                peers: Vec::new(),
                                next_query_at: None,
                            });
                        }
                    },
                    _ = context.sleep_until(deadline) => break,
                }
            }

            assert_eq!(
                refresh_count, 2,
                "expected 2 refreshes at dial_frequency without panicking, got {}",
                refresh_count
            );
        });
    }
}
