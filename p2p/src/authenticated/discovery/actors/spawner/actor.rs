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
    Mailbox,
};
use commonware_actor::mailbox;
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{CounterFamily, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Sink, Spawner, Stream,
};
use rand_core::CryptoRngCore;
use std::{num::NonZeroUsize, time::Duration};
use tracing::debug;

pub struct Actor<
    E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics,
    O: Sink,
    I: Stream,
    C: PublicKey,
> {
    context: ContextCell<E>,

    mailbox_size: NonZeroUsize,
    send_batch_size: NonZeroUsize,
    gossip_bit_vec_frequency: Duration,
    max_peer_set_size: u64,
    peer_gossip_max_count: usize,
    info_verifier: InfoVerifier<C>,

    receiver: mailbox::UnreliableReceiver<Message<O, I, C>>,

    sent_messages: CounterFamily<metrics::Message<C>>,
    received_messages: CounterFamily<metrics::Message<C>>,
    rate_limited: CounterFamily<metrics::Message<C>>,
}

impl<
        E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics,
        O: Sink,
        I: Stream,
        C: PublicKey,
    > Actor<E, O, I, C>
{
    #[allow(clippy::type_complexity)]
    pub fn new(context: E, cfg: Config<C>) -> (Self, Mailbox<Message<O, I, C>>) {
        let sent_messages = context.family("messages_sent", "messages sent");
        let received_messages = context.family("messages_received", "messages received");
        let rate_limited = context.family("messages_rate_limited", "messages rate limited");
        let (sender, receiver) = Mailbox::new(context.child("mailbox"), cfg.mailbox_size);

        (
            Self {
                context: ContextCell::new(context),
                mailbox_size: cfg.mailbox_size,
                send_batch_size: cfg.send_batch_size,
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                max_peer_set_size: cfg.max_peer_set_size,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                info_verifier: cfg.info_verifier,
                receiver,
                sent_messages,
                received_messages,
                rate_limited,
            },
            sender,
        )
    }

    pub fn start(mut self, tracker: tracker::Mailbox<C>, router: router::Mailbox<C>) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, router))
    }

    async fn run(mut self, tracker: tracker::Mailbox<C>, router: router::Mailbox<C>) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping spawner");
            },
            Some(msg) = self.receiver.recv() else {
                debug!("mailbox closed, stopping spawner");
                break;
            } => {
                match msg {
                    Message::Spawn {
                        peer,
                        connection,
                        reservation,
                    } => {
                        // Spawn peer
                        self.context.child("peer").spawn({
                            let sent_messages = self.sent_messages.clone();
                            let received_messages = self.received_messages.clone();
                            let rate_limited = self.rate_limited.clone();
                            let tracker = tracker.clone();
                            let router = router.clone();
                            let is_dialer = matches!(reservation.metadata(), Metadata::Dialer(..));
                            let info_verifier = self.info_verifier.clone();
                            move |context| async move {
                                // Create peer
                                debug!(?peer, "peer started");
                                let (peer_actor, peer_mailbox, messenger) = peer::Actor::new(
                                    context,
                                    peer::Config {
                                        sent_messages,
                                        received_messages,
                                        rate_limited,
                                        mailbox_size: self.mailbox_size,
                                        send_batch_size: self.send_batch_size,
                                        gossip_bit_vec_frequency: self.gossip_bit_vec_frequency,
                                        max_peer_set_size: self.max_peer_set_size,
                                        peer_gossip_max_count: self.peer_gossip_max_count,
                                        info_verifier,
                                    },
                                );

                                // Get greeting from tracker (returns None if not eligible)
                                let Some(greeting) = tracker
                                    .connect(peer.clone(), peer_mailbox, is_dialer)
                                    .await
                                else {
                                    debug!(?peer, "peer not eligible");
                                    drop(reservation);
                                    return;
                                };

                                // Register peer with the router (may fail during shutdown)
                                let Some(channels) = router.ready(peer.clone(), messenger).await
                                else {
                                    debug!(?peer, "router shut down during peer setup");
                                    drop(reservation);
                                    return;
                                };

                                // Run peer (greeting is sent first before main loop)
                                let result = peer_actor
                                    .run(peer.clone(), greeting, connection, tracker, channels)
                                    .await;

                                // Let the router know the peer has exited
                                match result {
                                    Ok(()) => debug!(?peer, "peer shutdown gracefully"),
                                    Err(e) => debug!(error = ?e, ?peer, "peer shutdown"),
                                }
                                let _ = router.release(peer);
                                // Release the reservation
                                drop(reservation);
                            }
                        });
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::{connection, discovery::types};
    use commonware_actor::{mailbox, Feedback, Unreliable};
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer as _,
    };
    use commonware_macros::select;
    use commonware_runtime::{deterministic, mocks, Runner as _, Supervisor as _};
    use commonware_stream::encrypted::Config as StreamConfig;
    use commonware_utils::{NZUsize, SystemTimeExt};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    const STREAM_NAMESPACE: &[u8] = b"test_discovery_spawner_actor";
    const IP_NAMESPACE: &[u8] = b"test_discovery_spawner_actor_IP";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    type Connection = (
        connection::Sender<mocks::Sink>,
        connection::Receiver<mocks::Stream>,
    );

    fn stream_config(key: PrivateKey) -> StreamConfig<PrivateKey> {
        StreamConfig {
            signing_key: key,
            namespace: STREAM_NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(10),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }

    fn spawner_config(me: PublicKey) -> Config<PublicKey> {
        Config {
            mailbox_size: NZUsize!(10),
            send_batch_size: NZUsize!(8),
            gossip_bit_vec_frequency: Duration::from_secs(30),
            max_peer_set_size: 128,
            peer_gossip_max_count: 10,
            info_verifier: types::Info::verifier(
                me,
                10,
                Duration::from_secs(60),
                IP_NAMESPACE.to_vec(),
            ),
        }
    }

    async fn connections(
        context: &deterministic::Context,
        peer_key: PrivateKey,
        local_key: PrivateKey,
    ) -> (Connection, Connection) {
        let peer = peer_key.public_key();
        let local = local_key.public_key();
        let (peer_sink, local_stream) = mocks::Channel::init();
        let (local_sink, peer_stream) = mocks::Channel::init();

        let listener = context.child("listener").spawn({
            let expected = peer.clone();
            move |context| async move {
                connection::listen(
                    context,
                    |_| async { true },
                    stream_config(local_key),
                    local_stream,
                    local_sink,
                    false,
                )
                .await
                .map(|(connected_peer, sender, receiver)| {
                    assert_eq!(connected_peer, expected);
                    (sender, receiver)
                })
            }
        });

        let dialer = connection::dial(
            context.child("dialer"),
            stream_config(peer_key),
            local,
            peer_stream,
            peer_sink,
            false,
        )
        .await
        .expect("dial failed");

        let listener = listener
            .await
            .expect("listener task failed")
            .expect("listen failed");

        (dialer, listener)
    }

    #[allow(clippy::type_complexity)]
    fn setup(
        context: deterministic::Context,
        local: PublicKey,
    ) -> (
        Mailbox<Message<mocks::Sink, mocks::Stream, PublicKey>>,
        mailbox::Receiver<tracker::Message<PublicKey>>,
        mailbox::UnreliableReceiver<router::Message<PublicKey>>,
        tracker::ingress::Releaser<PublicKey>,
        Handle<()>,
    ) {
        let (tracker_sender, tracker_receiver) = mailbox::new::<tracker::Message<PublicKey>>(
            context.child("tracker_mailbox"),
            NZUsize!(10),
        );
        let tracker_mailbox = tracker::Mailbox::new(tracker_sender.clone());
        let releaser = tracker::ingress::Releaser::new(tracker_sender);

        let (router_sender, router_receiver) = mailbox::new_unreliable::<router::Message<PublicKey>>(
            context.child("router_mailbox"),
            NZUsize!(10),
        );
        let router_mailbox = router::Mailbox::new(router_sender);

        let (spawner, spawner_mailbox) =
            Actor::<deterministic::Context, mocks::Sink, mocks::Stream, PublicKey>::new(
                context.child("spawner"),
                spawner_config(local),
            );
        let handle = spawner.start(tracker_mailbox, router_mailbox);

        (
            spawner_mailbox,
            tracker_receiver,
            router_receiver,
            releaser,
            handle,
        )
    }

    #[test]
    fn tracker_rejection_sends_no_greeting() {
        deterministic::Runner::default().start(|context| async move {
            let peer_key = PrivateKey::from_seed(1);
            let local_key = PrivateKey::from_seed(2);
            let peer = peer_key.public_key();
            let local = local_key.public_key();
            let ((_, mut peer_receiver), spawner_connection) =
                connections(&context, peer_key, local_key).await;
            let (mut spawner, mut tracker_receiver, _router_receiver, releaser, _handle) =
                setup(context.child("setup"), local);
            let reservation = tracker::Reservation::new(Metadata::Listener(peer.clone()), releaser);

            assert_eq!(
                spawner.spawn(spawner_connection, reservation),
                Unreliable::new(Feedback::Ok)
            );

            let tracker::Message::Connect {
                public_key,
                responder,
                ..
            } = tracker_receiver
                .recv()
                .await
                .expect("connect should be sent")
            else {
                panic!("unexpected tracker message");
            };
            assert_eq!(public_key, peer);
            drop(responder);

            select! {
                result = peer_receiver.recv() => {
                    if let Ok(msg) = result {
                        panic!("unexpected greeting after tracker rejection: {msg:?}");
                    }
                },
                _ = context.sleep(Duration::from_millis(50)) => {},
            }
        });
    }

    #[test]
    fn router_rejection_sends_no_greeting() {
        deterministic::Runner::default().start(|context| async move {
            let peer_key = PrivateKey::from_seed(1);
            let local_key = PrivateKey::from_seed(2);
            let peer = peer_key.public_key();
            let local = local_key.public_key();
            let ((_, mut peer_receiver), spawner_connection) =
                connections(&context, peer_key, local_key.clone()).await;
            let (mut spawner, mut tracker_receiver, mut router_receiver, releaser, _handle) =
                setup(context.child("setup"), local);
            let reservation = tracker::Reservation::new(Metadata::Listener(peer.clone()), releaser);

            assert_eq!(
                spawner.spawn(spawner_connection, reservation),
                Unreliable::new(Feedback::Ok)
            );

            let tracker::Message::Connect {
                public_key,
                responder,
                ..
            } = tracker_receiver
                .recv()
                .await
                .expect("connect should be sent")
            else {
                panic!("unexpected tracker message");
            };
            assert_eq!(public_key, peer);
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch_millis(),
            );
            assert!(responder.send(greeting).is_ok());

            let router::Message::Ready {
                peer: ready_peer,
                channels,
                ..
            } = router_receiver.recv().await.expect("ready should be sent")
            else {
                panic!("unexpected router message");
            };
            assert_eq!(ready_peer, peer);
            drop(channels);

            select! {
                result = peer_receiver.recv() => {
                    if let Ok(msg) = result {
                        panic!("unexpected greeting after router rejection: {msg:?}");
                    }
                },
                _ = context.sleep(Duration::from_millis(50)) => {},
            }
        });
    }
}
