use super::{Config, Error, Mailbox, Message};
use crate::authenticated::{
    channels::Channels,
    connection::{self, Inbox, Outbox},
    data::EncodedData,
    discovery::{
        actors::tracker,
        metrics,
        types::{self, InfoVerifier},
    },
    relay::{Receivers, Relay},
    throttle::Throttle,
};
use commonware_actor::mailbox;
use commonware_codec::Decode;
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{
    BufferPool, BufferPooler, Clock, IoBufs, Metrics, Quota, RateLimiter, Spawner,
    iobuf::EncodeExt,
    telemetry::metrics::{CounterFamily, raw::Counter},
};
use commonware_stream::{Receiver, Sender};
use commonware_utils::time::SYSTEM_TIME_PRECISION;
use rand_core::CryptoRng;
use std::{future::Future, time::Duration};
use tracing::debug;

/// Gossip channel and its send counters for one connection.
struct Gossip<C: PublicKey> {
    receiver: mailbox::UnreliableReceiver<Message<C>>,
    pool: BufferPool,
    bit_vec: Counter,
    peers: Counter,
}

impl<C: PublicKey> connection::Control for Gossip<C> {
    type Message = Message<C>;

    fn recv(&mut self) -> impl Future<Output = Option<Message<C>>> + Send {
        self.receiver.recv()
    }

    fn try_recv(&mut self) -> Option<Message<C>> {
        self.receiver.try_recv().ok()
    }

    fn encode(&self, msg: Message<C>) -> Option<IoBufs> {
        let (counter, payload) = match msg {
            Message::BitVec(bit_vec) => (&self.bit_vec, types::Payload::BitVec(bit_vec)),
            Message::Peers(peers) => (&self.peers, types::Payload::Peers(peers)),
            Message::Kill => return None,
        };
        counter.inc();
        Some(payload.encode_with_pool(&self.pool))
    }
}

pub struct Actor<E: Spawner + BufferPooler + Clock + Metrics, C: PublicKey> {
    context: E,

    gossip_bit_vec_frequency: Duration,
    send_batch_size: usize,
    info_verifier: InfoVerifier<C>,

    max_bit_vec: u64,
    max_peers: usize,

    control: mailbox::UnreliableReceiver<Message<C>>,
    receivers: Receivers<EncodedData>,

    sent_messages: CounterFamily<metrics::Message<C>>,
    received_messages: CounterFamily<metrics::Message<C>>,
    rate_limited: CounterFamily<metrics::Message<C>>,
}

impl<E: Spawner + BufferPooler + Clock + CryptoRng + Metrics, C: PublicKey> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>) -> (Self, Mailbox<C>, Relay<EncodedData>) {
        let (control_sender, control_receiver) =
            Mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let (relay, receivers) = Relay::new(context.child("relay"), cfg.mailbox_size);
        (
            Self {
                context,
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                send_batch_size: cfg.send_batch_size.get(),
                info_verifier: cfg.info_verifier,
                max_bit_vec: cfg.max_peer_set_size,
                max_peers: cfg.peer_gossip_max_count,
                control: control_receiver,
                receivers,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                rate_limited: cfg.rate_limited,
            },
            control_sender,
            relay,
        )
    }

    pub async fn run<S: Sender, R: Receiver>(
        self,
        peer: C,
        greeting: types::Info<C>,
        (mut conn_sender, mut conn_receiver): (S, R),
        tracker: tracker::Mailbox<C>,
        channels: Channels<C>,
    ) -> Result<(), Error<S::Error, R::Error>> {
        // Create per-connection counters and rate limiters
        let sent_messages = &self.sent_messages;
        let (received, rate_limited) = (&self.received_messages, &self.rate_limited);
        let sent_greeting =
            sent_messages.get_or_create_owned(&metrics::Message::new_greeting(&peer));
        let gossip = Gossip {
            receiver: self.control,
            pool: self.context.network_buffer_pool().clone(),
            bit_vec: sent_messages.get_or_create_owned(&metrics::Message::new_bit_vec(&peer)),
            peers: sent_messages.get_or_create_owned(&metrics::Message::new_peers(&peer)),
        };
        let inbox = Inbox::new(
            &self.context,
            peer.clone(),
            channels,
            received,
            rate_limited,
        );
        let received_greeting =
            received.get_or_create_owned(&metrics::Message::new_greeting(&peer));
        let mut outbox = Outbox::new(
            peer.clone(),
            gossip,
            self.receivers,
            inbox.channels(),
            sent_messages,
            self.send_batch_size,
        );

        // Use half the gossip frequency for rate limiting to allow for timing
        // jitter at message boundaries.
        let half = (self.gossip_bit_vec_frequency / 2).max(SYSTEM_TIME_PRECISION);
        let rate = Quota::with_period(half).unwrap();
        let limiter =
            RateLimiter::direct_with_clock(rate, self.context.child("bit_vec_rate_limiter"));
        let label = metrics::Message::new_bit_vec(&peer);
        let bit_vec_throttle = Throttle::new(limiter, received, rate_limited, &label);
        let limiter =
            RateLimiter::direct_with_clock(rate, self.context.child("peers_rate_limiter"));
        let label = metrics::Message::new_peers(&peer);
        let peers_throttle = Throttle::new(limiter, received, rate_limited, &label);

        // Send/Receive messages from the peer
        let send_handler = self.context.child("sender").spawn({
            let peer = peer.clone();
            let tracker = tracker.clone();
            move |context| async move {
                // Send the greeting before queued messages while the receiver runs concurrently.
                sent_greeting.inc();
                let greeting = types::Payload::Greeting(greeting)
                    .encode_with_pool(context.network_buffer_pool());
                conn_sender
                    .send(greeting)
                    .await
                    .map_err(Error::SendFailed)?;

                // Set the initial deadline to now to start gossiping immediately
                let mut deadline = context.current();

                // Enter into the main loop
                select_loop! {
                    context,
                    on_stopped => {},
                    _ = context.sleep_until(deadline) => {
                        // Get latest bitset from tracker (also used as ping)
                        tracker.construct(peer.clone());

                        // Reset ticker
                        deadline = context.current() + self.gossip_bit_vec_frequency;
                    },
                    // Await any outbound message (control, high, or low), then
                    // drain already-queued messages into one `send_many` call.
                    msg = outbox.recv() => {
                        outbox.push(msg)?;
                        outbox.fill()?;
                        conn_sender
                            .send_many(outbox.drain())
                            .await
                            .map_err(Error::SendFailed)?;
                    },
                }

                Ok(())
            }
        });
        let receive_handler = self
            .context
            .child("receiver")
            .spawn(move |context| async move {
                let mut greeting_received = false;
                let mut first_bit_vec_received = false;
                let mut first_peers_received = false;
                loop {
                    // Receive a message from the peer
                    let msg = conn_receiver.recv().await.map_err(Error::ReceiveFailed)?;

                    // Parse the message
                    let cfg = types::PayloadConfig {
                        max_bit_vec: self.max_bit_vec,
                        max_peers: self.max_peers,
                        max_data_length: msg.len(), // apply loose bound to data read to prevent memory exhaustion
                    };
                    let msg = match types::Payload::decode_cfg(msg, &cfg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            debug!(?err, ?peer, "failed to decode message");
                            inbox.invalid();
                            return Err(Error::DecodeFailed(err));
                        }
                    };

                    // Handle greeting messages first (they `continue` the loop).
                    if let types::Payload::Greeting(info) = msg {
                        received_greeting.inc();
                        if greeting_received {
                            debug!(?peer, "received duplicate greeting");
                            return Err(Error::DuplicateGreeting);
                        }
                        greeting_received = true;

                        // Verify the greeting is from the expected peer
                        if info.public_key != peer {
                            debug!(?peer, greeting_pk = ?info.public_key, "greeting public key mismatch");
                            return Err(Error::GreetingMismatch);
                        }

                        // Verify the greeting info is valid
                        self.info_verifier.validate(&context, std::slice::from_ref(&info)).map_err(Error::Types)?;

                        // Send greeting info to tracker
                        tracker.peers(vec![info]);
                        continue;
                    } else if !greeting_received {
                        debug!(?peer, "expected greeting as first message");
                        return Err(Error::MissingGreeting);
                    }

                    // We skip rate limiting for the first BitVec and first Peers message
                    // because they are expected immediately after the greeting exchange
                    // (we send BitVec right after our greeting, and they respond with Peers).
                    match msg {
                        types::Payload::Data(data) => inbox.deliver(data).await?,
                        types::Payload::Greeting(_) => unreachable!(),
                        types::Payload::BitVec(bit_vec) => {
                            // Rate limit every BitVec message after the first
                            bit_vec_throttle.receive(first_bit_vec_received).await;
                            first_bit_vec_received = true;

                            // Gather useful peers
                            tracker.bit_vec(peer.clone(), bit_vec);
                        }
                        types::Payload::Peers(peers) => {
                            // Rate limit every Peers message after the first
                            peers_throttle.receive(first_peers_received).await;
                            first_peers_received = true;

                            // Verify all info is valid
                            self.info_verifier.validate(&context, &peers).map_err(Error::Types)?;

                            // Send peers to tracker
                            tracker.peers(peers);
                        }
                    }
                }
            });

        // Wait for one of the handlers to finish or shutdown
        connection::wait(&self.context, send_handler, receive_handler)
            .await
            .map_err(Error::UnexpectedFailure)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Receiver as _,
        authenticated::{discovery::actors::tracker, router},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        BufferPooler, IoBuf, Runner, Spawner, Supervisor as _, deterministic, mocks,
        telemetry::metrics::MetricsExt as _,
    };
    use commonware_stream::{
        Handshake as _, encrypted::Handshake as StreamHandshake, utils::Timeout,
    };
    use commonware_utils::{NZU32, NZUsize, SystemTimeExt, bitmap::BitMap};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    const STREAM_NAMESPACE: &[u8] = b"test_peer_actor";
    const IP_NAMESPACE: &[u8] = b"test_peer_actor_IP";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    fn default_peer_config(context: impl Metrics, me: PublicKey) -> Config<PublicKey> {
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
            sent_messages: context.family("sent_messages", "test sent messages"),
            received_messages: context.family("received_messages", "test received messages"),
            rate_limited: context.family("rate_limited", "test rate limited messages"),
        }
    }

    fn handshake<S: Signer>(signer: S) -> Timeout<StreamHandshake<S>> {
        Timeout::new(
            StreamHandshake {
                signer,
                synchrony_bound: Duration::from_secs(10),
                max_handshake_age: Duration::from_secs(10),
            },
            Duration::from_secs(10),
        )
    }

    fn create_channels(context: impl BufferPooler + Metrics) -> Channels<PublicKey> {
        let (router_sender, _router_receiver) = commonware_actor::mailbox::new_unreliable::<
            router::Message<PublicKey>,
        >(
            context.child("router_mailbox"), NZUsize!(10)
        );
        let messenger = router::Messenger::unbound(context.network_buffer_pool().clone());
        messenger.bind(router::Mailbox::new(router_sender));
        Channels::new(messenger, MAX_MESSAGE_SIZE, NZUsize!(1))
    }

    #[test]
    fn greeting_and_queued_data_progress_with_backpressure() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            // Complete authentication over buffers smaller than a signed greeting.
            let signers = [PrivateKey::from_seed(1), PrivateKey::from_seed(2)];
            let public_keys = signers.each_ref().map(Signer::public_key);
            let (local_sink, remote_stream) = mocks::Channel::init_with_buffer_size(64);
            let (remote_sink, local_stream) = mocks::Channel::init_with_buffer_size(64);
            let remote_handshake = handshake(signers[1].clone());
            let listener = context.child("listener").spawn(move |context| async move {
                remote_handshake
                    .listen(
                        context,
                        STREAM_NAMESPACE,
                        MAX_MESSAGE_SIZE,
                        |_| async { true },
                        remote_stream,
                        remote_sink,
                    )
                    .await
                    .unwrap()
            });
            let local_connection = handshake(signers[0].clone())
                .dial(
                    context.child("dialer"),
                    STREAM_NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    public_keys[1].clone(),
                    local_stream,
                    local_sink,
                )
                .await
                .unwrap();
            let (authenticated, remote_sender, remote_receiver) = listener.await.unwrap();
            assert_eq!(authenticated, public_keys[0]);

            // Queue application data before startup so greeting ordering is exercised too.
            let messages: [&[u8]; 2] = [b"from dialer", b"from listener"];
            let (tracker_mailbox, _tracker_receiver) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(10),
            );
            let tracker = tracker::Mailbox::new(tracker_mailbox);
            let mut peer_mailboxes = Vec::new();
            let mut families = Vec::new();
            let mut receivers = Vec::new();
            let mut tasks = Vec::new();
            for (index, (signer, connection)) in signers
                .into_iter()
                .zip([local_connection, (remote_sender, remote_receiver)])
                .enumerate()
            {
                let context = context.child(["dial_peer", "listen_peer"][index]);
                let cfg = default_peer_config(context.child("config"), signer.public_key());
                families.push((cfg.sent_messages.clone(), cfg.received_messages.clone()));
                let (actor, mailbox, relay) = Actor::new(context.child("actor"), cfg);

                // Queue gossip ahead of the data so every message type crosses the
                // connection, with distinct counts per type.
                for _ in 0..2 {
                    mailbox.bit_vec(types::BitVec {
                        index: 0,
                        bits: BitMap::ones(10),
                    });
                }
                mailbox.peers(Vec::new());
                let greeting = types::Info::sign(
                    signer.public_key(),
                    IP_NAMESPACE,
                    SocketAddr::from(([127, 0, 0, 1], 8080 + index as u16)),
                    context.current().epoch_millis(),
                    |namespace, message| signer.sign(namespace, message),
                );
                let mut channels = create_channels(context.child("channels"));
                let (_, receiver) =
                    channels.register(0, Quota::per_second(NZU32!(1)), context.child("channel"));
                let message = EncodedData::new(
                    context.network_buffer_pool(),
                    0,
                    IoBuf::from(messages[index]).into(),
                );
                assert!(relay.send(message, false).accepted());
                peer_mailboxes.push((mailbox, relay));
                receivers.push(receiver);
                let peer = public_keys[1 - index].clone();
                let tracker = tracker.clone();
                tasks.push(
                    context
                        .spawn(move |_| actor.run(peer, greeting, connection, tracker, channels)),
                );
            }

            // Each receiver accepts data only after validating its peer's greeting.
            for (index, receiver) in receivers.iter_mut().enumerate() {
                let (peer, message) = receiver.recv().await.unwrap();
                assert_eq!(peer, public_keys[1 - index]);
                assert_eq!(message, messages[1 - index]);
            }

            // Each message is counted under its own label in both directions.
            for (index, (sent, received)) in families.iter().enumerate() {
                let peer = &public_keys[1 - index];
                for (label, count) in [
                    (metrics::Message::new_greeting(peer), 1),
                    (metrics::Message::new_bit_vec(peer), 2),
                    (metrics::Message::new_peers(peer), 1),
                    (metrics::Message::new_data(peer, 0), 1),
                ] {
                    assert_eq!(sent.get(&label).map(|c| c.get()), Some(count), "{label:?}");
                    assert_eq!(
                        received.get(&label).map(|c| c.get()),
                        Some(count),
                        "{label:?}"
                    );
                }
            }
            for task in &tasks {
                task.abort();
            }
            for task in tasks {
                assert!(task.await.is_err());
            }
        });
    }

    #[test]
    fn test_missing_greeting_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(1);
            let remote_signer = PrivateKey::from_seed(2);
            let local_pk = signer.public_key();
            let remote_pk = remote_signer.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_handshake = handshake(signer.clone());
            let remote_handshake = handshake(remote_signer.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    remote_handshake
                        .listen(
                            ctx,
                            STREAM_NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            remote_stream,
                            remote_sink,
                        )
                        .await
                        .map(|(pk, sender, receiver)| {
                            assert_eq!(pk, local_pk_clone);
                            (sender, receiver)
                        })
                }
            });

            let (mut local_sender, _local_receiver) = local_handshake
                .dial(
                    context.child("dialer"),
                    STREAM_NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    remote_pk.clone(),
                    local_stream,
                    local_sink,
                )
                .await
                .expect("dial failed");

            let (remote_sender, remote_receiver) = listener_handle
                .await
                .expect("listen failed")
                .expect("listen result failed");

            // Create peer actor (from remote's perspective, local is the peer)
            let (peer_actor, _mailbox, _messenger) =
                Actor::<deterministic::Context, PublicKey>::new(
                    context.child("peer"),
                    default_peer_config(context.child("config"), remote_pk),
                );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                signer.public_key(),
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
                |namespace, message| signer.sign(namespace, message),
            );

            // Create tracker mailbox
            let (tracker_mailbox, _tracker_receiver) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );

            // Create empty channels
            let channels = create_channels(context.child("channels"));

            // Send a non-greeting message first (BitVec)
            let bit_vec = types::Payload::<PublicKey>::BitVec(types::BitVec {
                index: 0,
                bits: BitMap::ones(10),
            });
            local_sender
                .send(bit_vec.encode())
                .await
                .expect("send failed");

            // Run peer actor and expect MissingGreeting error
            let result = peer_actor
                .run(
                    local_pk,
                    greeting,
                    (remote_sender, remote_receiver),
                    tracker::Mailbox::new(tracker_mailbox),
                    channels,
                )
                .await;

            assert!(
                matches!(result, Err(Error::MissingGreeting)),
                "Expected MissingGreeting error, got: {result:?}"
            );
        });
    }

    #[test]
    fn test_duplicate_greeting_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(1);
            let remote_signer = PrivateKey::from_seed(2);
            let local_pk = signer.public_key();
            let remote_pk = remote_signer.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_handshake = handshake(signer.clone());
            let remote_handshake = handshake(remote_signer.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    remote_handshake
                        .listen(
                            ctx,
                            STREAM_NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            remote_stream,
                            remote_sink,
                        )
                        .await
                        .map(|(pk, sender, receiver)| {
                            assert_eq!(pk, local_pk_clone);
                            (sender, receiver)
                        })
                }
            });

            let (mut local_sender, _local_receiver) = local_handshake
                .dial(
                    context.child("dialer"),
                    STREAM_NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    remote_pk.clone(),
                    local_stream,
                    local_sink,
                )
                .await
                .expect("dial failed");

            let (remote_sender, remote_receiver) = listener_handle
                .await
                .expect("listen failed")
                .expect("listen result failed");

            // Create peer actor (from remote's perspective, local is the peer)
            let (peer_actor, _mailbox, _messenger) =
                Actor::<deterministic::Context, PublicKey>::new(
                    context.child("peer"),
                    default_peer_config(context.child("config"), remote_pk),
                );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                signer.public_key(),
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
                |namespace, message| signer.sign(namespace, message),
            );

            // Create tracker mailbox
            let (tracker_mailbox, _tracker_receiver) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );

            // Create empty channels
            let channels = create_channels(context.child("channels"));

            // Send first greeting (valid)
            let first_greeting = types::Payload::<PublicKey>::Greeting(greeting.clone());
            local_sender
                .send(first_greeting.encode())
                .await
                .expect("send failed");

            // Send second greeting (should cause error)
            let second_greeting = types::Payload::<PublicKey>::Greeting(greeting.clone());
            local_sender
                .send(second_greeting.encode())
                .await
                .expect("send failed");

            // Run peer actor and expect DuplicateGreeting error
            let result = peer_actor
                .run(
                    local_pk,
                    greeting,
                    (remote_sender, remote_receiver),
                    tracker::Mailbox::new(tracker_mailbox),
                    channels,
                )
                .await;

            assert!(
                matches!(result, Err(Error::DuplicateGreeting)),
                "Expected DuplicateGreeting error, got: {result:?}"
            );
        });
    }

    #[test]
    fn test_greeting_public_key_mismatch_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(1);
            let remote_signer = PrivateKey::from_seed(2);
            let wrong_signer = PrivateKey::from_seed(3);
            let local_pk = signer.public_key();
            let remote_pk = remote_signer.public_key();
            let wrong_pk = wrong_signer.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_handshake = handshake(signer.clone());
            let remote_handshake = handshake(remote_signer.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    remote_handshake
                        .listen(
                            ctx,
                            STREAM_NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            remote_stream,
                            remote_sink,
                        )
                        .await
                        .map(|(pk, sender, receiver)| {
                            assert_eq!(pk, local_pk_clone);
                            (sender, receiver)
                        })
                }
            });

            let (mut local_sender, _local_receiver) = local_handshake
                .dial(
                    context.child("dialer"),
                    STREAM_NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    remote_pk.clone(),
                    local_stream,
                    local_sink,
                )
                .await
                .expect("dial failed");

            let (remote_sender, remote_receiver) = listener_handle
                .await
                .expect("listen failed")
                .expect("listen result failed");

            // Create peer actor (from remote's perspective, local is the peer)
            let (peer_actor, _mailbox, _messenger) =
                Actor::<deterministic::Context, PublicKey>::new(
                    context.child("peer"),
                    default_peer_config(context.child("config"), remote_pk),
                );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                signer.public_key(),
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
                |namespace, message| signer.sign(namespace, message),
            );

            // Create tracker mailbox
            let (tracker_mailbox, _tracker_receiver) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );

            // Create empty channels
            let channels = create_channels(context.child("channels"));

            // Send greeting with wrong public key (claims to be wrong_pk instead of local_pk)
            let mut wrong_greeting = types::Info::sign(
                signer.public_key(),
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
                |namespace, message| signer.sign(namespace, message),
            );
            wrong_greeting.public_key = wrong_pk;
            let greeting_payload = types::Payload::<PublicKey>::Greeting(wrong_greeting);
            local_sender
                .send(greeting_payload.encode())
                .await
                .expect("send failed");

            // Run peer actor and expect GreetingMismatch error
            let result = peer_actor
                .run(
                    local_pk,
                    greeting,
                    (remote_sender, remote_receiver),
                    tracker::Mailbox::new(tracker_mailbox),
                    channels,
                )
                .await;

            assert!(
                matches!(result, Err(Error::GreetingMismatch)),
                "Expected GreetingMismatch error, got: {result:?}"
            );
        });
    }

    #[test]
    fn test_invalid_channel_no_unbounded_metric_cardinality() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(1);
            let remote_signer = PrivateKey::from_seed(2);
            let local_pk = signer.public_key();
            let remote_pk = remote_signer.public_key();

            // Establish an encrypted connection between local (attacker) and
            // remote (victim) peers via mock channels.
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            let local_handshake = handshake(signer.clone());
            let remote_handshake = handshake(remote_signer.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    remote_handshake
                        .listen(
                            ctx,
                            STREAM_NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            remote_stream,
                            remote_sink,
                        )
                        .await
                        .map(|(pk, sender, receiver)| {
                            assert_eq!(pk, local_pk_clone);
                            (sender, receiver)
                        })
                }
            });

            let (mut local_sender, _local_receiver) = local_handshake
                .dial(
                    context.child("dialer"),
                    STREAM_NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    remote_pk.clone(),
                    local_stream,
                    local_sink,
                )
                .await
                .expect("dial failed");

            let (remote_sender, remote_receiver) = listener_handle
                .await
                .expect("listen failed")
                .expect("listen result failed");

            // Clone the metric families so we can inspect them after the
            // actor finishes.
            let cfg = default_peer_config(context.child("config"), remote_pk);
            let (received_messages, rate_limited) =
                (cfg.received_messages.clone(), cfg.rate_limited.clone());
            let (peer_actor, _mailbox, _messenger) =
                Actor::<deterministic::Context, PublicKey>::new(context.child("actor"), cfg);

            // Greeting the actor will send upon connecting to the peer.
            let greeting = types::Info::sign(
                signer.public_key(),
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
                |namespace, message| signer.sign(namespace, message),
            );

            let (tracker_mailbox, _tracker_receiver) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );

            // Only channel 0 is registered -- any other channel value is
            // attacker-controlled and must not produce a metric label.
            let mut channels = create_channels(context.child("channels"));
            let quota =
                commonware_runtime::Quota::per_second(std::num::NonZeroU32::new(100).unwrap());
            let (_sender, _receiver) = channels.register(0, quota, context.child("channel"));

            // Simulate the attack: the discovery protocol requires a valid
            // greeting before Data messages are accepted, so we send one
            // first, then follow with a Data message on an unregistered
            // channel. Before the fix, this would create a persistent
            // "data_99999" time series in the metrics Family.
            let local_pk_clone = local_pk.clone();
            context.child("task").spawn(move |_ctx| async move {
                // Valid greeting so the actor accepts subsequent messages.
                let greeting_payload = types::Payload::<PublicKey>::Greeting(types::Info::sign(
                    signer.public_key(),
                    IP_NAMESPACE,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                    0,
                    |namespace, message| signer.sign(namespace, message),
                ));
                local_sender
                    .send(greeting_payload.encode())
                    .await
                    .expect("send greeting failed");

                // Data on an arbitrary unregistered channel.
                let data = types::Payload::<PublicKey>::Data(crate::authenticated::data::Data {
                    channel: 99999,
                    message: IoBuf::from(b"attack"),
                });
                local_sender.send(data.encode()).await.expect("send failed");
            });

            // The actor should reject the message and return InvalidChannel.
            let result = peer_actor
                .run(
                    local_pk_clone.clone(),
                    greeting,
                    (remote_sender, remote_receiver),
                    tracker::Mailbox::new(tracker_mailbox),
                    channels,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Err(Error::Connection(connection::Error::InvalidChannel))
                ),
                "Expected InvalidChannel error, got: {result:?}"
            );

            // The registered channel has a series at zero from connection start.
            let registered_metric = metrics::Message::new_data(&local_pk_clone, 0);
            let registered_count = received_messages.get(&registered_metric).map(|c| c.get());
            assert_eq!(registered_count, Some(0));

            // The attacker-controlled channel value must NOT have created a
            // metric series. If it did, repeated reconnections with fresh
            // channel values would cause unbounded memory growth.
            let attacker_metric = metrics::Message::new_data(&local_pk_clone, 99999);
            assert!(
                received_messages.get(&attacker_metric).is_none()
                    && rate_limited.get(&attacker_metric).is_none(),
                "metric was created for attacker-controlled channel, unbounded cardinality bug"
            );

            // The bounded "invalid" metric should have been incremented instead.
            let invalid_metric = metrics::Message::new_invalid(&local_pk_clone);
            let invalid_count = received_messages.get(&invalid_metric).map(|c| c.get());
            assert_eq!(invalid_count, Some(1));
        });
    }
}
