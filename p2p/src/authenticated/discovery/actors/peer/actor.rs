use super::{Config, Error, Mailbox, Message};
use crate::{
    Channel,
    authenticated::{
        channels::{self, Channels},
        data::EncodedData,
        discovery::{
            actors::tracker,
            metrics,
            types::{self, InfoVerifier},
        },
        relay::{Message as RelayMessage, Prioritized, Relay, recv_prioritized, try_recv},
        throttle::Throttle,
    },
};
use commonware_actor::mailbox;
use commonware_codec::Decode;
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    BufferPooler, Clock, IoBufs, Metrics, Quota, RateLimiter, Spawner,
    iobuf::EncodeExt,
    telemetry::metrics::{CounterFamily, raw::Counter},
};
use commonware_stream::{Receiver, Sender};
use commonware_utils::time::SYSTEM_TIME_PRECISION;
use rand_core::CryptoRng;
use std::{collections::HashMap, time::Duration};
use tracing::debug;

/// Send counters for one connection.
struct Sent {
    greeting: Counter,
    bit_vec: Counter,
    peers: Counter,
    data: HashMap<Channel, Counter>,
}

pub struct Actor<E: Spawner + BufferPooler + Clock + Metrics, C: PublicKey> {
    context: E,

    gossip_bit_vec_frequency: Duration,
    send_batch_size: usize,
    info_verifier: InfoVerifier<C>,

    max_bit_vec: u64,
    max_peers: usize,

    control: mailbox::UnreliableReceiver<Message<C>>,
    high: mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,
    low: mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,

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
                high: receivers.high,
                low: receivers.low,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                rate_limited: cfg.rate_limited,
            },
            control_sender,
            relay,
        )
    }

    /// Converts a control message into an outbound counter/payload pair.
    ///
    /// Returns `Err` for `Kill` so the caller can terminate the connection.
    fn prepare_control<'a, S, R>(
        peer: &C,
        msg: Message<C>,
        pool: &commonware_runtime::BufferPool,
        sent: &'a Sent,
    ) -> Result<(&'a Counter, IoBufs), Error<S, R>> {
        let (counter, payload) = match msg {
            Message::BitVec(bit_vec) => (&sent.bit_vec, types::Payload::BitVec(bit_vec)),
            Message::Peers(peers) => (&sent.peers, types::Payload::Peers(peers)),
            Message::Kill => return Err(Error::PeerKilled(peer.to_string())),
        };
        Ok((counter, payload.encode_with_pool(pool)))
    }

    /// Converts pre-encoded data into an outbound counter/payload pair.
    fn prepare_data(msg: EncodedData, sent: &Sent) -> (&Counter, IoBufs) {
        let counter = sent
            .data
            .get(&msg.channel)
            .expect("outbound message on invalid channel");
        (counter, msg.payload)
    }

    /// Records the send metric and appends the payload to the batch.
    fn push_batched(batch: &mut Vec<IoBufs>, counter: &Counter, payload: IoBufs) {
        counter.inc();
        batch.push(payload);
    }

    /// Drains already-queued messages into `batch`.
    ///
    /// Priority order: control > high > low. Only consumes messages that are
    /// already ready, so batching adds no buffering latency.
    #[allow(clippy::too_many_arguments)]
    fn extend_send_many<S, R>(
        peer: &C,
        batch_size: usize,
        batch: &mut Vec<IoBufs>,
        control: &mut mailbox::UnreliableReceiver<Message<C>>,
        pool: &commonware_runtime::BufferPool,
        high: &mut mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,
        low: &mut mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,
        sent: &Sent,
    ) -> Result<(), Error<S, R>> {
        while batch.len() < batch_size {
            if let Ok(msg) = control.try_recv() {
                let (counter, payload) = Self::prepare_control(peer, msg, pool, sent)?;
                Self::push_batched(batch, counter, payload);
                continue;
            }
            if let Some(msg) = try_recv(high) {
                let (counter, payload) = Self::prepare_data(msg, sent);
                Self::push_batched(batch, counter, payload);
                continue;
            }
            if let Some(msg) = try_recv(low) {
                let (counter, payload) = Self::prepare_data(msg, sent);
                Self::push_batched(batch, counter, payload);
                continue;
            }
            break;
        }
        Ok(())
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
        let mut sent = Sent {
            greeting: sent_messages.get_or_create_owned(&metrics::Message::new_greeting(&peer)),
            bit_vec: sent_messages.get_or_create_owned(&metrics::Message::new_bit_vec(&peer)),
            peers: sent_messages.get_or_create_owned(&metrics::Message::new_peers(&peer)),
            data: HashMap::new(),
        };
        let mut inbound = HashMap::new();
        for (channel, (rate, sender)) in channels.collect() {
            let label = metrics::Message::new_data(&peer, channel);
            sent.data
                .insert(channel, sent_messages.get_or_create_owned(&label));
            let rate_limiter = RateLimiter::direct_with_clock(
                rate,
                self.context
                    .child("rate_limiter")
                    .with_attribute("channel", channel),
            );
            let throttle = Throttle::new(rate_limiter, received, rate_limited, &label);
            inbound.insert(channel, (throttle, sender));
        }
        let received_greeting =
            received.get_or_create_owned(&metrics::Message::new_greeting(&peer));
        let received_invalid = received.get_or_create_owned(&metrics::Message::new_invalid(&peer));
        let pool = self.context.network_buffer_pool().clone();

        // Send/Receive messages from the peer
        let mut send_handler = self.context.child("sender").spawn({
            let peer = peer.clone();
            let tracker = tracker.clone();
            move |context| async move {
                // Send the greeting before queued messages while the receiver runs concurrently.
                sent.greeting.inc();
                conn_sender
                    .send(types::Payload::Greeting(greeting).encode_with_pool(&pool))
                    .await
                    .map_err(Error::SendFailed)?;

                // Set the initial deadline to now to start gossiping immediately
                let mut deadline = context.current();

                // Enter into the main loop
                let mut batch = Vec::with_capacity(self.send_batch_size);
                let (control, high, low) = &mut (self.control, self.high, self.low);
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
                    // Priority order: control > high > low.
                    msg = recv_prioritized(control, high, low) => {
                        let (counter, payload) = match msg {
                            Prioritized::Closed => return Err(Error::PeerDisconnected),
                            Prioritized::Control(msg) => {
                                Self::prepare_control(&peer, msg, &pool, &sent)?
                            }
                            Prioritized::Data(encoded) => Self::prepare_data(encoded, &sent),
                        };
                        Self::push_batched(&mut batch, counter, payload);
                        Self::extend_send_many(
                            &peer,
                            self.send_batch_size,
                            &mut batch,
                            control,
                            &pool,
                            high,
                            low,
                            &sent,
                        )?;
                        conn_sender
                            .send_many(batch.drain(..))
                            .await
                            .map_err(Error::SendFailed)?;
                    },
                }

                Ok(())
            }
        });
        let mut receive_handler = self
            .context
            .child("receiver")
            .spawn(move |context| async move {
                // Use half the gossip frequency for rate limiting to allow for timing
                // jitter at message boundaries.
                let half = (self.gossip_bit_vec_frequency / 2).max(SYSTEM_TIME_PRECISION);
                let rate = Quota::with_period(half).unwrap();
                let (received, rate_limited) = (&self.received_messages, &self.rate_limited);
                let rate_limiter =
                    RateLimiter::direct_with_clock(rate, context.child("bit_vec_rate_limiter"));
                let label = metrics::Message::new_bit_vec(&peer);
                let bit_vec_throttle = Throttle::new(rate_limiter, received, rate_limited, &label);
                let rate_limiter =
                    RateLimiter::direct_with_clock(rate, context.child("peers_rate_limiter"));
                let label = metrics::Message::new_peers(&peer);
                let peers_throttle = Throttle::new(rate_limiter, received, rate_limited, &label);
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
                            received_invalid.inc();
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
                        types::Payload::Data(data) => {
                            let Some((throttle, sender)) = inbound.get(&data.channel) else {
                                debug!(?peer, channel = data.channel, "invalid channel");
                                received_invalid.inc();
                                return Err(Error::InvalidChannel);
                            };
                            throttle.receive(&context, true).await;

                            // Send message to application without blocking.
                            //
                            // We intentionally drop messages when the application buffer is
                            // full rather than blocking. Blocking here would also block
                            // processing of gossip messages (BitVec, Peers), causing the
                            // peer connection to stall and potentially disconnect.
                            let _ = sender.enqueue(channels::Inbound((peer.clone(), data.message)));
                        }
                        types::Payload::Greeting(_) => unreachable!(),
                        types::Payload::BitVec(bit_vec) => {
                            bit_vec_throttle.receive(&context, first_bit_vec_received).await;
                            first_bit_vec_received = true;

                            // Gather useful peers
                            tracker.bit_vec(peer.clone(), bit_vec);
                        }
                        types::Payload::Peers(peers) => {
                            peers_throttle.receive(&context, first_peers_received).await;
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
        let mut shutdown = self.context.stopped();
        let result = select! {
            _ = &mut shutdown => {
                debug!("context shutdown, stopping peer");
                Ok(Ok(()))
            },
            send_result = &mut send_handler => send_result,
            receive_result = &mut receive_handler => receive_result,
        };

        // Parse result
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(Error::UnexpectedFailure(e)),
        }
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
            let mut receivers = Vec::new();
            let mut tasks = Vec::new();
            for (index, (signer, connection)) in signers
                .into_iter()
                .zip([local_connection, (remote_sender, remote_receiver)])
                .enumerate()
            {
                let context = context.child(["dial_peer", "listen_peer"][index]);
                let (actor, mailbox, relay) = Actor::new(
                    context.child("actor"),
                    default_peer_config(context.child("config"), signer.public_key()),
                );
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

            // Clone the received_messages family so we can inspect it after
            // the actor finishes.
            let received_messages = context.family(
                "received_messages_override",
                "test received messages override",
            );
            let cfg = Config {
                received_messages: received_messages.clone(),
                ..default_peer_config(context.child("config"), remote_pk)
            };
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
                matches!(result, Err(Error::InvalidChannel)),
                "Expected InvalidChannel error, got: {result:?}"
            );

            // The attacker-controlled channel value must NOT have created a
            // metric series. If it did, repeated reconnections with fresh
            // channel values would cause unbounded memory growth.
            let attacker_metric = metrics::Message::new_data(&local_pk_clone, 99999);
            assert!(
                received_messages.get(&attacker_metric).is_none(),
                "metric was created for attacker-controlled channel, unbounded cardinality bug"
            );

            // The bounded "invalid" metric should have been incremented instead.
            let invalid_metric = metrics::Message::new_invalid(&local_pk_clone);
            let invalid_count = received_messages.get_or_create(&invalid_metric).get();
            assert_eq!(invalid_count, 1);
        });
    }
}
