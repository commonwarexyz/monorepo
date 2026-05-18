use super::{Config, Error, Mailbox, Message};
use crate::authenticated::{
    data::EncodedData,
    discovery::{
        actors::tracker,
        channels::{self, Channels},
        metrics,
        types::{self, InfoVerifier},
    },
    relay::{recv_prioritized, try_recv, Message as RelayMessage, Prioritized, Relay},
};
use commonware_actor::mailbox;
use commonware_codec::Decode;
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    iobuf::EncodeExt, telemetry::metrics::CounterFamily, BufferPooler, Clock, Handle, IoBufs,
    Metrics, Quota, RateLimiter, Sink, Spawner, Stream,
};
use commonware_stream::encrypted::{Receiver, Sender};
use commonware_utils::time::SYSTEM_TIME_PRECISION;
use rand_core::CryptoRngCore;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;

pub struct Actor<E: Spawner + BufferPooler + Clock + Metrics, C: PublicKey> {
    context: E,

    gossip_bit_vec_frequency: Duration,
    send_batch_size: usize,
    info_verifier: InfoVerifier<C>,

    max_bit_vec: u64,
    max_peers: usize,

    mailbox: Mailbox<C>,
    control: mailbox::Receiver<Message<C>>,
    high: mailbox::Receiver<RelayMessage<EncodedData>>,
    low: mailbox::Receiver<RelayMessage<EncodedData>>,

    sent_messages: CounterFamily<metrics::Message<C>>,
    received_messages: CounterFamily<metrics::Message<C>>,
    rate_limited: CounterFamily<metrics::Message<C>>,
}

impl<E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics, C: PublicKey> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>) -> (Self, Relay<EncodedData>) {
        let (control_sender, control_receiver) =
            Mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let (relay, receivers) = Relay::new(context.child("relay"), cfg.mailbox_size);
        (
            Self {
                context,
                mailbox: control_sender,
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
            relay,
        )
    }

    /// Converts a control message into an outbound metric/payload pair.
    ///
    /// Returns `Err` for `Kill` so the caller can terminate the connection.
    fn prepare_control(
        peer: &C,
        msg: Message<C>,
        pool: &commonware_runtime::BufferPool,
    ) -> Result<(metrics::Message<C>, IoBufs), Error> {
        let (metric, payload) = match msg {
            Message::BitVec(bit_vec) => (
                metrics::Message::new_bit_vec(peer),
                types::Payload::BitVec(bit_vec),
            ),
            Message::Peers(peers) => (
                metrics::Message::new_peers(peer),
                types::Payload::Peers(peers),
            ),
            Message::Kill => return Err(Error::PeerKilled(peer.to_string())),
        };
        Ok((metric, payload.encode_with_pool(pool)))
    }

    /// Converts pre-encoded data into an outbound metric/payload pair.
    fn prepare_data<V>(
        peer: &C,
        msg: EncodedData,
        rate_limits: &HashMap<u64, V>,
    ) -> (metrics::Message<C>, IoBufs) {
        let encoded = msg.validate_channel(rate_limits);
        (
            metrics::Message::new_data(peer, encoded.channel),
            encoded.payload,
        )
    }

    /// Records the send metric and appends the payload to the batch.
    fn push_batched(
        sent_messages: &CounterFamily<metrics::Message<C>>,
        batch: &mut Vec<IoBufs>,
        metric: metrics::Message<C>,
        payload: IoBufs,
    ) {
        sent_messages.get_or_create(&metric).inc();
        batch.push(payload);
    }

    /// Drains already-queued messages into `batch`.
    ///
    /// Priority order: control > high > low. Only consumes messages that are
    /// already ready (via `try_recv`), so this reduces runtime write calls
    /// without introducing a per-connection timer or extra buffering latency.
    #[allow(clippy::too_many_arguments)]
    fn extend_send_many<V>(
        peer: &C,
        batch_size: usize,
        batch: &mut Vec<IoBufs>,
        control: &mut mailbox::Receiver<Message<C>>,
        pool: &commonware_runtime::BufferPool,
        high: &mut mailbox::Receiver<RelayMessage<EncodedData>>,
        low: &mut mailbox::Receiver<RelayMessage<EncodedData>>,
        rate_limits: &HashMap<u64, V>,
        sent_messages: &CounterFamily<metrics::Message<C>>,
    ) -> Result<(), Error> {
        while batch.len() < batch_size {
            if let Ok(msg) = control.try_recv() {
                let (metric, payload) = Self::prepare_control(peer, msg, pool)?;
                Self::push_batched(sent_messages, batch, metric, payload);
                continue;
            }
            if let Some(msg) = try_recv(high) {
                let (metric, payload) = Self::prepare_data(peer, msg, rate_limits);
                Self::push_batched(sent_messages, batch, metric, payload);
                continue;
            }
            if let Some(msg) = try_recv(low) {
                let (metric, payload) = Self::prepare_data(peer, msg, rate_limits);
                Self::push_batched(sent_messages, batch, metric, payload);
                continue;
            }
            break;
        }
        Ok(())
    }

    pub async fn run<O: Sink, I: Stream>(
        self,
        peer: C,
        greeting: types::Info<C>,
        (mut conn_sender, mut conn_receiver): (Sender<O>, Receiver<I>),
        tracker: tracker::Mailbox<C>,
        channels: Channels<C>,
    ) -> Result<(), Error> {
        // Instantiate rate limiters for each message type
        let mut rate_limits = HashMap::new();
        let mut senders = HashMap::new();
        for (channel, (rate, sender)) in channels.collect() {
            let rate_limiter = RateLimiter::direct_with_clock(
                rate,
                self.context
                    .child("rate_limiter")
                    .with_attribute("channel", channel),
            );
            rate_limits.insert(channel, rate_limiter);
            senders.insert(channel, sender);
        }
        let rate_limits = Arc::new(rate_limits);
        let pool = self.context.network_buffer_pool().clone();

        // Send greeting first before any other messages
        self.sent_messages
            .get_or_create(&metrics::Message::new_greeting(&peer))
            .inc();
        conn_sender
            .send(types::Payload::Greeting(greeting).encode_with_pool(&pool))
            .await
            .map_err(Error::SendFailed)?;

        // Send/Receive messages from the peer
        let mut send_handler: Handle<Result<(), Error>> = self.context.child("sender").spawn({
            let peer = peer.clone();
            let tracker = tracker.clone();
            let mailbox = self.mailbox.clone();
            let rate_limits = rate_limits.clone();
            move |context| async move {
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
                        tracker.construct(peer.clone(), mailbox.clone());

                        // Reset ticker
                        deadline = context.current() + self.gossip_bit_vec_frequency;
                    },
                    // Await any outbound message (control, high, or low), then
                    // drain already-queued messages into a single runtime write.
                    // Priority order: control > high > low.
                    msg = recv_prioritized(control, high, low) => {
                        let (metric, payload) = match msg {
                            Prioritized::Closed => return Err(Error::PeerDisconnected),
                            Prioritized::Control(msg) => Self::prepare_control(&peer, msg, &pool)?,
                            Prioritized::Data(encoded) => {
                                Self::prepare_data(&peer, encoded, &rate_limits)
                            }
                        };
                        Self::push_batched(&self.sent_messages, &mut batch, metric, payload);
                        Self::extend_send_many(
                            &peer,
                            self.send_batch_size,
                            &mut batch,
                            control,
                            &pool,
                            high,
                            low,
                            &rate_limits,
                            &self.sent_messages,
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
        let mut receive_handler: Handle<Result<(), Error>> = self
            .context
            .child("receiver")
            .spawn(move |context| async move {
                // Use half the gossip frequency for rate limiting to allow for timing
                // jitter at message boundaries.
                let half = (self.gossip_bit_vec_frequency / 2).max(SYSTEM_TIME_PRECISION);
                let rate = Quota::with_period(half).unwrap();
                let bit_vec_rate_limiter =
                    RateLimiter::direct_with_clock(rate, context.child("bit_vec_rate_limiter"));
                let peers_rate_limiter =
                    RateLimiter::direct_with_clock(rate, context.child("peers_rate_limiter"));
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
                            self.received_messages
                                .get_or_create(&metrics::Message::new_invalid(&peer))
                                .inc();
                            return Err(Error::DecodeFailed(err));
                        }
                    };

                    // Handle greeting messages first (they `continue` the loop).
                    if let types::Payload::Greeting(info) = msg {
                        self.received_messages
                            .get_or_create(&metrics::Message::new_greeting(&peer))
                            .inc();
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

                    // Validate channel and resolve rate limiter before emitting
                    // any channel-labeled metrics (to avoid unbounded cardinality
                    // from attacker-controlled channel values).
                    //
                    // We skip rate limiting for the first BitVec and first Peers message
                    // because they are expected immediately after the greeting exchange
                    // (we send BitVec right after our greeting, and they respond with Peers).
                    let (metric, rate_limiter) = match &msg {
                        types::Payload::Data(data) => match rate_limits.get(&data.channel) {
                            Some(rate_limit) => {
                                (metrics::Message::new_data(&peer, data.channel), Some(rate_limit))
                            }
                            None => {
                                debug!(?peer, channel = data.channel, "invalid channel");
                                self.received_messages
                                    .get_or_create(&metrics::Message::new_invalid(&peer))
                                    .inc();
                                return Err(Error::InvalidChannel);
                            }
                        },
                        types::Payload::Greeting(_) => unreachable!(),
                        types::Payload::BitVec(_) => {
                            let rate_limiter = if first_bit_vec_received {
                                Some(&bit_vec_rate_limiter)
                            } else {
                                first_bit_vec_received = true;
                                None
                            };
                            (metrics::Message::new_bit_vec(&peer), rate_limiter)
                        }
                        types::Payload::Peers(_) => {
                            let rate_limiter = if first_peers_received {
                                Some(&peers_rate_limiter)
                            } else {
                                first_peers_received = true;
                                None
                            };
                            (metrics::Message::new_peers(&peer), rate_limiter)
                        }
                    };
                    self.received_messages.get_or_create(&metric).inc();
                    if let Some(rate_limiter) = rate_limiter {
                        if let Err(wait_until) = rate_limiter.check() {
                            self.rate_limited.get_or_create(&metric).inc();
                            let wait_duration = wait_until.wait_time_from(context.now());
                            context.sleep(wait_duration).await;
                        }
                    }

                    match msg {
                        types::Payload::Data(data) => {
                            // Send message to application without blocking.
                            //
                            // We intentionally drop messages when the application buffer is
                            // full rather than blocking. Blocking here would also block
                            // processing of gossip messages (BitVec, Peers), causing the
                            // peer connection to stall and potentially disconnect.
                            let sender = senders.get_mut(&data.channel).unwrap();
                            let _ = sender.enqueue(channels::Inbound((peer.clone(), data.message)));
                        }
                        types::Payload::Greeting(_) => unreachable!(),
                        types::Payload::BitVec(bit_vec) => {
                            // Gather useful peers
                            tracker.bit_vec(bit_vec, self.mailbox.clone());
                        }
                        types::Payload::Peers(peers) => {
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
    use crate::authenticated::discovery::{
        actors::{router, tracker},
        channels::Channels,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{
        deterministic, mocks, telemetry::metrics::MetricsExt as _, BufferPooler, IoBuf, Runner,
        Spawner, Supervisor as _,
    };
    use commonware_stream::encrypted::Config as StreamConfig;
    use commonware_utils::{bitmap::BitMap, NZUsize, SystemTimeExt};
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

    fn stream_config<S: Signer>(key: S) -> StreamConfig<S> {
        StreamConfig {
            signing_key: key,
            namespace: STREAM_NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(10),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }

    fn create_channels(context: impl BufferPooler + Metrics) -> Channels<PublicKey> {
        let (router_sender, _router_receiver) = commonware_actor::mailbox::new::<
            router::Message<PublicKey>,
        >(
            context.child("router_mailbox"), NZUsize!(10)
        );
        let messenger = router::Messenger::new(
            context.network_buffer_pool().clone(),
            router::Mailbox::new(router_sender),
        );
        Channels::new(messenger, MAX_MESSAGE_SIZE)
    }

    #[test]
    fn test_missing_greeting_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    commonware_stream::encrypted::listen(
                        ctx,
                        |_| async { true },
                        remote_config,
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

            let (mut local_sender, _local_receiver) = commonware_stream::encrypted::dial(
                context.child("dialer"),
                local_config,
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
            let (peer_actor, _messenger) = Actor::<deterministic::Context, PublicKey>::new(
                context.child("context"),
                default_peer_config(context.child("config"), remote_pk),
            );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
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
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    commonware_stream::encrypted::listen(
                        ctx,
                        |_| async { true },
                        remote_config,
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

            let (mut local_sender, _local_receiver) = commonware_stream::encrypted::dial(
                context.child("dialer"),
                local_config,
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
            let (peer_actor, _messenger) = Actor::<deterministic::Context, PublicKey>::new(
                context.child("context"),
                default_peer_config(context.child("config"), remote_pk),
            );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
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
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let wrong_key = PrivateKey::from_seed(3);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();
            let wrong_pk = wrong_key.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    commonware_stream::encrypted::listen(
                        ctx,
                        |_| async { true },
                        remote_config,
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

            let (mut local_sender, _local_receiver) = commonware_stream::encrypted::dial(
                context.child("dialer"),
                local_config,
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
            let (peer_actor, _messenger) = Actor::<deterministic::Context, PublicKey>::new(
                context.child("context"),
                default_peer_config(context.child("config"), remote_pk),
            );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
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
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
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
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();

            // Establish an encrypted connection between local (attacker) and
            // remote (victim) peers via mock channels.
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                move |ctx| async move {
                    commonware_stream::encrypted::listen(
                        ctx,
                        |_| async { true },
                        remote_config,
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

            let (mut local_sender, _local_receiver) = commonware_stream::encrypted::dial(
                context.child("dialer"),
                local_config,
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
            let (peer_actor, _messenger) =
                Actor::<deterministic::Context, PublicKey>::new(context.child("actor"), cfg);

            // Greeting the actor will send upon connecting to the peer.
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
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
            let (_sender, _receiver) = channels.register(0, quota, 10, context.child("channel"));

            // Simulate the attack: the discovery protocol requires a valid
            // greeting before Data messages are accepted, so we send one
            // first, then follow with a Data message on an unregistered
            // channel. Before the fix, this would create a persistent
            // "data_99999" time series in the metrics Family.
            let local_pk_clone = local_pk.clone();
            context.child("task").spawn(move |_ctx| async move {
                // Valid greeting so the actor accepts subsequent messages.
                let greeting_payload = types::Payload::<PublicKey>::Greeting(types::Info::sign(
                    &local_key,
                    IP_NAMESPACE,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                    0,
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
            let attacker_count = received_messages.get_or_create(&attacker_metric).get();
            assert_eq!(
                attacker_count, 0,
                "metric was created for attacker-controlled channel, unbounded cardinality bug"
            );

            // The bounded "invalid" metric should have been incremented instead.
            let invalid_metric = metrics::Message::new_invalid(&local_pk_clone);
            let invalid_count = received_messages.get_or_create(&invalid_metric).get();
            assert_eq!(invalid_count, 1);
        });
    }
}
