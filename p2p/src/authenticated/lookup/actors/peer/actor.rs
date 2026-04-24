use super::{ingress::Message, Config, Error};
use crate::authenticated::{
    data::EncodedData,
    mailbox::UnboundedMailbox,
    lookup::{channels::Channels, metrics, types},
    relay::{recv_prioritized, Prioritized, Relay},
};
use commonware_codec::Decode;
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    iobuf::EncodeExt, BufferPooler, Clock, Handle, IoBufs, Metrics, Quota, RateLimiter, Sink,
    Spawner, Stream,
};
use commonware_stream::encrypted::{Receiver, Sender};
use commonware_utils::{
    channel::mpsc::{self, error::TrySendError},
    time::SYSTEM_TIME_PRECISION,
};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand_core::CryptoRngCore;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;

pub struct Actor<E: Spawner + BufferPooler + Clock + Metrics, C: PublicKey> {
    context: E,

    ping_frequency: Duration,
    send_batch_size: usize,

    control: mpsc::UnboundedReceiver<Message>,
    high: mpsc::Receiver<EncodedData>,
    low: mpsc::Receiver<EncodedData>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    dropped_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
    _phantom: std::marker::PhantomData<C>,
}

impl<E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics, C: PublicKey> Actor<E, C> {
    pub fn new(context: E, cfg: Config) -> (Self, UnboundedMailbox<Message>, Relay<EncodedData>) {
        let (control_sender, control_receiver) = UnboundedMailbox::new();
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                ping_frequency: cfg.ping_frequency,
                send_batch_size: cfg.send_batch_size.get(),
                control: control_receiver,
                high: high_receiver,
                low: low_receiver,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                dropped_messages: cfg.dropped_messages,
                rate_limited: cfg.rate_limited,
                _phantom: std::marker::PhantomData,
            },
            control_sender,
            Relay::new(low_sender, high_sender),
        )
    }

    /// Converts pre-encoded data into an outbound metric/payload pair.
    fn prepare_data<V>(
        peer: &C,
        msg: EncodedData,
        rate_limits: &HashMap<u64, V>,
    ) -> (metrics::Message, IoBufs) {
        let encoded = msg.validate_channel(rate_limits);
        (
            metrics::Message::new_data(peer, encoded.channel),
            encoded.payload,
        )
    }

    /// Records the send metric and appends the payload to the batch.
    fn push_batched(
        sent_messages: &Family<metrics::Message, Counter>,
        batch: &mut Vec<IoBufs>,
        metric: metrics::Message,
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
        control: &mut mpsc::UnboundedReceiver<Message>,
        high: &mut mpsc::Receiver<EncodedData>,
        low: &mut mpsc::Receiver<EncodedData>,
        rate_limits: &HashMap<u64, V>,
        sent_messages: &Family<metrics::Message, Counter>,
    ) -> Result<(), Error> {
        while batch.len() < batch_size {
            if let Ok(msg) = control.try_recv() {
                match msg {
                    Message::Kill => return Err(Error::PeerKilled(peer.to_string())),
                }
            }
            if let Ok(msg) = high.try_recv() {
                let (metric, payload) = Self::prepare_data(peer, msg, rate_limits);
                Self::push_batched(sent_messages, batch, metric, payload);
                continue;
            }
            if let Ok(msg) = low.try_recv() {
                let (metric, payload) = Self::prepare_data(peer, msg, rate_limits);
                Self::push_batched(sent_messages, batch, metric, payload);
                continue;
            }
            break;
        }
        Ok(())
    }

    pub async fn run<Si: Sink, St: Stream>(
        self,
        peer: C,
        (mut conn_sender, mut conn_receiver): (Sender<Si>, Receiver<St>),
        channels: Channels<C>,
    ) -> Result<(), Error> {
        // Instantiate rate limiters for each message type
        let mut rate_limits = HashMap::new();
        let mut senders = HashMap::new();
        for (channel, (rate, sender)) in channels.collect() {
            let rate_limiter = RateLimiter::direct_with_clock(rate, self.context.clone());
            rate_limits.insert(channel, rate_limiter);
            senders.insert(channel, sender);
        }
        let rate_limits = Arc::new(rate_limits);
        let pool = self.context.network_buffer_pool().clone();

        // Use half the ping frequency for rate limiting to allow for timing
        // jitter at message boundaries.
        let half = (self.ping_frequency / 2).max(SYSTEM_TIME_PRECISION);
        let ping_rate = Quota::with_period(half).unwrap();
        let ping_rate_limiter = RateLimiter::direct_with_clock(ping_rate, self.context.clone());

        // Send/Receive messages from the peer
        let mut send_handler: Handle<Result<(), Error>> =
            self.context.with_label("sender").spawn({
                let peer = peer.clone();
                let rate_limits = rate_limits.clone();
                move |context| async move {
                    // Set the initial deadline (no need to send right away)
                    let mut deadline = context.current() + self.ping_frequency;

                    // Enter into the main loop
                    let mut batch = Vec::with_capacity(self.send_batch_size);
                    let (control, high, low) = &mut (self.control, self.high, self.low);
                    select_loop! {
                        context,
                        on_stopped => {},
                        _ = context.sleep_until(deadline) => {
                            // Periodically send a ping to the peer, batching
                            // any already-queued messages into the same write.
                            Self::push_batched(
                                &self.sent_messages,
                                &mut batch,
                                metrics::Message::new_ping(&peer),
                                types::Message::Ping.encode_with_pool(&pool),
                            );
                            Self::extend_send_many(
                                &peer,
                                self.send_batch_size,
                                &mut batch,
                                control,
                                high,
                                low,
                                &rate_limits,
                                &self.sent_messages,
                            )?;
                            conn_sender
                                .send_many(batch.drain(..))
                                .await
                                .map_err(Error::SendFailed)?;
                            deadline = context.current() + self.ping_frequency;
                        },
                        // Await any outbound message (control, high, or low), then
                        // drain already-queued messages into a single runtime write.
                        // Priority order: control > high > low.
                        msg = recv_prioritized(control, high, low) => {
                            match msg {
                                Prioritized::Closed => return Err(Error::PeerDisconnected),
                                Prioritized::Control(msg) => match msg {
                                    Message::Kill => {
                                        return Err(Error::PeerKilled(peer.to_string()))
                                    }
                                },
                                Prioritized::Data(encoded) => {
                                    let (metric, payload) =
                                        Self::prepare_data(&peer, encoded, &rate_limits);
                                    Self::push_batched(
                                        &self.sent_messages,
                                        &mut batch,
                                        metric,
                                        payload,
                                    );
                                }
                            }
                            Self::extend_send_many(
                                &peer,
                                self.send_batch_size,
                                &mut batch,
                                control,
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
            .with_label("receiver")
            .spawn(move |context| async move {
                loop {
                    // Receive a message from the peer
                    let msg = conn_receiver.recv().await.map_err(Error::ReceiveFailed)?;

                    // Parse the message
                    let max_data_length = msg.len(); // apply loose bound to data read to prevent memory exhaustion
                    let msg = match types::Message::decode_cfg(msg, &max_data_length) {
                        Ok(msg) => msg,
                        Err(err) => {
                            debug!(?err, ?peer, "failed to decode message");
                            self.received_messages
                                .get_or_create(&metrics::Message::new_invalid(&peer))
                                .inc();
                            return Err(Error::DecodeFailed(err));
                        }
                    };

                    // Validate channel and resolve rate limiter before emitting
                    // any channel-labeled metrics (to avoid unbounded cardinality
                    // from attacker-controlled channel values).
                    let (metric, rate_limiter) = match &msg {
                        types::Message::Data(data) => match rate_limits.get(&data.channel) {
                            Some(rate_limit) => {
                                (metrics::Message::new_data(&peer, data.channel), rate_limit)
                            }
                            None => {
                                debug!(?peer, channel = data.channel, "invalid channel");
                                self.received_messages
                                    .get_or_create(&metrics::Message::new_invalid(&peer))
                                    .inc();
                                return Err(Error::InvalidChannel);
                            }
                        },
                        types::Message::Ping => {
                            (metrics::Message::new_ping(&peer), &ping_rate_limiter)
                        }
                    };
                    self.received_messages.get_or_create(&metric).inc();
                    if let Err(wait_until) = rate_limiter.check() {
                        self.rate_limited.get_or_create(&metric).inc();
                        let wait_duration = wait_until.wait_time_from(context.now());
                        context.sleep(wait_duration).await;
                    }

                    match msg {
                        types::Message::Data(data) => {
                            // Send message to application using non-blocking try_send.
                            //
                            // We intentionally drop messages when the application buffer is
                            // full rather than blocking. Blocking here would also block
                            // processing of Ping messages, causing the peer connection to
                            // stall and potentially disconnect.
                            let sender = senders.get_mut(&data.channel).unwrap();
                            if let Err(e) = sender.try_send((peer.clone(), data.message)) {
                                if matches!(e, TrySendError::Full(_)) {
                                    self.dropped_messages
                                        .get_or_create(&metrics::Message::new_data(&peer, data.channel))
                                        .inc();
                                }
                                debug!(err=?e, channel=data.channel, "failed to send message to client");
                            }
                        }
                        types::Message::Ping => {
                            // We ignore ping messages, they are only used to keep
                            // the connection alive
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
    use crate::authenticated::{
        lookup::{actors::router, channels::Channels},
        Mailbox,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{
        deterministic, mocks, BufferPooler, Error as RuntimeError, IoBuf, IoBufs, Runner, Spawner,
    };
    use commonware_stream::encrypted::Config as StreamConfig;
    use commonware_utils::NZUsize;
    use prometheus_client::metrics::{counter::Counter, family::Family};
    use std::{
        num::NonZeroU32,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    const STREAM_NAMESPACE: &[u8] = b"test_lookup_peer_actor";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    struct CountingSink<S> {
        inner: S,
        sends: Arc<AtomicUsize>,
    }

    impl<S> CountingSink<S> {
        fn new(inner: S, sends: Arc<AtomicUsize>) -> Self {
            Self { inner, sends }
        }
    }

    impl<S: commonware_runtime::Sink> commonware_runtime::Sink for CountingSink<S> {
        async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), RuntimeError> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            self.inner.send(bufs).await
        }
    }

    fn default_peer_config() -> Config {
        Config {
            mailbox_size: 10,
            send_batch_size: NZUsize!(8),
            ping_frequency: Duration::from_secs(30),
            sent_messages: Family::<metrics::Message, Counter>::default(),
            received_messages: Family::<metrics::Message, Counter>::default(),
            dropped_messages: Family::<metrics::Message, Counter>::default(),
            rate_limited: Family::<metrics::Message, Counter>::default(),
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

    fn create_channels(context: &impl BufferPooler) -> Channels<PublicKey> {
        let (router_mailbox, _router_receiver) = Mailbox::<router::Message<PublicKey>>::new(10);
        let messenger =
            router::Messenger::new(context.network_buffer_pool().clone(), router_mailbox);
        Channels::new(messenger, MAX_MESSAGE_SIZE)
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
            let listener_handle = context.clone().spawn({
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
                context.clone(),
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
            let received_messages = Family::<metrics::Message, Counter>::default();
            let cfg = Config {
                received_messages: received_messages.clone(),
                ..default_peer_config()
            };
            let (peer_actor, _mailbox, _relay) =
                Actor::<deterministic::Context, PublicKey>::new(context.clone(), cfg);

            // Only channel 0 is registered -- any other channel value is
            // attacker-controlled and must not produce a metric label.
            let mut channels = create_channels(&context);
            let quota =
                commonware_runtime::Quota::per_second(std::num::NonZeroU32::new(100).unwrap());
            let (_sender, _receiver) = channels.register(0, quota, 10, context.clone());

            // Simulate the attack: send a Data message with an arbitrary
            // unregistered channel value. Before the fix, this would create
            // a persistent "data_99999" time series in the metrics Family.
            let invalid_channel = 99999;
            let msg = types::Message::Data(crate::authenticated::data::Data {
                channel: invalid_channel,
                message: commonware_runtime::IoBuf::from(b"attack"),
            });
            local_sender.send(msg.encode()).await.expect("send failed");

            // The actor should reject the message and return InvalidChannel.
            let result = peer_actor
                .run(local_pk.clone(), (remote_sender, remote_receiver), channels)
                .await;
            assert!(
                matches!(result, Err(Error::InvalidChannel)),
                "Expected InvalidChannel error, got: {result:?}"
            );

            // The attacker-controlled channel value must NOT have created a
            // metric series. If it did, repeated reconnections with fresh
            // channel values would cause unbounded memory growth.
            let attacker_metric = metrics::Message::new_data(&local_pk, invalid_channel);
            let attacker_count = received_messages.get_or_create(&attacker_metric).get();
            assert_eq!(
                attacker_count, 0,
                "metric was created for attacker-controlled channel, unbounded cardinality bug"
            );

            // The bounded "invalid" metric should have been incremented instead.
            let invalid_metric = metrics::Message::new_invalid(&local_pk);
            let invalid_count = received_messages.get_or_create(&invalid_metric).get();
            assert_eq!(
                invalid_count, 1,
                "invalid channel metric should be incremented"
            );
        });
    }

    #[test]
    fn test_batches_outbound_sends_into_single_runtime_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();

            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));

            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.clone().spawn({
                let sends = sends.clone();
                move |ctx| async move {
                    commonware_stream::encrypted::listen(
                        ctx,
                        |_| async { true },
                        remote_config,
                        remote_stream,
                        CountingSink::new(remote_sink, sends),
                    )
                    .await
                    .map(|(pk, sender, receiver)| {
                        assert_eq!(pk, local_pk_clone);
                        (sender, receiver)
                    })
                }
            });

            let (_local_sender, mut local_receiver) = commonware_stream::encrypted::dial(
                context.clone(),
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
            sends.store(0, Ordering::Relaxed);

            let cfg = Config {
                send_batch_size: NZUsize!(2),
                ..default_peer_config()
            };
            let (peer_actor, mut peer_mailbox, relay) =
                Actor::<deterministic::Context, PublicKey>::new(context.clone(), cfg);

            let mut channels = create_channels(&context);
            let quota = commonware_runtime::Quota::per_second(NonZeroU32::new(100).unwrap());
            let (_sender, _receiver) = channels.register(0, quota, 10, context.clone());

            let pool = context.network_buffer_pool().clone();
            relay
                .send(
                    types::Message::encode_data(&pool, 0, IoBufs::from(IoBuf::from(b"first"))),
                    false,
                )
                .expect("first send failed");
            relay
                .send(
                    types::Message::encode_data(&pool, 0, IoBufs::from(IoBuf::from(b"second"))),
                    false,
                )
                .expect("second send failed");

            let peer_handle = context.clone().spawn(move |_context| async move {
                peer_actor
                    .run(local_pk.clone(), (remote_sender, remote_receiver), channels)
                    .await
            });

            let first = local_receiver.recv().await.expect("recv failed");
            let first_len = first.len();
            let first = types::Message::decode_cfg(first, &first_len).expect("decode failed");
            let types::Message::Data(first) = first else {
                panic!("expected data message");
            };
            assert_eq!(first.message, IoBuf::from(b"first"));

            let second = local_receiver.recv().await.expect("recv failed");
            let second_len = second.len();
            let second = types::Message::decode_cfg(second, &second_len).expect("decode failed");
            let types::Message::Data(second) = second else {
                panic!("expected data message");
            };
            assert_eq!(second.message, IoBuf::from(b"second"));
            assert_eq!(sends.load(Ordering::Relaxed), 1);

            peer_mailbox.kill();
            let result = peer_handle.await.expect("peer task failed");
            assert!(
                matches!(result, Err(Error::PeerKilled(_))),
                "unexpected result: {result:?}"
            );
        });
    }
}
