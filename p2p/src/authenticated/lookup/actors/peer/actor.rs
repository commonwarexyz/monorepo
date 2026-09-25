use super::{Config, Error, Mailbox, Message};
use crate::{
    Channel,
    authenticated::{
        channels::{self, Channels},
        data::EncodedData,
        lookup::{metrics, types},
        relay::{self, Message as RelayMessage, Prioritized, Relay},
        throttle::Throttle,
    },
};
use commonware_actor::mailbox;
use commonware_codec::Decode;
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    BufferPool, BufferPooler, Clock, IoBufs, Metrics, Quota, RateLimiter, Spawner,
    iobuf::EncodeExt,
    telemetry::metrics::{CounterFamily, raw::Counter},
};
use commonware_stream::{Receiver, Sender};
use commonware_utils::{channel::ring, time::SYSTEM_TIME_PRECISION};
use futures::{FutureExt as _, StreamExt as _};
use rand_core::CryptoRng;
use std::{collections::BTreeMap, time::Duration, vec::Drain};
use tracing::debug;

/// Send counters for one connection.
struct Sent {
    ping: Counter,
    data: BTreeMap<Channel, Counter>,
}

/// Outbound queues, send counters and the pending batch for one connection.
struct Outbox<C: PublicKey> {
    peer: C,
    pool: BufferPool,

    control: ring::Receiver<Message>,
    high: mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,
    low: mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,

    sent: Sent,
    batch: Vec<IoBufs>,
    size: usize,
}

impl<C: PublicKey> Outbox<C> {
    /// Records a ping as sent and appends its payload to the batch.
    fn ping(&mut self) {
        self.sent.ping.inc();
        let ping = types::Message::Ping.encode_with_pool(&self.pool);
        self.batch.push(ping);
    }

    /// Awaits the next outbound message.
    ///
    /// Priority order: control > high > low.
    async fn recv(&mut self) -> Prioritized<Message, EncodedData> {
        select! {
            msg = self.control.next() => msg.map_or(Prioritized::Closed, Prioritized::Control),
            msg = self.high.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(
                msg.into_inner()
            )),
            msg = self.low.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(
                msg.into_inner()
            )),
        }
    }

    /// Returns the next already-queued outbound message, if any.
    ///
    /// Priority order: control > high > low.
    fn try_recv(&mut self) -> Option<Prioritized<Message, EncodedData>> {
        if let Some(msg) = self.control.next().now_or_never().flatten() {
            return Some(Prioritized::Control(msg));
        }
        relay::try_recv(&mut self.high)
            .or_else(|| relay::try_recv(&mut self.low))
            .map(Prioritized::Data)
    }

    /// Records a message as sent and appends its payload to the batch.
    ///
    /// Returns `Err` if `msg` terminates the connection (`Closed` or `Kill`).
    fn push<S, R>(&mut self, msg: Prioritized<Message, EncodedData>) -> Result<(), Error<S, R>> {
        let payload = match msg {
            Prioritized::Closed => return Err(Error::PeerDisconnected),
            Prioritized::Control(msg) => match msg {
                Message::Kill => return Err(Error::PeerKilled(self.peer.to_string())),
            },
            Prioritized::Data(msg) => {
                self.sent
                    .data
                    .get(&msg.channel)
                    .expect("outbound message on invalid channel")
                    .inc();
                msg.payload
            }
        };
        self.batch.push(payload);
        Ok(())
    }

    /// Appends already-queued messages to the batch until it is full.
    ///
    /// Only consumes messages that are already ready, so batching adds no
    /// buffering latency.
    fn fill<S, R>(&mut self) -> Result<(), Error<S, R>> {
        while self.batch.len() < self.size
            && let Some(msg) = self.try_recv()
        {
            self.push(msg)?;
        }
        Ok(())
    }

    /// Removes and returns the batched payloads.
    fn drain(&mut self) -> Drain<'_, IoBufs> {
        self.batch.drain(..)
    }
}

pub struct Actor<E: Spawner + BufferPooler + Clock + Metrics, C: PublicKey> {
    context: E,

    ping_frequency: Duration,
    send_batch_size: usize,

    control: ring::Receiver<Message>,
    high: mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,
    low: mailbox::UnreliableReceiver<RelayMessage<EncodedData>>,

    sent_messages: CounterFamily<metrics::Message<C>>,
    received_messages: CounterFamily<metrics::Message<C>>,
    rate_limited: CounterFamily<metrics::Message<C>>,
    _phantom: std::marker::PhantomData<C>,
}

impl<E: Spawner + BufferPooler + Clock + CryptoRng + Metrics, C: PublicKey> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>) -> (Self, Mailbox, Relay<EncodedData>) {
        let (control_sender, control_receiver) = Mailbox::new(cfg.mailbox_size);
        let (relay, receivers) = Relay::new(context.child("relay"), cfg.mailbox_size);
        (
            Self {
                context,
                ping_frequency: cfg.ping_frequency,
                send_batch_size: cfg.send_batch_size.get(),
                control: control_receiver,
                high: receivers.high,
                low: receivers.low,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                rate_limited: cfg.rate_limited,
                _phantom: std::marker::PhantomData,
            },
            control_sender,
            relay,
        )
    }

    pub async fn run<S: Sender, R: Receiver>(
        self,
        peer: C,
        (mut conn_sender, mut conn_receiver): (S, R),
        channels: Channels<C>,
    ) -> Result<(), Error<S::Error, R::Error>> {
        // Create per-connection counters and rate limiters
        let sent_messages = &self.sent_messages;
        let (received, rate_limited) = (&self.received_messages, &self.rate_limited);
        let mut sent = Sent {
            ping: sent_messages.get_or_create_owned(&metrics::Message::new_ping(&peer)),
            data: BTreeMap::new(),
        };
        let mut inbound = BTreeMap::new();
        for (channel, (rate, sender)) in channels.collect() {
            let label = metrics::Message::new_data(&peer, channel);
            sent.data
                .insert(channel, sent_messages.get_or_create_owned(&label));
            let limiter = RateLimiter::direct_with_clock(
                rate,
                self.context
                    .child("rate_limiter")
                    .with_attribute("channel", channel),
            );
            let throttle = Throttle::new(limiter, received, rate_limited, &label);
            inbound.insert(channel, (throttle, sender));
        }
        let received_invalid = received.get_or_create_owned(&metrics::Message::new_invalid(&peer));
        let mut outbox = Outbox {
            peer: peer.clone(),
            pool: self.context.network_buffer_pool().clone(),
            control: self.control,
            high: self.high,
            low: self.low,
            sent,
            batch: Vec::with_capacity(self.send_batch_size),
            size: self.send_batch_size,
        };

        // Use half the ping frequency for rate limiting to allow for timing
        // jitter at message boundaries.
        let half = (self.ping_frequency / 2).max(SYSTEM_TIME_PRECISION);
        let ping_rate = Quota::with_period(half).unwrap();
        let limiter =
            RateLimiter::direct_with_clock(ping_rate, self.context.child("ping_rate_limiter"));
        let label = metrics::Message::new_ping(&peer);
        let ping_throttle = Throttle::new(limiter, received, rate_limited, &label);

        // Send/Receive messages from the peer
        let mut send_handler = self
            .context
            .child("sender")
            .spawn(move |context| async move {
                // Set the initial deadline (no need to send right away)
                let mut deadline = context.current() + self.ping_frequency;

                // Enter into the main loop
                select_loop! {
                    context,
                    on_stopped => {},
                    _ = context.sleep_until(deadline) => {
                        // Periodically send a ping to the peer, batching
                        // any already-queued messages into the same batch.
                        outbox.ping();
                        outbox.fill()?;
                        conn_sender
                            .send_many(outbox.drain())
                            .await
                            .map_err(Error::SendFailed)?;
                        deadline = context.current() + self.ping_frequency;
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
            });
        let mut receive_handler = self.context.child("receiver").spawn(move |_| async move {
            loop {
                // Receive a message from the peer
                let msg = conn_receiver.recv().await.map_err(Error::ReceiveFailed)?;

                // Parse the message
                let max_data_length = msg.len(); // apply loose bound to data read to prevent memory exhaustion
                let msg = match types::Message::decode_cfg(msg, &max_data_length) {
                    Ok(msg) => msg,
                    Err(err) => {
                        debug!(?err, ?peer, "failed to decode message");
                        received_invalid.inc();
                        return Err(Error::DecodeFailed(err));
                    }
                };

                match msg {
                    types::Message::Data(data) => {
                        let Some((throttle, sender)) = inbound.get(&data.channel) else {
                            debug!(?peer, channel = data.channel, "invalid channel");
                            received_invalid.inc();
                            return Err(Error::InvalidChannel);
                        };
                        throttle.receive(true).await;

                        // Send message to application without blocking.
                        //
                        // We intentionally drop messages when the application buffer is
                        // full rather than blocking. Blocking here would also block
                        // processing of Ping messages, causing the peer connection to
                        // stall and potentially disconnect.
                        let _ = sender.enqueue(channels::Inbound((peer.clone(), data.message)));
                    }
                    types::Message::Ping => {
                        ping_throttle.receive(true).await;

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
    use crate::authenticated::router;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        BufferPooler, Error as RuntimeError, IoBuf, IoBufs, Runner, Spawner, Supervisor as _,
        deterministic, mocks, telemetry::metrics::MetricsExt as _,
    };
    use commonware_stream::{
        Handshake as _, encrypted::Handshake as StreamHandshake, utils::Timeout,
    };
    use commonware_utils::NZUsize;
    use std::{
        num::NonZeroU32,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
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

    fn default_peer_config(context: impl Metrics) -> Config<PublicKey> {
        Config {
            mailbox_size: NZUsize!(10),
            send_batch_size: NZUsize!(8),
            ping_frequency: Duration::from_secs(30),
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
            let cfg = default_peer_config(context.child("config"));
            let (received_messages, rate_limited) =
                (cfg.received_messages.clone(), cfg.rate_limited.clone());
            let (peer_actor, _mailbox, _relay) =
                Actor::<deterministic::Context, PublicKey>::new(context.child("actor"), cfg);

            // Only channel 0 is registered -- any other channel value is
            // attacker-controlled and must not produce a metric label.
            let mut channels = create_channels(context.child("channels"));
            let quota =
                commonware_runtime::Quota::per_second(std::num::NonZeroU32::new(100).unwrap());
            let (_sender, _receiver) = channels.register(0, quota, context.child("channel"));

            // A valid ping first, so its counters are pinned too.
            local_sender
                .send(types::Message::Ping.encode())
                .await
                .expect("send failed");

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

            // The ping is counted and not rate limited.
            let ping_metric = metrics::Message::new_ping(&local_pk);
            let ping_count = received_messages.get(&ping_metric).map(|c| c.get());
            assert_eq!(ping_count, Some(1));
            let ping_limited = rate_limited.get(&ping_metric).map(|c| c.get());
            assert_eq!(ping_limited, Some(0));

            // The registered channel has a series at zero from connection start.
            let registered_metric = metrics::Message::new_data(&local_pk, 0);
            let registered_count = received_messages.get(&registered_metric).map(|c| c.get());
            assert_eq!(registered_count, Some(0));

            // The attacker-controlled channel value must NOT have created a
            // metric series. If it did, repeated reconnections with fresh
            // channel values would cause unbounded memory growth.
            let attacker_metric = metrics::Message::new_data(&local_pk, invalid_channel);
            assert!(
                received_messages.get(&attacker_metric).is_none()
                    && rate_limited.get(&attacker_metric).is_none(),
                "metric was created for attacker-controlled channel, unbounded cardinality bug"
            );

            // The bounded "invalid" metric should have been incremented instead.
            let invalid_metric = metrics::Message::new_invalid(&local_pk);
            let invalid_count = received_messages.get(&invalid_metric).map(|c| c.get());
            assert_eq!(
                invalid_count,
                Some(1),
                "invalid channel metric should be incremented"
            );
        });
    }

    #[test]
    fn test_batches_outbound_sends_into_single_runtime_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let signer = PrivateKey::from_seed(1);
            let remote_signer = PrivateKey::from_seed(2);
            let local_pk = signer.public_key();
            let remote_pk = remote_signer.public_key();

            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));

            let local_handshake = handshake(signer.clone());
            let remote_handshake = handshake(remote_signer.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.child("listener").spawn({
                let sends = sends.clone();
                move |ctx| async move {
                    remote_handshake
                        .listen(
                            ctx,
                            STREAM_NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
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

            let (_local_sender, mut local_receiver) = local_handshake
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
            sends.store(0, Ordering::Relaxed);

            let cfg = Config {
                send_batch_size: NZUsize!(2),
                ..default_peer_config(context.child("config"))
            };
            let sent_messages = cfg.sent_messages.clone();
            let (peer_actor, peer_mailbox, relay) =
                Actor::<deterministic::Context, PublicKey>::new(context.child("actor"), cfg);

            let mut channels = create_channels(context.child("channels"));
            let quota = commonware_runtime::Quota::per_second(NonZeroU32::new(100).unwrap());
            let (_sender, _receiver) = channels.register(0, quota, context.child("channel"));

            let pool = context.network_buffer_pool().clone();
            assert!(
                relay
                    .send(
                        EncodedData::new(&pool, 0, IoBufs::from(IoBuf::from(b"first"))),
                        false,
                    )
                    .accepted(),
                "first send failed"
            );
            assert!(
                relay
                    .send(
                        EncodedData::new(&pool, 0, IoBufs::from(IoBuf::from(b"second"))),
                        false,
                    )
                    .accepted(),
                "second send failed"
            );

            let peer = local_pk.clone();
            let peer_handle = context.child("task").spawn(move |_context| async move {
                peer_actor
                    .run(peer, (remote_sender, remote_receiver), channels)
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

            // Both messages are counted under the data label and none as a ping
            let data_metric = metrics::Message::new_data(&local_pk, 0);
            let data_count = sent_messages.get(&data_metric).map(|c| c.get());
            assert_eq!(data_count, Some(2));
            let ping_metric = metrics::Message::new_ping(&local_pk);
            let ping_count = sent_messages.get(&ping_metric).map(|c| c.get());
            assert_eq!(ping_count, Some(0));

            // A full batch leaves the remaining message for the next write
            let payloads = [b"data3", b"data4", b"data5"];
            for payload in payloads {
                let data = EncodedData::new(&pool, 0, IoBufs::from(IoBuf::from(payload)));
                assert!(relay.send(data, false).accepted(), "send failed");
            }
            for payload in payloads {
                let frame = local_receiver.recv().await.expect("recv failed");
                let len = frame.len();
                let frame = types::Message::decode_cfg(frame, &len).expect("decode failed");
                let types::Message::Data(data) = frame else {
                    panic!("expected data message");
                };
                assert_eq!(data.message, IoBuf::from(payload));
            }
            assert_eq!(sends.load(Ordering::Relaxed), 3);

            // The next write is the periodic ping, counted under its own label
            let frame = local_receiver.recv().await.expect("recv failed");
            let len = frame.len();
            let frame = types::Message::decode_cfg(frame, &len).expect("decode failed");
            assert!(
                matches!(frame, types::Message::Ping),
                "expected ping message"
            );
            let ping_count = sent_messages.get(&ping_metric).map(|c| c.get());
            assert_eq!(ping_count, Some(1));

            peer_mailbox.kill();
            let result = peer_handle.await.expect("peer task failed");
            assert!(
                matches!(result, Err(Error::PeerKilled(_))),
                "unexpected result: {result:?}"
            );
        });
    }
}
