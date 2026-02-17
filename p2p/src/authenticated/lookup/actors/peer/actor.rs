use super::{ingress::Message, Config, Error};
use crate::authenticated::{
    data::EncodedData,
    lookup::{channels::Channels, metrics, types},
    relay::Relay,
    Mailbox,
};
use commonware_codec::Decode;
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    iobuf::EncodeExt, BufferPool, BufferPooler, Clock, Handle, IoBufs, Metrics, Quota, RateLimiter,
    Sink, Spawner, Stream,
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

    control: mpsc::Receiver<Message>,
    high: mpsc::Receiver<EncodedData>,
    low: mpsc::Receiver<EncodedData>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    dropped_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
    _phantom: std::marker::PhantomData<C>,
}

impl<E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics, C: PublicKey> Actor<E, C> {
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message>, Relay<EncodedData>) {
        let (control_sender, control_receiver) = Mailbox::new(cfg.mailbox_size);
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                ping_frequency: cfg.ping_frequency,
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

    /// Unpack outbound `msg` and assert the underlying `channel` is registered.
    fn validate_outbound_msg<V>(
        msg: Option<EncodedData>,
        rate_limits: &HashMap<u64, V>,
    ) -> Result<EncodedData, Error> {
        let encoded = match msg {
            Some(encoded) => encoded,
            None => return Err(Error::PeerDisconnected),
        };
        assert!(
            rate_limits.contains_key(&encoded.channel),
            "outbound message on invalid channel"
        );
        Ok(encoded)
    }

    /// Creates a message from a payload, then sends and increments metrics.
    async fn send_payload<Si: Sink>(
        pool: &BufferPool,
        sender: &mut Sender<Si>,
        sent_messages: &Family<metrics::Message, Counter>,
        metric: metrics::Message,
        payload: types::Message,
    ) -> Result<(), Error> {
        let msg = payload.encode_with_pool(pool);
        sender.send(msg).await.map_err(Error::SendFailed)?;
        sent_messages.get_or_create(&metric).inc();
        Ok(())
    }

    /// Sends pre-encoded bytes directly to the stream.
    async fn send_encoded<Si: Sink>(
        sender: &mut Sender<Si>,
        sent_messages: &Family<metrics::Message, Counter>,
        metric: metrics::Message,
        payload: IoBufs,
    ) -> Result<(), Error> {
        sender.send(payload).await.map_err(Error::SendFailed)?;
        sent_messages.get_or_create(&metric).inc();
        Ok(())
    }

    pub async fn run<Si: Sink, St: Stream>(
        mut self,
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
                    select_loop! {
                        context,
                        on_stopped => {},
                        _ = context.sleep_until(deadline) => {
                            // Periodically send a ping to the peer
                            Self::send_payload(
                                &pool,
                                &mut conn_sender,
                                &self.sent_messages,
                                metrics::Message::new_ping(&peer),
                                types::Message::Ping,
                            )
                            .await?;

                            // Reset ticker
                            deadline = context.current() + self.ping_frequency;
                        },
                        Some(msg) = self.control.recv() else {
                            return Err(Error::PeerDisconnected);
                        } => match msg {
                            Message::Kill => return Err(Error::PeerKilled(peer.to_string())),
                        },
                        msg_high = self.high.recv() => {
                            // Data is already pre-encoded, just forward to stream
                            let encoded = Self::validate_outbound_msg(msg_high, &rate_limits)?;
                            Self::send_encoded(
                                &mut conn_sender,
                                &self.sent_messages,
                                metrics::Message::new_data(&peer, encoded.channel),
                                encoded.payload,
                            )
                            .await?;
                        },
                        msg_low = self.low.recv() => {
                            // Data is already pre-encoded, just forward to stream
                            let encoded = Self::validate_outbound_msg(msg_low, &rate_limits)?;
                            Self::send_encoded(
                                &mut conn_sender,
                                &self.sent_messages,
                                metrics::Message::new_data(&peer, encoded.channel),
                                encoded.payload,
                            )
                            .await?;
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
    use commonware_runtime::{deterministic, mocks, BufferPooler, Runner, Spawner};
    use commonware_stream::encrypted::Config as StreamConfig;
    use prometheus_client::metrics::{counter::Counter, family::Family};
    use std::time::Duration;

    const STREAM_NAMESPACE: &[u8] = b"test_lookup_peer_actor";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    fn default_peer_config() -> Config {
        Config {
            mailbox_size: 10,
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

            // Create peer actor with metrics we can inspect
            let received_messages = Family::<metrics::Message, Counter>::default();
            let cfg = Config {
                received_messages: received_messages.clone(),
                ..default_peer_config()
            };
            let (peer_actor, _mailbox, _relay) =
                Actor::<deterministic::Context, PublicKey>::new(context.clone(), cfg);

            // Register channel 0 only
            let mut channels = create_channels(&context);
            let quota =
                commonware_runtime::Quota::per_second(std::num::NonZeroU32::new(100).unwrap());
            let (_sender, _receiver) = channels.register(0, quota, 10, context.clone());

            // Send a message on an unregistered channel (attacker-controlled value)
            let invalid_channel = 99999;
            let msg = types::Message::Data(crate::authenticated::data::Data {
                channel: invalid_channel,
                message: commonware_runtime::IoBuf::from(b"attack"),
            });
            local_sender.send(msg.encode()).await.expect("send failed");

            // Run peer actor - should fail with InvalidChannel
            let result = peer_actor
                .run(local_pk.clone(), (remote_sender, remote_receiver), channels)
                .await;
            assert!(
                matches!(result, Err(Error::InvalidChannel)),
                "Expected InvalidChannel error, got: {result:?}"
            );

            // Verify: no metric was created for the attacker-controlled channel value.
            // Only the "invalid" metric should exist.
            let attacker_metric = metrics::Message::new_data(&local_pk, invalid_channel);
            let attacker_count = received_messages.get_or_create(&attacker_metric).get();
            assert_eq!(
                attacker_count, 0,
                "metric was created for attacker-controlled channel, unbounded cardinality bug"
            );

            let invalid_metric = metrics::Message::new_invalid(&local_pk);
            let invalid_count = received_messages.get_or_create(&invalid_metric).get();
            assert_eq!(
                invalid_count, 1,
                "invalid channel metric should be incremented"
            );
        });
    }
}
