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

                    // Update metrics
                    let metric = match &msg {
                        types::Message::Data(data) => {
                            metrics::Message::new_data(&peer, data.channel)
                        }
                        types::Message::Ping => metrics::Message::new_ping(&peer),
                    };
                    self.received_messages.get_or_create(&metric).inc();

                    // Wait until rate limiter allows us to process the message
                    let rate_limiter = match &msg {
                        types::Message::Data(data) => {
                            match rate_limits.get(&data.channel) {
                                Some(rate_limit) => rate_limit,
                                None => { // Treat unknown channels as invalid
                                    debug!(?peer, channel = data.channel, "invalid channel");
                                    self.received_messages
                                        .get_or_create(&metrics::Message::new_invalid(&peer))
                                        .inc();
                                    return Err(Error::InvalidChannel);
                                }
                            }
                        }
                        types::Message::Ping => &ping_rate_limiter,
                    };
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
