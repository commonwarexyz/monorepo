use super::{ingress::Message, Config, Error};
use crate::authenticated::{
    data::Data,
    lookup::{channels::Channels, metrics, types},
    relay::Relay,
    Mailbox,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{Clock, Handle, Metrics, Sink, Spawner, Stream};
use commonware_stream::{Receiver, Sender};
use futures::{channel::mpsc, SinkExt, StreamExt};
use governor::{
    clock::{Clock as GClock, ReasonablyRealtime},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;

type ChannelRateLimiter<E> =
    RateLimiter<NotKeyed, InMemoryState, E, NoOpMiddleware<<E as GClock>::Instant>>;
type OutboundRateLimits<E> = Option<Arc<HashMap<u64, ChannelRateLimiter<E>>>>;

pub struct Actor<E: Spawner + Clock + ReasonablyRealtime + Metrics, C: PublicKey> {
    context: E,

    ping_frequency: Duration,
    allowed_ping_rate: Quota,

    control: mpsc::Receiver<Message>,
    high: mpsc::Receiver<Data>,
    low: mpsc::Receiver<Data>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
    rate_limit_outbound: bool,
    outbound_rate_limited: Family<metrics::Message, Counter>,
    _phantom: std::marker::PhantomData<C>,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + Metrics, C: PublicKey>
    Actor<E, C>
{
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message>, Relay<Data>) {
        let (control_sender, control_receiver) = Mailbox::new(cfg.mailbox_size);
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                ping_frequency: cfg.ping_frequency,
                allowed_ping_rate: cfg.allowed_ping_rate,
                control: control_receiver,
                high: high_receiver,
                low: low_receiver,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                rate_limited: cfg.rate_limited,
                rate_limit_outbound: cfg.rate_limit_outbound,
                outbound_rate_limited: cfg.outbound_rate_limited,
                _phantom: std::marker::PhantomData,
            },
            control_sender,
            Relay::new(low_sender, high_sender),
        )
    }

    /// Unpack outbound `msg` and assert the underlying `channel` is registered.
    fn validate_outbound_msg<V>(
        msg: Option<Data>,
        rate_limits: &HashMap<u64, V>,
    ) -> Result<Data, Error> {
        let data = match msg {
            Some(data) => data,
            None => return Err(Error::PeerDisconnected),
        };
        assert!(
            rate_limits.contains_key(&data.channel),
            "outbound message on invalid channel"
        );
        Ok(data)
    }

    /// Creates a message from a payload, then sends and increments metrics.
    async fn send<Si: Sink>(
        sender: &mut Sender<Si>,
        sent_messages: &Family<metrics::Message, Counter>,
        metric: metrics::Message,
        payload: types::Message,
    ) -> Result<(), Error> {
        let msg = payload.encode();
        sender.send(&msg).await.map_err(Error::SendFailed)?;
        sent_messages.get_or_create(&metric).inc();
        Ok(())
    }

    /// Applies outbound rate limiting if enabled, sleeping until the rate limit allows.
    async fn apply_outbound_rate_limit(
        context: &E,
        outbound_limits: &OutboundRateLimits<E>,
        metric: &Family<metrics::Message, Counter>,
        peer: &C,
        channel: u64,
    ) {
        if let Some(ref limits) = outbound_limits {
            if let Some(limiter) = limits.get(&channel) {
                if let Err(wait_until) = limiter.check() {
                    metric
                        .get_or_create(&metrics::Message::new_data(peer, channel))
                        .inc();
                    let wait_duration = wait_until.wait_time_from(context.now());
                    context.sleep(wait_duration).await;
                }
            }
        }
    }

    pub async fn run<Si: Sink, St: Stream>(
        mut self,
        peer: C,
        (mut conn_sender, mut conn_receiver): (Sender<Si>, Receiver<St>),
        channels: Channels<C>,
    ) -> Result<(), Error> {
        // Collect channel info first so we can iterate twice
        let channel_info = channels.collect();

        // Instantiate rate limiters for each message type (inbound)
        let mut rate_limits = HashMap::new();
        let mut senders = HashMap::new();
        for (channel, (rate, sender)) in &channel_info {
            let rate_limiter = RateLimiter::direct_with_clock(*rate, self.context.clone());
            rate_limits.insert(*channel, rate_limiter);
            senders.insert(*channel, sender.clone());
        }
        let rate_limits = Arc::new(rate_limits);

        // Instantiate outbound rate limiters if enabled
        let outbound_rate_limits = if self.rate_limit_outbound {
            let outbound = channel_info
                .iter()
                .map(|(channel, (rate, _))| {
                    let rate_limiter = RateLimiter::direct_with_clock(*rate, self.context.clone());
                    (*channel, rate_limiter)
                })
                .collect::<HashMap<_, _>>();
            Some(Arc::new(outbound))
        } else {
            None
        };

        let ping_rate_limiter =
            RateLimiter::direct_with_clock(self.allowed_ping_rate, self.context.clone());

        // Send/Receive messages from the peer
        let mut send_handler: Handle<Result<(), Error>> = self.context.with_label("sender").spawn( {
            let peer = peer.clone();
            let rate_limits = rate_limits.clone();
            let outbound_rate_limits = outbound_rate_limits.clone();
            move |context| async move {
                // Set the initial deadline to now to start pinging immediately
                let mut deadline = context.current();

                // Enter into the main loop
                select_loop! {
                    context,
                    on_stopped => {},
                    _ = context.sleep_until(deadline) => {
                        // Periodically send a ping to the peer
                        Self::send(
                            &mut conn_sender,
                            &self.sent_messages,
                            metrics::Message::new_ping(&peer),
                            types::Message::Ping,
                        ).await?;

                        // Reset ticker
                        deadline = context.current() + self.ping_frequency;
                    },
                    msg_control = self.control.next() => {
                        let msg = match msg_control {
                            Some(msg_control) => msg_control,
                            None => return Err(Error::PeerDisconnected),
                        };
                        match msg {
                            Message::Kill => {
                                return Err(Error::PeerKilled(peer.to_string()))
                            }
                        }
                    },
                    msg_high = self.high.next() => {
                        let msg = Self::validate_outbound_msg(msg_high, &rate_limits)?;
                        Self::apply_outbound_rate_limit(&context, &outbound_rate_limits, &self.outbound_rate_limited, &peer, msg.channel).await;
                        Self::send(&mut conn_sender, &self.sent_messages, metrics::Message::new_data(&peer, msg.channel), msg.into())
                            .await?;
                    },
                    msg_low = self.low.next() => {
                        let msg = Self::validate_outbound_msg(msg_low, &rate_limits)?;
                        Self::apply_outbound_rate_limit(&context, &outbound_rate_limits, &self.outbound_rate_limited, &peer, msg.channel).await;
                        Self::send(&mut conn_sender, &self.sent_messages, metrics::Message::new_data(&peer, msg.channel), msg.into())
                            .await?;
                    }
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
                        types::Message::Ping => {
                            // We ignore ping messages, they are only used to keep
                            // the connection alive
                        }
                        types::Message::Data(data) => {
                            // Send message to client
                            //
                            // If the channel handler is closed, we log an error but don't
                            // close the peer (as other channels may still be open).
                            let sender = senders.get_mut(&data.channel).unwrap();
                            let _ = sender.send((peer.clone(), data.message)).await.inspect_err(
                                |e| debug!(err=?e, channel=data.channel, "failed to send message to client"),
                            );
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
            send_result = &mut send_handler => {
                send_result
            },
            receive_result = &mut receive_handler => {
                receive_result
            }
        };

        // Parse result
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(Error::UnexpectedFailure(e)),
        }
    }
}
