use super::{Config, Error, Message};
use crate::authenticated::{
    data::Data,
    discovery::{actors::tracker, channels::Channels, metrics, types},
    relay::Relay,
    Mailbox,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Metrics, Sink, Spawner, Stream};
use commonware_stream::{
    public_key::{Connection, Sender},
    Receiver as _, Sender as _,
};
use futures::{channel::mpsc, SinkExt, StreamExt};
use governor::{clock::ReasonablyRealtime, Quota, RateLimiter};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::{debug, info};

pub struct Actor<E: Spawner + Clock + ReasonablyRealtime + Metrics, C: PublicKey> {
    context: E,

    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,

    codec_config: types::Config,

    mailbox: Mailbox<Message<C>>,
    control: mpsc::Receiver<Message<C>>,
    high: mpsc::Receiver<Data>,
    low: mpsc::Receiver<Data>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + Metrics, C: PublicKey>
    Actor<E, C>
{
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<Message<C>>, Relay<Data>) {
        let (control_sender, control_receiver) = mpsc::channel(cfg.mailbox_size);
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(control_sender);
        (
            Self {
                context,
                mailbox: mailbox.clone(),
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: cfg.allowed_bit_vec_rate,
                allowed_peers_rate: cfg.allowed_peers_rate,
                codec_config: types::Config {
                    max_bit_vec: cfg.max_peer_set_size,
                    max_peers: cfg.peer_gossip_max_count,
                },
                control: control_receiver,
                high: high_receiver,
                low: low_receiver,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                rate_limited: cfg.rate_limited,
            },
            mailbox,
            Relay::new(low_sender, high_sender),
        )
    }

    /// Unpack `msg` and verify the underlying `channel` is registered.
    fn validate_msg<V>(msg: Option<Data>, rate_limits: &HashMap<u32, V>) -> Result<Data, Error> {
        let data = match msg {
            Some(data) => data,
            None => return Err(Error::PeerDisconnected),
        };
        if !rate_limits.contains_key(&data.channel) {
            return Err(Error::InvalidChannel);
        }
        Ok(data)
    }

    /// Creates a message from a payload, then sends and increments metrics.
    async fn send<Si: Sink>(
        sender: &mut Sender<Si>,
        sent_messages: &Family<metrics::Message, Counter>,
        metric: metrics::Message,
        payload: types::Payload<C>,
    ) -> Result<(), Error> {
        let msg = payload.encode();
        sender.send(&msg).await.map_err(Error::SendFailed)?;
        sent_messages.get_or_create(&metric).inc();
        Ok(())
    }

    pub async fn run<Si: Sink, St: Stream>(
        mut self,
        peer: C,
        connection: Connection<Si, St>,
        mut tracker: Mailbox<tracker::Message<E, C>>,
        channels: Channels<C>,
    ) -> Error {
        // Instantiate rate limiters for each message type
        let mut rate_limits = HashMap::new();
        let mut senders = HashMap::new();
        for (channel, (rate, sender)) in channels.collect() {
            let rate_limiter = RateLimiter::direct_with_clock(rate, &self.context);
            rate_limits.insert(channel, rate_limiter);
            senders.insert(channel, sender);
        }
        let rate_limits = Arc::new(rate_limits);

        // Send/Receive messages from the peer
        let (mut conn_sender, mut conn_receiver) = connection.split();
        let mut send_handler: Handle<Result<(), Error>> = self.context.with_label("sender").spawn( {
            let peer = peer.clone();
            let mut tracker = tracker.clone();
            let mailbox = self.mailbox.clone();
            let rate_limits = rate_limits.clone();
            move |context| async move {
                // Set the initial deadline to now to start gossiping immediately
                let mut deadline = context.current();

                // Enter into the main loop
                loop {
                    select! {
                        _ = context.sleep_until(deadline) => {
                            // Get latest bitset from tracker (also used as ping)
                            tracker.construct(peer.clone(), mailbox.clone()).await;

                            // Reset ticker
                            deadline = context.current() + self.gossip_bit_vec_frequency;
                        },
                        msg_control = self.control.next() => {
                            let msg = match msg_control {
                                Some(msg_control) => msg_control,
                                None => return Err(Error::PeerDisconnected),
                            };
                            let (metric, payload) = match msg {
                                Message::BitVec(bit_vec) =>
                                    (metrics::Message::new_bit_vec(&peer), types::Payload::BitVec(bit_vec)),
                                Message::Peers(peers) =>
                                    (metrics::Message::new_peers(&peer), types::Payload::Peers(peers)),
                                Message::Kill => {
                                    return Err(Error::PeerKilled(peer.to_string()))
                                }
                            };
                            Self::send(&mut conn_sender, &self.sent_messages, metric, payload)
                                .await?;
                        },
                        msg_high = self.high.next() => {
                            let msg = Self::validate_msg(msg_high, &rate_limits)?;
                            Self::send(&mut conn_sender, &self.sent_messages, metrics::Message::new_data(&peer, msg.channel), types::Payload::Data(msg))
                                .await?;
                        },
                        msg_low = self.low.next() => {
                            let msg = Self::validate_msg(msg_low, &rate_limits)?;
                            Self::send(&mut conn_sender, &self.sent_messages, metrics::Message::new_data(&peer, msg.channel), types::Payload::Data(msg))
                                .await?;
                        }
                    }
                }
            }
        });
        let mut receive_handler: Handle<Result<(), Error>> = self
            .context
            .with_label("receiver")
            .spawn(move |context| async move {
                let bit_vec_rate_limiter =
                    RateLimiter::direct_with_clock(self.allowed_bit_vec_rate, &context);
                let peers_rate_limiter =
                    RateLimiter::direct_with_clock(self.allowed_peers_rate, &context);
                loop {
                    // Receive a message from the peer
                    let msg = conn_receiver
                        .receive()
                        .await
                        .map_err(Error::ReceiveFailed)?;

                    // Parse the message
                    let msg = match types::Payload::decode_cfg(msg, &self.codec_config) {
                        Ok(msg) => msg,
                        Err(err) => {
                            info!(?err, ?peer, "failed to decode message");
                            self.received_messages
                                .get_or_create(&metrics::Message::new_invalid(&peer))
                                .inc();
                            return Err(Error::DecodeFailed(err));
                        }
                    };

                    // Update metrics
                    let metric = match &msg {
                        types::Payload::BitVec(_) => &metrics::Message::new_bit_vec(&peer),
                        types::Payload::Peers(_) => &metrics::Message::new_peers(&peer),
                        types::Payload::Data(data) => &metrics::Message::new_data(&peer, data.channel),
                    };
                    self.received_messages.get_or_create(metric).inc();

                    // Wait until rate limiter allows us to process the message
                    let rate_limiter = match &msg {
                        types::Payload::BitVec(_) => &bit_vec_rate_limiter,
                        types::Payload::Peers(_) => &peers_rate_limiter,
                        types::Payload::Data(data) => {
                            match rate_limits.get(&data.channel) {
                                Some(rate_limit) => rate_limit,
                                None => { // Treat unknown channels as malformed
                                    debug!(?peer, channel = data.channel, "unknown channel");
                                    self.received_messages
                                        .get_or_create(&metrics::Message::new_invalid(&peer))
                                        .inc();
                                    return Err(Error::UnknownChannel);
                                }
                            }
                        }
                    };
                    if let Err(wait_until) = rate_limiter.check() {
                        self.rate_limited
                            .get_or_create(metric)
                            .inc();
                        let wait_duration = wait_until.wait_time_from(context.now());
                        context.sleep(wait_duration).await;
                    }


                    match msg {
                        types::Payload::BitVec(bit_vec) => {
                            // Gather useful peers
                            tracker.bit_vec(bit_vec, self.mailbox.clone()).await;
                        }
                        types::Payload::Peers(peers) => {
                            // Send peers to tracker
                            tracker.peers(peers, self.mailbox.clone()).await;
                        }
                        types::Payload::Data(data) => {
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

        // Wait for one of the handlers to finish
        //
        // It is only possible for a handler to exit if there is an error.
        let result = select! {
            send_result = &mut send_handler => {
                receive_handler.abort();
                send_result
            },
            receive_result = &mut receive_handler => {
                send_handler.abort();
                receive_result
            }
        };

        // Parse error
        match result {
            Ok(e) => e.unwrap_err(),
            Err(e) => Error::UnexpectedFailure(e),
        }
    }
}
