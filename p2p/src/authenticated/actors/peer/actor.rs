use super::{Config, Error, Mailbox, Message, Relay};
use crate::authenticated::{actors::tracker, channels::Channels, metrics, types};
use commonware_codec::Codec;
use commonware_cryptography::Verifier;
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

pub struct Actor<E: Spawner + Clock + ReasonablyRealtime + Metrics, C: Verifier> {
    context: E,

    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,

    mailbox: Mailbox<C>,
    control: mpsc::Receiver<Message<C>>,
    high: mpsc::Receiver<types::Data>,
    low: mpsc::Receiver<types::Data>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,

    // When reservation goes out-of-scope, the tracker will be notified.
    _reservation: tracker::Reservation<E, C>,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + Metrics, C: Verifier> Actor<E, C> {
    pub fn new(context: E, cfg: Config, reservation: tracker::Reservation<E, C>) -> (Self, Relay) {
        let (control_sender, control_receiver) = mpsc::channel(cfg.mailbox_size);
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);

        (
            Self {
                context,
                mailbox: Mailbox::new(control_sender),
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: cfg.allowed_bit_vec_rate,
                allowed_peers_rate: cfg.allowed_peers_rate,
                control: control_receiver,
                high: high_receiver,
                low: low_receiver,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                rate_limited: cfg.rate_limited,
                _reservation: reservation,
            },
            Relay::new(low_sender, high_sender),
        )
    }

    /// Unpack `msg` and verify the underlying `channel` is registered.
    fn validate_msg<V>(
        msg: Option<types::Data>,
        rate_limits: &HashMap<u32, V>,
    ) -> Result<types::Data, Error> {
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
        peer: C::PublicKey,
        connection: Connection<Si, St>,
        mut tracker: tracker::Mailbox<E, C>,
        channels: Channels<C::PublicKey>,
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
                let mut deadline = context.current() + self.gossip_bit_vec_frequency;
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
                                Message::BitVec { bit_vec } =>
                                    (metrics::Message::new_bit_vec(&peer), types::Payload::BitVec(bit_vec)),
                                Message::Peers { peers: msg } =>
                                    (metrics::Message::new_peers(&peer), types::Payload::Peers(msg)),
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
                    let msg = conn_receiver
                        .receive()
                        .await
                        .map_err(Error::ReceiveFailed)?;
                    let msg = match types::Payload::<C>::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            info!(?err, ?peer, "failed to decode message");
                            self.received_messages
                                .get_or_create(&metrics::Message::new_invalid(&peer))
                                .inc();
                            return Err(Error::DecodeFailed(err));
                        }
                    };
                    match msg {
                        types::Payload::BitVec(bit_vec) => {
                            self.received_messages
                                .get_or_create(&metrics::Message::new_bit_vec(&peer))
                                .inc();

                            // Ensure peer is not spamming us with bit vectors
                            match bit_vec_rate_limiter.check() {
                                Ok(_) => {}
                                Err(negative) => {
                                    self.rate_limited
                                        .get_or_create(&metrics::Message::new_bit_vec(&peer))
                                        .inc();
                                    let wait = negative.wait_time_from(context.now());
                                    context.sleep(wait).await;
                                }
                            }

                            // Gather useful peers
                            tracker.bit_vec(bit_vec, self.mailbox.clone()).await;
                        }
                        types::Payload::Peers(peers) => {
                            self.received_messages
                                .get_or_create(&metrics::Message::new_peers(&peer))
                                .inc();

                            // Ensure peer is not spamming us with peer messages
                            match peers_rate_limiter.check() {
                                Ok(_) => {}
                                Err(negative) => {
                                    self.rate_limited
                                        .get_or_create(&metrics::Message::new_peers(&peer))
                                        .inc();
                                    let wait = negative.wait_time_from(context.now());
                                    context.sleep(wait).await;
                                }
                            }

                            // Send peers to tracker
                            tracker.peers(peers, self.mailbox.clone()).await;
                        }
                        types::Payload::Data(data) => {
                            self.received_messages
                                .get_or_create(&metrics::Message::new_data(&peer, data.channel))
                                .inc();

                            // Ensure peer is not spamming us with content messages
                            let entry = rate_limits.get(&data.channel);
                            if entry.is_none() {
                                // We permit unknown messages to be received in case peers
                                // are on a newer version than us
                                continue;
                            }
                            let rate_limiter = entry.unwrap();
                            match rate_limiter.check() {
                                Ok(_) => {}
                                Err(negative) => {
                                    self.rate_limited
                                        .get_or_create(&metrics::Message::new_data(
                                            &peer,
                                            data.channel,
                                        ))
                                        .inc();
                                    let wait = negative.wait_time_from(context.now());
                                    context.sleep(wait).await;
                                }
                            }

                            // Send message to client
                            //
                            // If the channel handler is closed, we log an error but don't
                            // close the peer (as other channels may still be open).
                            let sender = senders.get_mut(&data.channel).unwrap();
                            if let Err(e) = sender
                                .send((peer.clone(), data.message))
                                .await
                                .map_err(|_| Error::ChannelClosed(data.channel))
                            {
                                debug!(err=?e, "failed to send message to client");
                            }
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
