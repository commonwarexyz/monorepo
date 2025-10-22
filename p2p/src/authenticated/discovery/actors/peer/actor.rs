use super::{Config, Error, Message};
use crate::authenticated::{
    data::Data,
    discovery::{
        actors::tracker,
        channels::Channels,
        metrics,
        types::{self, InfoVerifier},
    },
    mailbox::UnboundedMailbox,
    relay::Relay,
    Mailbox,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Metrics, Sink, Spawner, Stream};
use commonware_stream::{Receiver, Sender};
use futures::{channel::mpsc, SinkExt, StreamExt};
use governor::{clock::ReasonablyRealtime, Quota, RateLimiter};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;

pub struct Actor<E: Spawner + Clock + ReasonablyRealtime + Metrics, C: PublicKey> {
    context: E,

    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,
    info_verifier: InfoVerifier<C>,

    max_bit_vec: u64,
    max_peers: usize,

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
    pub fn new(context: E, cfg: Config<C>) -> (Self, Mailbox<Message<C>>, Relay<Data>) {
        let (control_sender, control_receiver) = Mailbox::new(cfg.mailbox_size);
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                mailbox: control_sender.clone(),
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: cfg.allowed_bit_vec_rate,
                allowed_peers_rate: cfg.allowed_peers_rate,
                info_verifier: cfg.info_verifier,
                max_bit_vec: cfg.max_peer_set_size,
                max_peers: cfg.peer_gossip_max_count,
                control: control_receiver,
                high: high_receiver,
                low: low_receiver,
                sent_messages: cfg.sent_messages,
                received_messages: cfg.received_messages,
                rate_limited: cfg.rate_limited,
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
        payload: types::Payload<C>,
    ) -> Result<(), Error> {
        let msg = payload.encode();
        sender.send(&msg).await.map_err(Error::SendFailed)?;
        sent_messages.get_or_create(&metric).inc();
        Ok(())
    }

    pub async fn run<O: Sink, I: Stream>(
        mut self,
        peer: C,
        (mut conn_sender, mut conn_receiver): (Sender<O>, Receiver<I>),
        mut tracker: UnboundedMailbox<tracker::Message<C>>,
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
                            tracker.construct(peer.clone(), mailbox.clone());

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
                            let msg = Self::validate_outbound_msg(msg_high, &rate_limits)?;
                            Self::send(&mut conn_sender, &self.sent_messages, metrics::Message::new_data(&peer, msg.channel), types::Payload::Data(msg))
                                .await?;
                        },
                        msg_low = self.low.next() => {
                            let msg = Self::validate_outbound_msg(msg_low, &rate_limits)?;
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
                        .recv()
                        .await
                        .map_err(Error::ReceiveFailed)?;

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
                                None => { // Treat unknown channels as invalid
                                    debug!(?peer, channel = data.channel, "invalid channel");
                                    self.received_messages
                                        .get_or_create(&metrics::Message::new_invalid(&peer))
                                        .inc();
                                    return Err(Error::InvalidChannel);
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
                            tracker.bit_vec(bit_vec, self.mailbox.clone());
                        }
                        types::Payload::Peers(peers) => {
                            // Verify all info is valid
                            self.info_verifier.validate(&context, &peers).map_err(Error::Types)?;

                            // Send peers to tracker
                            tracker.peers(peers);
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
