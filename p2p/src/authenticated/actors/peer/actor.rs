use super::{ingress::Data, Config, Error, Mailbox, Message, Relay};
use crate::authenticated::{
    actors::tracker,
    channels::Channels,
    metrics, wire,
};
use bytes::{Bytes, BytesMut};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Sink, Spawner, Stream};
use commonware_stream::connection::{Instance, Sender};
use commonware_utils::hex;
use futures::{channel::mpsc, SinkExt, StreamExt};
use governor::{clock::ReasonablyRealtime, Quota, RateLimiter};
use prometheus_client::metrics::{counter::Counter, family::Family};
use prost::Message as _;
use rand::{CryptoRng, Rng};
use std::{cmp::min, collections::HashMap, sync::Arc, time::Duration};
use tracing::{debug, trace};

pub struct Actor<E: Spawner + Clock + ReasonablyRealtime> {
    runtime: E,

    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,

    mailbox: Mailbox,
    control: mpsc::Receiver<Message>,
    high: mpsc::Receiver<Data>,
    low: mpsc::Receiver<Data>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,
    rate_limited: Family<metrics::Message, Counter>,

    // When reservation goes out-of-scope, the tracker will be notified.
    _reservation: tracker::Reservation<E>,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng> Actor<E> {
    pub fn new(runtime: E, cfg: Config, reservation: tracker::Reservation<E>) -> (Self, Relay) {
        let (control_sender, control_receiver) = mpsc::channel(cfg.mailbox_size);
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);

        (
            Self {
                runtime,
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

    async fn send_content<Si: Sink>(
        max_size: usize,
        max_content_size: usize,
        sender: &mut Sender<Si>,
        peer: &PublicKey,
        data: Data,
        sent_messages: &Family<metrics::Message, Counter>,
    ) -> Result<(), Error> {
        // Ensure message is not too large
        let message_len = data.message.len();
        if message_len > max_size {
            return Err(Error::MessageTooLarge(message_len));
        }

        // Compute required parts
        let mut total_parts = message_len / max_content_size;
        if message_len % max_content_size != 0 {
            total_parts += 1;
        }
        if total_parts > u32::MAX as usize {
            // Should never happen
            return Err(Error::MessageTooLarge(message_len));
        }

        // Chunk data
        let mut part = 0;
        let channel = data.channel;
        while part < total_parts {
            let start = part * max_content_size;
            let end = min((part + 1) * max_content_size, message_len);
            let content = data.message.slice(start..end);
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Chunk({
                    wire::Chunk {
                        channel,
                        part: part as u32,
                        total_parts: total_parts as u32,
                        content,
                    }
                })),
            }.encode_to_vec();
            trace!(
                part = part,
                total_parts = total_parts - 1,
                peer = hex(peer),
                "sending chunk",
            );
            sender.send(Bytes::from(msg)).await.map_err(Error::SendFailed)?;
            sent_messages
                .get_or_create(&metrics::Message::new_chunk(peer, channel))
                .inc();
            part += 1;
        }
        Ok(())
    }

    pub async fn run<C: Scheme, Si: Sink, St: Stream>(
        mut self,
        peer: PublicKey,
        connection: Instance<C, Si, St>,
        mut tracker: tracker::Mailbox<E>,
        channels: Channels,
    ) -> Error {
        // Instantiate rate limiters for each message type
        let mut rate_limits = HashMap::new();
        let mut senders = HashMap::new();
        for (channel, (rate, max_size, sender)) in channels.collect() {
            let rate_limiter = RateLimiter::direct_with_clock(rate, &self.runtime);
            rate_limits.insert(channel, (rate_limiter, max_size));
            senders.insert(channel, sender);
        }
        let rate_limits = Arc::new(rate_limits);

        // Send/Receive messages from the peer
        let (max_content_size, mut conn_sender, mut conn_receiver) = connection.split();
        let mut send_handler: Handle<Result<(), Error>> = self.runtime.spawn("sender",{
            let runtime = self.runtime.clone();
            let mut tracker = tracker.clone();
            let peer = peer.clone();
            let mailbox = self.mailbox.clone();
            let rate_limits = rate_limits.clone();
            async move {
                let mut deadline = runtime.current() + self.gossip_bit_vec_frequency;
                loop {
                    select! {
                        _ = runtime.sleep_until(deadline) => {
                            // Get latest bitset from tracker (also used as ping)
                            tracker.construct(peer.clone(), mailbox.clone()).await;

                            // Reset ticker
                            deadline = runtime.current() + self.gossip_bit_vec_frequency;
                        },
                        msg_control = self.control.next() => {
                            let msg = match msg_control {
                                Some(msg_control) => msg_control,
                                None => return Err(Error::PeerDisconnected),
                            };
                            match msg {
                                Message::BitVec { bit_vec } => {
                                    let msg = wire::Message{
                                        payload: Some(wire::message::Payload::BitVec(bit_vec)),
                                    }.encode_to_vec();
                                    conn_sender.send(Bytes::from(msg))
                                        .await
                                        .map_err(Error::SendFailed)?;
                                    self.sent_messages
                                        .get_or_create(&metrics::Message::new_bit_vec(&peer))
                                        .inc();
                                }
                                Message::Peers { peers: msg } => {
                                    let msg = wire::Message{
                                        payload: Some(wire::message::Payload::Peers(msg)),
                                    }.encode_to_vec();
                                    conn_sender.send(Bytes::from(msg)).await.map_err(Error::SendFailed)?;
                                    self.sent_messages
                                        .get_or_create(&metrics::Message::new_peers(&peer))
                                        .inc();
                                }
                                Message::Kill => {
                                    return Err(Error::PeerKilled(hex(&peer)))
                                }
                            }
                        },
                        msg_high = self.high.next() => {
                            let msg = match msg_high {
                                Some(msg_high) => msg_high,
                                None => return Err(Error::PeerDisconnected),
                            };
                            let entry = rate_limits.get(&msg.channel);
                            if entry.is_none() {
                                return Err(Error::InvalidChannel);
                            }
                            let (_, max_size) = entry.unwrap();
                            Self::send_content(*max_size, max_content_size, &mut conn_sender, &peer, msg, &self.sent_messages).await?;
                        },
                        msg_low = self.low.next() => {
                            let msg = match msg_low {
                                Some(msg_low) => msg_low,
                                None => return Err(Error::PeerDisconnected),
                            };
                            let entry = rate_limits.get(&msg.channel);
                            if entry.is_none() {
                                return Err(Error::InvalidChannel);
                            }
                            let (_, max_size) = entry.unwrap();
                            Self::send_content(*max_size, max_content_size, &mut conn_sender, &peer, msg, &self.sent_messages).await?;
                        }
                    }
                }
            }
        });
        let mut receive_handler: Handle<Result<(), Error>> = self.runtime.spawn("receiver", {
            let runtime = self.runtime.clone();
            async move {
                let bit_vec_rate_limiter =
                    RateLimiter::direct_with_clock(self.allowed_bit_vec_rate, &runtime);
                let peers_rate_limiter =
                    RateLimiter::direct_with_clock(self.allowed_peers_rate, &runtime);
                loop {
                    let msg = conn_receiver
                        .receive()
                        .await
                        .map_err(Error::ReceiveFailed)?;
                    let msg = wire::Message::decode(&msg[..])
                        .map_err(Error::DecodeFailed)?;
                    match msg.payload
                    {
                        Some(wire::message::Payload::BitVec(bit_vec)) => {
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
                                    let wait = negative.wait_time_from(runtime.now());
                                    runtime.sleep(wait).await;
                                }
                            }

                            // Gather useful peers
                            tracker.bit_vec(bit_vec, self.mailbox.clone()).await;
                        }
                        Some(wire::message::Payload::Peers(peers)) => {
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
                                    let wait = negative.wait_time_from(runtime.now());
                                    runtime.sleep(wait).await;
                                }
                            }

                            // Send peers to tracker
                            tracker.peers(peers, self.mailbox.clone()).await;
                        }
                        Some(wire::message::Payload::Chunk(chunk)) => {
                            self.received_messages
                                .get_or_create(&metrics::Message::new_chunk(&peer, chunk.channel))
                                .inc();

                            // Ensure peer is not spamming us with content messages
                            let entry = rate_limits.get(&chunk.channel);
                            if entry.is_none() {
                                // We permit unknown messages to be received in case peers
                                // are on a newer version than us
                                continue;
                            }
                            let (rate_limiter, max_size) = entry.unwrap();
                            match rate_limiter.check() {
                                Ok(_) => {}
                                Err(negative) => {
                                    self.rate_limited
                                        .get_or_create(&metrics::Message::new_chunk(
                                            &peer,
                                            chunk.channel,
                                        ))
                                        .inc();
                                    let wait = negative.wait_time_from(runtime.now());
                                    runtime.sleep(wait).await;
                                }
                            }

                            // Ensure message is not too large
                            let chunk_len = chunk.content.len();
                            if chunk_len > *max_size {
                                return Err(Error::MessageTooLarge(chunk_len));
                            }

                            // Gather all chunks
                            let mut message = BytesMut::from(&chunk.content[..]);
                            let total_parts = chunk.total_parts;
                            if total_parts > 1 {
                                // Ensure first part is the max size
                                if chunk_len != max_content_size {
                                    return Err(Error::InvalidChunk);
                                }

                                // Read chunk messages until we have all parts
                                let channel = chunk.channel;
                                let mut next_part = chunk.part + 1;
                                while next_part < total_parts {
                                    let msg = conn_receiver
                                        .receive()
                                        .await
                                        .map_err(Error::ReceiveFailed)?;
                                    let msg = wire::Message::decode(&msg[..])
                                        .map_err(Error::DecodeFailed)?;
                                    let chunk = match msg.payload {
                                        Some(wire::message::Payload::Chunk(chunk)) => chunk,
                                        _ => return Err(Error::InvalidChunk),
                                    };
                                    if chunk.channel != channel {
                                        return Err(Error::InvalidChunk);
                                    }
                                    if chunk.total_parts != total_parts {
                                        return Err(Error::InvalidChunk);
                                    }
                                    if chunk.part != next_part {
                                        return Err(Error::InvalidChunk);
                                    }
                                    let chunk_len = chunk.content.len();
                                    if chunk.part != total_parts - 1
                                        && chunk_len != max_content_size
                                    {
                                        return Err(Error::InvalidChunk);
                                    }
                                    let new_len = message.len() + chunk_len;
                                    if new_len > *max_size {
                                        return Err(Error::MessageTooLarge(new_len));
                                    }
                                    message.extend_from_slice(&chunk.content);
                                    next_part += 1;
                                }
                            }

                            // Send message to client
                            //
                            // If the channel handler is closed, we log an error but don't
                            // close the peer (as other channels may still be open).
                            let sender = senders.get_mut(&chunk.channel).unwrap();
                            if let Err(e) = sender
                                .send((peer.clone(), message.freeze()))
                                .await
                                .map_err(|_| Error::ChannelClosed(chunk.channel))
                            {
                                debug!(err=?e, "failed to send message to client");
                            }
                        }
                        _ => {
                            self.received_messages
                                .get_or_create(&metrics::Message::new_unknown(&peer))
                                .inc();

                            // We permit unknown messages to be received in case
                            // peers are on a newer version than us
                            continue;
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
