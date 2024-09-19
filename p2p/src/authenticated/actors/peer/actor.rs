use super::{ingress::Data, Config, Error, Mailbox, Message, Relay};
use crate::authenticated::{
    actors::tracker,
    channels::Channels,
    connection::{Sender, Stream},
    metrics, wire,
};
use bytes::BytesMut;
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_runtime::{Clock, Handle, Spawner};
use futures::try_join;
use governor::{DefaultDirectRateLimiter, Quota};
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::{cmp::min, collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::mpsc;

pub struct Actor<E: Spawner + Clock> {
    context: E,

    gossip_bit_vec_frequency: Duration,
    allowed_bit_vec_rate: Quota,
    allowed_peers_rate: Quota,

    mailbox: Mailbox,
    control: mpsc::Receiver<Message>,
    high: mpsc::Receiver<Data>,
    low: mpsc::Receiver<Data>,

    sent_messages: Family<metrics::Message, Counter>,
    received_messages: Family<metrics::Message, Counter>,

    // When reservation goes out-of-scope, the tracker will be notified.
    _reservation: tracker::Reservation<E>,
}

impl<E: Spawner + Clock> Actor<E> {
    pub fn new(context: E, cfg: Config, reservation: tracker::Reservation<E>) -> (Self, Relay) {
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
                _reservation: reservation,
            },
            Relay::new(low_sender, high_sender),
        )
    }

    async fn send_content(
        max_size: usize,
        max_content_size: usize,
        sender: &mut Sender,
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
            };
            sender.send(msg).await.map_err(Error::SendFailed)?;
            sent_messages
                .get_or_create(&metrics::Message::new_chunk(peer, channel))
                .inc();
            part += 1;
        }
        Ok(())
    }

    pub async fn run<C: Scheme>(
        mut self,
        peer: PublicKey,
        connection: Stream<E, C>,
        tracker: tracker::Mailbox<E>,
        channels: Channels,
    ) -> Error {
        // Instantiate rate limiters for each message type
        let mut rate_limits = HashMap::new();
        for (channel, (rate, max_size, sender)) in channels.collect() {
            let rate_limiter = DefaultDirectRateLimiter::direct(rate);
            rate_limits.insert(channel, (rate_limiter, max_size, sender));
        }
        let rate_limits = Arc::new(rate_limits);

        // Send/Receive messages from the peer
        let (max_content_size, mut conn_sender, mut conn_receiver) = connection.split();
        let send_tracker = tracker.clone();
        let send_peer = peer.clone();
        let send_mailbox = self.mailbox.clone();
        let send_rate_limits = rate_limits.clone();
        let mut send_handler: Handle<Result<(), Error>> = self.context.spawn(async move {
            let mut ticker = tokio::time::interval(self.gossip_bit_vec_frequency);
            loop {
                tokio::select! {
                    // Ensure we send ip gossip before any user messages
                    biased;

                    _ = ticker.tick() => {
                        // Get latest bitset from tracker (also used as ping)
                        send_tracker.construct(send_peer.clone(), send_mailbox.clone()).await;
                    }
                    Some(msg) = self.control.recv() => {
                        match msg {
                            Message::BitVec { bit_vec } => {
                                conn_sender.send(wire::Message{
                                    payload: Some(wire::message::Payload::BitVec(bit_vec)),
                                }).await.map_err(Error::SendFailed)?;
                                self.sent_messages
                                    .get_or_create(&metrics::Message::new_bit_vec(&send_peer))
                                    .inc();
                            }
                            Message::Peers { peers: msg } => {
                                conn_sender.send(wire::Message{
                                    payload: Some(wire::message::Payload::Peers(msg)),
                                }).await.map_err(Error::SendFailed)?;
                                self.sent_messages
                                    .get_or_create(&metrics::Message::new_peers(&send_peer))
                                    .inc();
                            }
                            Message::Kill => {
                                return Err(Error::PeerKilled(hex(&send_peer)))
                            }
                        }
                    }
                    Some(msg) = self.high.recv() => {
                        let entry = send_rate_limits.get(&msg.channel);
                        if entry.is_none() {
                            return Err(Error::InvalidChannel);
                        }
                        let (_, max_size, _) = entry.unwrap();
                        Self::send_content(*max_size, max_content_size, &mut conn_sender, &send_peer, msg, &self.sent_messages).await?;
                    }
                    Some(msg) = self.low.recv() => {
                        let entry = send_rate_limits.get(&msg.channel);
                        if entry.is_none() {
                            return Err(Error::InvalidChannel);
                        }
                        let (_, max_size, _) = entry.unwrap();
                        Self::send_content(*max_size, max_content_size, &mut conn_sender, &send_peer, msg, &self.sent_messages).await?;
                    }
                    else => return Err(Error::PeerDisconnected),
                }
            }
        });
        let mut receive_handler: Handle<Result<(), Error>> = self.context.spawn(async move {
            let bit_vec_rate_limiter = DefaultDirectRateLimiter::direct(self.allowed_bit_vec_rate);
            let peers_rate_limiter = DefaultDirectRateLimiter::direct(self.allowed_peers_rate);
            loop {
                match conn_receiver
                    .receive()
                    .await
                    .map_err(Error::ReceiveFailed)?
                    .payload
                {
                    Some(wire::message::Payload::BitVec(bit_vec)) => {
                        self.received_messages
                            .get_or_create(&metrics::Message::new_bit_vec(&peer))
                            .inc();

                        // Ensure peer is not spamming us with bit vectors
                        bit_vec_rate_limiter.until_ready().await;

                        // Gather useful peers
                        tracker.bit_vec(bit_vec, self.mailbox.clone()).await;
                    }
                    Some(wire::message::Payload::Peers(peers)) => {
                        self.received_messages
                            .get_or_create(&metrics::Message::new_peers(&peer))
                            .inc();

                        // Ensure peer is not spamming us with peer messages
                        peers_rate_limiter.until_ready().await;

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
                        let (rate_limiter, max_size, sender) = entry.unwrap();
                        rate_limiter.until_ready().await;

                        // Ensure messasge is not too large
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
                                let chunk = match conn_receiver
                                    .receive()
                                    .await
                                    .map_err(Error::ReceiveFailed)?
                                    .payload
                                {
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
                                if chunk.part != total_parts - 1 && chunk_len != max_content_size {
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
                        sender.send((peer.clone(), message.freeze())).await.unwrap();
                    }
                    Some(wire::message::Payload::Handshake(_)) => {
                        self.received_messages
                            .get_or_create(&metrics::Message::new_handshake(&peer))
                            .inc();
                        return Err(Error::UnexpectedHandshake);
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
        });

        // Wait for one of the handlers to finish
        //
        // It is only possible for a handler to exit if there is an error.
        let result = try_join!(&mut send_handler, &mut receive_handler);

        // Ensure both handlers are aborted when one of them exits
        send_handler.abort();
        receive_handler.abort();

        // Handle the join of handlers
        match result {
            Ok((first, second)) => match first {
                Ok(_) => second.unwrap_err(),
                Err(e) => e,
            },
            Err(e) => Error::UnexpectedFailure(e),
        }
    }
}
