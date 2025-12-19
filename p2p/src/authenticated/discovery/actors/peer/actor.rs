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
use commonware_macros::{select, select_loop};
use commonware_runtime::{Clock, Handle, Metrics, Quota, RateLimiter, Sink, Spawner, Stream};
use commonware_stream::{Receiver, Sender};
use commonware_utils::time::SYSTEM_TIME_PRECISION;
use futures::{channel::mpsc, SinkExt, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;

pub struct Actor<E: Spawner + Clock + Metrics, C: PublicKey> {
    context: E,

    gossip_bit_vec_frequency: Duration,
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

impl<E: Spawner + Clock + Rng + CryptoRng + Metrics, C: PublicKey> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>) -> (Self, Relay<Data>) {
        let (control_sender, control_receiver) = Mailbox::new(cfg.mailbox_size);
        let (high_sender, high_receiver) = mpsc::channel(cfg.mailbox_size);
        let (low_sender, low_receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                mailbox: control_sender,
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
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
        greeting: types::Info<C>,
        (mut conn_sender, mut conn_receiver): (Sender<O>, Receiver<I>),
        mut tracker: UnboundedMailbox<tracker::Message<C>>,
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

        // Send greeting first before any other messages
        Self::send(
            &mut conn_sender,
            &self.sent_messages,
            metrics::Message::new_greeting(&peer),
            types::Payload::Greeting(greeting),
        )
        .await?;

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
                select_loop! {
                    context,
                    on_stopped => {},
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

                Ok(())
            }
        });
        let mut receive_handler: Handle<Result<(), Error>> = self
            .context
            .with_label("receiver")
            .spawn(move |context| async move {
                // Use half the gossip frequency for rate limiting to allow for timing
                // jitter at message boundaries.
                let half = (self.gossip_bit_vec_frequency / 2).max(SYSTEM_TIME_PRECISION);
                let rate = Quota::with_period(half).unwrap();
                let bit_vec_rate_limiter =
                    RateLimiter::direct_with_clock(rate, context.clone());
                let peers_rate_limiter =
                    RateLimiter::direct_with_clock(rate, context.clone());
                let mut greeting_received = false;
                let mut first_bit_vec_received = false;
                let mut first_peers_received = false;
                loop {
                    // Receive a message from the peer
                    let msg = conn_receiver.recv().await.map_err(Error::ReceiveFailed)?;

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
                        types::Payload::Data(data) => &metrics::Message::new_data(&peer, data.channel),
                        types::Payload::Greeting(_) => &metrics::Message::new_greeting(&peer),
                        types::Payload::BitVec(_) => &metrics::Message::new_bit_vec(&peer),
                        types::Payload::Peers(_) => &metrics::Message::new_peers(&peer),
                    };
                    self.received_messages.get_or_create(metric).inc();

                    // Ensure we start with a greeting message and then never receive another
                    if let types::Payload::Greeting(info) = msg {
                        if greeting_received {
                            debug!(?peer, "received duplicate greeting");
                            return Err(Error::DuplicateGreeting);
                        }
                        greeting_received = true;

                        // Verify the greeting is from the expected peer
                        if info.public_key != peer {
                            debug!(?peer, greeting_pk = ?info.public_key, "greeting public key mismatch");
                            return Err(Error::GreetingMismatch);
                        }

                        // Verify the greeting info is valid
                        self.info_verifier.validate(&context, std::slice::from_ref(&info)).map_err(Error::Types)?;

                        // Send greeting info to tracker
                        tracker.peers(vec![info]);
                        continue;
                    } else if !greeting_received {
                        debug!(?peer, "expected greeting as first message");
                        return Err(Error::MissingGreeting);
                    }

                    // Wait until rate limiter allows us to process the message
                    //
                    // We skip rate limiting for the first BitVec and first Peers message
                    // because they are expected immediately after the greeting exchange
                    // (we send BitVec right after our greeting, and they respond with Peers).
                    let rate_limiter = match &msg {
                        types::Payload::Data(data) => {
                            match rate_limits.get(&data.channel) {
                                Some(rate_limit) => Some(rate_limit),
                                None => {
                                    debug!(?peer, channel = data.channel, "invalid channel");
                                    self.received_messages
                                        .get_or_create(&metrics::Message::new_invalid(&peer))
                                        .inc();
                                    return Err(Error::InvalidChannel);
                                }
                            }
                        }
                        types::Payload::Greeting(_) => unreachable!(),
                        types::Payload::BitVec(_) => {
                            if first_bit_vec_received {
                                Some(&bit_vec_rate_limiter)
                            } else {
                                first_bit_vec_received = true;
                                None
                            }
                        }
                        types::Payload::Peers(_) => {
                            if first_peers_received {
                                Some(&peers_rate_limiter)
                            } else {
                                first_peers_received = true;
                                None
                            }
                        }
                    };
                    if let Some(rate_limiter) = rate_limiter {
                        if let Err(wait_until) = rate_limiter.check() {
                            self.rate_limited.get_or_create(metric).inc();
                            let wait_duration = wait_until.wait_time_from(context.now());
                            context.sleep(wait_duration).await;
                        }
                    }


                    match msg {
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
                        types::Payload::Greeting(_) => unreachable!(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::{
        discovery::{
            actors::{router, tracker},
            channels::Channels,
        },
        mailbox::UnboundedMailbox,
        Mailbox,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{deterministic, mocks, Runner, Spawner};
    use commonware_stream::{self, Config as StreamConfig};
    use commonware_utils::{bitmap::BitMap, SystemTimeExt};
    use prometheus_client::metrics::{counter::Counter, family::Family};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    const STREAM_NAMESPACE: &[u8] = b"test_peer_actor";
    const IP_NAMESPACE: &[u8] = b"test_peer_actor_IP";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    fn default_peer_config(me: PublicKey) -> Config<PublicKey> {
        Config {
            mailbox_size: 10,
            gossip_bit_vec_frequency: Duration::from_secs(30),
            max_peer_set_size: 128,
            peer_gossip_max_count: 10,
            info_verifier: types::Info::verifier(
                me,
                10,
                Duration::from_secs(60),
                IP_NAMESPACE.to_vec(),
            ),
            sent_messages: Family::<metrics::Message, Counter>::default(),
            received_messages: Family::<metrics::Message, Counter>::default(),
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

    fn create_channels() -> Channels<PublicKey> {
        let (router_mailbox, _router_receiver) = Mailbox::<router::Message<PublicKey>>::new(10);
        let messenger = router::Messenger::new(router_mailbox);
        Channels::new(messenger, MAX_MESSAGE_SIZE)
    }

    #[test]
    fn test_missing_greeting_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.clone().spawn({
                move |ctx| async move {
                    commonware_stream::listen(
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

            let (mut local_sender, _local_receiver) = commonware_stream::dial(
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

            // Create peer actor (from remote's perspective, local is the peer)
            let (peer_actor, _messenger) = Actor::<deterministic::Context, PublicKey>::new(
                context.clone(),
                default_peer_config(remote_pk),
            );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
            );

            // Create tracker mailbox
            let (tracker_mailbox, _tracker_receiver) =
                UnboundedMailbox::<tracker::Message<PublicKey>>::new();

            // Create empty channels
            let channels = create_channels();

            // Send a non-greeting message first (BitVec)
            let bit_vec = types::Payload::<PublicKey>::BitVec(types::BitVec {
                index: 0,
                bits: BitMap::ones(10),
            });
            local_sender
                .send(&bit_vec.encode())
                .await
                .expect("send failed");

            // Run peer actor and expect MissingGreeting error
            let result = peer_actor
                .run(
                    local_pk,
                    greeting,
                    (remote_sender, remote_receiver),
                    tracker_mailbox,
                    channels,
                )
                .await;

            assert!(
                matches!(result, Err(Error::MissingGreeting)),
                "Expected MissingGreeting error, got: {result:?}"
            );
        });
    }

    #[test]
    fn test_duplicate_greeting_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.clone().spawn({
                move |ctx| async move {
                    commonware_stream::listen(
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

            let (mut local_sender, _local_receiver) = commonware_stream::dial(
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

            // Create peer actor (from remote's perspective, local is the peer)
            let (peer_actor, _messenger) = Actor::<deterministic::Context, PublicKey>::new(
                context.clone(),
                default_peer_config(remote_pk),
            );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
            );

            // Create tracker mailbox
            let (tracker_mailbox, _tracker_receiver) =
                UnboundedMailbox::<tracker::Message<PublicKey>>::new();

            // Create empty channels
            let channels = create_channels();

            // Send first greeting (valid)
            let first_greeting = types::Payload::<PublicKey>::Greeting(greeting.clone());
            local_sender
                .send(&first_greeting.encode())
                .await
                .expect("send failed");

            // Send second greeting (should cause error)
            let second_greeting = types::Payload::<PublicKey>::Greeting(greeting.clone());
            local_sender
                .send(&second_greeting.encode())
                .await
                .expect("send failed");

            // Run peer actor and expect DuplicateGreeting error
            let result = peer_actor
                .run(
                    local_pk,
                    greeting,
                    (remote_sender, remote_receiver),
                    tracker_mailbox,
                    channels,
                )
                .await;

            assert!(
                matches!(result, Err(Error::DuplicateGreeting)),
                "Expected DuplicateGreeting error, got: {result:?}"
            );
        });
    }

    #[test]
    fn test_greeting_public_key_mismatch_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let local_key = PrivateKey::from_seed(1);
            let remote_key = PrivateKey::from_seed(2);
            let wrong_key = PrivateKey::from_seed(3);
            let local_pk = local_key.public_key();
            let remote_pk = remote_key.public_key();
            let wrong_pk = wrong_key.public_key();

            // Set up mock channels for the connection
            let (local_sink, remote_stream) = mocks::Channel::init();
            let (remote_sink, local_stream) = mocks::Channel::init();

            // Establish encrypted connection via handshake
            let local_config = stream_config(local_key.clone());
            let remote_config = stream_config(remote_key.clone());

            let local_pk_clone = local_pk.clone();
            let listener_handle = context.clone().spawn({
                move |ctx| async move {
                    commonware_stream::listen(
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

            let (mut local_sender, _local_receiver) = commonware_stream::dial(
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

            // Create peer actor (from remote's perspective, local is the peer)
            let (peer_actor, _messenger) = Actor::<deterministic::Context, PublicKey>::new(
                context.clone(),
                default_peer_config(remote_pk),
            );

            // Create greeting info for the peer actor to send
            let greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
            );

            // Create tracker mailbox
            let (tracker_mailbox, _tracker_receiver) =
                UnboundedMailbox::<tracker::Message<PublicKey>>::new();

            // Create empty channels
            let channels = create_channels();

            // Send greeting with wrong public key (claims to be wrong_pk instead of local_pk)
            let mut wrong_greeting = types::Info::sign(
                &local_key,
                IP_NAMESPACE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                context.current().epoch().as_millis() as u64,
            );
            wrong_greeting.public_key = wrong_pk;
            let greeting_payload = types::Payload::<PublicKey>::Greeting(wrong_greeting);
            local_sender
                .send(&greeting_payload.encode())
                .await
                .expect("send failed");

            // Run peer actor and expect GreetingMismatch error
            let result = peer_actor
                .run(
                    local_pk,
                    greeting,
                    (remote_sender, remote_receiver),
                    tracker_mailbox,
                    channels,
                )
                .await;

            assert!(
                matches!(result, Err(Error::GreetingMismatch)),
                "Expected GreetingMismatch error, got: {result:?}"
            );
        });
    }
}
