//! Implementation of a simulated p2p network.

use super::{
    ingress::{self, Oracle},
    metrics,
    transmitter::{self, Completion},
    Error,
};
use crate::{Channel, Message, Recipients};
use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Listener as _, Metrics, Network as RNetwork, Spawner,
};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use either::Either;
use futures::{
    channel::{mpsc, oneshot},
    future, SinkExt, StreamExt,
};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime},
};
use tracing::{error, trace};

/// Task type representing a message to be sent within the network.
type Task<P> = (Channel, P, Recipients<P>, Bytes, oneshot::Sender<Vec<P>>);

/// Configuration for the simulated network.
pub struct Config {
    /// Maximum size of a message that can be sent over the network.
    pub max_size: usize,

    /// True if peers should disconnect upon being blocked. While production networking would
    /// typically disconnect, for testing purposes it may be useful to keep peers connected,
    /// allowing byzantine actors the ability to continue sending messages.
    pub disconnect_on_block: bool,
}

/// Implementation of a simulated network.
pub struct Network<E: RNetwork + Spawner + Rng + Clock + Metrics, P: PublicKey> {
    context: ContextCell<E>,

    // Maximum size of a message that can be sent over the network
    max_size: usize,

    // True if peers should disconnect upon being blocked.
    // While production networking would typically disconnect, for testing purposes it may be useful
    // to keep peers connected, allowing byzantine actors the ability to continue sending messages.
    disconnect_on_block: bool,

    // Next socket address to assign to a new peer
    // Incremented for each new peer
    next_addr: SocketAddr,

    // Channel to receive messages from the oracle
    ingress: mpsc::UnboundedReceiver<ingress::Message<P>>,

    // A channel to receive tasks from peers
    // The sender is cloned and given to each peer
    // The receiver is polled in the main loop
    sender: mpsc::UnboundedSender<Task<P>>,
    receiver: mpsc::UnboundedReceiver<Task<P>>,

    // A map from a pair of public keys (from, to) to a link between the two peers
    links: HashMap<(P, P), Link>,

    // A map from a public key to a peer
    peers: BTreeMap<P, Peer<P>>,

    // A map of peers blocking each other
    blocks: HashSet<(P, P)>,

    // State of the transmitter
    transmitter: transmitter::State<P>,

    // Metrics for received and sent messages
    received_messages: Family<metrics::Message, Counter>,
    sent_messages: Family<metrics::Message, Counter>,
}

impl<E: RNetwork + Spawner + Rng + Clock + Metrics, P: PublicKey> Network<E, P> {
    /// Create a new simulated network with a given runtime and configuration.
    ///
    /// Returns a tuple containing the network instance and the oracle that can
    /// be used to modify the state of the network during context.
    pub fn new(mut context: E, cfg: Config) -> (Self, Oracle<P>) {
        let (sender, receiver) = mpsc::unbounded();
        let (oracle_sender, oracle_receiver) = mpsc::unbounded();
        let sent_messages = Family::<metrics::Message, Counter>::default();
        let received_messages = Family::<metrics::Message, Counter>::default();
        context.register("messages_sent", "messages sent", sent_messages.clone());
        context.register(
            "messages_received",
            "messages received",
            received_messages.clone(),
        );

        // Start with a pseudo-random IP address to assign sockets to for new peers
        let next_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(context.next_u32())), 0);
        (
            Self {
                context: ContextCell::new(context),
                max_size: cfg.max_size,
                disconnect_on_block: cfg.disconnect_on_block,
                next_addr,
                ingress: oracle_receiver,
                sender,
                receiver,
                links: HashMap::new(),
                peers: BTreeMap::new(),
                blocks: HashSet::new(),
                transmitter: transmitter::State::new(),
                received_messages,
                sent_messages,
            },
            Oracle::new(oracle_sender.clone()),
        )
    }

    /// Returns (and increments) the next available socket address.
    ///
    /// The port number is incremented for each call, and the IP address is incremented if the port
    /// number overflows.
    fn get_next_socket(&mut self) -> SocketAddr {
        let result = self.next_addr;

        // Increment the port number, or the IP address if the port number overflows.
        // Allows the ip address to overflow (wrapping).
        match self.next_addr.port().checked_add(1) {
            Some(port) => {
                self.next_addr.set_port(port);
            }
            None => {
                let ip = match self.next_addr.ip() {
                    IpAddr::V4(ipv4) => ipv4,
                    _ => unreachable!(),
                };
                let next_ip = Ipv4Addr::to_bits(ip).wrapping_add(1);
                self.next_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(next_ip)), 0);
            }
        }

        result
    }

    /// Handle an ingress message.
    ///
    /// This method is called when a message is received from the oracle.
    async fn handle_ingress(&mut self, message: ingress::Message<P>) {
        // It is important to ensure that no failed receipt of a message will cause us to exit.
        // This could happen if the caller drops the `Oracle` after updating the network topology.
        // Thus, we create a helper function to send the result to the oracle and log any errors.
        fn send_result<T: std::fmt::Debug>(
            result: oneshot::Sender<Result<T, Error>>,
            value: Result<T, Error>,
        ) {
            let success = value.is_ok();
            if let Err(e) = result.send(value) {
                error!(?e, "failed to send result to oracle (ok = {})", success);
            }
        }

        match message {
            ingress::Message::Register {
                public_key,
                channel,
                result,
            } => {
                // If peer does not exist, then create it.
                if !self.peers.contains_key(&public_key) {
                    let peer = Peer::new(
                        self.context.with_label("peer"),
                        public_key.clone(),
                        self.get_next_socket(),
                        self.max_size,
                    );
                    self.peers.insert(public_key.clone(), peer);
                }

                // Create a receiver that allows receiving messages from the network for a certain channel
                let peer = self.peers.get_mut(&public_key).unwrap();
                let receiver = match peer.register(channel).await {
                    Ok(receiver) => Receiver { receiver },
                    Err(err) => return send_result(result, Err(err)),
                };

                // Create a sender that allows sending messages to the network for a certain channel
                let sender = Sender::new(
                    self.context.with_label("sender"),
                    public_key,
                    channel,
                    self.max_size,
                    self.sender.clone(),
                );
                send_result(result, Ok((sender, receiver)))
            }
            ingress::Message::LimitBandwidth {
                public_key,
                egress_cap,
                ingress_cap,
                result,
            } => match self.peers.contains_key(&public_key) {
                true => {
                    // Update bandwidth limits
                    let now = self.context.current();
                    let completions =
                        self.transmitter
                            .limit(now, &public_key, egress_cap, ingress_cap);
                    self.process_completions(completions);

                    // Alert application of update
                    send_result(result, Ok(()));
                }
                false => send_result(result, Err(Error::PeerMissing)),
            },
            ingress::Message::AddLink {
                sender,
                receiver,
                sampler,
                success_rate,
                result,
            } => {
                // Require both peers to be registered
                if !self.peers.contains_key(&sender) {
                    return send_result(result, Err(Error::PeerMissing));
                }
                let peer = match self.peers.get(&receiver) {
                    Some(peer) => peer,
                    None => return send_result(result, Err(Error::PeerMissing)),
                };

                // Require link to not already exist
                let key = (sender.clone(), receiver.clone());
                if self.links.contains_key(&key) {
                    return send_result(result, Err(Error::LinkExists));
                }

                let link = Link::new(
                    &mut self.context,
                    sender,
                    receiver,
                    peer.socket,
                    sampler,
                    success_rate,
                    self.max_size,
                    self.received_messages.clone(),
                );
                self.links.insert(key, link);
                send_result(result, Ok(()))
            }
            ingress::Message::RemoveLink {
                sender,
                receiver,
                result,
            } => {
                match self.links.remove(&(sender, receiver)) {
                    Some(_) => (),
                    None => return send_result(result, Err(Error::LinkMissing)),
                }
                send_result(result, Ok(()))
            }
            ingress::Message::Block { from, to } => {
                self.blocks.insert((from, to));
            }
            ingress::Message::Blocked { result } => {
                send_result(result, Ok(self.blocks.iter().cloned().collect()))
            }
        }
    }
}

impl<E: RNetwork + Spawner + Rng + Clock + Metrics, P: PublicKey> Network<E, P> {
    /// Process completions from the transmitter.
    fn process_completions(&mut self, completions: Vec<Completion<P>>) {
        for completion in completions {
            // If there is no message to deliver, then skip
            let Some(deliver_at) = completion.deliver_at else {
                trace!(
                    origin = ?completion.origin,
                    recipient = ?completion.recipient,
                    "message dropped before delivery",
                );
                continue;
            };

            // Send message to link
            let key = (completion.origin.clone(), completion.recipient.clone());
            let Some(link) = self.links.get_mut(&key) else {
                // This can happen if the link is removed before the message is delivered
                trace!(
                    origin = ?completion.origin,
                    recipient = ?completion.recipient,
                    "missing link for completion",
                );
                continue;
            };
            if let Err(err) = link.send(completion.channel, completion.message, deliver_at) {
                error!(?err, "failed to send");
            }
        }
    }

    /// Handle a task.
    ///
    /// This method is called when a task is received from the sender, which can come from
    /// any peer in the network.
    fn handle_task(&mut self, task: Task<P>) {
        // Collect recipients
        let (channel, origin, recipients, message, reply) = task;
        let recipients = match recipients {
            Recipients::All => self.peers.keys().cloned().collect(),
            Recipients::Some(keys) => keys,
            Recipients::One(key) => vec![key],
        };

        // Send to all recipients
        let now = self.context.current();
        let mut sent = Vec::new();
        for recipient in recipients {
            // Skip self
            if recipient == origin {
                trace!(?recipient, reason = "self", "dropping message");
                continue;
            }

            // Determine if the sender or recipient has blocked the other
            let o_r = (origin.clone(), recipient.clone());
            let r_o = (recipient.clone(), origin.clone());
            if self.disconnect_on_block
                && (self.blocks.contains(&o_r) || self.blocks.contains(&r_o))
            {
                trace!(?origin, ?recipient, reason = "blocked", "dropping message");
                continue;
            }

            // Determine if there is a link between the origin and recipient
            let Some(link) = self.links.get_mut(&o_r) else {
                trace!(?origin, ?recipient, reason = "no link", "dropping message");
                continue;
            };

            // Record sent message as soon as we determine there is a link with recipient (approximates
            // having an open connection)
            self.sent_messages
                .get_or_create(&metrics::Message::new(&origin, &recipient, channel))
                .inc();

            // Sample latency
            let latency = Duration::from_millis(link.sampler.sample(&mut self.context) as u64);

            // Determine if the message should be delivered
            let should_deliver = self.context.gen_bool(link.success_rate);

            // Enqueue message for delivery
            let completions = self.transmitter.enqueue(
                now,
                origin.clone(),
                recipient.clone(),
                channel,
                message.clone(),
                latency,
                should_deliver,
            );
            self.process_completions(completions);

            sent.push(recipient);
        }

        // Alert application of sent messages
        if let Err(err) = reply.send(sent) {
            error!(?err, "failed to send ack");
        }
    }

    /// Run the simulated network.
    ///
    /// It is not necessary to invoke this method before modifying the network topology, however,
    /// no messages will be sent until this method is called.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        loop {
            let tick = match self.transmitter.next() {
                Some(when) => Either::Left(self.context.sleep_until(when)),
                None => Either::Right(future::pending()),
            };
            select! {
                _ = tick => {
                    let now = self.context.current();
                    let completions = self.transmitter.advance(now);
                    self.process_completions(completions);
                },
                message = self.ingress.next() => {
                    // If ingress is closed, exit
                    let message = match message {
                        Some(message) => message,
                        None => break,
                    };
                    self.handle_ingress(message).await;
                },
                task = self.receiver.next() => {
                    // If receiver is closed, exit
                    let task = match task {
                        Some(task) => task,
                        None => break,
                    };
                    self.handle_task(task);
                },
            }
        }
    }
}

/// Implementation of a [crate::Sender] for the simulated network.
#[derive(Clone, Debug)]
pub struct Sender<P: PublicKey> {
    me: P,
    channel: Channel,
    max_size: usize,
    high: mpsc::UnboundedSender<Task<P>>,
    low: mpsc::UnboundedSender<Task<P>>,
}

impl<P: PublicKey> Sender<P> {
    fn new(
        context: impl Spawner + Metrics,
        me: P,
        channel: Channel,
        max_size: usize,
        mut sender: mpsc::UnboundedSender<Task<P>>,
    ) -> Self {
        // Listen for messages
        let (high, mut high_receiver) = mpsc::unbounded();
        let (low, mut low_receiver) = mpsc::unbounded();
        context.with_label("sender").spawn(move |_| async move {
            loop {
                // Wait for task
                let task;
                select! {
                    high_task = high_receiver.next() => {
                        task = match high_task {
                            Some(task) => task,
                            None => break,
                        };
                    },
                    low_task = low_receiver.next() => {
                        task = match low_task {
                            Some(task) => task,
                            None => break,
                        };
                    }
                }

                // Send task
                if let Err(err) = sender.send(task).await {
                    error!(?err, channel, "failed to send task");
                }
            }
        });

        // Return sender
        Self {
            me,
            channel,
            max_size,
            high,
            low,
        }
    }
}

impl<P: PublicKey> crate::Sender for Sender<P> {
    type Error = Error;
    type PublicKey = P;

    async fn send(
        &mut self,
        recipients: Recipients<P>,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<P>, Error> {
        // Check message size
        if message.len() > self.max_size {
            return Err(Error::MessageTooLarge(message.len()));
        }

        // Send message
        let (sender, receiver) = oneshot::channel();
        let mut channel = if priority { &self.high } else { &self.low };
        channel
            .send((self.channel, self.me.clone(), recipients, message, sender))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)
    }
}

type MessageReceiver<P> = mpsc::UnboundedReceiver<Message<P>>;
type MessageReceiverResult<P> = Result<MessageReceiver<P>, Error>;

/// Implementation of a [crate::Receiver] for the simulated network.
#[derive(Debug)]
pub struct Receiver<P: PublicKey> {
    receiver: MessageReceiver<P>,
}

impl<P: PublicKey> crate::Receiver for Receiver<P> {
    type Error = Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Error> {
        self.receiver.next().await.ok_or(Error::NetworkClosed)
    }
}

/// A peer in the simulated network.
///
/// The peer can register channels, which allows it to receive messages sent to the channel from other peers.
struct Peer<P: PublicKey> {
    // Socket address that the peer is listening on
    socket: SocketAddr,

    // Control to register new channels
    control: mpsc::UnboundedSender<(Channel, oneshot::Sender<MessageReceiverResult<P>>)>,
}

impl<P: PublicKey> Peer<P> {
    /// Create and return a new peer.
    ///
    /// The peer will listen for incoming connections on the given `socket` address.
    /// `max_size` is the maximum size of a message that can be sent to the peer.
    fn new<E: Spawner + RNetwork + Metrics + Clock>(
        context: E,
        public_key: P,
        socket: SocketAddr,
        max_size: usize,
    ) -> Self {
        // The control is used to register channels.
        // There is exactly one mailbox created for each channel that the peer is registered for.
        let (control_sender, mut control_receiver) = mpsc::unbounded();

        // Whenever a message is received from a peer, it is placed in the inbox.
        // The router polls the inbox and forwards the message to the appropriate mailbox.
        let (inbox_sender, mut inbox_receiver) = mpsc::unbounded();

        // Spawn router
        context.with_label("router").spawn(|_| async move {
            // Map of channels to mailboxes (senders to particular channels)
            let mut mailboxes = HashMap::new();

            // Continually listen for control messages and outbound messages
            loop {
                select! {
                    // Listen for control messages, which are used to register channels
                    control = control_receiver.next() => {
                        // If control is closed, exit
                        let (channel, result): (Channel, oneshot::Sender<MessageReceiverResult<P>>) = match control {
                            Some(control) => control,
                            None => break,
                        };

                        // Check if channel is registered
                        if mailboxes.contains_key(&channel) {
                            result.send(Err(Error::ChannelAlreadyRegistered(channel))).unwrap();
                            continue;
                        }

                        // Register channel
                        let (sender, receiver) = mpsc::unbounded();
                        mailboxes.insert(channel, sender);
                        result.send(Ok(receiver)).unwrap();
                    },

                    // Listen for messages from the inbox, which are forwarded to the appropriate mailbox
                    inbox = inbox_receiver.next() => {
                        // If inbox is closed, exit
                        let (channel, message) = match inbox {
                            Some(message) => message,
                            None => break,
                        };

                        // Send message to mailbox
                        match mailboxes.get_mut(&channel) {
                            Some(mailbox) => {
                                if let Err(err) = mailbox.send(message).await {
                                    error!(?err, "failed to send message to mailbox");
                                }
                            }
                            None => {
                                trace!(
                                    recipient = ?public_key,
                                    channel,
                                    reason = "missing channel",
                                    "dropping message",
                                );
                            }
                        }
                    },
                }
            }
        });

        // Spawn a task that accepts new connections and spawns a task for each connection
        context.with_label("listener").spawn({
            let inbox_sender = inbox_sender.clone();
            move |context| async move {
                // Initialize listener
                let mut listener = context.bind(socket).await.unwrap();

                // Continually accept new connections
                while let Ok((_, _, mut stream)) = listener.accept().await {
                    // New connection accepted. Spawn a task for this connection
                    context.with_label("receiver").spawn({
                        let mut inbox_sender = inbox_sender.clone();
                        move |_| async move {
                            // Receive dialer's public key as a handshake
                            let dialer = match recv_frame(&mut stream, max_size).await {
                                Ok(data) => data,
                                Err(_) => {
                                    error!("failed to receive public key from dialer");
                                    return;
                                }
                            };
                            let Ok(dialer) = P::decode(dialer.as_ref()) else {
                                error!("received public key is invalid");
                                return;
                            };

                            // Continually receive messages from the dialer and send them to the inbox
                            while let Ok(data) = recv_frame(&mut stream, max_size).await {
                                let channel = Channel::from_be_bytes(
                                    data[..Channel::SIZE].try_into().unwrap(),
                                );
                                let message = data.slice(Channel::SIZE..);
                                if let Err(err) = inbox_sender
                                    .send((channel, (dialer.clone(), message)))
                                    .await
                                {
                                    error!(?err, "failed to send message to mailbox");
                                    break;
                                }
                            }
                        }
                    });
                }
            }
        });

        // Return peer
        Self {
            socket,
            control: control_sender,
        }
    }

    /// Register a channel with the peer.
    ///
    /// This allows the peer to receive messages sent to the channel.
    /// Returns a receiver that can be used to receive messages sent to the channel.
    async fn register(&mut self, channel: Channel) -> MessageReceiverResult<P> {
        let (sender, receiver) = oneshot::channel();
        self.control
            .send((channel, sender))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)?
    }
}

// A unidirectional link between two peers.
// Messages can be sent over the link with a given latency, jitter, and success rate.
struct Link {
    sampler: Normal<f64>,
    success_rate: f64,
    // Messages with their receive time for ordered delivery
    inbox: mpsc::UnboundedSender<(Channel, Bytes, SystemTime)>,
}

/// Buffered payload waiting for earlier messages on the same link to complete.
impl Link {
    #[allow(clippy::too_many_arguments)]
    fn new<E: Spawner + RNetwork + Clock + Metrics, P: PublicKey>(
        context: &mut E,
        dialer: P,
        receiver: P,
        socket: SocketAddr,
        sampler: Normal<f64>,
        success_rate: f64,
        max_size: usize,
        received_messages: Family<metrics::Message, Counter>,
    ) -> Self {
        // Spawn a task that will wait for messages to be sent to the link and then send them
        // over the network.
        let (inbox, mut outbox) = mpsc::unbounded::<(Channel, Bytes, SystemTime)>();
        context.with_label("link").spawn(move |context| async move {
            // Dial the peer and handshake by sending it the dialer's public key
            let (mut sink, _) = context.dial(socket).await.unwrap();
            if let Err(err) = send_frame(&mut sink, &dialer, max_size).await {
                error!(?err, "failed to send public key to listener");
                return;
            }

            // Process messages in order, waiting for their receive time
            while let Some((channel, message, receive_complete_at)) = outbox.next().await {
                // Wait until the message should arrive at receiver
                context.sleep_until(receive_complete_at).await;

                // Send the message
                let mut data = bytes::BytesMut::with_capacity(Channel::SIZE + message.len());
                data.extend_from_slice(&channel.to_be_bytes());
                data.extend_from_slice(&message);
                let data = data.freeze();
                send_frame(&mut sink, &data, max_size).await.unwrap();

                // Bump received messages metric
                received_messages
                    .get_or_create(&metrics::Message::new(&dialer, &receiver, channel))
                    .inc();
            }
        });

        Self {
            sampler,
            success_rate,
            inbox,
        }
    }

    // Send a message over the link with receive timing.
    fn send(
        &mut self,
        channel: Channel,
        message: Bytes,
        receive_complete_at: SystemTime,
    ) -> Result<(), Error> {
        self.inbox
            .unbounded_send((channel, message, receive_complete_at))
            .map_err(|_| Error::NetworkClosed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver as _, Recipients, Sender as _};
    use bytes::Bytes;
    use commonware_cryptography::{ed25519, PrivateKeyExt as _, Signer as _};
    use commonware_runtime::{deterministic, Runner as _};
    const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

    #[test]
    fn test_register_and_link() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
            };
            let network_context = context.with_label("network");
            let (network, mut oracle) = Network::new(network_context.clone(), cfg);
            network_context.spawn(|_| network.run());

            // Create two public keys
            let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
            let pk2 = ed25519::PrivateKey::from_seed(2).public_key();

            // Register
            oracle.register(pk1.clone(), 0).await.unwrap();
            oracle.register(pk1.clone(), 1).await.unwrap();
            oracle.register(pk2.clone(), 0).await.unwrap();
            oracle.register(pk2.clone(), 1).await.unwrap();

            // Expect error when registering again
            assert!(matches!(
                oracle.register(pk1.clone(), 1).await,
                Err(Error::ChannelAlreadyRegistered(_))
            ));

            // Add link
            let link = ingress::Link {
                latency: Duration::from_millis(2),
                jitter: Duration::from_millis(1),
                success_rate: 0.9,
            };
            oracle
                .add_link(pk1.clone(), pk2.clone(), link.clone())
                .await
                .unwrap();

            // Expect error when adding link again
            assert!(matches!(
                oracle.add_link(pk1, pk2, link).await,
                Err(Error::LinkExists)
            ));
        });
    }

    #[test]
    fn test_get_next_socket() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            type PublicKey = ed25519::PublicKey;
            let (mut network, _) =
                Network::<deterministic::Context, PublicKey>::new(context.clone(), cfg);

            // Test that the next socket address is incremented correctly
            let mut original = network.next_addr;
            let next = network.get_next_socket();
            assert_eq!(next, original);
            let next = network.get_next_socket();
            original.set_port(1);
            assert_eq!(next, original);

            // Test that the port number overflows correctly
            let max_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 0, 255, 255)), 65535);
            network.next_addr = max_addr;
            let next = network.get_next_socket();
            assert_eq!(next, max_addr);
            let next = network.get_next_socket();
            assert_eq!(
                next,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 1, 0, 0)), 0)
            );
        });
    }

    #[test]
    fn test_fifo_burst_same_recipient() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            let (network, mut oracle) = Network::new(context.with_label("network"), cfg);
            let network_handle = network.start();

            let sender_pk = ed25519::PrivateKey::from_seed(10).public_key();
            let recipient_pk = ed25519::PrivateKey::from_seed(11).public_key();

            let (mut sender, _sender_recv) = oracle.register(sender_pk.clone(), 0).await.unwrap();
            let (_sender2, mut receiver) = oracle.register(recipient_pk.clone(), 0).await.unwrap();

            oracle
                .limit_bandwidth(sender_pk.clone(), Some(5_000), None)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(recipient_pk.clone(), None, Some(5_000))
                .await
                .unwrap();

            oracle
                .add_link(
                    sender_pk.clone(),
                    recipient_pk.clone(),
                    ingress::Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            const COUNT: usize = 50;
            let mut expected = Vec::with_capacity(COUNT);
            for i in 0..COUNT {
                let msg = Bytes::from(vec![i as u8; 64]);
                sender
                    .send(Recipients::One(recipient_pk.clone()), msg.clone(), false)
                    .await
                    .unwrap();
                expected.push(msg);
            }

            for expected_msg in expected {
                let (_pk, bytes) = receiver.recv().await.unwrap();
                assert_eq!(bytes, expected_msg);
            }

            drop(oracle);
            drop(sender);
            network_handle.abort();
        });
    }

    #[test]
    fn test_broadcast_respects_transmit_latency() {
        let cfg = Config {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: true,
        };
        let runner = deterministic::Runner::default();

        runner.start(|context| async move {
            let (network, mut oracle) = Network::new(context.with_label("network"), cfg);
            let network_handle = network.start();

            let sender_pk = ed25519::PrivateKey::from_seed(42).public_key();
            let recipient_a = ed25519::PrivateKey::from_seed(43).public_key();
            let recipient_b = ed25519::PrivateKey::from_seed(44).public_key();

            let (mut sender, _recv_sender) = oracle.register(sender_pk.clone(), 0).await.unwrap();
            let (_sender2, mut recv_a) = oracle.register(recipient_a.clone(), 0).await.unwrap();
            let (_sender3, mut recv_b) = oracle.register(recipient_b.clone(), 0).await.unwrap();

            oracle
                .limit_bandwidth(sender_pk.clone(), Some(1_000), None)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(recipient_a.clone(), None, Some(1_000))
                .await
                .unwrap();
            oracle
                .limit_bandwidth(recipient_b.clone(), None, Some(1_000))
                .await
                .unwrap();

            let link = ingress::Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(sender_pk.clone(), recipient_a.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(sender_pk.clone(), recipient_b.clone(), link)
                .await
                .unwrap();

            let big_msg = Bytes::from(vec![7u8; 10_000]);
            let start = context.current();
            sender
                .send(Recipients::All, big_msg.clone(), false)
                .await
                .unwrap();

            let (_pk, received_a) = recv_a.recv().await.unwrap();
            assert_eq!(received_a, big_msg);
            let elapsed_a = context.current().duration_since(start).unwrap();
            assert!(elapsed_a >= Duration::from_secs(20));

            let (_pk, received_b) = recv_b.recv().await.unwrap();
            assert_eq!(received_b, big_msg);
            let elapsed_b = context.current().duration_since(start).unwrap();
            assert!(elapsed_b >= Duration::from_secs(20));

            // Because bandwidth is shared, the two messages should take about the same time
            assert!(elapsed_a.abs_diff(elapsed_b) <= Duration::from_secs(1));

            drop(oracle);
            drop(sender);
            network_handle.abort();
        });
    }
}
