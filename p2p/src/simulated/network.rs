//! Implementation of a simulated p2p network.

use super::{
    ingress::{self, Oracle},
    metrics, Error,
};
use crate::{Channel, Message, Recipients};
use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_macros::select;
use commonware_runtime::{
    deterministic::{Listener, Sink, Stream},
    Clock, Handle, Listener as _, Metrics, Network as RNetwork, Spawner,
};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use prometheus_client::metrics::{counter::Counter, family::Family};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tracing::{error, trace};

/// Task type representing a message to be sent within the network.
type Task<P> = (Channel, P, Recipients<P>, Bytes, oneshot::Sender<Vec<P>>);

/// Configuration for the simulated network.
pub struct Config {
    /// Maximum size of a message that can be sent over the network.
    pub max_size: usize,
}

/// Implementation of a simulated network.
pub struct Network<E: RNetwork<Listener, Sink, Stream> + Spawner + Rng + Clock + Metrics, P: Array>
{
    context: E,

    // Maximum size of a message that can be sent over the network
    max_size: usize,

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

    // Metrics for received and sent messages
    received_messages: Family<metrics::Message, Counter>,
    sent_messages: Family<metrics::Message, Counter>,
}

impl<E: RNetwork<Listener, Sink, Stream> + Spawner + Rng + Clock + Metrics, P: Array>
    Network<E, P>
{
    /// Create a new simulated network with a given runtime and configuration.
    ///
    /// Returns a tuple containing the network instance and the oracle that can
    /// be used to modify the state of the network during context.
    pub fn new(context: E, cfg: Config) -> (Self, Oracle<P>) {
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
        let next_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from_bits(context.clone().next_u32())),
            0,
        );
        (
            Self {
                context,
                max_size: cfg.max_size,
                next_addr,
                ingress: oracle_receiver,
                sender,
                receiver,
                links: HashMap::new(),
                peers: BTreeMap::new(),
                received_messages,
                sent_messages,
            },
            Oracle::new(oracle_sender),
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
                        &mut self.context.clone(),
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
                    self.context.clone(),
                    public_key,
                    channel,
                    self.max_size,
                    self.sender.clone(),
                );
                send_result(result, Ok((sender, receiver)))
            }
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
                let key = (sender.clone(), receiver);
                if self.links.contains_key(&key) {
                    return send_result(result, Err(Error::LinkExists));
                }

                let link = Link::new(
                    &mut self.context,
                    sender,
                    peer.socket,
                    sampler,
                    success_rate,
                    self.max_size,
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
        let mut sent = Vec::new();
        let (acquired_sender, mut acquired_receiver) = mpsc::channel(recipients.len());
        for recipient in recipients {
            // Skip self
            if recipient == origin {
                trace!(?recipient, reason = "self", "dropping message",);
                continue;
            }

            // Determine if there is a link between the sender and recipient
            let mut link = match self
                .links
                .get(&(origin.clone(), recipient.clone()))
                .cloned()
            {
                Some(link) => link,
                None => {
                    trace!(?origin, ?recipient, reason = "no link", "dropping message",);
                    continue;
                }
            };

            // Record sent message as soon as we determine there is a link with recipient (approximates
            // having an open connection)
            self.sent_messages
                .get_or_create(&metrics::Message::new(&origin, &recipient, channel))
                .inc();

            // Apply link settings
            let delay = link.sampler.sample(&mut self.context);
            let should_deliver = self.context.gen_bool(link.success_rate);
            trace!(?origin, ?recipient, ?delay, "sending message",);

            // Send message
            self.context.with_label("messenger").spawn({
                let message = message.clone();
                let recipient = recipient.clone();
                let origin = origin.clone();
                let mut acquired_sender = acquired_sender.clone();
                let received_messages = self.received_messages.clone();
                move |context| async move {
                    // Mark as sent as soon as soon as execution starts
                    acquired_sender.send(()).await.unwrap();

                    // Apply delay to send (once link is not saturated)
                    //
                    // Note: messages can be sent out of order (will not occur when using a
                    // stable TCP connection)
                    context.sleep(Duration::from_millis(delay as u64)).await;

                    // Drop message if success rate is too low
                    if !should_deliver {
                        trace!(
                            ?recipient,
                            reason = "random link failure",
                            "dropping message",
                        );
                        return;
                    }

                    // Send message
                    if let Err(err) = link.send(channel, message).await {
                        // This can only happen if the receiver exited.
                        error!(?origin, ?recipient, ?err, "failed to send",);
                        return;
                    }

                    // Only record received messages that were successfully sent
                    received_messages
                        .get_or_create(&metrics::Message::new(&origin, &recipient, channel))
                        .inc();
                }
            });
            sent.push(recipient);
        }

        // Notify sender of successful sends
        self.context
            .clone()
            .with_label("notifier")
            .spawn(|_| async move {
                // Wait for semaphore to be acquired on all sends
                for _ in 0..sent.len() {
                    acquired_receiver.next().await.unwrap();
                }

                // Notify sender of successful sends
                if let Err(err) = reply.send(sent) {
                    // This can only happen if the sender exited.
                    error!(?err, "failed to send ack");
                }
            });
    }

    /// Run the simulated network.
    ///
    /// It is not necessary to invoke this method before modifying the network topology, however,
    /// no messages will be sent until this method is called.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(mut self) {
        loop {
            select! {
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
                }
            }
        }
    }
}

/// Implementation of a [`crate::Sender`] for the simulated network.
#[derive(Clone, Debug)]
pub struct Sender<P: Array> {
    me: P,
    channel: Channel,
    max_size: usize,
    high: mpsc::UnboundedSender<Task<P>>,
    low: mpsc::UnboundedSender<Task<P>>,
}

impl<P: Array> Sender<P> {
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

impl<P: Array> crate::Sender for Sender<P> {
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

/// Implementation of a [`crate::Receiver`] for the simulated network.
#[derive(Debug)]
pub struct Receiver<P: Array> {
    receiver: MessageReceiver<P>,
}

impl<P: Array> crate::Receiver for Receiver<P> {
    type Error = Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Error> {
        self.receiver.next().await.ok_or(Error::NetworkClosed)
    }
}

/// A peer in the simulated network.
///
/// The peer can register channels, which allows it to receive messages sent to the channel from other peers.
struct Peer<P: Array> {
    // Socket address that the peer is listening on
    socket: SocketAddr,

    // Control to register new channels
    control: mpsc::UnboundedSender<(Channel, oneshot::Sender<MessageReceiverResult<P>>)>,
}

impl<P: Array> Peer<P> {
    /// Create and return a new peer.
    ///
    /// The peer will listen for incoming connections on the given `socket` address.
    /// `max_size` is the maximum size of a message that can be sent to the peer.
    fn new<E: Spawner + RNetwork<Listener, Sink, Stream> + Metrics>(
        context: &mut E,
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
#[derive(Clone)]
struct Link {
    sampler: Normal<f64>,
    success_rate: f64,
    inbox: mpsc::UnboundedSender<(Channel, Bytes)>,
}

impl Link {
    fn new<E: Spawner + RNetwork<Listener, Sink, Stream> + Metrics, P: Array>(
        context: &mut E,
        dialer: P,
        socket: SocketAddr,
        sampler: Normal<f64>,
        success_rate: f64,
        max_size: usize,
    ) -> Self {
        let (inbox, mut outbox) = mpsc::unbounded();
        let result = Self {
            sampler,
            success_rate,
            inbox,
        };

        // Spawn a task that will wait for messages to be sent to the link and then send them
        // over the network.
        context
            .clone()
            .with_label("link")
            .spawn(move |context| async move {
                // Dial the peer and handshake by sending it the dialer's public key
                let (mut sink, _) = context.dial(socket).await.unwrap();
                if let Err(err) = send_frame(&mut sink, &dialer, max_size).await {
                    error!(?err, "failed to send public key to listener");
                    return;
                }

                // For any item placed in the inbox, send it to the sink
                while let Some((channel, message)) = outbox.next().await {
                    let mut data = bytes::BytesMut::with_capacity(Channel::SIZE + message.len());
                    data.extend_from_slice(&channel.to_be_bytes());
                    data.extend_from_slice(&message);
                    let data = data.freeze();
                    send_frame(&mut sink, &data, max_size).await.unwrap();
                }
            });

        result
    }

    // Send a message over the link.
    async fn send(&mut self, channel: Channel, message: Bytes) -> Result<(), Error> {
        self.inbox
            .send((channel, message))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Ed25519, Signer, Specification};
    use commonware_runtime::{
        deterministic::{Context, Executor},
        Runner,
    };

    const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

    #[test]
    fn test_register_and_link() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                max_size: MAX_MESSAGE_SIZE,
            };
            let network_context = context.with_label("network");
            let (network, mut oracle) = Network::new(network_context.clone(), cfg);
            network_context.spawn(|_| network.run());

            // Create two public keys
            let pk1 = Ed25519::from_seed(1).public_key();
            let pk2 = Ed25519::from_seed(2).public_key();

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
                latency: 2.0,
                jitter: 1.0,
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
        };
        let (_, context, _) = Executor::default();
        type PublicKey = <Ed25519 as Specification>::PublicKey;
        let (mut network, _) = Network::<Context, PublicKey>::new(context.clone(), cfg);

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
    }
}
