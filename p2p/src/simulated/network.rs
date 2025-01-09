//! Implementation of a simulated p2p network.

use super::{
    ingress::{self, Oracle},
    metrics, Error,
};
use crate::{Channel, Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::{
    deterministic::{Listener, Sink, Stream},
    Clock, Listener as _, Network as RNetwork, Spawner,
};
use commonware_stream::public_key::utils::codec::{recv_frame, send_frame};
use commonware_utils::hex;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use prometheus_client::{
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{error, trace};

/// Task type representing a message to be sent within the network.
type Task = (
    Channel,
    PublicKey,
    Recipients,
    Bytes,
    oneshot::Sender<Vec<PublicKey>>,
);

/// Configuration for the simulated network.
pub struct Config {
    /// Registry for prometheus metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Maximum size of a message that can be sent over the network.
    pub max_size: usize,
}

/// Implementation of a simulated network.
pub struct Network<E: RNetwork<Listener, Sink, Stream> + Spawner + Rng + Clock> {
    runtime: E,

    max_size: usize,
    next_addr: SocketAddr,

    ingress: mpsc::UnboundedReceiver<ingress::Message>,

    sender: mpsc::UnboundedSender<Task>,
    receiver: mpsc::UnboundedReceiver<Task>,

    links: HashMap<(PublicKey, PublicKey), Link>,
    peers: BTreeMap<PublicKey, Peer>,

    received_messages: Family<metrics::Message, Counter>,
    sent_messages: Family<metrics::Message, Counter>,
}

impl<E: RNetwork<Listener, Sink, Stream> + Spawner + Rng + Clock> Network<E> {
    /// Create a new simulated network with a given runtime and configuration.
    ///
    /// Returns a tuple containing the network instance and the oracle that can
    /// be used to modify the state of the network during runtime.
    pub fn new(runtime: E, cfg: Config) -> (Self, Oracle) {
        let (sender, receiver) = mpsc::unbounded();
        let sent_messages = Family::<metrics::Message, Counter>::default();
        let received_messages = Family::<metrics::Message, Counter>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("messages_sent", "messages sent", sent_messages.clone());
            registry.register(
                "messages_received",
                "messages received",
                received_messages.clone(),
            );
        }
        let (oracle_sender, oracle_receiver) = mpsc::unbounded();
        (
            Self {
                runtime,
                max_size: cfg.max_size,
                next_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
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

    fn get_next_socket(&mut self) -> SocketAddr {
        let result = self.next_addr;
        self.next_addr.set_port(self.next_addr.port() + 1);
        result
    }

    fn handle_ingress(&mut self, message: ingress::Message) {
        // Handle ingress message
        //
        // It is important to ensure that no failed receipt of a message will cause us to exit.
        // This could happen if the caller drops the `Oracle` after updating the network topology.
        match message {
            ingress::Message::Register {
                public_key,
                channel,
                result,
            } => {
                // If peer does not exist, then create it.
                if !self.peers.contains_key(&public_key) {
                    let peer = Peer::new(
                        &mut self.runtime.clone(),
                        self.get_next_socket(),
                        self.max_size,
                    );
                    self.peers.insert(public_key.clone(), peer);
                }

                // Create a receiver that allows receiving messages from the network for a certain channel
                let peer = self.peers.get_mut(&public_key).unwrap();
                let receiver = match peer.register(channel) {
                    Ok(receiver) => Receiver { receiver },
                    Err(err) => {
                        let result = result.send(Err(err));
                        if let Err(err) = result {
                            error!(?err, "failed to send register err to oracle");
                        }
                        return;
                    }
                };

                // Create a sender that allows sending messages to the network for a certain channel
                let sender = Sender::new(
                    self.runtime.clone(),
                    public_key,
                    channel,
                    self.max_size,
                    self.sender.clone(),
                );

                // Return values via callback
                let result = result.send(Ok((sender, receiver)));
                if let Err(err) = result {
                    error!(?err, "failed to send register ack to oracle");
                }
            }
            ingress::Message::AddLink {
                sender,
                receiver,
                sampler,
                success_rate,
                result,
            } => {
                let peer = match self.peers.get(&sender) {
                    Some(peer) => peer,
                    None => {
                        let result = result.send(Err(Error::PeerMissing));
                        if let Err(err) = result {
                            error!(?err, "failed to send add link err to oracle");
                        }
                        return;
                    }
                };
                let key = (sender.clone(), receiver);
                if self.links.contains_key(&key) {
                    let result = result.send(Err(Error::LinkExists));
                    if let Err(err) = result {
                        error!(?err, "failed to send add link err to oracle");
                    }
                    return;
                }

                let link = Link::new(
                    &mut self.runtime,
                    sender.clone(),
                    peer.socket,
                    sampler,
                    success_rate,
                    self.max_size,
                );
                self.links.insert(key, link);

                if let Err(err) = result.send(Ok(())) {
                    error!(?err, "failed to send add link ack to oracle");
                }
            }
            ingress::Message::RemoveLink {
                sender,
                receiver,
                result,
            } => {
                if self.links.remove(&(sender, receiver)).is_none() {
                    if let Err(err) = result.send(Err(Error::LinkMissing)) {
                        error!(?err, "failed to send remove link err to oracle");
                    }
                    return;
                }
                if let Err(err) = result.send(Ok(())) {
                    error!(?err, "failed to send remove link ack to oracle");
                }
            }
        }
    }

    fn handle_task(&mut self, task: Task) {
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
                trace!(
                    recipient = hex(&recipient),
                    reason = "self",
                    "dropping message",
                );
                continue;
            }

            // Determine if recipient exists
            if !self.peers.contains_key(&recipient) {
                trace!(
                    recipient = hex(&recipient),
                    reason = "no agent",
                    "dropping message",
                );
                continue;
            };

            // Determine if there is a link between the sender and recipient
            let link = match self
                .links
                .get(&(origin.clone(), recipient.clone()))
                .cloned()
            {
                Some(link) => link,
                None => {
                    trace!(
                        origin = hex(&origin),
                        recipient = hex(&recipient),
                        reason = "no link",
                        "dropping message",
                    );
                    continue;
                }
            };

            // Record sent message as soon as we determine there is a link with recipient (approximates
            // having an open connection)
            self.sent_messages
                .get_or_create(&metrics::Message::new(&origin, &recipient, channel))
                .inc();

            // Apply link settings
            let delay = link.sampler.sample(&mut self.runtime);
            let should_deliver = self.runtime.gen_bool(link.success_rate);
            trace!(
                origin = hex(&origin),
                recipient = hex(&recipient),
                ?delay,
                "sending message",
            );

            // Send message
            self.runtime.spawn("messenger", {
                let runtime = self.runtime.clone();
                let recipient = recipient.clone();
                let message = message.clone();
                let mut acquired_sender = acquired_sender.clone();
                let origin = origin.clone();
                let received_messages = self.received_messages.clone();
                async move {
                    // Mark as sent as soon as soon as execution starts
                    acquired_sender.send(()).await.unwrap();

                    // Apply delay to send (once link is not saturated)
                    //
                    // Note: messages can be sent out of order (will not occur when using a
                    // stable TCP connection)
                    runtime.sleep(Duration::from_millis(delay as u64)).await;

                    // Drop message if success rate is too low
                    if !should_deliver {
                        trace!(
                            recipient = hex(&recipient),
                            reason = "random link failure",
                            "dropping message",
                        );
                        return;
                    }

                    // Send message
                    link.send(channel, message).await.unwrap();

                    // Only record received messages that were successfully sent
                    received_messages
                        .get_or_create(&metrics::Message::new(&origin, &recipient, channel))
                        .inc();
                }
            });
            sent.push(recipient);
        }

        // Notify sender of successful sends
        self.runtime.spawn("notifier", async move {
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
    pub async fn run(mut self) {
        loop {
            select! {
                message = self.ingress.next() => {
                    // If ingress is closed, exit
                    let message = match message {
                        Some(message) => message,
                        None => break,
                    };

                    self.handle_ingress(message);
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
pub struct Sender {
    me: PublicKey,
    channel: Channel,
    max_size: usize,
    high: mpsc::UnboundedSender<Task>,
    low: mpsc::UnboundedSender<Task>,
}

impl Sender {
    fn new(
        runtime: impl Spawner,
        me: PublicKey,
        channel: Channel,
        max_size: usize,
        mut sender: mpsc::UnboundedSender<Task>,
    ) -> Self {
        // Listen for messages
        let (high, mut high_receiver) = mpsc::unbounded();
        let (low, mut low_receiver) = mpsc::unbounded();
        runtime.spawn("sender", async move {
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

impl crate::Sender for Sender {
    type Error = Error;

    async fn send(
        &mut self,
        recipients: Recipients,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<PublicKey>, Error> {
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

/// Implementation of a [`crate::Receiver`] for the simulated network.
#[derive(Debug)]
pub struct Receiver {
    receiver: mpsc::UnboundedReceiver<Message>,
}

impl crate::Receiver for Receiver {
    type Error = Error;

    async fn recv(&mut self) -> Result<Message, Error> {
        self.receiver.next().await.ok_or(Error::NetworkClosed)
    }
}

// A peer in the simulated network.
// The peer can receive messages over any registered channel.
struct Peer {
    // Map from channel to a sender that can deliver messages to that channel
    mailboxes: Arc<Mutex<HashMap<Channel, mpsc::UnboundedSender<Message>>>>,

    // Socket address that the peer is listening on
    socket: SocketAddr,
}

impl Peer {
    fn new<E: Spawner + RNetwork<Listener, Sink, Stream>>(
        runtime: &mut E,
        socket: SocketAddr,
        max_size: usize,
    ) -> Self {
        let result = Self {
            mailboxes: Arc::new(Mutex::new(HashMap::new())),
            socket,
        };

        // Continually listen for incoming connections on the socket
        runtime.spawn("listener", {
            let runtime = runtime.clone();
            let mailboxes = result.mailboxes.clone();
            async move {
                while let Ok(mut listener) = runtime.bind(socket).await {
                    let (_, _, mut stream) = listener.accept().await.unwrap();

                    // Spawn a task for this connection
                    runtime.spawn("receiver", {
                        let mailboxes = mailboxes.clone();
                        async move {
                            // Receive dialer's public key as a handshake
                            let dialer = match recv_frame(&mut stream, max_size).await {
                                Ok(data) => data,
                                Err(_) => {
                                    error!("failed to receive public key from dialer");
                                    return;
                                }
                            };

                            // Continually receive messages from the dialer and send them to the appropriate mailbox
                            while let Ok(data) = recv_frame(&mut stream, max_size).await {
                                const C: usize = size_of::<Channel>();
                                let channel = Channel::from_be_bytes(data[..C].try_into().unwrap());
                                let message = data.slice(C..);
                                let mut mailbox = match mailboxes.lock().unwrap().get(&channel) {
                                    Some(s) => s.clone(),
                                    None => {
                                        error!("failed to find mailbox for channel");
                                        continue;
                                    }
                                };
                                mailbox.send((dialer.clone(), message)).await.unwrap();
                            }
                        }
                    });
                }
            }
        });

        result
    }

    fn register(&mut self, channel: Channel) -> Result<mpsc::UnboundedReceiver<Message>, Error> {
        let mut mailboxes = self.mailboxes.lock().unwrap();

        // Error if channel already exists
        if mailboxes.contains_key(&channel) {
            return Err(Error::ChannelAlreadyRegistered(channel));
        }

        // Insert new channel
        let (sender, receiver) = mpsc::unbounded();
        mailboxes.insert(channel, sender);
        Ok(receiver)
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
    fn new<E: Spawner + RNetwork<Listener, Sink, Stream>>(
        runtime: &mut E,
        dialer: PublicKey,
        socket: SocketAddr,
        sampler: Normal<f64>,
        success_rate: f64,
        max_size: usize,
    ) -> Self {
        let (inbox, mut outbox) = mpsc::unbounded();

        // Spawn a task that will wait for messages to be sent to the link and then send them
        // over the network.
        runtime.spawn("sender", {
            let runtime = runtime.clone();
            async move {
                // Dial the peer and handshake by sending it the dialer's public key
                let (mut sink, _) = runtime.dial(socket).await.unwrap();
                send_frame(&mut sink, &dialer, max_size).await.unwrap();

                // For any item placed in the inbox, send it to the sink
                loop {
                    let (channel, message): (Channel, Bytes) = outbox.next().await.unwrap();
                    let mut data =
                        bytes::BytesMut::with_capacity(size_of::<Channel>() + message.len());
                    data.extend_from_slice(&channel.to_be_bytes());
                    data.extend_from_slice(&message);
                    let data = data.freeze();
                    send_frame(&mut sink, &data, max_size).await.unwrap();
                }
            }
        });

        Self {
            sampler,
            success_rate,
            inbox,
        }
    }

    // Send a message over the link.
    async fn send(&self, channel: Channel, message: Bytes) -> Result<(), Error> {
        let mut inbox = self.inbox.clone();
        inbox
            .send((channel, message))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        Ok(())
    }
}
