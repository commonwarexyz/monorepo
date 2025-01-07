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
    Clock,
    Network as RNetwork,
    Spawner,
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
    cmp::max,
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
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

struct Dialee {
    socket: SocketAddr,
    listener: Option<Listener>,
}

impl Dialee {
    fn new<E: Rng>(runtime: &mut E) -> Self {
        // Generate a random IP address
        let ip1 = runtime.next_u64();
        let ip2 = runtime.next_u64();
        let socket = SocketAddr::from(([
            (ip1 >> 48) as u16,
            (ip1 >> 32) as u16,
            (ip1 >> 16) as u16,
            ip1 as u16,
            (ip2 >> 48) as u16,
            (ip2 >> 32) as u16,
            (ip2 >> 16) as u16,
            ip2 as u16,
        ], 0));

        Dialee { socket, listener: None }
    }

    fn get_socket(&self) -> SocketAddr {
        self.socket
    }

    async fn accept<E: RNetwork<Listener, Sink, Stream>>(&mut self, runtime: &E) -> Result<Stream, Error> {
        let listener = match self.listener.take() {
            Some(listener) => listener,
            None => {
                let listener = runtime.bind(self.socket).await.map_err(|_| Error::BindFailed)?;
                self.listener = Some(listener);
                let listener_clone = listener.clone();
                listener_clone
            },
        };
        let (_, _, stream) = listener.accept().await.map_err(|_| Error::AcceptFailed)?;
        Ok(stream)
    }
}

struct Mailbox {
    // Map from channel to a tuple of max_size and the sender to the receiver for that channel
    senders: HashMap<Channel, (usize, mpsc::UnboundedSender<Message>)>,
}

impl Mailbox {
    fn new() -> Self {
        Self {
            senders: HashMap::new(),
        }
    }

    fn register(&mut self, channel: Channel, max_size: usize) -> Result<mpsc::UnboundedReceiver<Message>, Error> {
        // Error if channel already exists
        if self.senders.contains_key(&channel) {
            return Err(Error::ChannelAlreadyRegistered(channel));
        }

        // Insert new channel
        let (sender, receiver) = mpsc::unbounded();
        self.senders.insert(channel, (max_size, sender));
        Ok(receiver)
    }

    fn get_max_size(&self, channel: Channel) -> Option<usize> {
        match self.senders.get(&channel) {
            Some((max_size, _)) => Some(*max_size),
            None => None,
        }
    }

    async fn send(&mut self, channel: Channel, message: Message) {
        if let Some((_, sender)) = self.senders.get_mut(&channel) {
            if let Err(err) = sender.send(message).await {
                error!(?err, "failed to send message");
            }
        }
    }
}

struct Link {
    sink: Arc<Mutex<Sink>>,
    sampler: Normal<f64>,
    success_rate: f64,
}

impl Link {
    fn new(sink: Sink, sampler: Normal<f64>, success_rate: f64) -> Self {
        Self {
            sink: Arc::new(Mutex::new(sink)),
            sampler,
            success_rate,
        }
    }

    async fn send(&self, message: Bytes, max_size: usize) -> Result<(), Error> {
        let mut sink = self.sink.lock().unwrap();
        send_frame(&mut *sink, &message, max_size).await.map_err(|_| Error::SendFrameFailed)
    }
}

/// Configuration for the simulated network.
pub struct Config {
    /// Registry for prometheus metrics.
    pub registry: Arc<Mutex<Registry>>,
}

/// Implementation of a simulated network.
pub struct Network<E: RNetwork<Listener, Sink, Stream> + Spawner + Rng + Clock> {
    runtime: E,

    max_size: usize,

    ingress: mpsc::UnboundedReceiver<ingress::Message>,

    sender: mpsc::UnboundedSender<Task>,
    receiver: mpsc::UnboundedReceiver<Task>,

    links: HashMap<(PublicKey, PublicKey), Link>,
    peers: BTreeMap<PublicKey, Mailbox>,
    dialees: HashMap<PublicKey, Arc<Mutex<Dialee>>>,

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
                ingress: oracle_receiver,
                sender,
                receiver,
                max_size: 1024, // TODO
                links: HashMap::new(),
                peers: BTreeMap::new(),
                dialees: HashMap::new(),
                received_messages,
                sent_messages,
            },
            Oracle::new(oracle_sender),
        )
    }

    async fn handle_ingress(&mut self, message: ingress::Message) {
        // Handle ingress message
        //
        // It is important to ensure that no failed receipt of a message will cause us to exit.
        // This could happen if the caller drops the `Oracle` after updating the network topology.
        match message {
            ingress::Message::Register {
                public_key,
                channel,
                max_size,
                result,
            } => {
                // Get or create mailbox for peer
                let mailbox = self.peers.entry(public_key.clone()).or_insert_with(Mailbox::new);

                // Create a receiver that allows receiving messages from the network for a certain channel
                let receiver = match mailbox.register(channel, max_size) {
                    Ok(receiver) => Receiver { receiver } ,
                    Err(err) => {
                        let result = result.send(Err(err));
                        if let Err(err) = result {
                            error!(?err, "failed to send register err to oracle");
                        }
                        return;
                    }
                };

                self.max_size = max(self.max_size, max_size);

                // Create a sender that allows sending messages to the network for a certain channel
                let sender = Sender::new(
                    self.runtime.clone(),
                    public_key,
                    channel,
                    max_size,
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
                // Either get a mutable dialee from self.dialees, or insert a new one if it doesn't exist
                let dialee = self.dialees
                    .entry(sender.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(Dialee::new(&mut self.runtime))));
                let dialee = dialee.lock().unwrap();
                
                // Create connection by dialing and accepting at the same time
                let socket = dialee.get_socket();
                let runtime_clone = self.runtime.clone();
                let dial = self.runtime.spawn("dial", async move {
                    runtime_clone.dial(socket).await.map_err(|_| Error::DialFailed)
                });
                let runtime_clone = self.runtime.clone();
                let accept = self.runtime.spawn("accept", async move {
                    dialee.accept(&runtime_clone).await
                });
                let connection_result = futures::try_join!(dial, accept);

                // Process results
                let (sink, mut stream) = match connection_result {
                    Ok((Ok((sink, _)), Ok(stream))) => (sink, stream),
                    Ok((Err(err), _)) => {
                        let result = result.send(Err(err.into()));
                        if let Err(err) = result {
                            error!(?err, "failed to send add link err to oracle");
                        }
                        return;
                    }
                    Ok((_, Err(err))) => {
                        let result = result.send(Err(err.into()));
                        if let Err(err) = result {
                            error!(?err, "failed to send add link err to oracle");
                        }
                        return;
                    }
                    Err(_) => {
                        let result = result.send(Err(Error::NetworkClosed));
                        if let Err(err) = result {
                            error!(?err, "failed to send add link err to oracle");
                        }
                        return;
                    }
                };

                // Spawn a thread that processes messages sent over the connection and put them in the appropriate mailbox
                let mailbox = match self.peers.get_mut(&receiver) {
                    Some(mailbox) => mailbox,
                    None => {
                        let result = result.send(Err(Error::PeerMissing));
                        if let Err(err) = result {
                            error!(?err, "failed to send add link err to oracle");
                        }
                        return;
                    }
                };
                let max_size = self.max_size;
                let sender_clone = sender.clone();
                self.runtime.spawn("receiver", async move {
                    while let Ok(data) = recv_frame(&mut stream, max_size).await {
                        let channel = Channel::from_be_bytes(data[..4].try_into().unwrap());
                        let message = Bytes::from(data.slice(4..));
                        mailbox.send(channel, (sender.clone(), message));
                    }
                });

                let link = Link::new(sink, sampler, success_rate);
                self.links.insert((sender_clone, receiver), link);

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
            let link = match self.links.get(&(origin.clone(), recipient.clone())) {
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
            let max_size = self.max_size;
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
                    link.send(message, max_size).await.unwrap();

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
    channel: Channel,
    max_size: usize,

    me: PublicKey,
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
            channel,
            max_size,

            me,
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
