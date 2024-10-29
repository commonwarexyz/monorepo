//! Implementation of a simulated p2p network.

use super::{
    ingress::{self, Oracle},
    metrics, Error,
};
use crate::{Channel, Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::{Clock, Spawner};
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

/// Implementation of a simulated network.
pub struct Network<E: Spawner + Rng + Clock> {
    runtime: E,

    ingress: mpsc::UnboundedReceiver<ingress::Message>,

    sender: mpsc::UnboundedSender<Task>,
    receiver: mpsc::UnboundedReceiver<Task>,
    links: HashMap<PublicKey, HashMap<PublicKey, (Normal<f64>, f64)>>,
    peers: BTreeMap<PublicKey, HashMap<Channel, (usize, mpsc::UnboundedSender<Message>)>>,

    received_messages: Family<metrics::Message, Counter>,
    sent_messages: Family<metrics::Message, Counter>,
}

/// Describes a connection between two peers.
///
/// Links are unidirectional (and must be set up in both directions
/// for a bidirectional connection).
pub struct Link {
    /// Mean latency for the delivery of a message in milliseconds.
    pub latency: f64,

    /// Standard deviation of the latency for the delivery of a message in milliseconds.
    pub jitter: f64,

    /// Probability of a message being delivered successfully (in range \[0,1\]).
    pub success_rate: f64,
}

/// Configuration for the simulated network.
pub struct Config {
    /// Registry for prometheus metrics.
    pub registry: Arc<Mutex<Registry>>,
}

impl<E: Spawner + Rng + Clock> Network<E> {
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
                links: HashMap::new(),
                peers: BTreeMap::new(),
                received_messages,
                sent_messages,
            },
            Oracle::new(oracle_sender),
        )
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
                max_size,
                result,
            } => {
                // Ensure doesn't already exist
                let entry = self.peers.entry(public_key.clone()).or_default();
                if entry.get(&channel).is_some() {
                    if let Err(err) = result.send(Err(Error::ChannelAlreadyRegistered(channel))) {
                        error!(?err, "failed to send register err to oracle");
                    }
                    return;
                }

                // Initialize agent channel
                let (sender, receiver) = mpsc::unbounded();
                entry.insert(channel, (max_size, sender));
                let result = result.send(Ok((
                    Sender::new(
                        self.runtime.clone(),
                        public_key,
                        channel,
                        max_size,
                        self.sender.clone(),
                    ),
                    Receiver { receiver },
                )));
                if let Err(err) = result {
                    error!(?err, "failed to send register ack to oracle");
                }
            }
            ingress::Message::Deregister { public_key, result } => {
                if self.peers.remove(&public_key).is_none() {
                    if let Err(err) = result.send(Err(Error::PeerMissing)) {
                        error!(?err, "failed to send deregister err to oracle");
                    }
                    return;
                }
                if let Err(err) = result.send(Ok(())) {
                    error!(?err, "failed to send deregister ack to oracle");
                }
            }
            ingress::Message::AddLink {
                sender,
                receiver,
                sampler,
                success_rate,
                result,
            } => {
                self.links
                    .entry(sender)
                    .or_default()
                    .insert(receiver, (sampler, success_rate));
                if let Err(err) = result.send(()) {
                    error!(?err, "failed to send add link ack to oracle");
                }
            }
            ingress::Message::RemoveLink {
                sender,
                receiver,
                result,
            } => {
                let recipients = match self.links.get_mut(&sender) {
                    Some(entry) => entry,
                    None => {
                        if let Err(err) = result.send(Err(Error::LinkMissing)) {
                            error!(?err, "failed to send remove link err to oracle");
                        }
                        return;
                    }
                };
                if recipients.remove(&receiver).is_none() {
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
            let sender = match self.peers.get(&recipient) {
                Some(sender) => sender,
                None => {
                    trace!(
                        recipient = hex(&recipient),
                        reason = "no agent",
                        "dropping message",
                    );
                    continue;
                }
            };

            // Determine if there is a link between the sender and recipient
            let link = match self
                .links
                .get(&origin)
                .and_then(|links| links.get(&recipient))
            {
                Some(link) => link,
                None => {
                    trace!(
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
            let delay = link.0.sample(&mut self.runtime);
            let should_deliver = self.runtime.gen_bool(link.1);
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
                let sender = sender.get(&channel).cloned();
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

                    // Drop message if not listening on channel
                    let (max_size, mut sender) = match sender {
                        Some(sender) => sender,
                        None => {
                            trace!(
                                recipient = hex(&recipient),
                                channel,
                                reason = "missing channel",
                                "dropping message",
                            );
                            return;
                        }
                    };

                    // Drop message if too large
                    if message.len() > max_size {
                        trace!(
                            recipient = hex(&recipient),
                            channel,
                            size = message.len(),
                            max_size,
                            reason = "message too large",
                            "dropping message",
                        );
                        return;
                    }

                    // Send message
                    if let Err(err) = sender.send((origin.clone(), message)).await {
                        // This can only happen if the receiver exited.
                        error!(
                            origin = hex(&origin),
                            recipient = hex(&recipient),
                            ?err,
                            "failed to send",
                        );
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
        self.receiver.next().await.ok_or(Error::PeerClosed)
    }
}
