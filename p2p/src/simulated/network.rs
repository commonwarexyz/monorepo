//! Implementation of a `simulated` network.

use super::metrics;
use super::Error;
use crate::{Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{select, Clock, Spawner};
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
use tracing::{debug, error};

type Channel = u32;

type Task = (
    Channel,
    PublicKey,
    Recipients,
    Bytes,
    oneshot::Sender<Vec<PublicKey>>,
);

/// Implementation of a `simulated` network.
pub struct Network<E: Spawner + Rng + Clock> {
    runtime: E,
    // cfg: Config,
    sender: mpsc::UnboundedSender<Task>,
    receiver: mpsc::UnboundedReceiver<Task>,
    links: HashMap<PublicKey, HashMap<PublicKey, Link>>,
    agents: BTreeMap<PublicKey, HashMap<Channel, (usize, mpsc::UnboundedSender<Message>)>>,

    received_messages: Family<metrics::Message, Counter>,
    sent_messages: Family<metrics::Message, Counter>,
}

/// Describes a connection between two peers.
///
/// Links are unidirectional (and must be set up in both directions
/// for a bidirectional connection).
pub struct Link {
    /// Mean latency for the delivery of a message in milliseconds.
    pub latency_mean: f64,

    /// Standard deviation of the latency for the delivery of a message in milliseconds.
    pub latency_stddev: f64,

    /// Probability of a message being delivered successfully (in range [0,1]).
    pub success_rate: f64,
}

/// Configuration for a `simulated` network.
pub struct Config {
    pub registry: Arc<Mutex<Registry>>,
}

impl<E: Spawner + Rng + Clock> Network<E> {
    /// Create a new simulated network with a given runtime and configuration.
    pub fn new(runtime: E, cfg: Config) -> Self {
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

        Self {
            runtime,
            sender,
            receiver,
            links: HashMap::new(),
            agents: BTreeMap::new(),
            received_messages,
            sent_messages,
        }
    }

    /// Register a new peer with the network that can interact over a given channel.
    ///
    /// By default, the peer will not be linked to any other peers.
    pub fn register(
        &mut self,
        public_key: PublicKey,
        channel: Channel,
        max_size: usize,
    ) -> Result<(Sender, Receiver), Error> {
        // Ensure doesn't already exist
        let entry = self.agents.entry(public_key.clone()).or_default();
        if entry.get(&channel).is_some() {
            return Err(Error::ChannelAlreadyRegistered(channel));
        }

        // Initialize agent channel
        let (sender, receiver) = mpsc::unbounded();
        entry.insert(channel, (max_size, sender));
        Ok((
            Sender::new(
                self.runtime.clone(),
                public_key,
                channel,
                max_size,
                self.sender.clone(),
            ),
            Receiver { receiver },
        ))
    }

    /// Create a unidirectional link between two peers.
    ///
    /// Link can be called multiple times for the same sender/receiver. The latest
    /// setting will be used.
    pub fn link(
        &mut self,
        sender: PublicKey,
        receiver: PublicKey,
        config: Link,
    ) -> Result<(), Error> {
        if sender == receiver {
            return Err(Error::LinkingSelf);
        }
        if config.success_rate < 0.0 || config.success_rate > 1.0 {
            return Err(Error::InvalidSuccessRate(config.success_rate));
        }
        self.links
            .entry(sender)
            .or_default()
            .insert(receiver, config);
        Ok(())
    }

    /// Run the simulated network.
    pub async fn run(mut self) {
        // Process messages
        while let Some((channel, origin, recipients, message, reply)) = self.receiver.next().await {
            // Collect recipients
            let recipients = match recipients {
                Recipients::All => self.agents.keys().cloned().collect(),
                Recipients::Some(keys) => keys,
                Recipients::One(key) => vec![key],
            };

            // Send to all recipients
            let mut sent = Vec::new();
            let (acquired_sender, mut acquired_receiver) = mpsc::channel(recipients.len());
            for recipient in recipients {
                // Skip self
                if recipient == origin {
                    debug!(
                        recipient = hex(&recipient),
                        reason = "self",
                        "dropping message",
                    );
                    continue;
                }

                // Determine if recipient exists
                let sender = match self.agents.get(&recipient) {
                    Some(sender) => sender,
                    None => {
                        debug!(
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
                        debug!(
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
                let should_deliver = self.runtime.gen_bool(link.success_rate);
                let delay = Normal::new(link.latency_mean, link.latency_stddev)
                    .unwrap()
                    .sample(&mut self.runtime);
                debug!(
                    origin = hex(&origin),
                    recipient = hex(&recipient),
                    ?delay,
                    "sending message",
                );

                // Send message
                self.runtime.spawn("messenger", {
                    let runtime = self.runtime.clone();
                    let mut sender = sender.clone();
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
                            debug!(
                                recipient = hex(&recipient),
                                reason = "random link failure",
                                "dropping message",
                            );
                            return;
                        }

                        // Drop message if not listening on channel
                        let (max_size, sender) = match sender.get_mut(&channel) {
                            Some(sender) => sender,
                            None => {
                                debug!(
                                    recipient = hex(&recipient),
                                    channel,
                                    reason = "missing channel",
                                    "dropping message",
                                );
                                return;
                            }
                        };

                        // Drop message if too large
                        if message.len() > *max_size {
                            debug!(
                                recipient = hex(&recipient),
                                channel,
                                size = message.len(),
                                max_size = *max_size,
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
    }
}

/// Implementation of a [`crate::Sender`] for the simulated network.
#[derive(Clone)]
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
        channel: u32,
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
pub struct Receiver {
    receiver: mpsc::UnboundedReceiver<Message>,
}

impl crate::Receiver for Receiver {
    type Error = Error;

    async fn recv(&mut self) -> Result<Message, Error> {
        self.receiver.next().await.ok_or(Error::NetworkClosed)
    }
}
