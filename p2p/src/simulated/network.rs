//! Implementation of a `simulated` network.

use super::Error;
use crate::{Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey};
use commonware_runtime::{select, Clock, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};
use tracing::{debug, error};

type Task = (
    PublicKey,
    Recipients,
    Bytes,
    oneshot::Sender<Result<Vec<PublicKey>, Error>>,
);

/// Implementation of a `simulated` network.
pub struct Network<E: Spawner + Rng + Clock> {
    runtime: E,
    cfg: Config,

    sender: mpsc::UnboundedSender<Task>,
    receiver: mpsc::UnboundedReceiver<Task>,
    links: HashMap<PublicKey, HashMap<PublicKey, Link>>,
    agents: BTreeMap<PublicKey, mpsc::UnboundedSender<Message>>,
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
    /// Maximum size of a message in bytes.
    pub max_message_size: usize,
}

impl<E: Spawner + Rng + Clock> Network<E> {
    /// Create a new simulated network with a given runtime and configuration.
    pub fn new(runtime: E, cfg: Config) -> Self {
        let (sender, receiver) = mpsc::unbounded();
        Self {
            runtime,
            cfg,
            sender,
            receiver,
            links: HashMap::new(),
            agents: BTreeMap::new(),
        }
    }

    /// Register a new peer with the network.
    ///
    /// By default, the peer will not be linked to any other peers.
    pub fn register(&mut self, public_key: PublicKey) -> (Sender, Receiver) {
        let (sender, receiver) = mpsc::unbounded();
        self.agents.insert(public_key.clone(), sender);
        (
            Sender::new(self.runtime.clone(), public_key, self.sender.clone()),
            Receiver { receiver },
        )
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
        while let Some((origin, recipients, message, reply)) = self.receiver.next().await {
            // Ensure message is valid
            if message.len() > self.cfg.max_message_size {
                if let Err(err) = reply.send(Err(Error::MessageTooLarge(message.len()))) {
                    // This can only happen if the sender exited.
                    error!("failed to send error: {:?}", err);
                }
                continue;
            }

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
                    debug!("dropping message to {}: self", hex(&recipient));
                    continue;
                }

                // Determine if recipient exists
                let sender = match self.agents.get(&recipient) {
                    Some(sender) => sender,
                    None => {
                        debug!("dropping message to {}: no agent", hex(&recipient));
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
                        debug!("dropping message to {}: no link", hex(&recipient));
                        continue;
                    }
                };

                // Apply link settings
                let should_deliver = self.runtime.gen_bool(link.success_rate);
                let delay = Normal::new(link.latency_mean, link.latency_stddev)
                    .unwrap()
                    .sample(&mut self.runtime);
                debug!("sending message to {}: delay={}ms", hex(&recipient), delay);

                // Send message
                self.runtime.spawn({
                    let runtime = self.runtime.clone();
                    let mut sender = sender.clone();
                    let recipient = recipient.clone();
                    let message = message.clone();
                    let mut acquired_sender = acquired_sender.clone();
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
                                "dropping message to {}: random link failure",
                                hex(&recipient)
                            );
                            return;
                        }

                        // Send message
                        if let Err(err) = sender.send((recipient.clone(), message)).await {
                            // This can only happen if the receiver exited.
                            error!("failed to send to {}: {:?}", hex(&recipient), err);
                        }
                    }
                });
                sent.push(recipient);
            }

            // Notify sender of successful sends
            self.runtime.spawn(async move {
                // Wait for semaphore to be acquired on all sends
                for _ in 0..sent.len() {
                    acquired_receiver.next().await.unwrap();
                }

                // Notify sender of successful sends
                if let Err(err) = reply.send(Ok(sent)) {
                    // This can only happen if the sender exited.
                    error!("failed to send ack: {:?}", err);
                }
            });
        }
    }
}

/// Implementation of a [`crate::Sender`] for the simulated network.
#[derive(Clone)]
pub struct Sender {
    me: PublicKey,
    high: mpsc::UnboundedSender<Task>,
    low: mpsc::UnboundedSender<Task>,
}

impl Sender {
    fn new(runtime: impl Spawner, me: PublicKey, mut sender: mpsc::UnboundedSender<Task>) -> Self {
        // Listen for messages
        let (high, mut high_receiver) = mpsc::unbounded();
        let (low, mut low_receiver) = mpsc::unbounded();
        runtime.spawn(async move {
            loop {
                select! {
                    high_task = high_receiver.next() => {
                        if let Err(err) = sender.send(high_task.unwrap()).await{
                            error!("failed to send high priority task: {:?}", err);
                        }
                    },
                    low_task = low_receiver.next() => {
                        if let Err(err) = sender.send(low_task.unwrap()).await{
                            error!("failed to send low priority task: {:?}", err);
                        }
                    }
                }
            }
        });

        // Return sender
        Self { me, high, low }
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
        let (sender, receiver) = oneshot::channel();
        let mut channel = if priority { &self.high } else { &self.low };
        channel
            .send((self.me.clone(), recipients, message, sender))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)?
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
