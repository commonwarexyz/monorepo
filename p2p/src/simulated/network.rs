use super::Error;
use crate::{Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey};
use commonware_executor::{Clock, Executor};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{self, Duration},
};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tracing::{debug, error};

type Task = (
    PublicKey,
    Recipients,
    Bytes,
    oneshot::Sender<Result<Vec<PublicKey>, Error>>,
);

pub struct Network<E: Executor + Rng + Clock> {
    executor: E,
    cfg: Config,

    sender: mpsc::UnboundedSender<Task>,
    receiver: mpsc::UnboundedReceiver<Task>,
    links: HashMap<PublicKey, HashMap<PublicKey, (Link, Arc<Semaphore>)>>,
    agents: HashMap<PublicKey, mpsc::UnboundedSender<Message>>,
}

/// Describes a connection between two peers.
///
/// Links are unidirectional and must be set up in both directions for a bidirectional connection.
pub struct Link {
    /// Mean latency for the delivery of a message in milliseconds.
    pub latency_mean: f64,

    /// Standard deviation of the latency for the delivery of a message in milliseconds.
    pub latency_stddev: f64,

    /// Probability of a message being delivered successfully (in range [0,1]).
    pub success_rate: f64,

    /// Maximum number of messages that can be in-flight at once before blocking.
    pub capacity: usize,
}

/// Configuration for a simulated network.
pub struct Config {
    /// Maximum size of a message in bytes.
    pub max_message_size: usize,
}

impl<E: Executor + Rng + Clock + Send> Network<E> {
    /// Create a new simulated network.
    pub fn new(executor: E, cfg: Config) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            executor,
            cfg,
            sender,
            receiver,
            links: HashMap::new(),
            agents: HashMap::new(),
        }
    }

    /// Register a new peer with the network.
    ///
    /// By default, the peer will not be linked to any other peers.
    pub fn register(&mut self, public_key: PublicKey) -> (Sender, Receiver) {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.agents.insert(public_key.clone(), sender);
        (
            Sender::new(self.executor.clone(), public_key, self.sender.clone()),
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
        let capacity = Arc::new(Semaphore::new(config.capacity));
        self.links
            .entry(sender)
            .or_default()
            .insert(receiver, (config, capacity));
        Ok(())
    }

    /// Run the simulated network.
    pub async fn run(mut self) {
        // Process messages
        while let Some((origin, recipients, message, reply)) = self.receiver.recv().await {
            // Ensure message is valid
            if message.len() > self.cfg.max_message_size {
                if let Err(err) = reply.send(Err(Error::MessageTooLarge(message.len()))) {
                    // This can only happen if the sender exited.
                    error!("failed to send error: {:?}", err);
                }
                continue;
            }

            // Collect recipients
            let mut recipients = match recipients {
                Recipients::All => self.agents.keys().cloned().collect(),
                Recipients::Some(keys) => keys,
                Recipients::One(key) => vec![key],
            };

            // Sort recipients to ensure same seed yields same latency/drop assignments
            recipients.sort();

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
                let should_deliver = self.executor.gen_bool(link.0.success_rate);
                let delay = Normal::new(link.0.latency_mean, link.0.latency_stddev)
                    .unwrap()
                    .sample(&mut self.executor);
                debug!("sending message to {}: delay={}ms", hex(&recipient), delay);

                // Send message
                self.executor.spawn({
                    let executor = self.executor.clone();
                    let sender = sender.clone();
                    let recipient = recipient.clone();
                    let message = message.clone();
                    let semaphore = link.1.clone();
                    let acquired_sender = acquired_sender.clone();
                    async move {
                        // Mark as sent as soon as acquire semaphore
                        let _permit = semaphore.acquire().await.unwrap();
                        acquired_sender.send(()).await.unwrap();

                        // Apply delay to send (once link is not saturated)
                        //
                        // Note: messages can be sent out of order (will not occur when using a
                        // stable TCP connection)
                        executor.sleep(Duration::from_millis(delay as u64)).await;

                        // Drop message if success rate is too low
                        if !should_deliver {
                            debug!(
                                "dropping message to {}: random link failure",
                                hex(&recipient)
                            );
                            return;
                        }

                        // Send message
                        if let Err(err) = sender.send((recipient.clone(), message)) {
                            // This can only happen if the receiver exited.
                            error!("failed to send to {}: {:?}", hex(&recipient), err);
                        }
                    }
                });
                sent.push(recipient);
            }

            // Notify sender of successful sends
            self.executor.spawn(async move {
                // Wait for semaphore to be acquired on all sends
                for _ in 0..sent.len() {
                    acquired_receiver.recv().await.unwrap();
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

#[derive(Clone)]
pub struct Sender {
    me: PublicKey,
    high: mpsc::UnboundedSender<Task>,
    low: mpsc::UnboundedSender<Task>,
}

impl Sender {
    fn new(executor: impl Executor, me: PublicKey, sender: mpsc::UnboundedSender<Task>) -> Self {
        // Listen for messages
        let (high, mut high_receiver) = mpsc::unbounded_channel();
        let (low, mut low_receiver) = mpsc::unbounded_channel();
        executor.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    task = high_receiver.recv() => {
                        if let Err(err) = sender.send(task.unwrap()) {
                            error!("failed to send high priority task: {:?}", err);
                        }
                    }
                    task = low_receiver.recv() => {
                        if let Err(err) = sender.send(task.unwrap()) {
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
        &self,
        recipients: Recipients,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<PublicKey>, Error> {
        let (sender, receiver) = oneshot::channel();
        let channel = if priority { &self.high } else { &self.low };
        channel
            .send((self.me.clone(), recipients, message, sender))
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)?
    }
}

pub struct Receiver {
    receiver: mpsc::UnboundedReceiver<Message>,
}

impl crate::Receiver for Receiver {
    type Error = Error;

    async fn recv(&mut self) -> Result<Message, Error> {
        self.receiver.recv().await.ok_or(Error::NetworkClosed)
    }
}
