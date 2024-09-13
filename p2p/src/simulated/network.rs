use super::Error;
use crate::{Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::{utils::hex, PublicKey};
use rand::RngCore;
use rand_distr::{Distribution, Normal};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tracing::error;

type Task = (
    Recipients,
    Bytes,
    oneshot::Sender<Result<Vec<PublicKey>, Error>>,
);

pub struct Network {
    cfg: Config,

    sender: mpsc::Sender<Task>,
    receiver: mpsc::Receiver<Task>,
    links: HashMap<PublicKey, HashMap<PublicKey, Link>>,
    agents: HashMap<PublicKey, mpsc::Sender<Message>>,
}

pub struct Link {
    pub latency_mean: Duration,
    pub latency_stddev: Duration,

    /// Blocks after this amount (and priority will jump the queue).
    pub outstanding: usize,
}

pub struct Config {
    pub max_size: usize,
}

impl Network {
    pub fn new(cfg: Config) -> Self {
        let (sender, receiver) = mpsc::channel(1024);
        Self {
            cfg,
            sender,
            receiver,
            links: HashMap::new(),
            agents: HashMap::new(),
        }
    }

    /// Link can be called multiple times for the same sender/receiver. The latest
    /// setting will be used.
    pub fn link(&mut self, sender: PublicKey, receiver: PublicKey, config: Link) {
        self.links
            .entry(sender)
            .or_default()
            .insert(receiver, config);
    }

    pub fn register(&mut self, public_key: PublicKey) -> (Sender, Receiver) {
        let (sender, receiver) = mpsc::channel(1024);
        self.agents.insert(public_key, sender);
        (
            Sender {
                sender: self.sender.clone(),
            },
            Receiver { receiver },
        )
    }

    pub async fn run(mut self) {
        // Initialize RNG
        //
        // TODO: make message sending determinisitic using a single seed (look at video from research notes)
        let mut rng = rand::thread_rng();

        // Process messages
        while let Some((recipients, message, reply)) = self.receiver.recv().await {
            // Ensure message is valid
            if message.len() > self.cfg.max_size {
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
            for recipient in recipients {
                // Determine if there is a link between the sender and recipient
                let link = match self
                    .links
                    .get(&recipient)
                    .and_then(|links| links.get(&recipient))
                {
                    Some(link) => link,
                    None => {
                        continue;
                    }
                };

                // TODO: Apply link settings
                let delay = Normal::new(
                    link.latency_mean.as_millis() as f64,
                    link.latency_stddev.as_millis() as f64,
                )
                .unwrap()
                .sample(rng);

                // Send message
                if let Some(sender) = self.agents.get(&recipient) {
                    // TODO: add message delay/corruption/backlog/priority/etc
                    if let Err(err) = sender.send((recipient.clone(), message.clone())).await {
                        // This can only happen if the receiver exited.
                        error!("failed to send to {}: {:?}", hex(&recipient), err);
                        continue;
                    }
                    sent.push(recipient);
                }
            }

            // Notify sender of successful sends
            if let Err(err) = reply.send(Ok(sent)) {
                // This can only happen if the sender exited.
                error!("failed to send ack: {:?}", err);
            }
        }
    }
}

#[derive(Clone)]
pub struct Sender {
    sender: mpsc::Sender<Task>,
}

impl crate::Sender for Sender {
    type Error = Error;

    async fn send(
        &self,
        recipients: Recipients,
        message: Bytes,
        _: bool, // TODO: re-add support for priority
    ) -> Result<Vec<PublicKey>, Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send((recipients, message, sender))
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)?
    }
}

pub struct Receiver {
    receiver: mpsc::Receiver<Message>,
}

impl crate::Receiver for Receiver {
    type Error = Error;

    async fn recv(&mut self) -> Result<Message, Error> {
        self.receiver.recv().await.ok_or(Error::NetworkClosed)
    }
}
