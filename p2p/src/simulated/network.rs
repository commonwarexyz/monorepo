use super::Error;
use crate::{Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

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
            .or_insert_with(HashMap::new)
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
        while let Some((recipients, message, reply)) = self.receiver.recv().await {
            // Ensure message is valid
            if message.len() > self.cfg.max_size {
                let _ = reply.send(Err(Error::MessageTooLarge(message.len())));
                continue;
            }

            // Collect recipients
            let recipients = match recipients {
                Recipients::All => self.agents.keys().cloned().collect(),
                Recipients::Some(keys) => keys,
                Recipients::One(key) => vec![key],
            };

            // Send to all recipients
            let mut sent_to = Vec::new();
            for recipient in recipients {
                if let Some(sender) = self.agents.get(&recipient) {
                    if let Err(_) = sender.send((recipient.clone(), message.clone())).await {
                        continue;
                    }
                    sent_to.push(recipient);
                }
            }

            // Notify sender of successful sends
            let _ = reply.send(sent_to);
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
        priority: bool,
    ) -> Result<Vec<PublicKey>, Error> {
    }
}

pub struct Receiver {
    receiver: mpsc::Receiver<Message>,
}

impl crate::Receiver for Receiver {
    type Error = Error;

    async fn recv(&mut self) -> Result<Message, Error> {}
}
