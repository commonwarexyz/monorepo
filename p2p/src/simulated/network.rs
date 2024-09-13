use super::Error;
use crate::Recipients;
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

type Message = (Recipients, Bytes);

pub struct Network {
    sender: mpsc::Sender<Message>,
    receiver: mpsc::Receiver<Message>,
    links: HashMap<PublicKey, HashMap<PublicKey, Link>>,
    agents: HashMap<PublicKey, mpsc::Sender<Message>>,
}

pub struct Link {
    pub latency: Duration,
}

impl Network {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1024);
        Self {
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

    pub fn run(self) {}
}

#[derive(Clone)]
pub struct Sender {
    sender: mpsc::Sender<Message>,
}

impl crate::Sender for Sender {
    type Error = Error;

    async fn send(
        &self,
        recipients: crate::Recipients,
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

    async fn recv(&mut self) -> Result<crate::Message, Error> {}
}
