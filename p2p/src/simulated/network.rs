use super::Error;
use commonware_cryptography::PublicKey;
use std::time::Duration;

pub struct Network {}

pub struct Link {
    pub latency: Duration,
}

impl Network {
    pub fn new() -> Self {
        Self {}
    }

    pub fn set(&mut self, sender: PublicKey, receiver: PublicKey, config: Link) {}

    pub fn register(&mut self, public_key: PublicKey) -> (Sender, Receiver) {}
}

#[derive(Clone)]
pub struct Sender {}

impl crate::Sender for Sender {
    type Error = Error;

    async fn send(
        &self,
        recipients: crate::Recipients,
        message: bytes::Bytes,
        priority: bool,
    ) -> Result<Vec<PublicKey>, Error> {
    }
}

pub struct Receiver {}

impl crate::Receiver for Receiver {
    type Error = Error;

    async fn recv(&mut self) -> Result<crate::Message, Error> {}
}
