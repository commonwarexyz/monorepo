use super::Error;
use crate::authenticated::wire;
use bytes::Bytes;
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    BitVec { bit_vec: wire::BitVec },
    Peers { peers: wire::Peers },
    Kill,
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    #[cfg(test)]
    pub fn test() -> (Self, mpsc::Receiver<Message>) {
        let (sender, receiver) = mpsc::channel(1);
        (Self { sender }, receiver)
    }

    pub async fn bit_vec(&mut self, bit_vec: wire::BitVec) {
        let _ = self.sender.send(Message::BitVec { bit_vec }).await;
    }

    pub async fn peers(&mut self, peers: wire::Peers) {
        let _ = self.sender.send(Message::Peers { peers }).await;
    }

    pub async fn kill(&mut self) {
        let _ = self.sender.send(Message::Kill).await;
    }
}

pub struct Data {
    pub channel: u32,
    pub message: Bytes,
}

#[derive(Clone)]
pub struct Relay {
    low: mpsc::Sender<Data>,
    high: mpsc::Sender<Data>,
}

impl Relay {
    pub fn new(low: mpsc::Sender<Data>, high: mpsc::Sender<Data>) -> Self {
        Self { low, high }
    }

    /// content sends a message to the peer.
    ///
    /// We return a Result here instead of unwrapping the send
    /// because the peer may have disconnected in the normal course of
    /// business.
    pub async fn content(
        &mut self,
        channel: u32,
        message: Bytes,
        priority: bool,
    ) -> Result<(), Error> {
        if priority {
            return self
                .high
                .send(Data { channel, message })
                .await
                .map_err(|_| Error::MessageDropped);
        }
        self.low
            .send(Data { channel, message })
            .await
            .map_err(|_| Error::MessageDropped)
    }
}
