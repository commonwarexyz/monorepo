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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic::Executor, Runner};
    use prometheus_client::registry::Registry;
    use std::{sync::{Arc, Mutex}, time::Duration};

    #[test]
    fn test_relay_content_priority() {
        let (executor, _, _) = Executor::init(0, Duration::from_millis(1),  Arc::new(Mutex::new(Registry::default())));
        executor.start(async move {
            let (low_sender, mut low_receiver) = mpsc::channel(1);
            let (high_sender, mut high_receiver) = mpsc::channel(1);
            let mut relay = Relay::new(low_sender, high_sender);

            // Send a high priority message
            let data = Data {
                channel: 1,
                message: Bytes::from("test high prio message"),
            };
            relay
                .content(data.channel, data.message.clone(), true)
                .await
                .unwrap();
            match high_receiver.try_next() {
                Ok(Some(received_data)) => {
                    assert_eq!(data.channel, received_data.channel);
                    assert_eq!(data.message, received_data.message);
                }
                _ => panic!("Expected high priority message"),
            }
            assert!(low_receiver.try_next().is_err());

            // Send a low priority message
            let data = Data {
                channel: 1,
                message: Bytes::from("test low prio message"),
            };
            relay
                .content(data.channel, data.message.clone(), false)
                .await
                .unwrap();
            match low_receiver.try_next() {
                Ok(Some(received_data)) => {
                    assert_eq!(data.channel, received_data.channel);
                    assert_eq!(data.message, received_data.message);
                }
                _ => panic!("Expected high priority message"),
            }
            assert!(high_receiver.try_next().is_err());
        });
    }
}
