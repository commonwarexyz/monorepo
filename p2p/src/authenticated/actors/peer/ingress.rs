use super::Error;
use crate::{authenticated::types, Channel};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use futures::{channel::mpsc, SinkExt};

/// Messages that can be sent to the peer [`Actor`](`super::Actor`).
#[derive(Clone, Debug)]
pub enum Message<C: PublicKey> {
    /// Send a bit vector to the peer.
    BitVec(types::BitVec),

    /// Send a list of [`types::PeerInfo`] to the peer.
    Peers(Vec<types::PeerInfo<C>>),

    /// Kill the peer actor.
    Kill,
}

#[derive(Clone)]
pub struct Relay {
    low: mpsc::Sender<types::Data>,
    high: mpsc::Sender<types::Data>,
}

impl Relay {
    pub fn new(low: mpsc::Sender<types::Data>, high: mpsc::Sender<types::Data>) -> Self {
        Self { low, high }
    }

    /// content sends a message to the peer.
    ///
    /// We return a Result here instead of unwrapping the send
    /// because the peer may have disconnected in the normal course of
    /// business.
    pub async fn content(
        &mut self,
        channel: Channel,
        message: Bytes,
        priority: bool,
    ) -> Result<(), Error> {
        let sender = if priority {
            &mut self.high
        } else {
            &mut self.low
        };
        sender
            .send(types::Data { channel, message })
            .await
            .map_err(|_| Error::MessageDropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner};

    #[test]
    fn test_relay_content_priority() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (low_sender, mut low_receiver) = mpsc::channel(1);
            let (high_sender, mut high_receiver) = mpsc::channel(1);
            let mut relay = Relay::new(low_sender, high_sender);

            // Send a high priority message
            let data = types::Data {
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
            let data = types::Data {
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
