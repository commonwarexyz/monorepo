use futures::{channel::mpsc, SinkExt};

/// Messages that can be sent to the peer [`Actor`](`super::Actor`).
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
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

    pub async fn kill(&mut self) {
        let _ = self.sender.send(Message::Kill).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::{data::Data, relay::Relay};
    use bytes::Bytes;
    use commonware_runtime::{deterministic, Runner};

    #[test]
    fn test_relay_content_priority() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (low_sender, mut low_receiver) = mpsc::channel(1);
            let (high_sender, mut high_receiver) = mpsc::channel(1);
            let mut relay = Relay::new(low_sender, high_sender);

            // Send a high priority message
            let data = Data {
                channel: 1,
                message: Bytes::from("test high prio message"),
            };
            relay
                .send(
                    Data {
                        channel: data.channel,
                        message: data.message.clone(),
                    },
                    true,
                )
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
                .send(
                    Data {
                        channel: data.channel,
                        message: data.message.clone(),
                    },
                    false,
                )
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
