pub mod discovery;
pub mod lookup;
use futures::{channel::mpsc, SinkExt as _};
use thiserror::Error;

// TODO danlaine: remove this and just use sender directly
/// A mailbox for sending messages to an actor.
#[derive(Debug)]
pub struct Mailbox<T>(mpsc::Sender<T>);

impl<T> Mailbox<T> {
    fn new(sender: mpsc::Sender<T>) -> Self {
        Self(sender)
    }

    /// Returns a new mailbox and a receiver for testing purposes.
    /// The capacity of the channel is 1.
    #[cfg(test)]
    pub fn test() -> (Self, mpsc::Receiver<T>) {
        let (sender, receiver) = mpsc::channel(1);
        (Self(sender), receiver)
    }
}

impl<T> Clone for Mailbox<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Clone)]
pub struct Relay<T> {
    low: mpsc::Sender<T>,
    high: mpsc::Sender<T>,
}

impl<T> Relay<T> {
    pub fn new(low: mpsc::Sender<T>, high: mpsc::Sender<T>) -> Self {
        Self { low, high }
    }

    /// content sends a message to the receiver.
    ///
    /// We return a Result here instead of unwrapping the send
    /// because the receiver may have disconnected in the normal course of
    /// business.
    pub async fn content(&mut self, msg: T, priority: bool) -> Result<(), Error> {
        let sender = if priority {
            &mut self.high
        } else {
            &mut self.low
        };
        sender.send(msg).await.map_err(|_| Error::MessageDropped)
    }
}

// TODO danlaine: where should this live?
#[derive(Error, Debug)]
pub enum Error {
    #[error("message dropped")]
    MessageDropped,
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
            let data = "high priority message".to_string();
            relay.content(data.clone(), true).await.unwrap();
            match high_receiver.try_next() {
                Ok(Some(received_data)) => {
                    assert_eq!(data, received_data);
                }
                _ => panic!("Expected high priority message"),
            }
            assert!(low_receiver.try_next().is_err());

            // Send a low priority message
            let data = "low priority message".to_string();
            relay.content(data.clone(), false).await.unwrap();
            match low_receiver.try_next() {
                Ok(Some(received_data)) => {
                    assert_eq!(data, received_data);
                }
                _ => panic!("Expected low priority message"),
            }
            assert!(high_receiver.try_next().is_err());
        });
    }
}
