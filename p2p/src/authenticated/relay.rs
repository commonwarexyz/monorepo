use futures::{channel::mpsc, SinkExt as _};

#[derive(Clone, Debug)]
pub struct Relay<T> {
    low: mpsc::Sender<T>,
    high: mpsc::Sender<T>,
}

impl<T> Relay<T> {
    pub fn new(low: mpsc::Sender<T>, high: mpsc::Sender<T>) -> Self {
        Self { low, high }
    }

    /// Sends the given `message` to the appropriate channel based on `priority`.
    pub async fn send(&mut self, message: T, priority: bool) -> Result<(), mpsc::SendError> {
        let sender = if priority {
            &mut self.high
        } else {
            &mut self.low
        };
        sender.send(message).await
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
            let data = 123;
            relay.send(data, true).await.unwrap();
            match high_receiver.try_next() {
                Ok(Some(received_data)) => {
                    assert_eq!(data, received_data);
                }
                _ => panic!("Expected high priority message"),
            }
            assert!(low_receiver.try_next().is_err());

            // Send a low priority message
            let data = 456;
            relay.send(data, false).await.unwrap();
            match low_receiver.try_next() {
                Ok(Some(received_data)) => {
                    assert_eq!(data, received_data);
                }
                _ => panic!("Expected high priority message"),
            }
            assert!(high_receiver.try_next().is_err());
        });
    }
}
