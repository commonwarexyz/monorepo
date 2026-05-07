use commonware_macros::select;
use commonware_utils::channel::{
    actor::{ActorInbox, MessagePolicy},
    mpsc::{self, error::TrySendError},
};

#[derive(Clone, Debug)]
pub struct Relay<T> {
    low: mpsc::Sender<T>,
    high: mpsc::Sender<T>,
}

impl<T> Relay<T> {
    pub const fn new(low: mpsc::Sender<T>, high: mpsc::Sender<T>) -> Self {
        Self { low, high }
    }

    /// Sends the given `message` to the appropriate channel based on `priority`.
    ///
    /// Uses non-blocking `try_send` to avoid blocking the caller when the
    /// channel buffer is full. Returns an error if the channel is full or
    /// disconnected.
    pub fn send(&self, message: T, priority: bool) -> Result<(), TrySendError<T>> {
        let sender = if priority { &self.high } else { &self.low };
        sender.try_send(message)
    }
}

/// Message received from one of the prioritized relay channels.
pub enum Prioritized<C, D> {
    /// Control message received from the control channel.
    Control(C),
    /// Data message received from either the high- or low-priority data channel.
    Data(D),
    /// One of the relay channels closed before yielding a message.
    Closed,
}

/// Awaits a message from an actor control inbox, high, or low priority receivers.
pub async fn recv_actor_prioritized<C: MessagePolicy, D>(
    control: &mut ActorInbox<C>,
    high: &mut mpsc::Receiver<D>,
    low: &mut mpsc::Receiver<D>,
) -> Prioritized<C, D> {
    select! {
        msg = control.recv() => msg.map_or(Prioritized::Closed, Prioritized::Control),
        msg = high.recv() => msg.map_or(Prioritized::Closed, Prioritized::Data),
        msg = low.recv() => msg.map_or(Prioritized::Closed, Prioritized::Data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_content_priority() {
        let (low_sender, mut low_receiver) = mpsc::channel(1);
        let (high_sender, mut high_receiver) = mpsc::channel(1);
        let relay = Relay::new(low_sender, high_sender);

        // Send a high priority message
        let data = 123;
        relay.send(data, true).unwrap();
        match high_receiver.try_recv() {
            Ok(received_data) => {
                assert_eq!(data, received_data);
            }
            _ => panic!("Expected high priority message"),
        }
        assert!(low_receiver.try_recv().is_err());

        // Send a low priority message
        let data = 456;
        relay.send(data, false).unwrap();
        match low_receiver.try_recv() {
            Ok(received_data) => {
                assert_eq!(data, received_data);
            }
            _ => panic!("Expected low priority message"),
        }
        assert!(high_receiver.try_recv().is_err());
    }
}
