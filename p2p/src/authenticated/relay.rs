use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_macros::select;
use std::{collections::VecDeque, num::NonZeroUsize};

pub(crate) struct Message<T>(pub(crate) T);

impl<T> Policy for Message<T> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) {}
}

pub(crate) struct Receivers<T> {
    pub(crate) low: mailbox::Receiver<Message<T>>,
    pub(crate) high: mailbox::Receiver<Message<T>>,
}

#[derive(Clone, Debug)]
pub struct Relay<T> {
    low: mailbox::Sender<Message<T>>,
    high: mailbox::Sender<Message<T>>,
}

impl<T> Relay<T> {
    pub fn new(size: NonZeroUsize) -> (Self, Receivers<T>) {
        let (low_sender, low_receiver) = mailbox::new(size);
        let (high_sender, high_receiver) = mailbox::new(size);
        (
            Self {
                low: low_sender,
                high: high_sender,
            },
            Receivers {
                low: low_receiver,
                high: high_receiver,
            },
        )
    }

    pub fn send(&self, message: T, priority: bool) -> Feedback {
        let sender = if priority { &self.high } else { &self.low };
        sender.enqueue(Message(message))
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

/// Awaits a message from control, high, or low priority receivers.
pub async fn recv_prioritized<C: Policy, D>(
    control: &mut mailbox::Receiver<C>,
    high: &mut mailbox::Receiver<Message<D>>,
    low: &mut mailbox::Receiver<Message<D>>,
) -> Prioritized<C, D> {
    select! {
        msg = control.recv() => msg.map_or(Prioritized::Closed, Prioritized::Control),
        msg = high.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(msg.0)),
        msg = low.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(msg.0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZUsize;

    #[test]
    fn test_relay_content_priority() {
        let (relay, mut receivers) = Relay::new(NZUsize!(1));

        let data = 123;
        assert_eq!(relay.send(data, true), Feedback::Ok);
        match receivers.high.try_recv().map(|msg| msg.0) {
            Ok(received_data) => {
                assert_eq!(data, received_data);
            }
            _ => panic!("Expected high priority message"),
        }
        assert!(receivers.low.try_recv().is_err());

        let data = 456;
        assert_eq!(relay.send(data, false), Feedback::Ok);
        match receivers.low.try_recv().map(|msg| msg.0) {
            Ok(received_data) => {
                assert_eq!(data, received_data);
            }
            _ => panic!("Expected low priority message"),
        }
        assert!(receivers.high.try_recv().is_err());
    }

    #[test]
    fn test_relay_drops_on_overflow() {
        let (relay, mut receivers) = Relay::new(NZUsize!(1));

        assert_eq!(relay.send(1, false), Feedback::Ok);
        assert_eq!(relay.send(2, false), Feedback::Backoff);
        assert_eq!(receivers.low.try_recv().map(|msg| msg.0), Ok(1));
        assert!(receivers.low.try_recv().is_err());
    }
}
