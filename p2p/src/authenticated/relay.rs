use commonware_actor::{
    mailbox::{self, UnreliablePolicy},
    Feedback, Unreliable,
};
use commonware_macros::select;
use commonware_runtime::Metrics;
use std::{collections::VecDeque, num::NonZeroUsize};

pub(crate) struct Message<T>(T);

impl<T> Message<T> {
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}

impl<T> UnreliablePolicy for Message<T> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

pub(crate) struct Receivers<T> {
    pub(crate) low: mailbox::UnreliableReceiver<Message<T>>,
    pub(crate) high: mailbox::UnreliableReceiver<Message<T>>,
}

#[derive(Clone, Debug)]
pub struct Relay<T> {
    low: mailbox::UnreliableSender<Message<T>>,
    high: mailbox::UnreliableSender<Message<T>>,
}

impl<T> Relay<T> {
    /// Creates a prioritized relay backed by bounded low and high priority mailboxes.
    pub fn new(metrics: impl Metrics, size: NonZeroUsize) -> (Self, Receivers<T>) {
        let (low_sender, low_receiver) = mailbox::new_unreliable(metrics.child("low"), size);
        let (high_sender, high_receiver) = mailbox::new_unreliable(metrics.child("high"), size);
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

    /// Submits `message` to the priority channel selected by `priority`.
    ///
    /// This never waits for capacity. [`Unreliable::Rejected`] means the selected channel was full
    /// and did not handle the message, and [`Feedback::Closed`] means the receiver is gone.
    pub fn send(&self, message: T, priority: bool) -> Unreliable<Feedback> {
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
pub async fn recv_prioritized<C: UnreliablePolicy, D>(
    control: &mut mailbox::UnreliableReceiver<C>,
    high: &mut mailbox::UnreliableReceiver<Message<D>>,
    low: &mut mailbox::UnreliableReceiver<Message<D>>,
) -> Prioritized<C, D> {
    select! {
        msg = control.recv() => msg.map_or(Prioritized::Closed, Prioritized::Control),
        msg = high.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(
            msg.into_inner()
        )),
        msg = low.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(
            msg.into_inner()
        )),
    }
}

/// Attempts to receive one data message from a relay receiver.
pub(crate) fn try_recv<T>(receiver: &mut mailbox::UnreliableReceiver<Message<T>>) -> Option<T> {
    receiver.try_recv().ok().map(Message::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::mocks::Metrics;
    use commonware_utils::NZUsize;

    #[test]
    fn test_relay_content_priority() {
        let (relay, mut receivers) = Relay::new(Metrics, NZUsize!(1));

        let data = 123;
        assert_eq!(relay.send(data, true), Unreliable::new(Feedback::Ok));
        match receivers.high.try_recv().map(Message::into_inner) {
            Ok(received_data) => {
                assert_eq!(data, received_data);
            }
            _ => panic!("Expected high priority message"),
        }
        assert!(receivers.low.try_recv().is_err());

        let data = 456;
        assert_eq!(relay.send(data, false), Unreliable::new(Feedback::Ok));
        match receivers.low.try_recv().map(Message::into_inner) {
            Ok(received_data) => {
                assert_eq!(data, received_data);
            }
            _ => panic!("Expected low priority message"),
        }
        assert!(receivers.high.try_recv().is_err());
    }

    #[test]
    fn test_relay_rejects_on_overflow() {
        let (relay, mut receivers) = Relay::new(Metrics, NZUsize!(1));

        assert_eq!(relay.send(1, false), Unreliable::new(Feedback::Ok));
        assert_eq!(relay.send(2, false), Unreliable::Rejected);
        assert_eq!(receivers.low.try_recv().map(Message::into_inner), Ok(1));
        assert!(receivers.low.try_recv().is_err());
    }
}
