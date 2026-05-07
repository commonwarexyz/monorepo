use commonware_macros::select;
use commonware_utils::channel::{
    actor::{ActorInbox, ActorMailbox, Enqueue, MessagePolicy},
};

#[derive(Clone, Debug)]
pub struct Relay<T: MessagePolicy> {
    low: ActorMailbox<T>,
    high: ActorMailbox<T>,
}

impl<T: MessagePolicy> Relay<T> {
    pub const fn new(low: ActorMailbox<T>, high: ActorMailbox<T>) -> Self {
        Self { low, high }
    }

    /// Sends the given `message` to the appropriate channel based on `priority`.
    pub fn send(&self, message: T, priority: bool) -> Enqueue<T> {
        let sender = if priority { &self.high } else { &self.low };
        sender.enqueue(message)
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
pub async fn recv_actor_prioritized<C: MessagePolicy, D: MessagePolicy>(
    control: &mut ActorInbox<C>,
    high: &mut ActorInbox<D>,
    low: &mut ActorInbox<D>,
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
    use commonware_utils::channel::actor::{self, Backpressure};
    use std::collections::VecDeque;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Data(u32);

    impl MessagePolicy for Data {
        fn backpressure(_queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
            Backpressure::Skip(message)
        }
    }

    #[test]
    fn test_relay_content_priority() {
        let (low_sender, mut low_receiver) = actor::channel(1);
        let (high_sender, mut high_receiver) = actor::channel(1);
        let relay = Relay::new(low_sender, high_sender);

        // Send a high priority message
        let data = Data(123);
        assert!(relay.send(data.clone(), true).accepted());
        assert_eq!(high_receiver.try_recv(), Ok(data));
        assert!(low_receiver.try_recv().is_err());

        // Send a low priority message
        let data = Data(456);
        assert!(relay.send(data.clone(), false).accepted());
        assert_eq!(low_receiver.try_recv(), Ok(data));
        assert!(high_receiver.try_recv().is_err());
    }
}
