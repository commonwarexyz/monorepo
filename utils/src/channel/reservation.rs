//! Channel reservation helpers.

use super::mpsc::{
    self,
    error::{SendError, TrySendError},
    OwnedPermit,
};
use futures::future::BoxFuture;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// A reserved channel slot bundled with the value to send.
#[must_use = "call send to deliver the reserved message"]
pub struct Reserved<T> {
    permit: OwnedPermit<T>,
    value: T,
}

impl<T> Reserved<T> {
    /// Sends the buffered value through the reserved slot.
    pub fn send(self) -> mpsc::Sender<T> {
        self.permit.send(self.value)
    }
}

/// A future that waits for a channel slot and keeps ownership of the value.
///
/// The lifetime tracks any borrows held by `T`; the reservation does not borrow
/// the original sender.
#[must_use = "await the reservation to acquire a channel slot"]
pub struct Reservation<'a, T> {
    future: BoxFuture<'a, Result<OwnedPermit<T>, SendError<()>>>,
    value: Option<T>,
}

impl<'a, T> Reservation<'a, T> {
    fn new(
        future: impl Future<Output = Result<OwnedPermit<T>, SendError<()>>> + Send + 'a,
        value: T,
    ) -> Self {
        Self {
            future: Box::pin(future),
            value: Some(value),
        }
    }
}

impl<T> Unpin for Reservation<'_, T> {}

impl<T> Future for Reservation<'_, T> {
    type Output = Result<Reserved<T>, SendError<T>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let permit = match self.future.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(permit) => permit,
        };
        let value = self
            .value
            .take()
            .expect("reservation polled after completion");
        Poll::Ready(match permit {
            Ok(permit) => Ok(Reserved { permit, value }),
            Err(SendError(())) => Err(SendError(value)),
        })
    }
}

/// Extension trait for bounded channel sends that can reserve capacity.
pub trait ReservationExt<T> {
    /// Attempts to send immediately, reserving the message when the channel is full.
    ///
    /// Returns:
    /// - `Ok(None)` when the value was sent immediately.
    /// - `Ok(Some(_))` when the channel was full. Await the reservation and call
    ///   [`Reserved::send`] to deliver the value.
    /// - `Err(_)` when the receiver has been dropped.
    #[must_use = "await and send any reservation"]
    fn send_or_reserve<'a>(&self, value: T) -> Result<Option<Reservation<'a, T>>, SendError<T>>
    where
        T: 'a;
}

impl<T: Send> ReservationExt<T> for mpsc::Sender<T> {
    fn send_or_reserve<'a>(&self, value: T) -> Result<Option<Reservation<'a, T>>, SendError<T>>
    where
        T: 'a,
    {
        match self.try_send(value) {
            Ok(()) => Ok(None),
            Err(TrySendError::Full(value)) => {
                Ok(Some(Reservation::new(self.clone().reserve_owned(), value)))
            }
            Err(TrySendError::Closed(value)) => Err(SendError(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_async;
    use std::collections::BTreeMap;

    #[test]
    fn test_send_or_reserve_sends_immediately() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(sender.send_or_reserve(1).unwrap().is_none());
        assert_eq!(receiver.try_recv(), Ok(1));
    }

    #[test]
    fn test_send_or_reserve_closed_returns_value() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);

        match sender.send_or_reserve(1) {
            Ok(_) => panic!("send should fail"),
            Err(SendError(value)) => assert_eq!(value, 1),
        }
    }

    #[test_async]
    async fn test_send_or_reserve_waits_for_capacity() {
        let (sender, mut receiver) = mpsc::channel(1);
        sender.try_send(1).unwrap();

        let reservation = sender
            .send_or_reserve(2)
            .unwrap()
            .expect("channel should be full");
        assert_eq!(receiver.recv().await, Some(1));
        reservation.await.unwrap().send();
        assert_eq!(receiver.recv().await, Some(2));
    }

    #[test_async]
    async fn test_send_or_reserve_returns_value_when_closed_while_waiting() {
        let (sender, receiver) = mpsc::channel(1);
        sender.try_send(1).unwrap();

        let reservation = sender
            .send_or_reserve(2)
            .unwrap()
            .expect("channel should be full");
        drop(receiver);

        match reservation.await {
            Ok(_) => panic!("reservation should fail"),
            Err(SendError(value)) => assert_eq!(value, 2),
        }
    }

    #[test_async]
    async fn test_send_or_reserve_reservations_can_be_stored() {
        let (sender, mut receiver) = mpsc::channel(1);
        sender.try_send(0).unwrap();

        let mut reservations = Vec::new();
        reservations.push(
            sender
                .send_or_reserve(1)
                .unwrap()
                .expect("channel should be full"),
        );

        let mut reservation_map = BTreeMap::new();
        reservation_map.insert(
            "next",
            sender
                .send_or_reserve(2)
                .unwrap()
                .expect("channel should be full"),
        );

        assert_eq!(receiver.recv().await, Some(0));
        reservations.pop().unwrap().await.unwrap().send();
        assert_eq!(receiver.recv().await, Some(1));
        reservation_map
            .remove("next")
            .unwrap()
            .await
            .unwrap()
            .send();
        assert_eq!(receiver.recv().await, Some(2));
    }

    #[test_async]
    async fn test_send_or_reserve_reservation_can_hold_borrowed_value() {
        let messages = [String::from("pending"), String::from("reserved")];
        let (sender, mut receiver) = mpsc::channel(1);
        sender.try_send(messages[0].as_str()).unwrap();

        let mut reservations: Vec<Reservation<'_, &str>> = Vec::new();
        reservations.push(
            sender
                .send_or_reserve(messages[1].as_str())
                .unwrap()
                .expect("channel should be full"),
        );

        assert_eq!(receiver.recv().await, Some("pending"));
        reservations.pop().unwrap().await.unwrap().send();
        assert_eq!(receiver.recv().await, Some("reserved"));
    }
}
