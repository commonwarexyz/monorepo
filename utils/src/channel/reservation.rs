//! Channel reservation helpers.

use super::mpsc::{
    self,
    error::{SendError, TrySendError},
    OwnedPermit,
};
use pin_project::pin_project;
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
#[pin_project]
#[must_use = "await the reservation to acquire a channel slot"]
pub struct Reservation<F, T>
where
    F: Future<Output = Result<OwnedPermit<T>, SendError<()>>>,
{
    #[pin]
    future: F,
    value: Option<T>,
}

impl<F, T> From<(F, T)> for Reservation<F, T>
where
    F: Future<Output = Result<OwnedPermit<T>, SendError<()>>>,
{
    fn from((future, value): (F, T)) -> Self {
        Self {
            future,
            value: Some(value),
        }
    }
}

impl<F, T> Future for Reservation<F, T>
where
    F: Future<Output = Result<OwnedPermit<T>, SendError<()>>>,
{
    type Output = Result<Reserved<T>, SendError<T>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let permit = match this.future.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(permit) => permit,
        };
        let value = this.value.take().expect("reservation polled after completion");
        Poll::Ready(match permit {
            Ok(permit) => Ok(Reserved { permit, value }),
            Err(SendError(())) => Err(SendError(value)),
        })
    }
}

/// Extension trait for bounded channel sends that can reserve capacity.
pub trait ChannelExt<T> {
    /// Attempts to send immediately, reserving the message when the channel is full.
    ///
    /// Returns:
    /// - `Ok(None)` when the value was sent immediately.
    /// - `Ok(Some(_))` when the channel was full. Await the reservation and call
    ///   [`Reserved::send`] to deliver the value.
    /// - `Err(_)` when the receiver has been dropped.
    fn send_or_reserve(
        &self,
        value: T,
    ) -> Result<
        Option<
            Reservation<
                impl Future<Output = Result<OwnedPermit<T>, SendError<()>>> + Send + use<T, Self>,
                T,
            >,
        >,
        SendError<T>,
    >;
}

impl<T: Send> ChannelExt<T> for mpsc::Sender<T> {
    fn send_or_reserve(
        &self,
        value: T,
    ) -> Result<
        Option<
            Reservation<
                impl Future<Output = Result<OwnedPermit<T>, SendError<()>>> + Send + use<T>,
                T,
            >,
        >,
        SendError<T>,
    > {
        match self.try_send(value) {
            Ok(()) => Ok(None),
            Err(TrySendError::Full(value)) => {
                Ok(Some((self.clone().reserve_owned(), value).into()))
            }
            Err(TrySendError::Closed(value)) => Err(SendError(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_async;

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
}
