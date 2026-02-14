//! Shared ingress mailbox primitives for actors.

use crate::{Ask, Tell};
use commonware_macros::select;
use commonware_utils::channel::{mpsc, oneshot};
use std::{
    fmt::{self, Debug, Formatter},
    future::Future,
    pin::pin,
};
use thiserror::Error;

/// An error that can occur when sending a message to an actor.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MailboxError {
    /// The underlying channel to the actor was closed.
    #[error("mailbox closed")]
    Closed,
    /// The bounded channel is full.
    #[error("mailbox full")]
    Full,
    /// The actor dropped its response handle.
    #[error("response channel was cancelled")]
    Cancelled,
    /// The caller waited longer than the configured timeout for the response.
    #[error("request timed out")]
    Timeout,
}

async fn await_response_or_timeout<A, T>(
    rx: oneshot::Receiver<A>,
    timeout: T,
) -> Result<A, MailboxError>
where
    T: Future<Output = ()> + Send,
{
    let mut timeout = pin!(timeout);
    let mut rx = pin!(rx);
    select! {
        _ = &mut timeout => Err(MailboxError::Timeout),
        response = &mut rx => response.map_err(|_| MailboxError::Cancelled),
    }
}

/// Bounded mailbox endpoint used by callers to deliver ingress values to an actor.
///
/// Use this mailbox when senders should experience backpressure.
pub struct Mailbox<I> {
    tx: mpsc::Sender<I>,
}

impl<I> Clone for Mailbox<I> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<I> Debug for Mailbox<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mailbox").finish_non_exhaustive()
    }
}

impl<I> Mailbox<I> {
    /// Create a new [`Mailbox`] with the given sender.
    pub const fn new(tx: mpsc::Sender<I>) -> Self {
        Self { tx }
    }

    /// Send a fire-and-forget message.
    ///
    /// Returns [`MailboxError::Closed`] if the actor is no longer receiving.
    pub async fn tell<T>(&self, msg: T) -> Result<(), MailboxError>
    where
        T: Tell<I>,
    {
        self.tx
            .send(msg.into_ingress())
            .await
            .map_err(|_| MailboxError::Closed)
    }

    /// Try to send a fire-and-forget message without blocking.
    ///
    /// Returns `Ok(())` if the message was enqueued, or a [`MailboxError`] if the
    /// channel is full or closed. This is useful when the caller must not block
    /// (e.g., a router dispatching to many peers).
    pub fn try_tell<T>(&self, msg: T) -> Result<(), MailboxError>
    where
        T: Tell<I>,
    {
        self.tx
            .try_send(msg.into_ingress())
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => MailboxError::Full,
                mpsc::error::TrySendError::Closed(_) => MailboxError::Closed,
            })
    }

    /// Send a fire-and-forget message, ignoring closed-mailbox errors.
    ///
    /// Returns `true` when ingress was delivered and `false` if the mailbox was closed.
    pub async fn tell_lossy<T>(&self, msg: T) -> bool
    where
        T: Tell<I>,
    {
        self.tx.send(msg.into_ingress()).await.is_ok()
    }

    /// Send a request and wait for a response.
    ///
    /// Waits indefinitely unless the actor closes or drops the response channel.
    pub async fn ask<A>(&self, msg: A) -> Result<A::Response, MailboxError>
    where
        A: Ask<I>,
    {
        let (tx, rx) = oneshot::channel::<A::Response>();
        self.tx
            .send(msg.into_ingress(tx))
            .await
            .map_err(|_| MailboxError::Closed)?;
        rx.await.map_err(|_| MailboxError::Cancelled)
    }

    /// Send a request and race the response against `timeout`.
    ///
    /// Returns:
    /// - [`MailboxError::Closed`] if ingress cannot be delivered
    /// - [`MailboxError::Timeout`] if `timeout` resolves first
    /// - [`MailboxError::Cancelled`] if actor drops the response sender
    pub async fn ask_timeout<A, T>(&self, msg: A, timeout: T) -> Result<A::Response, MailboxError>
    where
        A: Ask<I>,
        T: Future<Output = ()> + Send,
    {
        let (tx, rx) = oneshot::channel::<A::Response>();
        self.tx
            .send(msg.into_ingress(tx))
            .await
            .map_err(|_| MailboxError::Closed)?;

        await_response_or_timeout(rx, timeout).await
    }
}

impl<I> From<mpsc::Sender<I>> for Mailbox<I> {
    fn from(tx: mpsc::Sender<I>) -> Self {
        Self::new(tx)
    }
}

/// Unbounded mailbox endpoint used by callers to deliver ingress values to an actor.
///
/// Use this mailbox when callers should never block on enqueue.
pub struct UnboundedMailbox<I> {
    tx: mpsc::UnboundedSender<I>,
}

impl<I> Clone for UnboundedMailbox<I> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<I> Debug for UnboundedMailbox<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnboundedMailbox").finish_non_exhaustive()
    }
}

impl<I> UnboundedMailbox<I> {
    /// Create a new [`UnboundedMailbox`] with the given sender.
    pub const fn new(tx: mpsc::UnboundedSender<I>) -> Self {
        Self { tx }
    }

    /// Send a fire-and-forget message.
    ///
    /// Returns [`MailboxError::Closed`] if the actor is no longer receiving.
    pub fn tell<T>(&self, msg: T) -> Result<(), MailboxError>
    where
        T: Tell<I>,
    {
        self.tx
            .send(msg.into_ingress())
            .map_err(|_| MailboxError::Closed)
    }

    /// Send a fire-and-forget message, ignoring closed-mailbox errors.
    ///
    /// Returns `true` when ingress was delivered and `false` if the mailbox was closed.
    pub fn tell_lossy<T>(&self, msg: T) -> bool
    where
        T: Tell<I>,
    {
        self.tx.send(msg.into_ingress()).is_ok()
    }

    /// Send a request and wait for a response.
    ///
    /// Waits indefinitely unless the actor closes or drops the response channel.
    pub async fn ask<A>(&self, msg: A) -> Result<A::Response, MailboxError>
    where
        A: Ask<I>,
    {
        let (tx, rx) = oneshot::channel::<A::Response>();
        self.tx
            .send(msg.into_ingress(tx))
            .map_err(|_| MailboxError::Closed)?;
        rx.await.map_err(|_| MailboxError::Cancelled)
    }

    /// Send a request and race the response against `timeout`.
    ///
    /// Returns:
    /// - [`MailboxError::Closed`] if ingress cannot be delivered
    /// - [`MailboxError::Timeout`] if `timeout` resolves first
    /// - [`MailboxError::Cancelled`] if actor drops the response sender
    pub async fn ask_timeout<A, T>(&self, msg: A, timeout: T) -> Result<A::Response, MailboxError>
    where
        A: Ask<I>,
        T: Future<Output = ()> + Send,
    {
        let (tx, rx) = oneshot::channel::<A::Response>();
        self.tx
            .send(msg.into_ingress(tx))
            .map_err(|_| MailboxError::Closed)?;

        await_response_or_timeout(rx, timeout).await
    }
}

impl<I> From<mpsc::UnboundedSender<I>> for UnboundedMailbox<I> {
    fn from(tx: mpsc::UnboundedSender<I>) -> Self {
        Self::new(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner};

    enum TestIngress {
        Tell,
        Ask { response: oneshot::Sender<u64> },
    }

    struct TellMsg;
    impl Tell<TestIngress> for TellMsg {
        fn into_ingress(self) -> TestIngress {
            TestIngress::Tell
        }
    }

    struct AskMsg;
    impl Ask<TestIngress> for AskMsg {
        type Response = u64;

        fn into_ingress(self, response: oneshot::Sender<Self::Response>) -> TestIngress {
            TestIngress::Ask { response }
        }
    }

    #[test]
    fn tell_returns_closed_when_receiver_dropped() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let (tx, rx) = mpsc::channel::<TestIngress>(1);
            drop(rx);
            let mailbox = Mailbox::new(tx);

            let err = mailbox.tell(TellMsg).await.unwrap_err();
            assert_eq!(err, MailboxError::Closed);
        });
    }

    #[test]
    fn ask_timeout_returns_timeout() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let (tx, _rx) = mpsc::channel::<TestIngress>(1);
            let mailbox = Mailbox::new(tx);

            let err = mailbox.ask_timeout(AskMsg, async {}).await.unwrap_err();
            assert_eq!(err, MailboxError::Timeout);
        });
    }

    #[test]
    fn unbounded_tell_returns_closed_when_receiver_dropped() {
        let (tx, rx) = mpsc::unbounded_channel::<TestIngress>();
        drop(rx);
        let mailbox = UnboundedMailbox::new(tx);
        let err = mailbox.tell(TellMsg).unwrap_err();
        assert_eq!(err, MailboxError::Closed);
    }

    #[test]
    fn unbounded_ask_timeout_returns_timeout() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let (tx, _rx) = mpsc::unbounded_channel::<TestIngress>();
            let mailbox = UnboundedMailbox::new(tx);

            let err = mailbox.ask_timeout(AskMsg, async {}).await.unwrap_err();
            assert_eq!(err, MailboxError::Timeout);
        });
    }

    #[test]
    fn request_roundtrip_succeeds_when_actor_replies() {
        let runner = deterministic::Runner::default();
        runner.start(|_context| async move {
            let (tx, mut rx) = mpsc::channel::<TestIngress>(1);
            let mailbox = Mailbox::new(tx);

            let requester =
                async move { mailbox.ask(AskMsg).await.expect("request should succeed") };
            let responder = async move {
                if let Some(TestIngress::Ask { response }) = rx.recv().await {
                    let _ = response.send(9);
                }
            };
            let value = futures::join!(requester, responder).0;
            assert_eq!(value, 9);
        });
    }
}
