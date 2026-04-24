//! Request/response helpers for bounded actor mailboxes.
//!
//! These helpers let an actor keep a request acknowledgement pending without
//! blocking its event loop. The returned futures own both the bounded send and
//! the response receiver, so callers can poll them alongside mailbox input.

use super::{mpsc, oneshot};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use futures::{stream::FuturesUnordered, Stream};

/// A pending acknowledgement.
pub struct Pending<T> {
    future: Pin<Box<dyn Future<Output = T> + Send + 'static>>,
}

impl<T> Pending<T> {
    /// Creates a pending acknowledgement from a future.
    pub fn from_future<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        Self {
            future: Box::pin(future),
        }
    }
}

impl<T> Future for Pending<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().future.as_mut().poll(cx)
    }
}

impl<T> Unpin for Pending<T> {}

/// A pool of pending acknowledgements.
///
/// This is the actor-loop friendly form of request/response: callers enqueue
/// requests and poll completed acknowledgements alongside mailbox input.
pub struct Pool<T> {
    pending: FuturesUnordered<Pending<T>>,
}

impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self {
            pending: FuturesUnordered::new(),
        }
    }
}

impl<T> Pool<T> {
    /// Adds a pending acknowledgement to the pool.
    pub fn push(&mut self, pending: Pending<T>) {
        self.pending.push(pending);
    }

    /// Returns the number of pending requests.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns true if there are no pending requests.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Polls the next completed acknowledgement.
    ///
    /// If the pool is empty, this future remains pending. This makes it safe
    /// to include unconditionally in an actor `select`.
    pub fn next_completed(&mut self) -> NextCompleted<'_, T> {
        NextCompleted { pool: self }
    }
}

impl<R> Pool<Option<R>> {
    /// Adds a pending bounded-mailbox request to the pool.
    pub fn request<T, F>(&mut self, sender: &mpsc::Sender<T>, make_msg: F)
    where
        T: Send + 'static,
        R: Send + 'static,
        F: FnOnce(oneshot::Sender<R>) -> T + Send + 'static,
    {
        self.push(pending(sender, make_msg));
    }
}

/// Future returned by [Pool::next_completed].
pub struct NextCompleted<'a, T> {
    pool: &'a mut Pool<T>,
}

impl<T> Future for NextCompleted<'_, T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.pool.pending.is_empty() {
            return Poll::Pending;
        }
        match Pin::new(&mut this.pool.pending).poll_next(cx) {
            Poll::Ready(Some(response)) => Poll::Ready(response),
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }
}

/// Creates a pending request from a bounded mailbox sender.
///
/// The future resolves to `None` if the mailbox is closed or if the receiver
/// drops the response channel without sending a value.
pub fn pending<T, R, F>(sender: &mpsc::Sender<T>, make_msg: F) -> Pending<Option<R>>
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(oneshot::Sender<R>) -> T + Send + 'static,
{
    let sender = sender.clone();
    Pending::from_future(async move {
        let (tx, rx) = oneshot::channel();
        if sender.send(make_msg(tx)).await.is_err() {
            return None;
        }
        rx.await.ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_async;

    enum Message {
        Get {
            response: oneshot::Sender<u64>,
        },
    }

    #[test_async]
    async fn pending_waits_for_capacity_and_response() {
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .send(Message::Get {
                response: oneshot::channel().0,
            })
            .await
            .unwrap();

        let request = pending(&sender, |response| Message::Get { response });
        let driver = async {
            let _ = receiver.recv().await.unwrap();
            match receiver.recv().await.unwrap() {
                Message::Get { response } => response.send(7).unwrap(),
            }
        };
        let (response, _) = futures::join!(request, driver);
        assert_eq!(response, Some(7));
    }

    #[test_async]
    async fn pool_returns_completed_acknowledgements() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut pool = Pool::default();
        pool.request(&sender, |response| Message::Get { response });

        let next = pool.next_completed();
        let driver = async {
            match receiver.recv().await.unwrap() {
                Message::Get { response } => response.send(11).unwrap(),
            }
        };
        let (response, _) = futures::join!(next, driver);
        assert_eq!(response, Some(11));
        assert!(pool.is_empty());
    }
}
