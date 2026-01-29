//! Utilities for graceful channel shutdown handling.
//!
//! When actors communicate via channels, senders may outlive receivers during shutdown.
//! This module provides extension traits and helpers that handle disconnection gracefully
//! rather than panicking.
//!
//! # Example
//!
//! ```ignore
//! use commonware_utils::channels::fallible::FallibleExt;
//!
//! // Fire-and-forget: silently ignore disconnection
//! sender.send_lossy(Message::Shutdown);
//!
//! // Request-response: return None on disconnection
//! let result = sender.request(|tx| Message::Query { responder: tx }).await;
//! ```

use super::{mpsc, oneshot};

/// Extension trait for channel operations that may fail due to disconnection.
///
/// Use these methods when the receiver may be dropped during shutdown
/// and you want to handle that gracefully rather than panicking.
pub trait FallibleExt<T> {
    /// Send a message, returning `true` if successful.
    ///
    /// Use this for fire-and-forget messages where the receiver
    /// may have been dropped during shutdown. The return value can
    /// be ignored if the caller doesn't need to know whether the
    /// send succeeded.
    fn send_lossy(&self, msg: T) -> bool;

    /// Send a request message containing a oneshot responder and await the response.
    ///
    /// Returns `None` if:
    /// - The receiver has been dropped (send fails)
    /// - The responder is dropped without sending (receive fails)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let dialable: Option<Vec<PublicKey>> = sender
    ///     .request(|tx| Message::Dialable { responder: tx })
    ///     .await;
    /// ```
    fn request<R, F>(&self, make_msg: F) -> impl std::future::Future<Output = Option<R>> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send;

    /// Send a request and return the provided default on failure.
    ///
    /// This is a convenience wrapper around [`request`](Self::request) for cases
    /// where you have a sensible default value.
    fn request_or<R, F>(
        &self,
        make_msg: F,
        default: R,
    ) -> impl std::future::Future<Output = R> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send;

    /// Send a request and return `R::default()` on failure.
    ///
    /// This is a convenience wrapper around [`request`](Self::request) for types
    /// that implement [`Default`].
    fn request_or_default<R, F>(&self, make_msg: F) -> impl std::future::Future<Output = R> + Send
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send;
}

impl<T: Send> FallibleExt<T> for mpsc::UnboundedSender<T> {
    fn send_lossy(&self, msg: T) -> bool {
        self.send(msg).is_ok()
    }

    async fn request<R, F>(&self, make_msg: F) -> Option<R>
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        let (tx, rx) = oneshot::channel();
        if self.send(make_msg(tx)).is_err() {
            return None;
        }
        rx.await.ok()
    }

    async fn request_or<R, F>(&self, make_msg: F, default: R) -> R
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.request(make_msg).await.unwrap_or(default)
    }

    async fn request_or_default<R, F>(&self, make_msg: F) -> R
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.request(make_msg).await.unwrap_or_default()
    }
}

/// Extension trait for bounded channel operations that may fail due to disconnection.
///
/// Similar to [`FallibleExt`] but for bounded channels where send operations are async.
pub trait AsyncFallibleExt<T> {
    /// Send a message asynchronously, returning `true` if successful.
    ///
    /// Use this for fire-and-forget messages where the receiver
    /// may have been dropped during shutdown. The return value can
    /// be ignored if the caller doesn't need to know whether the
    /// send succeeded.
    fn send_lossy(&mut self, msg: T) -> impl std::future::Future<Output = bool> + Send;

    /// Try to send a message without blocking, returning `true` if successful.
    ///
    /// Use this for fire-and-forget messages where you don't want to wait
    /// if the channel is full. Returns `false` if the channel is full or
    /// disconnected.
    fn try_send_lossy(&mut self, msg: T) -> bool;

    /// Send a request message containing a oneshot responder and await the response.
    ///
    /// Returns `None` if:
    /// - The receiver has been dropped (send fails)
    /// - The responder is dropped without sending (receive fails)
    fn request<R, F>(&mut self, make_msg: F) -> impl std::future::Future<Output = Option<R>> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send;

    /// Send a request and return the provided default on failure.
    fn request_or<R, F>(
        &mut self,
        make_msg: F,
        default: R,
    ) -> impl std::future::Future<Output = R> + Send
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send;

    /// Send a request and return `R::default()` on failure.
    fn request_or_default<R, F>(
        &mut self,
        make_msg: F,
    ) -> impl std::future::Future<Output = R> + Send
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send;
}

impl<T: Send> AsyncFallibleExt<T> for mpsc::Sender<T> {
    async fn send_lossy(&mut self, msg: T) -> bool {
        self.send(msg).await.is_ok()
    }

    fn try_send_lossy(&mut self, msg: T) -> bool {
        self.try_send(msg).is_ok()
    }

    async fn request<R, F>(&mut self, make_msg: F) -> Option<R>
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        let (tx, rx) = oneshot::channel();
        if self.send(make_msg(tx)).await.is_err() {
            return None;
        }
        rx.await.ok()
    }

    async fn request_or<R, F>(&mut self, make_msg: F, default: R) -> R
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.request(make_msg).await.unwrap_or(default)
    }

    async fn request_or_default<R, F>(&mut self, make_msg: F) -> R
    where
        R: Default + Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        self.request(make_msg).await.unwrap_or_default()
    }
}

/// Extension trait for oneshot sender operations that may fail due to disconnection.
///
/// Use this when the receiver may have been dropped during shutdown
/// and you want to handle that gracefully rather than panicking.
pub trait OneshotExt<T> {
    /// Send a value, returning `true` if successful.
    ///
    /// Use this for fire-and-forget responses where the requester
    /// may have been dropped during shutdown. The return value can
    /// be ignored if the caller doesn't need to know whether the
    /// send succeeded.
    ///
    /// Consumes the sender.
    fn send_lossy(self, msg: T) -> bool;
}

impl<T> OneshotExt<T> for oneshot::Sender<T> {
    fn send_lossy(self, msg: T) -> bool {
        self.send(msg).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_async;

    #[derive(Debug)]
    #[allow(dead_code)]
    enum TestMessage {
        FireAndForget(u32),
        Request {
            responder: oneshot::Sender<String>,
        },
        RequestBool {
            responder: oneshot::Sender<bool>,
        },
        RequestVec {
            responder: oneshot::Sender<Vec<u32>>,
        },
    }

    #[test]
    fn test_send_lossy_success() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(tx.send_lossy(TestMessage::FireAndForget(42)));

        // Message should be received
        assert!(matches!(rx.try_recv(), Ok(TestMessage::FireAndForget(42))));
    }

    #[test]
    fn test_send_lossy_disconnected() {
        let (tx, rx) = mpsc::unbounded_channel::<TestMessage>();
        drop(rx);

        // Should not panic, returns false
        assert!(!tx.send_lossy(TestMessage::FireAndForget(42)));
    }

    #[test_async]
    async fn test_request_send_disconnected() {
        let (tx, rx) = mpsc::unbounded_channel::<TestMessage>();
        drop(rx);

        let result: Option<String> = tx
            .request(|responder| TestMessage::Request { responder })
            .await;

        assert_eq!(result, None);
    }

    #[test_async]
    async fn test_request_or_disconnected() {
        let (tx, rx) = mpsc::unbounded_channel::<TestMessage>();
        drop(rx);

        let result = tx
            .request_or(|responder| TestMessage::RequestBool { responder }, false)
            .await;

        assert!(!result);
    }

    #[test_async]
    async fn test_request_or_default_disconnected() {
        let (tx, rx) = mpsc::unbounded_channel::<TestMessage>();
        drop(rx);

        let result: Vec<u32> = tx
            .request_or_default(|responder| TestMessage::RequestVec { responder })
            .await;

        assert!(result.is_empty());
    }

    // AsyncFallibleExt tests for bounded channels

    #[test_async]
    async fn test_async_send_lossy_success() {
        let (mut tx, mut rx) = mpsc::channel(1);
        assert!(tx.send_lossy(TestMessage::FireAndForget(42)).await);

        // Message should be received
        assert!(matches!(rx.try_recv(), Ok(TestMessage::FireAndForget(42))));
    }

    #[test_async]
    async fn test_async_send_lossy_disconnected() {
        let (mut tx, rx) = mpsc::channel::<TestMessage>(1);
        drop(rx);

        // Should not panic, returns false
        assert!(!tx.send_lossy(TestMessage::FireAndForget(42)).await);
    }

    #[test_async]
    async fn test_async_request_send_disconnected() {
        let (mut tx, rx) = mpsc::channel::<TestMessage>(1);
        drop(rx);

        let result: Option<String> =
            AsyncFallibleExt::request(&mut tx, |responder| TestMessage::Request { responder })
                .await;

        assert_eq!(result, None);
    }

    #[test_async]
    async fn test_async_request_or_disconnected() {
        let (mut tx, rx) = mpsc::channel::<TestMessage>(1);
        drop(rx);

        let result = AsyncFallibleExt::request_or(
            &mut tx,
            |responder| TestMessage::RequestBool { responder },
            false,
        )
        .await;

        assert!(!result);
    }

    #[test_async]
    async fn test_async_request_or_default_disconnected() {
        let (mut tx, rx) = mpsc::channel::<TestMessage>(1);
        drop(rx);

        let result: Vec<u32> = AsyncFallibleExt::request_or_default(&mut tx, |responder| {
            TestMessage::RequestVec { responder }
        })
        .await;

        assert!(result.is_empty());
    }

    // try_send_lossy tests

    #[test]
    fn test_try_send_lossy_success() {
        let (mut tx, mut rx) = mpsc::channel(1);
        assert!(tx.try_send_lossy(TestMessage::FireAndForget(42)));

        // Message should be received
        assert!(matches!(rx.try_recv(), Ok(TestMessage::FireAndForget(42))));
    }

    #[test]
    fn test_try_send_lossy_disconnected() {
        let (mut tx, rx) = mpsc::channel::<TestMessage>(1);
        drop(rx);

        // Should not panic, returns false
        assert!(!tx.try_send_lossy(TestMessage::FireAndForget(42)));
    }

    // OneshotExt tests

    #[test]
    fn test_oneshot_send_lossy_success() {
        let (tx, mut rx) = oneshot::channel::<u32>();
        assert!(tx.send_lossy(42));
        assert_eq!(rx.try_recv(), Ok(42));
    }

    #[test]
    fn test_oneshot_send_lossy_disconnected() {
        let (tx, rx) = oneshot::channel::<u32>();
        drop(rx);
        assert!(!tx.send_lossy(42));
    }
}
