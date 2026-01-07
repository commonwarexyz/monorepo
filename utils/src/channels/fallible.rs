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
//! sender.try_send(Message::Shutdown);
//!
//! // Request-response: return None on disconnection
//! let result = sender.request(|tx| Message::Query { responder: tx }).await;
//! ```

use futures::channel::{mpsc, oneshot};

/// Extension trait for channel operations that may fail due to disconnection.
///
/// Use these methods when the receiver may be dropped during shutdown
/// and you want to handle that gracefully rather than panicking.
pub trait FallibleExt<T> {
    /// Send a message, silently ignoring disconnection errors.
    ///
    /// Use this for fire-and-forget messages where the receiver
    /// may have been dropped during shutdown.
    fn try_send(&self, msg: T);

    /// Send a message, returning `true` if successful.
    ///
    /// Returns `false` if the receiver has been dropped.
    fn try_send_checked(&self, msg: T) -> bool;

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
    fn try_send(&self, msg: T) {
        let _ = self.unbounded_send(msg);
    }

    fn try_send_checked(&self, msg: T) -> bool {
        self.unbounded_send(msg).is_ok()
    }

    async fn request<R, F>(&self, make_msg: F) -> Option<R>
    where
        R: Send,
        F: FnOnce(oneshot::Sender<R>) -> T + Send,
    {
        let (tx, rx) = oneshot::channel();
        if self.unbounded_send(make_msg(tx)).is_err() {
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
    fn test_try_send_success() {
        let (tx, mut rx) = mpsc::unbounded();
        tx.try_send(TestMessage::FireAndForget(42));

        // Message should be received
        assert!(matches!(
            rx.try_next(),
            Ok(Some(TestMessage::FireAndForget(42)))
        ));
    }

    #[test]
    fn test_try_send_disconnected() {
        let (tx, rx) = mpsc::unbounded::<TestMessage>();
        drop(rx);

        // Should not panic
        tx.try_send(TestMessage::FireAndForget(42));
    }

    #[test]
    fn test_try_send_checked_success() {
        let (tx, _rx) = mpsc::unbounded();
        assert!(tx.try_send_checked(TestMessage::FireAndForget(42)));
    }

    #[test]
    fn test_try_send_checked_disconnected() {
        let (tx, rx) = mpsc::unbounded::<TestMessage>();
        drop(rx);
        assert!(!tx.try_send_checked(TestMessage::FireAndForget(42)));
    }

    #[test_async]
    async fn test_request_send_disconnected() {
        let (tx, rx) = mpsc::unbounded::<TestMessage>();
        drop(rx);

        let result: Option<String> = tx
            .request(|responder| TestMessage::Request { responder })
            .await;

        assert_eq!(result, None);
    }

    #[test_async]
    async fn test_request_or_disconnected() {
        let (tx, rx) = mpsc::unbounded::<TestMessage>();
        drop(rx);

        let result = tx
            .request_or(|responder| TestMessage::RequestBool { responder }, false)
            .await;

        assert!(!result);
    }

    #[test_async]
    async fn test_request_or_default_disconnected() {
        let (tx, rx) = mpsc::unbounded::<TestMessage>();
        drop(rx);

        let result: Vec<u32> = tx
            .request_or_default(|responder| TestMessage::RequestVec { responder })
            .await;

        assert!(result.is_empty());
    }
}
