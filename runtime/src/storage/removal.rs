//! The completion of removal batches.

use crate::{Error, Handle};
use futures::{
    FutureExt as _,
    future::{BoxFuture, Shared},
};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// The completion of removal batches submitted through [crate::Storage::start_remove_many].
///
/// A batch can wait on a [Removal] through its `after` argument. Every value comes from a batch
/// already submitted, a join of such values, or a known result, so for consumers of a conforming
/// [crate::Storage] implementation a batch can never wait on work that has not been submitted,
/// which would stall the storage instance.
///
/// Clones observe the same completion, and dropping one does not cancel its batch.
#[derive(Clone)]
pub struct Removal(Shared<BoxFuture<'static, Result<(), Error>>>);

impl Removal {
    /// A removal that has already finished with `result`.
    pub fn ready(result: Result<(), Error>) -> Self {
        let removal = Self(futures::future::ready(result).boxed().shared());
        let _ = removal.peek();
        removal
    }

    /// A removal that completes once both `first` and `second` have succeeded, and otherwise
    /// with the first failure. A removal that has already succeeded is left out.
    pub fn join(first: Self, second: Self) -> Self {
        if matches!(first.peek(), Some(Ok(()))) {
            return second;
        }
        if matches!(second.peek(), Some(Ok(()))) {
            return first;
        }
        Self(
            async move {
                first.await?;
                second.await
            }
            .boxed()
            .shared(),
        )
    }

    /// The completion of a batch, reported by `handle`.
    ///
    /// Only a [crate::Storage] implementation may call this, for a batch it has already
    /// submitted. A consumer that calls it recreates the stall [Removal] exists to prevent.
    pub fn submitted(handle: Handle<()>) -> Self {
        Self(handle.boxed().shared())
    }

    /// The result, if the removal has finished, without waiting.
    pub fn peek(&self) -> Option<&Result<(), Error>> {
        // A shared completion records its result only when polled, so poll it once without
        // waiting before reading it.
        if self.0.peek().is_none() {
            let _ = self.0.clone().now_or_never();
        }
        self.0.peek()
    }
}

impl Future for Removal {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

impl fmt::Debug for Removal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Removal").field(&self.0.peek()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ready_is_finished() {
        let removal = Removal::ready(Err(Error::Closed));
        assert!(matches!(removal.peek(), Some(Err(Error::Closed))));
        assert!(matches!(
            futures::executor::block_on(removal),
            Err(Error::Closed)
        ));
    }

    #[test]
    fn test_join_reports_first_failure() {
        let failed = Removal::ready(Err(Error::Closed));
        let missing = Removal::ready(Err(Error::ReadFailed));
        let joined = Removal::join(failed, missing);
        assert!(matches!(
            futures::executor::block_on(joined),
            Err(Error::Closed)
        ));
    }

    #[test]
    fn test_join_waits_for_both() {
        let (sender, receiver) = commonware_utils::channel::oneshot::channel();
        let pending = Removal::submitted(Handle::from_receiver(receiver));
        let joined = Removal::join(Removal::ready(Ok(())), pending.clone());
        assert!(joined.peek().is_none());
        sender.send(Err(Error::Closed)).unwrap();
        assert!(matches!(joined.peek(), Some(Err(Error::Closed))));
        assert!(matches!(pending.peek(), Some(Err(Error::Closed))));
    }
}
