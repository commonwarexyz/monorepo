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
    task::{Context, Poll, ready},
};

/// The completion of removal batches submitted through [crate::Storage::start_remove_many].
///
/// A batch can wait on a [Removal] through its `after` argument. A batch waiting on a completion
/// that never resolves stalls the storage operations queued behind it. [Removal::ready] and
/// [Removal::join] cannot create one. [Removal::submitted] can, so it requires its caller to pass
/// the completion of a batch already submitted.
///
/// Clones observe the same completion, and dropping one does not cancel its batch. A finished
/// removal reports its result to every holder, however often it is polled, peeked, or cloned.
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
    /// The caller must have already submitted the batch, so `handle` resolves without further
    /// action from it. This is meant for [crate::Storage] implementations. The type does not
    /// check it, and a `handle` that never resolves stalls every batch that follows it.
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
        let result = ready!(self.0.poll_unpin(cx));

        // A shared future keeps no output for the handle that returned it, so this holder
        // continues as a finished removal with the same result.
        *self = Self::ready(result.clone());
        Poll::Ready(result)
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
    use crate::{Storage as _, storage::memory::Storage as MemoryStorage};
    use commonware_utils::channel::oneshot;
    use futures::executor::block_on;

    /// Whether `result` is the outcome `expected` names, comparing a failure by its message.
    fn same(result: &Result<(), Error>, expected: &Result<(), Error>) -> bool {
        match (result, expected) {
            (Ok(()), Ok(())) => true,
            (Err(error), Err(expected)) => error.to_string() == expected.to_string(),
            _ => false,
        }
    }

    /// A removal awaited through a mutable reference stays readable and usable from every
    /// holder: peek, a clone, a join, and a batch following it all observe its result.
    #[test]
    fn test_awaited_by_reference_stays_usable() {
        for expected in [Ok(()), Err(Error::ReadFailed)] {
            block_on(async {
                let (sender, receiver) = oneshot::channel();
                let mut removal = Removal::submitted(Handle::from_receiver(receiver));
                sender.send(expected.clone()).unwrap();
                assert!(same(&(&mut removal).await, &expected));

                // Every later use observes the same result.
                assert!(same(removal.peek().unwrap(), &expected));
                assert!(same(&removal.clone().await, &expected));
                let joined = Removal::join(removal.clone(), Removal::ready(Ok(())));
                assert!(same(&joined.await, &expected));

                // A batch following it removes its blob only if it succeeded.
                let storage = MemoryStorage::new();
                drop(storage.open("partition", b"blob").await.unwrap());
                let batch = vec![("partition".to_string(), b"blob".to_vec())];
                let following = storage.start_remove_many(batch, Some(removal)).await;
                assert!(same(&following.await, &expected));
                let remaining = storage.scan("partition").await.unwrap();
                assert_eq!(remaining.is_empty(), expected.is_ok());
            });
        }
    }

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

    /// A join of two pending removals finishes only once both have, and reports the failure of
    /// the second when the first succeeded.
    #[test]
    fn test_join_waits_for_both_pending() {
        let (first_sender, first) = oneshot::channel();
        let (second_sender, second) = oneshot::channel();
        let joined = Removal::join(
            Removal::submitted(Handle::from_receiver(first)),
            Removal::submitted(Handle::from_receiver(second)),
        );
        assert!(joined.peek().is_none());
        first_sender.send(Ok(())).unwrap();
        assert!(joined.peek().is_none());
        second_sender.send(Err(Error::ReadFailed)).unwrap();
        assert!(matches!(joined.peek(), Some(Err(Error::ReadFailed))));
    }

    /// A join with a removal that already succeeded follows the other removal.
    #[test]
    fn test_join_with_succeeded_input_follows_other() {
        let (sender, receiver) = commonware_utils::channel::oneshot::channel();
        let pending = Removal::submitted(Handle::from_receiver(receiver));
        let joined = Removal::join(Removal::ready(Ok(())), pending.clone());
        assert!(joined.peek().is_none());
        sender.send(Err(Error::Closed)).unwrap();
        assert!(matches!(joined.peek(), Some(Err(Error::Closed))));
        assert!(matches!(pending.peek(), Some(Err(Error::Closed))));
    }
}
