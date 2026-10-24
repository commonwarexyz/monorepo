//! Concurrent collection with ordered results and prompt error propagation.

use futures::{StreamExt as _, future::Either, stream::FuturesUnordered};
use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Tags a future's successful output with its position in the batch. It stores only the inner
/// future and that position.
#[pin_project]
struct Indexed<F> {
    #[pin]
    future: F,
    index: usize,
}

impl<F, T, E> Future for Indexed<F>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<(usize, T), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.future
            .poll(cx)
            .map(|result| result.map(|value| (*this.index, value)))
    }
}

/// Reports the size hint read when the batch starts, less one per item taken, saturating at zero.
///
/// Upstream queries the size hint again after wrapping the iterator. An iterator whose hint
/// becomes unknown in between would make upstream choose its ordered collector. That collector
/// holds a later error behind earlier pending futures.
struct Bounded<I> {
    inner: I,
    lower: usize,
    upper: usize,
}

impl<I: Iterator> Iterator for Bounded<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.inner.next();
        self.lower = self.lower.saturating_sub(1);
        self.upper = self.upper.saturating_sub(1);
        next
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.lower, Some(self.upper))
    }
}

/// Runs futures concurrently, returning successful values in input order.
///
/// Consumes the iterator immediately and polls its futures only when the returned future is
/// polled. The first error observed is returned without waiting for earlier futures. Every
/// pending future and collected value is dropped before the error is returned.
///
/// Each future is dropped once it completes, but successful values are retained until the
/// returned future completes. A future must not wait for another future's value to be dropped.
///
/// # Cancellation
///
/// Dropping the returned future drops every remaining future and collected value. Dropping a
/// future that only observes separately spawned work does not cancel that work.
///
/// # Examples
///
/// ```
/// use commonware_utils::futures::try_join_all;
/// use futures::{executor::block_on, future::ready};
///
/// let values = block_on(try_join_all([ready(Ok::<_, ()>(1)), ready(Ok(2))]));
/// assert_eq!(values, Ok(vec![1, 2]));
/// ```
pub fn try_join_all<F, T, E>(
    futures: impl IntoIterator<Item = F>,
) -> impl Future<Output = Result<Vec<T>, E>>
where
    F: Future<Output = Result<T, E>>,
{
    let futures = futures.into_iter();
    let (lower, upper) = futures.size_hint();

    // A known upper bound of at most 30 futures, the limit of upstream's small collector (its
    // private `join_all::SMALL`), goes to that collector. It polls every future on each poll,
    // returns the first error it meets, and allocates one slice for the whole batch. The 30-future
    // test cases fail if upstream lowers that limit.
    if let Some(upper) = upper.filter(|&upper| upper <= 30) {
        #[allow(clippy::disallowed_methods)]
        return Either::Left(futures::future::try_join_all(Bounded {
            inner: futures,
            lower,
            upper,
        }));
    }

    // Larger or unknown batches use a `FuturesUnordered` so each output arrives as its future
    // completes. Upstream's collector for these batches holds a later error behind earlier
    // pending futures (https://github.com/rust-lang/futures-rs/issues/2866). Collecting outside
    // the async block consumes the iterator before this function returns.
    let futures = futures
        .enumerate()
        .map(|(index, future)| Indexed { index, future })
        .collect::<FuturesUnordered<_>>();
    Either::Right(async move {
        let mut futures = futures;

        // Each output fills the slot at its input position. An error returns early, dropping the
        // filled slots and every pending future.
        let mut values: Vec<_> = (0..futures.len()).map(|_| None).collect();
        while let Some(result) = futures.next().await {
            let (index, value) = result?;
            values[index] = Some(value);
        }

        // Every future succeeded, so every slot is filled.
        Ok(values.into_iter().map(Option::unwrap).collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::oneshot;
    use futures::{
        FutureExt as _,
        future::{Either, ready},
        task::{ArcWake, waker},
    };
    use std::{
        cell::Cell,
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// Counts its drops in the shared counter.
    #[derive(Debug)]
    struct CountDrop(Arc<AtomicUsize>);

    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Polls `future` and drops `_on_drop` along with it.
    #[pin_project]
    struct Watch<F, D> {
        #[pin]
        future: F,
        _on_drop: D,
    }

    impl<F: Future, D> Future for Watch<F, D> {
        type Output = F::Output;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.project().future.poll(cx)
        }
    }

    /// Reports the inner size hint while `known` is set and an unknown bound otherwise. With
    /// `forget`, the first query clears `known`.
    struct WithHint<I> {
        inner: I,
        known: Cell<bool>,
        forget: bool,
    }

    impl<I: Iterator> Iterator for WithHint<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            self.inner.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let known = self.known.get();
            if self.forget {
                self.known.set(false);
            }
            if known {
                self.inner.size_hint()
            } else {
                (0, None)
            }
        }
    }

    #[rstest::rstest]
    #[case(0)]
    #[case(1)]
    #[case(30)]
    #[case(31)]
    #[case(64)]
    fn preserves_order(#[case] count: usize) {
        // Complete the futures from last to first. The batch must stay pending until the first
        // one completes and then return every value in input order.
        let (senders, futures): (Vec<_>, Vec<_>) = (0..count)
            .map(|_| oneshot::channel::<Result<usize, ()>>())
            .map(|(sender, receiver)| (sender, async move { receiver.await.unwrap() }))
            .unzip();
        let mut joined = Box::pin(try_join_all(futures));
        for (index, sender) in senders.into_iter().enumerate().rev() {
            assert!(joined.as_mut().now_or_never().is_none());
            sender.send(Ok(index)).unwrap();
        }
        assert_eq!(
            joined.as_mut().now_or_never(),
            Some(Ok((0..count).collect()))
        );
    }

    #[rstest::rstest]
    #[case(2)]
    #[case(30)]
    #[case(31)]
    #[case(64)]
    fn later_error_drops_futures_and_values(
        #[case] count: usize,
        #[values(false, true)] known: bool,
    ) {
        // The first future stays pending, the middle ones succeed with counted values, and the
        // last one fails. Without `known`, the unknown size hint selects the `FuturesUnordered`
        // path for every count.
        let future_drops = Arc::new(AtomicUsize::new(0));
        let value_drops = Arc::new(AtomicUsize::new(0));
        let (pending_tx, pending_rx) = oneshot::channel();
        let mut pending_rx = Some(pending_rx);
        let futures = (0..count).map(|index| Watch {
            future: if index == 0 {
                let receiver = pending_rx.take().unwrap();
                Either::Left(async move { receiver.await.unwrap() })
            } else {
                Either::Right(ready(if index == count - 1 {
                    Err("failed")
                } else {
                    Ok(CountDrop(value_drops.clone()))
                }))
            },
            _on_drop: CountDrop(future_drops.clone()),
        });
        let mut joined = Box::pin(try_join_all(WithHint {
            inner: futures,
            known: Cell::new(known),
            forget: false,
        }));

        // The first poll must return the error, with every future, every collected value, and the
        // pending receiver already dropped while the outer future is still alive.
        assert!(matches!(
            joined.as_mut().now_or_never(),
            Some(Err("failed"))
        ));
        assert_eq!(future_drops.load(Ordering::SeqCst), count);
        assert_eq!(value_drops.load(Ordering::SeqCst), count - 2);
        assert!(pending_tx.send(Err("cancelled")).is_err());
        drop(joined);
    }

    #[rstest::rstest]
    #[case(1)]
    #[case(30)]
    #[case(31)]
    #[case(64)]
    fn cancellation_drops_futures_and_values(
        #[case] count: usize,
        #[values(false, true)] poll: bool,
    ) {
        // Each future waits for its sender and returns a counted value.
        let future_drops = Arc::new(AtomicUsize::new(0));
        let value_drops = Arc::new(AtomicUsize::new(0));
        let (mut senders, futures): (Vec<_>, Vec<_>) = (0..count)
            .map(|_| {
                let (sender, receiver) = oneshot::channel::<Result<CountDrop, ()>>();
                (
                    sender,
                    Watch {
                        future: async move { receiver.await.unwrap() },
                        _on_drop: CountDrop(future_drops.clone()),
                    },
                )
            })
            .unzip();
        let mut joined = Box::pin(try_join_all(futures));

        // With `poll`, half the futures are completed before the first poll. That poll drops those
        // futures and retains their values.
        let completed = if poll { count / 2 } else { 0 };
        for sender in senders.drain(..completed) {
            sender.send(Ok(CountDrop(value_drops.clone()))).unwrap();
        }
        if poll {
            assert!(joined.as_mut().now_or_never().is_none());
            assert_eq!(future_drops.load(Ordering::SeqCst), completed);
            assert_eq!(value_drops.load(Ordering::SeqCst), 0);
        }

        // Dropping the outer future drops every remaining future and retained value, closing
        // each remaining receiver.
        drop(joined);
        assert_eq!(future_drops.load(Ordering::SeqCst), count);
        assert_eq!(value_drops.load(Ordering::SeqCst), completed);
        for sender in senders {
            assert!(sender.send(Err(())).is_err());
        }
    }

    /// Sends on its channel when dropped.
    struct ReleaseOnDrop(Option<oneshot::Sender<()>>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                sender.send(()).unwrap();
            }
        }
    }

    #[rstest::rstest]
    #[case(2)]
    #[case(31)]
    #[case(64)]
    fn completed_future_drop_unblocks_another(#[case] count: usize) {
        // The first future waits for a release that the second future's wrapper sends when the
        // second future completes and is dropped.
        let (sender, receiver) = oneshot::channel();
        let mut sender = Some(sender);
        let mut receiver = Some(receiver);
        let futures = (0..count).map(|index| Watch {
            future: if index == 0 {
                let receiver = receiver.take().unwrap();
                Either::Left(async move {
                    receiver.await.unwrap();
                    Ok::<_, ()>(index)
                })
            } else {
                Either::Right(ready(Ok(index)))
            },
            _on_drop: ReleaseOnDrop(if index == 1 { sender.take() } else { None }),
        });
        let mut joined = Box::pin(try_join_all(futures));

        // In the small collector, the release wakes the first future during the same pass, so that
        // pass can return pending. A second poll must then finish the batch.
        let result = joined
            .as_mut()
            .now_or_never()
            .or_else(|| joined.as_mut().now_or_never());
        assert_eq!(result, Some(Ok((0..count).collect())));
    }

    /// Counts wakeups.
    struct WakeCount(AtomicUsize);

    impl ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[rstest::rstest]
    #[case(2)]
    #[case(31)]
    #[case(64)]
    fn later_error_wakes_caller(#[case] count: usize) {
        let (mut senders, receivers): (Vec<_>, Vec<_>) = (0..count)
            .map(|_| oneshot::channel::<Result<(), &str>>())
            .unzip();
        let mut joined = Box::pin(try_join_all(
            receivers
                .into_iter()
                .map(|receiver| async move { receiver.await.unwrap() }),
        ));

        // Failing the last future must wake the caller, and the next poll must return the error.
        // A `FuturesUnordered` wakes the caller itself after polling every future, so the count
        // restarts after the first poll.
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = waker(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(joined.as_mut().poll(&mut cx).is_pending());
        wakes.0.store(0, Ordering::SeqCst);
        senders.pop().unwrap().send(Err("failed")).unwrap();
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert_eq!(joined.as_mut().poll(&mut cx), Poll::Ready(Err("failed")));
    }

    #[test]
    fn consumes_non_send_iterator_before_returning_send_future() {
        fn assert_send(_: &impl Send) {}

        // The iterator captures an `Rc`, so the batch is `Send` only because the iterator was
        // consumed before `try_join_all` returned.
        let offset = Rc::new(7);
        let futures = (0..2).map(move |index| ready(Ok::<_, ()>(index + *offset)));
        let joined = try_join_all(futures);
        assert_send(&joined);
        assert_eq!(joined.now_or_never(), Some(Ok(vec![7, 8])));
    }

    #[test]
    fn supports_borrowed_non_send_values() {
        let values = [Rc::new(1), Rc::new(2)];
        let joined = try_join_all(values.iter().map(|value| ready(Ok::<_, ()>(value))));
        assert_eq!(joined.now_or_never(), Some(Ok(values.iter().collect())));
    }

    #[test]
    fn size_hint_can_change() {
        // The hint is known only on the first query. The batch must keep the collector chosen
        // from that query and return the error while the first future stays pending.
        let futures = [
            Either::Left(futures::future::pending::<Result<(), &str>>()),
            Either::Right(ready(Err("failed"))),
        ];
        let joined = try_join_all(WithHint {
            inner: futures.into_iter(),
            known: Cell::new(true),
            forget: true,
        });
        assert_eq!(joined.now_or_never(), Some(Err("failed")));
    }
}
