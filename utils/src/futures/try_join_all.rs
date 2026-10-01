//! Concurrent collection with ordered results and prompt error propagation.

use futures::{StreamExt as _, future::Either, stream::FuturesUnordered};
use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Attaches an index without an async block's extra storage for the inner future.
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

/// Preserves the selected size bound across upstream's repeated size-hint queries.
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
/// Consumes the iterator immediately and polls its futures when the returned future is polled.
/// The first observed error is returned without waiting for earlier futures. Pending futures
/// and collected successful values are dropped before returning the error.
///
/// Successful values are retained until the batch finishes. Futures must not depend on those
/// values being released while the batch is pending.
///
/// # Cancellation
///
/// Dropping the returned future drops all remaining futures and collected values. Dropping a
/// future that observes separately spawned work does not necessarily cancel that work.
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
    // Upstream's small collector handles errors promptly without per-future allocations.
    if let Some(upper) = upper.filter(|&upper| upper <= 30) {
        #[allow(clippy::disallowed_methods)]
        return Either::Left(futures::future::try_join_all(Bounded {
            inner: futures,
            lower,
            upper,
        }));
    }
    // The upstream ordered collector delays errors behind earlier pending futures:
    // https://github.com/rust-lang/futures-rs/issues/2866
    let futures = futures
        .enumerate()
        .map(|(index, future)| Indexed { index, future })
        .collect::<FuturesUnordered<_>>();
    Either::Right(async move {
        let mut futures = futures;
        let mut values: Vec<_> = (0..futures.len()).map(|_| None).collect();
        while let Some(result) = futures.next().await {
            let (index, value) = result?;
            values[index] = Some(value);
        }
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

    #[derive(Debug)]
    struct CountDrop(Arc<AtomicUsize>);

    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

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
    #[case(31)]
    #[case(64)]
    fn cancellation_drops_futures_and_values(
        #[case] count: usize,
        #[values(false, true)] poll: bool,
    ) {
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
        let completed = if poll { count / 2 } else { 0 };
        for sender in senders.drain(..completed) {
            sender.send(Ok(CountDrop(value_drops.clone()))).unwrap();
        }
        if poll {
            assert!(joined.as_mut().now_or_never().is_none());
            assert_eq!(future_drops.load(Ordering::SeqCst), completed);
            assert_eq!(value_drops.load(Ordering::SeqCst), 0);
        }
        drop(joined);
        assert_eq!(future_drops.load(Ordering::SeqCst), count);
        assert_eq!(value_drops.load(Ordering::SeqCst), completed);
        for sender in senders {
            assert!(sender.send(Err(())).is_err());
        }
    }

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
        // The first pass may yield after the release wakes the earlier future.
        let result = joined
            .as_mut()
            .now_or_never()
            .or_else(|| joined.as_mut().now_or_never());
        assert_eq!(result, Some(Ok((0..count).collect())));
    }

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
