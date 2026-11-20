#[cfg(all(test, feature = "std"))]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "commonware_utils depends on this crate, so its channels are not available here"
)]
mod tests {
    use commonware_macros::{select, select_loop};
    use futures::executor::block_on;
    use std::future::Future;
    use tokio::sync::mpsc;

    #[test]
    fn test_select_macro() {
        block_on(async move {
            // Populate channels
            let (high_tx, mut high_rx) = mpsc::unbounded_channel();
            high_tx.send(3).unwrap();
            let (mid_tx, mut mid_rx) = mpsc::unbounded_channel();
            mid_tx.send(2).unwrap();
            let (low_tx, mut low_rx) = mpsc::unbounded_channel();
            low_tx.send(1).unwrap();

            // Process messages on all channels (preferring higher priority channels)
            let mut completed = Vec::new();
            while completed.len() < 3 {
                select! {
                    result = high_rx.recv() => {
                        completed.push(result.unwrap());
                    },
                    result = mid_rx.recv() => {
                        completed.push(result.unwrap());
                    },
                    result = low_rx.recv() => {
                        completed.push(result.unwrap());
                    },
                }
            }

            // Ensure messages were processed in the correct order
            assert_eq!(completed, vec![3, 2, 1]);
        });
    }

    /// A mock signaler that never resolves.
    ///
    /// Used in place of a proper `Signal` from `commonware_runtime` to avoid cyclical
    /// dependencies.
    struct MockSignaler;

    impl MockSignaler {
        pub fn stopped(&self) -> impl Future<Output = ()> + use<> {
            futures::future::pending()
        }
    }

    /// A mock signaler that resolves immediately.
    ///
    /// Used in place of a proper `Signal` from `commonware_runtime` to avoid cyclical
    /// dependencies.
    struct MockSignalerResolves;

    impl MockSignalerResolves {
        pub fn stopped(&self) -> impl Future<Output = ()> + use<> {
            futures::future::ready(())
        }
    }

    #[test]
    fn test_select_loop_basic() {
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(1).unwrap();
            tx.send(2).unwrap();
            tx.send(3).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                msg = rx.recv() => match msg {
                    Some(v) => received.push(v),
                    None => break,
                },
            }
            assert_eq!(received, vec![1, 2, 3]);
        });
    }

    #[test]
    fn test_select_loop_basic_shuts_down() {
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(1).unwrap();
            drop(tx);

            #[allow(unused)]
            let mut did_shutdown = false;

            let mock_context = MockSignalerResolves;
            select_loop! {
                mock_context,
                on_stopped => {
                    did_shutdown = true;
                },
                _ = rx.recv() => {
                    // sink msg
                },
            }

            assert!(did_shutdown);
        });
    }

    #[test]
    fn test_select_loop_continue() {
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            for i in 1..=5 {
                tx.send(i).unwrap();
            }
            drop(tx);

            let mut evens = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                msg = rx.recv() => match msg {
                    Some(v) if v % 2 != 0 => continue,
                    Some(v) => evens.push(v),
                    None => break,
                },
            }
            assert_eq!(evens, vec![2, 4]);
        });
    }

    #[test]
    fn test_select_loop_multiple_branches() {
        block_on(async move {
            let (high_tx, mut high_rx) = mpsc::unbounded_channel();
            let (low_tx, mut low_rx) = mpsc::unbounded_channel();

            high_tx.send(100).unwrap();
            low_tx.send(1).unwrap();
            high_tx.send(200).unwrap();
            low_tx.send(2).unwrap();

            let mut results = Vec::new();
            let mut count = 0;

            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                msg = high_rx.recv() => {
                    if let Some(v) = msg {
                        results.push(v);
                        count += 1;
                    }
                    if count == 4 {
                        break;
                    }
                },
                msg = low_rx.recv() => {
                    if let Some(v) = msg {
                        results.push(v);
                        count += 1;
                    }
                    if count == 4 {
                        break;
                    }
                },
            }

            // High priority channel is processed first (biased select)
            assert_eq!(results, vec![100, 200, 1, 2]);
        });
    }

    #[test]
    fn test_select_loop_lifecycle_hooks() {
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(10).unwrap();
            tx.send(20).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mut start_count = 0;
            let mut end_count = 0;
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_start => {
                    start_count += 1;
                },
                on_stopped => {},
                msg = rx.recv() => match msg {
                    Some(v) => received.push(v),
                    None => break,
                },
                on_end => {
                    end_count += 1;
                },
            }
            assert_eq!(received, vec![10, 20]);
            // on_start runs before each iteration: 2 messages + 1 for the None
            assert_eq!(start_count, 3);
            // on_end runs after each arm but not after break: 2 messages
            assert_eq!(end_count, 2);
        });
    }

    #[test]
    fn test_select_loop_on_start_continue() {
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(1).unwrap();
            tx.send(2).unwrap();
            tx.send(3).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mut start_count = 0;
            let mut end_count = 0;
            let mut skip_count = 0;
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_start => {
                    start_count += 1;
                    // Skip the first iteration (don't run select)
                    if start_count == 1 {
                        skip_count += 1;
                        continue;
                    }
                },
                on_stopped => {},
                msg = rx.recv() => match msg {
                    Some(v) => received.push(v),
                    None => break,
                },
                on_end => {
                    end_count += 1;
                },
            }
            // All messages received (continue just skips one iteration, not a message)
            assert_eq!(received, vec![1, 2, 3]);
            // on_start runs 5 times: 1 (skip), 2 (recv 1), 3 (recv 2), 4 (recv 3), 5 (None)
            assert_eq!(start_count, 5);
            // on_end runs 3 times (once per message, not on skip or break)
            assert_eq!(end_count, 3);
            // We skipped once
            assert_eq!(skip_count, 1);
        });
    }

    #[test]
    fn test_select_loop_on_end_not_called_on_shutdown() {
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(1).unwrap();
            drop(tx);

            let mut end_count = 0;
            #[allow(unused)]
            let mut did_shutdown = false;

            let mock_context = MockSignalerResolves;
            select_loop! {
                mock_context,
                on_stopped => {
                    did_shutdown = true;
                },
                _ = rx.recv() => {
                    // sink msg
                },
                on_end => {
                    end_count += 1;
                },
            }

            assert!(did_shutdown);
            // on_end should NOT be called when shutdown triggers
            assert_eq!(end_count, 0);
        });
    }

    #[test]
    fn test_select_loop_on_start_variable_visibility() {
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(5).unwrap();
            tx.send(3).unwrap();
            drop(tx);

            let mut results = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_start => {
                    // Declare a variable in on_start
                    let multiplier = 10;
                },
                on_stopped => {},
                msg = rx.recv() => {
                    match msg {
                        // Use the variable from on_start in the select arm
                        Some(v) => results.push(v * multiplier),
                        None => break,
                    }
                },
                on_end => {
                    // Use the variable from on_start in on_end
                    results.push(multiplier);
                },
            }
            // First iteration: receive 5, push 5*10=50, then on_end pushes 10
            // Second iteration: receive 3, push 3*10=30, then on_end pushes 10
            // Third iteration: receive None, break (on_end not called)
            assert_eq!(results, vec![50, 10, 30, 10]);
        });
    }

    #[test]
    fn test_select_braceless_expressions() {
        block_on(async move {
            let mut results = Vec::new();

            // Test braceless assignment expression
            let (tx1, mut rx1) = mpsc::unbounded_channel::<i32>();
            tx1.send(42).unwrap();
            drop(tx1);

            #[allow(unused_assignments)]
            let mut result = 0;
            select! {
                msg = rx1.recv() => result = msg.unwrap_or(0),
            }
            assert_eq!(result, 42);

            // Test braceless method call
            let (tx2, mut rx2) = mpsc::unbounded_channel();
            tx2.send(100).unwrap();
            drop(tx2);

            select! {
                msg = rx2.recv() => results.push(msg.unwrap()),
            }

            // Test braced syntax still works
            let (tx3, mut rx3) = mpsc::unbounded_channel();
            tx3.send(1).unwrap();
            drop(tx3);

            select! {
                msg = rx3.recv() => {
                    if let Some(v) = msg {
                        results.push(v);
                    }
                },
            }

            assert_eq!(results, vec![100, 1]);
        });
    }

    #[test]
    fn test_select_loop_braceless_syntax() {
        block_on(async move {
            // Test all braceless: on_start, on_stopped, branch, on_end
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(10).unwrap();
            tx.send(20).unwrap();
            drop(tx);

            let mut start_count = 0;
            let mut end_count = 0;
            let mut received = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_start => start_count += 1,
                on_stopped => {},
                msg = rx.recv() => match msg {
                    Some(v) => received.push(v),
                    None => break,
                },
                on_end => end_count += 1,
            }
            assert_eq!(received, vec![10, 20]);
            assert_eq!(start_count, 3); // 2 messages + None
            assert_eq!(end_count, 2); // 2 messages, not break

            // Test braceless on_stopped with immediate shutdown
            let (_tx2, mut rx2) = mpsc::unbounded_channel::<i32>();
            #[allow(unused_assignments)]
            let mut did_shutdown = false;
            let mock_context2 = MockSignalerResolves;
            select_loop! {
                mock_context2,
                on_stopped => did_shutdown = true,
                _ = rx2.recv() => {},
            }
            assert!(did_shutdown);
        });
    }

    #[test]
    fn test_select_loop_refutable_pattern_else_variants() {
        block_on(async move {
            // else break
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(1).unwrap();
            tx.send(2).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                Some(msg) = rx.recv() else break => {
                    received.push(msg);
                },
            }
            assert_eq!(received, vec![1, 2]);

            // else return
            async fn with_return() -> Vec<i32> {
                let (tx, mut rx) = mpsc::unbounded_channel();
                tx.send(10).unwrap();
                tx.send(20).unwrap();
                drop(tx);

                let mut received = Vec::new();
                let mock_context = MockSignaler;
                select_loop! {
                    mock_context,
                    on_stopped => {},
                    Some(msg) = rx.recv() else return received => {
                        received.push(msg);
                    },
                }
                received.push(999); // Should not be reached
                received
            }
            assert_eq!(with_return().await, vec![10, 20]);

            // else custom block
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(100).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mut closed = false;
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                Some(msg) = rx.recv() else {
                    closed = true;
                    break;
                } => {
                    received.push(msg);
                },
            }
            assert_eq!(received, vec![100]);
            assert!(closed);

            // else continue
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(Some(1)).unwrap();
            tx.send(None).unwrap(); // Triggers else continue
            tx.send(Some(2)).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mut iterations = 0;
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_start => {
                    iterations += 1;
                    if iterations > 10 {
                        break;
                    }
                },
                on_stopped => {},
                Some(Some(value)) = rx.recv() else continue => {
                    received.push(value);
                },
            }
            assert_eq!(received, vec![1, 2]);

            // nested pattern
            let (tx, mut rx) = mpsc::unbounded_channel::<Result<i32, &str>>();
            tx.send(Ok(1)).unwrap();
            tx.send(Err("skip")).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                Some(Ok(value)) = rx.recv() else break => {
                    received.push(value);
                },
            }
            assert_eq!(received, vec![1]);
        });
    }

    #[test]
    fn test_select_loop_backward_compatibility() {
        // Verify existing patterns still work exactly as before
        block_on(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            tx.send(1).unwrap();
            tx.send(2).unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                msg = rx.recv() => match msg {
                    Some(v) => received.push(v),
                    None => break,
                },
            }
            assert_eq!(received, vec![1, 2]);
        });
    }
}

#[cfg(all(test, feature = "std"))]
mod coop_tests {
    use commonware_macros::{__coop, select, select_loop};
    use std::{
        future::{Future, pending, ready},
        pin::{Pin, pin},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    /// Counts the wakes it receives.
    #[derive(Default)]
    struct Wakes(
        /// Wakes received so far.
        AtomicUsize,
    );

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Poll `future` once with `waker`.
    fn poll_once<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(waker))
    }

    /// Install a budget of `units` on this thread.
    fn set_budget(units: u32) {
        __coop::REMAINING.set(units);
    }

    /// Spend one unit of the budget, if one is installed.
    fn charge() {
        let left = __coop::REMAINING.get();
        if left != __coop::UNCONSTRAINED {
            __coop::REMAINING.set(left.saturating_sub(1));
        }
    }

    /// A receive with a value queued that takes part in the budget: it
    /// defers while the budget is spent and spends one unit when it delivers.
    struct Queued(
        /// The queued value.
        u32,
    );

    impl Future for Queued {
        type Output = u32;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u32> {
            if __coop::exhausted() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            charge();
            Poll::Ready(self.0)
        }
    }

    /// A future that spends one unit of the budget on every poll and never
    /// completes, like a composite branch that consumes the last unit.
    struct Spender;

    impl Future for Spender {
        type Output = u32;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u32> {
            charge();
            Poll::Pending
        }
    }

    /// Signals shutdown never.
    struct NeverStopped;

    impl NeverStopped {
        fn stopped(&self) -> impl Future<Output = ()> + use<> {
            pending()
        }
    }

    #[test]
    fn test_spent_budget_defers_the_whole_select() {
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());

        // A poll that has spent its budget, with a value queued on the first
        // branch and the second branch ready without the budget.
        set_budget(0);
        let mut chosen = pin!(async {
            select! {
                value = Queued(7) => value,
                _ = ready(()) => 0,
            }
        });

        // The ready second branch does not overtake the first: the whole
        // select defers and wakes the task.
        assert!(poll_once(chosen.as_mut(), &waker).is_pending());
        assert!(wakes.0.load(Ordering::SeqCst) > 0);

        // The next poll's fresh budget tries the branches in order.
        set_budget(32);
        assert_eq!(poll_once(chosen.as_mut(), &waker), Poll::Ready(7));
        set_budget(__coop::UNCONSTRAINED);
    }

    #[test]
    fn test_branch_spending_the_last_unit_defers_later_branches() {
        let waker = Waker::from(Arc::new(Wakes::default()));

        // The first branch spends the last unit of the budget while pending.
        set_budget(1);
        let mut chosen = pin!(async {
            select! {
                value = Spender => value,
                _ = ready(()) => 0,
            }
        });

        // The ready second branch must not complete in the same poll.
        assert!(poll_once(chosen.as_mut(), &waker).is_pending());

        // With budget to spare, the second branch completes behind the first.
        set_budget(32);
        assert_eq!(poll_once(chosen.as_mut(), &waker), Poll::Ready(0));
        set_budget(__coop::UNCONSTRAINED);
    }

    #[test]
    fn test_select_is_unchanged_without_a_budget() {
        let waker = Waker::from(Arc::new(Wakes::default()));

        // No budget is installed, so nothing defers.
        set_budget(__coop::UNCONSTRAINED);
        let mut chosen = pin!(async {
            select! {
                value = pending::<u32>() => value,
                _ = ready(()) => 9,
            }
        });
        assert_eq!(poll_once(chosen.as_mut(), &waker), Poll::Ready(9));
    }

    #[test]
    fn test_select_loop_keeps_order_under_a_spent_budget() {
        let waker = Waker::from(Arc::new(Wakes::default()));

        // A loop whose first arm has a value queued and whose second arm is
        // always ready, in a poll that has spent its budget.
        set_budget(0);
        let context = NeverStopped;
        let mut chosen = pin!(async move {
            let mut first = None;
            select_loop! {
                context,
                on_stopped => {},
                value = Queued(5) => {
                    first = Some(value);
                    break;
                },
                _ = ready(()) => {
                    first = Some(0);
                    break;
                },
            }
            first
        });

        // The loop defers instead of taking the second arm.
        assert!(poll_once(chosen.as_mut(), &waker).is_pending());

        // A fresh budget takes the first arm.
        set_budget(32);
        assert_eq!(poll_once(chosen.as_mut(), &waker), Poll::Ready(Some(5)));
        set_budget(__coop::UNCONSTRAINED);
    }
}
