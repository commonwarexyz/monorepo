#[cfg(test)]
mod tests {
    use commonware_macros::{select, select_loop};
    use futures::{channel::mpsc, executor::block_on, SinkExt, StreamExt};
    use std::future::Future;

    #[test]
    fn test_select_macro() {
        block_on(async move {
            // Populate channels
            let (mut high_tx, mut high_rx) = mpsc::unbounded();
            high_tx.send(3).await.unwrap();
            let (mut mid_tx, mut mid_rx) = mpsc::unbounded();
            mid_tx.send(2).await.unwrap();
            let (mut low_tx, mut low_rx) = mpsc::unbounded();
            low_tx.send(1).await.unwrap();

            // Process messages on all channels (preferring higher priority channels)
            let mut completed = Vec::new();
            while completed.len() < 3 {
                select! {
                    result = high_rx.next() => {
                        completed.push(result.unwrap());
                    },
                    result = mid_rx.next() => {
                        completed.push(result.unwrap());
                    },
                    result = low_rx.next() => {
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
        pub fn stopped(&self) -> impl Future<Output = ()> {
            futures::future::pending()
        }
    }

    /// A mock signaler that resolves immediately.
    ///
    /// Used in place of a proper `Signal` from `commonware_runtime` to avoid cyclical
    /// dependencies.
    struct MockSignalerResolves;

    impl MockSignalerResolves {
        pub fn stopped(&self) -> impl Future<Output = ()> {
            futures::future::ready(())
        }
    }

    #[test]
    fn test_select_loop_basic() {
        block_on(async move {
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(1).await.unwrap();
            tx.send(2).await.unwrap();
            tx.send(3).await.unwrap();
            drop(tx);

            let mut received = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                msg = rx.next() => match msg {
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
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(1).await.unwrap();
            drop(tx);

            #[allow(unused)]
            let mut did_shutdown = false;

            let mock_context = MockSignalerResolves;
            select_loop! {
                mock_context,
                on_stopped => {
                    did_shutdown = true;
                },
                _ = rx.next() => {
                    // sink msg
                },
            }

            assert!(did_shutdown);
        });
    }

    #[test]
    fn test_select_loop_continue() {
        block_on(async move {
            let (mut tx, mut rx) = mpsc::unbounded();
            for i in 1..=5 {
                tx.send(i).await.unwrap();
            }
            drop(tx);

            let mut evens = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                msg = rx.next() => match msg {
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
            let (mut high_tx, mut high_rx) = mpsc::unbounded();
            let (mut low_tx, mut low_rx) = mpsc::unbounded();

            high_tx.send(100).await.unwrap();
            low_tx.send(1).await.unwrap();
            high_tx.send(200).await.unwrap();
            low_tx.send(2).await.unwrap();

            let mut results = Vec::new();
            let mut count = 0;

            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_stopped => {},
                msg = high_rx.next() => {
                    if let Some(v) = msg {
                        results.push(v);
                        count += 1;
                    }
                    if count == 4 {
                        break;
                    }
                },
                msg = low_rx.next() => {
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
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(10).await.unwrap();
            tx.send(20).await.unwrap();
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
                msg = rx.next() => match msg {
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
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(1).await.unwrap();
            tx.send(2).await.unwrap();
            tx.send(3).await.unwrap();
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
                msg = rx.next() => match msg {
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
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(1).await.unwrap();
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
                _ = rx.next() => {
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
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(5).await.unwrap();
            tx.send(3).await.unwrap();
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
                msg = rx.next() => {
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
            let (mut tx1, mut rx1) = mpsc::unbounded::<i32>();
            tx1.send(42).await.unwrap();
            drop(tx1);

            #[allow(unused_assignments)]
            let mut result = 0;
            select! {
                msg = rx1.next() => result = msg.unwrap_or(0),
            }
            assert_eq!(result, 42);

            // Test braceless method call
            let (mut tx2, mut rx2) = mpsc::unbounded();
            tx2.send(100).await.unwrap();
            drop(tx2);

            select! {
                msg = rx2.next() => results.push(msg.unwrap()),
            }

            // Test braced syntax still works
            let (mut tx3, mut rx3) = mpsc::unbounded();
            tx3.send(1).await.unwrap();
            drop(tx3);

            select! {
                msg = rx3.next() => {
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
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(10).await.unwrap();
            tx.send(20).await.unwrap();
            drop(tx);

            let mut start_count = 0;
            let mut end_count = 0;
            let mut received = Vec::new();
            let mock_context = MockSignaler;
            select_loop! {
                mock_context,
                on_start => start_count += 1,
                on_stopped => {},
                msg = rx.next() => match msg {
                    Some(v) => received.push(v),
                    None => break,
                },
                on_end => end_count += 1,
            }
            assert_eq!(received, vec![10, 20]);
            assert_eq!(start_count, 3); // 2 messages + None
            assert_eq!(end_count, 2); // 2 messages, not break

            // Test braceless on_stopped with immediate shutdown
            let (_tx2, mut rx2) = mpsc::unbounded::<i32>();
            #[allow(unused_assignments)]
            let mut did_shutdown = false;
            let mock_context2 = MockSignalerResolves;
            select_loop! {
                mock_context2,
                on_stopped => did_shutdown = true,
                _ = rx2.next() => {},
            }
            assert!(did_shutdown);
        });
    }
}
