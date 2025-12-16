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
                msg = rx.next() => {
                    match msg {
                        Some(v) => received.push(v),
                        None => break,
                    }
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
                msg = rx.next() => {
                    match msg {
                        Some(v) if v % 2 != 0 => continue,
                        Some(v) => evens.push(v),
                        None => break,
                    }
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
}
