#[cfg(test)]
mod tests {
    use commonware_macros::{select, select_loop};
    use futures::{channel::mpsc, executor::block_on, SinkExt, StreamExt};

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

    #[test]
    fn test_select_loop_basic() {
        block_on(async move {
            let (mut tx, mut rx) = mpsc::unbounded();
            tx.send(1).await.unwrap();
            tx.send(2).await.unwrap();
            tx.send(3).await.unwrap();
            drop(tx);

            let mut received = Vec::new();
            select_loop! {
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
    fn test_select_loop_continue() {
        block_on(async move {
            let (mut tx, mut rx) = mpsc::unbounded();
            for i in 1..=5 {
                tx.send(i).await.unwrap();
            }
            drop(tx);

            let mut evens = Vec::new();
            select_loop! {
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

            select_loop! {
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
