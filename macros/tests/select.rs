#[cfg(test)]
mod tests {
    use commonware_macros::select;
    use futures::{channel::mpsc, executor::block_on, SinkExt, StreamExt};
    use futures_timer::Delay;
    use std::{thread, time::Duration};

    #[test]
    fn test_select_macro() {
        block_on(async move {
            // Create channels to track futures that complete at different times
            let (mut tx, mut rx) = mpsc::unbounded();

            // Spawn another future with a shorter delay
            let mut tx_clone = tx.clone();
            thread::spawn(move || {
                block_on(async move {
                    Delay::new(Duration::from_millis(50)).await;
                    tx_clone.send(2).await.unwrap();
                });
            });

            // Spawn a future that sends a message immediately
            thread::spawn(move || {
                block_on(async move {
                    tx.send(3).await.unwrap();
                });
            });

            // Wait for task to complete
            let mut completed = Vec::new();
            while completed.len() < 3 {
                select! {
                    // Use wildcard pattern for the first future
                    _ = Delay::new(Duration::from_millis(45)) => {
                        completed.push(1);
                    },
                    // Bind the result to a variable 'result' for the second future
                    result = rx.next() => {
                        completed.push(result.unwrap());
                    },
                }
            }

            // Ensure that the futures completed in the correct order
            assert_eq!(completed, vec![3, 1, 2]);
        });
    }
}
