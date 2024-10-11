#[cfg(test)]
mod tests {
    use commonware_macros::select;
    use commonware_runtime::{deterministic::Executor, Clock, Runner, Spawner};
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use std::time::Duration;

    #[test]
    fn test_select_macro() {
        // Create a deterministic executor
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create channels to track futures that complete at different times
            let (mut tx, mut rx) = mpsc::unbounded();

            // Spawn another future with a shorter delay
            runtime.spawn("task 2", {
                let runtime = runtime.clone();
                let mut tx = tx.clone();
                async move {
                    runtime.sleep(Duration::from_millis(50)).await;
                    tx.send(2).await.unwrap();
                }
            });

            // Spawn a future that sends a message immediately
            runtime.spawn("task 3", async move {
                tx.send(3).await.unwrap();
            });

            // Wait for task to complete
            let mut completed = Vec::new();
            while completed.len() < 3 {
                select! {
                    // Use wildcard pattern for the first future
                    _ = runtime.sleep(Duration::from_millis(45)) => {
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
