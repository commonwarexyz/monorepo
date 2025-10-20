#[cfg(test)]
mod tests {
    use commonware_macros::select;
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
}
