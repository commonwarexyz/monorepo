#[cfg(test)]
mod tests {
    use commonware_macros::boxed;
    use futures::executor::block_on;
    use std::future::ready;

    #[boxed]
    async fn sum(values: &[u64]) -> u64 {
        let mut total = 0;
        for value in values {
            ready(()).await;
            total += value;
        }
        total
    }

    #[boxed(dyn)]
    async fn sum_erased(values: &[u64]) -> u64 {
        let mut total = 0;
        for value in values {
            ready(()).await;
            total += value;
        }
        total
    }

    #[boxed(dyn)]
    async fn buffered() -> usize {
        let buffer = [0u8; 1024];
        ready(()).await;
        buffer.len()
    }

    struct Counter(u64);

    impl Counter {
        #[boxed(dyn)]
        async fn add(&mut self, amount: u64) -> Result<u64, &'static str> {
            ready(()).await;
            self.0 = self.0.checked_add(amount).ok_or("overflow")?;
            Ok(self.0)
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    fn assert_sync<T: Sync>(_: &T) {}

    /// Every type implements this trait with marker `()`, and a `Sync` type also implements it
    /// with `u8`. Inference cannot pick a marker for a `Sync` type, so `assert_not_sync` compiles
    /// only for a type that is not `Sync`.
    trait NotSync<Marker> {
        fn assert_not_sync(&self) {}
    }

    impl<T: ?Sized> NotSync<()> for T {}

    impl<T: ?Sized + Sync> NotSync<u8> for T {}

    #[test]
    fn test_boxed_dyn_matches_boxed_output() {
        let values = [1, 2, 3];
        assert_eq!(block_on(sum_erased(&values)), block_on(sum(&values)));
    }

    #[test]
    fn test_boxed_dyn_borrows_and_propagates_errors() {
        let mut counter = Counter(u64::MAX - 1);
        assert_eq!(block_on(counter.add(1)), Ok(u64::MAX));
        assert_eq!(block_on(counter.add(1)), Err("overflow"));
        assert_eq!(counter.0, u64::MAX);
    }

    #[test]
    fn test_boxed_dyn_moves_state_to_heap() {
        // The 1 KiB buffer lives on the heap, so the returned future holds little more than the
        // boxed trait object's two-word pointer.
        let future = buffered();
        assert!(std::mem::size_of_val(&future) <= 3 * std::mem::size_of::<usize>());
        assert_eq!(block_on(future), 1024);
    }

    #[test]
    fn test_boxed_dyn_erases_type() {
        // The two functions share a body whose state machine is `Send` and `Sync`. The plain boxed
        // future keeps that type, so it is both. The erased future is a `dyn Future + Send`, so it
        // is `Send` and not `Sync`.
        let values = [1, 2, 3];
        let kept = sum(&values);
        assert_send(&kept);
        assert_sync(&kept);
        let erased = sum_erased(&values);
        assert_send(&erased);
        erased.assert_not_sync();
        assert_eq!(block_on(kept), block_on(erased));
    }

    mod item_named_future {
        use super::{block_on, boxed, ready};

        /// Shares its name with a local that an expansion could bind.
        #[allow(non_upper_case_globals)]
        const future: u64 = 7;

        #[boxed(dyn)]
        async fn reads_item() -> u64 {
            ready(()).await;
            future
        }

        #[test]
        fn test_boxed_dyn_binds_no_local() {
            assert_eq!(block_on(reads_item()), 7);
        }
    }
}
