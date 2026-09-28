//! Ownership tests for the by-value database set.
//!
//! - snapshots publish ahead of their parked flush, and the next capture waits
//!   for it as real storage does ([`publication_runs_ahead_of_a_parked_flush`])
//!
//! The deterministic runtime advances time only at quiescence, so `blocked_on`
//! resolving to its timeout proves the probed future could not progress at any
//! scheduling point.

use super::mocks::{FlushControl, TestDb, TestMerkleized};
use crate::stateful::db::{Barrier, DatabaseSet, Publisher, Single};
use commonware_consensus::types::Height;
use commonware_macros::test_traced;
use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, deterministic};
use std::time::Duration;

/// How long `blocked_on` waits before declaring the probed future blocked.
const BLOCKED: Duration = Duration::from_secs(1);

/// A parked single-member set plus the flush controls driving it.
fn parked_set() -> (Single<TestDb>, FlushControl) {
    let control = FlushControl::default();
    (Single::from(TestDb::gated(control.clone())), control)
}

/// Apply an empty batch and start its durability, pinning the set's environment
/// to the deterministic runtime ([`TestDb`] works in any environment).
async fn finalize(set: Single<TestDb>) -> (Single<TestDb>, u64, Barrier) {
    let set = DatabaseSet::<deterministic::Context>::apply(set, TestMerkleized).await;
    DatabaseSet::<deterministic::Context>::finalize(set).await
}

/// Await `future` against a deterministic timeout, `Ok` if it completed and
/// `Err(future)` if the runtime reached quiescence without it progressing.
async fn blocked_on<F, T>(context: &deterministic::Context, future: F) -> Result<T, F>
where
    F: std::future::Future<Output = T> + Unpin,
{
    let mut future = future;
    commonware_macros::select! {
        result = &mut future => Ok(result),
        _ = context.sleep(BLOCKED) => Err(future),
    }
}

/// Release the oldest parked flush.
fn release(control: &FlushControl) {
    control.flushes.lock().remove(0).send(Ok(())).unwrap();
}

/// Snapshots publish while their flush is parked, and the next capture waits
/// for that flush.
#[test_traced]
fn publication_runs_ahead_of_a_parked_flush() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, control) = parked_set();
        let (mut publisher, reader) = Publisher::new(&context);

        // The first snapshots publish at finalize while their flush is parked.
        let (set, snapshot, first) = finalize(set).await;
        publisher.publish(Height::new(1), snapshot);
        assert_eq!(reader.latest(), Some(1));

        // The next capture waits for the parked flush.
        let next = context.child("finalize").spawn(move |_| finalize(set));
        let next = blocked_on(&context, next)
            .await
            .map(|_| ())
            .expect_err("the next capture must wait for the parked flush");
        release(&control);
        assert!(first.durable().await);
        let (_, snapshot, second) = next.await.unwrap();
        publisher.publish(Height::new(2), snapshot);
        assert_eq!(reader.latest(), Some(2));
        release(&control);
        assert!(second.durable().await);
    });
}
