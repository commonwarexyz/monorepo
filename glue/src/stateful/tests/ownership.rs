//! Ownership tests for the by-value database set. Readers and the writer
//! share nothing that can block either side.
//!
//! - a parked flush holds back neither the writer nor publication
//!   ([`parked_flush_never_delays_the_writer`])
//! - a serve holding a published snapshot across parked I/O cannot delay the
//!   writer, and its snapshot stays frozen while publication moves on
//!   ([`parked_serve_never_delays_the_writer`])
//!
//! The deterministic runtime advances time only at quiescence, so `blocked_on`
//! resolving to its timeout proves the probed future could not progress at any
//! scheduling point.

use super::mocks::{FlushControl, TestDb, TestMerkleized};
use crate::stateful::db::{Barrier, DatabaseSet, Publisher, Single};
use commonware_consensus::types::Height;
use commonware_macros::test_traced;
use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::channel::oneshot;
use std::time::Duration;

/// How long `blocked_on` waits before declaring the probed future blocked.
const BLOCKED: Duration = Duration::from_secs(1);

/// A parked single-member set plus the flush controls driving it.
fn parked_set() -> (Single<TestDb>, FlushControl) {
    let control = FlushControl::default();
    (Single::from(TestDb::gated(control.clone())), control)
}

/// Finalize an empty batch, pinning the set's environment to the
/// deterministic runtime ([`TestDb`] works in any environment).
async fn finalize(set: Single<TestDb>) -> (Single<TestDb>, u64, Barrier) {
    DatabaseSet::<deterministic::Context>::finalize(set, TestMerkleized).await
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

/// A parked flush holds back neither the writer nor publication.
#[test_traced]
fn parked_flush_never_delays_the_writer() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, control) = parked_set();
        let (mut publisher, reader) = Publisher::new(&context);

        // The first snapshots publish at apply while their flush is parked.
        let (set, snapshot, first) = finalize(set).await;
        publisher.publish(Height::new(1), snapshot);
        assert_eq!(reader.latest(), Some(1));

        // The parked flush does not hold the writer back.
        let next = context.child("finalize").spawn(move |_| finalize(set));
        let (_, snapshot, second) = blocked_on(&context, next)
            .await
            .unwrap_or_else(|_| panic!("a parked flush delayed the writer"))
            .unwrap();
        publisher.publish(Height::new(2), snapshot);
        assert_eq!(reader.latest(), Some(2));

        // Flushes still resolve durability, in order.
        release(&control);
        assert!(first.durable().await);
        release(&control);
        assert!(second.durable().await);
    });
}

/// A serve holding a published snapshot across parked I/O cannot delay the
/// writer, and the held snapshot stays frozen while publication moves on.
#[test_traced]
fn parked_serve_never_delays_the_writer() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, control) = parked_set();
        let (mut publisher, reader) = Publisher::new(&context);
        let (set, snapshot, barrier) = finalize(set).await;
        publisher.publish(Height::new(1), snapshot);
        release(&control);
        assert!(barrier.durable().await);

        // A serve takes the published snapshot and parks mid-assembly.
        let served = reader.latest().unwrap();
        let (io_done, io_gate) = oneshot::channel();
        let serve = context.child("serve").spawn(move |_| async move {
            let _ = io_gate.await;
            served
        });

        // The parked serve shares nothing with the writer, so the next
        // finalize and publication proceed without delay.
        let next = context.child("finalize").spawn(move |_| finalize(set));
        let (_, snapshot, barrier) = blocked_on(&context, next)
            .await
            .unwrap_or_else(|_| panic!("a parked serve delayed the writer"))
            .unwrap();
        publisher.publish(Height::new(2), snapshot);
        release(&control);
        assert!(barrier.durable().await);

        // The serve completes against its captured snapshot while the reader
        // already serves the newer snapshots.
        io_done.send(()).unwrap();
        let held = serve.await.unwrap();
        assert_eq!(held, 1, "the held snapshot never moved");
        assert_eq!(
            reader.latest(),
            Some(2),
            "publication moved on while the serve was parked"
        );
    });
}
