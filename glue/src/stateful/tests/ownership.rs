//! Causal ownership tests for the by-value database set: readers and the writer
//! share nothing that can block either side.
//!
//! - a generation whose flush is still parked is never published, and does not
//!   hold the writer back ([`unpublished_generation_stays_invisible`])
//! - a serve holding a published snapshot across parked I/O cannot delay the
//!   writer, and its snapshot stays frozen while publication moves on
//!   ([`parked_serve_never_delays_the_writer`])
//!
//! The deterministic runtime advances time only at quiescence, so `blocked_on`
//! resolving to its timeout proves the probed future could not progress at any
//! scheduling point.

use super::mocks::{FlushControl, TestDb, TestMerkleized};
use crate::stateful::db::{
    Barrier, DatabaseSet, PendingPublication, Publisher, ServeSource as _, Single,
};
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
async fn finalize(set: Single<TestDb>) -> (Single<TestDb>, (), Barrier) {
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

/// Staging alone publishes nothing: a staged generation stays invisible until
/// published, and an unpublished generation does not hold the writer back.
/// The actor publishes only after durability, which the processing-loop and
/// publication tests pin.
#[test_traced]
fn unpublished_generation_stays_invisible() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, control) = parked_set();
        let (mut publisher, reader) = Publisher::new(&context);

        // The first generation applies but its flush is parked, so it stays
        // staged and no subscriber can see it.
        let (set, snapshot, first) = finalize(set).await;
        let staged = publisher.stage(snapshot);
        assert!(
            reader.latest().is_none(),
            "an applied but non-durable generation must not be visible"
        );

        // The unpublished generation does not hold the writer back.
        let next = context.child("finalize").spawn(move |_| finalize(set));
        let (_, snapshot, second) = blocked_on(&context, next)
            .await
            .unwrap_or_else(|_| panic!("an unpublished generation delayed the writer"))
            .unwrap();
        let staged_second = publisher.stage(snapshot);

        // Durability publishes, in order.
        release(&control);
        assert!(
            PendingPublication::new(staged, first)
                .publish_when_durable()
                .await
        );
        assert_eq!(reader.generation(), Some(0));
        release(&control);
        assert!(
            PendingPublication::new(staged_second, second)
                .publish_when_durable()
                .await
        );
        assert_eq!(reader.generation(), Some(1));
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
        let staged = publisher.stage(snapshot);
        release(&control);
        assert!(
            PendingPublication::new(staged, barrier)
                .publish_when_durable()
                .await
        );

        // A serve takes the published snapshot and parks mid-assembly.
        assert_eq!(reader.generation(), Some(0));
        assert!(reader.latest().is_some());
        let (io_done, io_gate) = oneshot::channel();
        let serve = context.child("serve").spawn(move |_| async move {
            let _ = io_gate.await;
        });

        // The parked serve shares nothing with the writer, so the next
        // finalize and publication proceed without delay.
        let next = context.child("finalize").spawn(move |_| finalize(set));
        let (_, snapshot, barrier) = blocked_on(&context, next)
            .await
            .unwrap_or_else(|_| panic!("a parked serve delayed the writer"))
            .unwrap();
        let staged = publisher.stage(snapshot);
        release(&control);
        assert!(
            PendingPublication::new(staged, barrier)
                .publish_when_durable()
                .await
        );

        // The serve completes against its captured snapshot while the
        // reader already serves the newer generation.
        io_done.send(()).unwrap();
        serve.await.unwrap();
        assert_eq!(
            reader.generation(),
            Some(1),
            "publication moved on while the serve was parked"
        );
    });
}
