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
use crate::stateful::db::{Barrier, DbSet, PendingPublication, Publisher, Single};
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
    DbSet::<deterministic::Context>::finalize(set, TestMerkleized::new()).await
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
/// installed, and an unpublished generation does not hold the writer back.
/// The actor installs only after durability, which the processing-loop and
/// publication tests pin.
#[test_traced]
fn unpublished_generation_stays_invisible() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, control) = parked_set();
        let (mut publisher, source) = Publisher::new(&context);

        // The first generation applies but its flush is parked, so it stays
        // staged and no subscriber can see it.
        let (set, snapshot, first) = finalize(set).await;
        let staged = publisher.stage(snapshot);
        assert!(
            source.latest().is_none(),
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
                .install_when_durable()
                .await
        );
        assert_eq!(source.latest().unwrap().number(), 0);
        release(&control);
        assert!(
            PendingPublication::new(staged_second, second)
                .install_when_durable()
                .await
        );
        assert_eq!(source.latest().unwrap().number(), 1);
    });
}

/// A serve holding a published snapshot across parked I/O cannot delay the
/// writer, and the held snapshot stays frozen while publication moves on.
#[test_traced]
fn parked_serve_never_delays_the_writer() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, control) = parked_set();
        let (mut publisher, source) = Publisher::new(&context);
        let (set, snapshot, barrier) = finalize(set).await;
        let staged = publisher.stage(snapshot);
        release(&control);
        assert!(
            PendingPublication::new(staged, barrier)
                .install_when_durable()
                .await
        );

        // A serve clones the published generation and parks mid-assembly.
        let served = source.latest().unwrap();
        let (io_done, io_gate) = oneshot::channel();
        let serve = context.child("serve").spawn(move |_| async move {
            let number = served.number();
            let _ = io_gate.await;
            (number, served)
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
                .install_when_durable()
                .await
        );

        // The serve completes against its captured generation while the
        // source already serves the newer one.
        io_done.send(()).unwrap();
        let (number, held) = serve.await.unwrap();
        assert_eq!(number, 0, "the serve captured the first generation");
        assert_eq!(held.number(), 0, "the held generation never moved");
        assert_eq!(
            source.latest().unwrap().number(),
            1,
            "publication moved on while the serve was parked"
        );
    });
}
