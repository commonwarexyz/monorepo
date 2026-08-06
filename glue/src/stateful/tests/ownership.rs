//! Causal ownership tests for the by-value database set.
//!
//! The old shared-lock design let a slow reader block the writer and a parked
//! flush block serving. These tests pin that the ownership design has no such
//! coupling at the public seams:
//!
//! - a generation whose flush is still parked is never published, so no
//!   subscriber can observe state a crash could roll back, while the writer
//!   proceeds ([`unpublished_generation_stays_invisible`])
//! - a serve holding a published snapshot across parked I/O cannot delay the
//!   writer, and its snapshot stays frozen while publication moves on
//!   ([`parked_serve_never_delays_the_writer`])
//!
//! Causality, not timing. The deterministic runtime advances time only when
//! every task is blocked, so `blocked_on` resolving to its timeout proves the
//! probed future could not progress at any scheduling point, and a probe that
//! completes proves nothing was ever in its way. Generation ordering under
//! pipelining is covered by the publication and processing tests.

use super::mocks::{FlushControl, TestDb, TestMerkleized};
use crate::stateful::db::{Barrier, DatabaseSet, Publisher, Single};
use commonware_macros::test_traced;
use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::channel::oneshot;
use std::time::Duration;

/// How long `blocked_on` waits before declaring the probed future blocked.
///
/// Deterministic time only advances at quiescence, so any value works. This
/// one keeps traces readable.
const BLOCKED: Duration = Duration::from_secs(1);

/// A parked single-member set plus the flush controls driving it.
fn parked_set() -> (Single<TestDb>, FlushControl) {
    let control = FlushControl::default();
    (Single::from(TestDb::gated(control.clone())), control)
}

/// Finalize an empty batch, pinning the set's environment to the
/// deterministic runtime ([`TestDb`] works in any environment).
async fn finalize(set: Single<TestDb>) -> (Single<TestDb>, (), Barrier) {
    DatabaseSet::<deterministic::Context>::finalize(set, TestMerkleized::new()).await
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

/// Release the oldest parked flush and prove its barrier durable.
async fn release(control: &FlushControl, barrier: Barrier) {
    control.flushes.lock().remove(0).send(Ok(())).unwrap();
    assert!(
        barrier.durable().await,
        "flush release must prove durability"
    );
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
        let (_, snapshot, second) = blocked_on(&context, Box::pin(next))
            .await
            .unwrap_or_else(|_| panic!("an unpublished generation delayed the writer"))
            .unwrap();
        let staged_second = publisher.stage(snapshot);

        // Durability publishes, in order.
        release(&control, first).await;
        staged.install();
        assert_eq!(source.latest().unwrap().generation(), 0);
        release(&control, second).await;
        staged_second.install();
        assert_eq!(source.latest().unwrap().generation(), 1);
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
        release(&control, barrier).await;
        staged.install();

        // A serve clones the published generation and parks mid-assembly.
        let served = source.latest().unwrap();
        let (io_done, io_gate) = oneshot::channel();
        let serve = context.child("serve").spawn(move |_| async move {
            let generation = served.generation();
            let _ = io_gate.await;
            (generation, served)
        });

        // The parked serve shares nothing with the writer, so the next
        // finalize and publication proceed without delay.
        let next = context.child("finalize").spawn(move |_| finalize(set));
        let (_, snapshot, barrier) = blocked_on(&context, Box::pin(next))
            .await
            .unwrap_or_else(|_| panic!("a parked serve delayed the writer"))
            .unwrap();
        let staged = publisher.stage(snapshot);
        release(&control, barrier).await;
        staged.install();

        // The serve completes against its captured generation while the
        // source already serves the newer one.
        io_done.send(()).unwrap();
        let (generation, held) = serve.await.unwrap();
        assert_eq!(generation, 0, "the serve captured the first generation");
        assert_eq!(held.generation(), 0, "the held snapshot never moved");
        assert_eq!(
            source.latest().unwrap().generation(),
            1,
            "publication moved on while the serve was parked"
        );
    });
}
