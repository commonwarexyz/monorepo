//! Causal ownership tests for the by-value database set.
//!
//! These tests assert the ownership invariants at the public seams, proving
//! the baseline convoys are gone rather than merely faster.
//!
//! - a finalize whose flush is still parked hands the set back immediately,
//!   so the writer keeps committing while durability resolves off the hot
//!   path ([`parked_flush_never_blocks_the_next_finalize`])
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

use super::mocks::{TestMerkleized, TestUnmerkleized};
use crate::stateful::db::{Barrier, DatabaseSet, ManagedDb, Publisher};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Error as RuntimeError, Handle, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{sync::Arc, time::Duration};

/// How long `blocked_on` waits before declaring the probed future blocked.
///
/// Deterministic time only advances at quiescence, so any value works. This
/// one keeps traces readable.
const BLOCKED: Duration = Duration::from_secs(1);

/// Pending flush releases, shared between a [`ParkedDb`] and its test.
type Flushes = Arc<Mutex<Vec<oneshot::Sender<Result<(), RuntimeError>>>>>;

/// A database whose finalize applies instantly and parks its flush on an
/// externally held release, mirroring `start_sync` pipelining.
struct ParkedDb {
    flushes: Flushes,
}

/// A parked single-member set plus the release queue driving its flushes.
fn parked_set() -> ((ParkedDb,), Flushes) {
    let flushes: Flushes = Arc::new(Mutex::new(Vec::new()));
    let db = ParkedDb {
        flushes: flushes.clone(),
    };
    ((db,), flushes)
}

impl ManagedDb<deterministic::Context> for ParkedDb {
    type Unmerkleized = TestUnmerkleized;
    type Merkleized = TestMerkleized;
    type Error = std::convert::Infallible;
    type Config = ();
    type SyncTarget = ();
    type Snapshot = ();

    fn initial_sync_target() -> Self::SyncTarget {}

    async fn init(
        _context: deterministic::Context,
        _config: Self::Config,
    ) -> Result<Self, Self::Error> {
        unreachable!("constructed directly in tests")
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        TestUnmerkleized
    }

    fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
        true
    }

    async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
        Ok((self, ()))
    }

    async fn finalize(
        self,
        _batch: Self::Merkleized,
    ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
        let (release, released) = oneshot::channel();
        self.flushes.lock().push(release);
        Ok((self, (), Handle::from_receiver(released)))
    }

    fn sync_target(&self) -> Self::SyncTarget {}

    async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
        Ok(self)
    }
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
async fn release(flushes: &Flushes, barrier: Barrier) {
    flushes.lock().remove(0).send(Ok(())).unwrap();
    assert!(
        barrier.durable().await,
        "flush release must prove durability"
    );
}

/// A finalize whose flush is parked hands the set back immediately, so the
/// writer keeps committing while durability resolves off the hot path.
#[test_traced]
fn parked_flush_never_blocks_the_next_finalize() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, flushes) = parked_set();
        let (set, _, first) = set.finalize((TestMerkleized,)).await;
        assert_eq!(flushes.lock().len(), 1, "the first flush is parked");

        // The baseline held the write slot across the flush and this probe
        // timed out. With the set owned by value, the next finalize proceeds
        // immediately.
        let next = context
            .child("finalize")
            .spawn(move |_| async move { set.finalize((TestMerkleized,)).await });
        let (_, _, second) = blocked_on(&context, Box::pin(next))
            .await
            .unwrap_or_else(|_| panic!("a parked flush blocked the next finalize"))
            .unwrap();

        release(&flushes, first).await;
        release(&flushes, second).await;
    });
}

/// A generation whose flush is parked is never published, so no subscriber
/// can observe state a crash could roll back, and the writer proceeds while
/// the generation waits.
#[test_traced]
fn unpublished_generation_stays_invisible() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (set, flushes) = parked_set();
        let (mut publisher, source) = Publisher::new(&context);

        // The first generation applies but its flush is parked, so it stays
        // staged and no subscriber can see it.
        let (set, snapshot, first) = set.finalize((TestMerkleized,)).await;
        let staged = publisher.stage(snapshot);
        assert!(
            source.latest().is_none(),
            "an applied but non durable generation must not be visible"
        );

        // The unpublished generation does not hold the writer back.
        let next = context
            .child("finalize")
            .spawn(move |_| async move { set.finalize((TestMerkleized,)).await });
        let (_, snapshot, second) = blocked_on(&context, Box::pin(next))
            .await
            .unwrap_or_else(|_| panic!("an unpublished generation delayed the writer"))
            .unwrap();
        let staged_second = publisher.stage(snapshot);

        // Durability publishes, in order.
        release(&flushes, first).await;
        staged.install();
        assert_eq!(source.latest().unwrap().generation(), 0);
        release(&flushes, second).await;
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
        let (set, flushes) = parked_set();
        let (mut publisher, source) = Publisher::new(&context);
        let (set, snapshot, barrier) = set.finalize((TestMerkleized,)).await;
        let staged = publisher.stage(snapshot);
        release(&flushes, barrier).await;
        staged.install();

        // A serve clones the published generation and parks mid assembly.
        let served = source.latest().unwrap();
        let (io_done, io_gate) = oneshot::channel();
        let serve = context.child("serve").spawn(move |_| async move {
            let generation = served.generation();
            let _ = io_gate.await;
            (generation, served)
        });

        // The parked serve shares nothing with the writer, so the next
        // finalize and publication proceed without delay.
        let next = context
            .child("finalize")
            .spawn(move |_| async move { set.finalize((TestMerkleized,)).await });
        let (_, snapshot, barrier) = blocked_on(&context, Box::pin(next))
            .await
            .unwrap_or_else(|_| panic!("a parked serve delayed the writer"))
            .unwrap();
        let staged = publisher.stage(snapshot);
        release(&flushes, barrier).await;
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
