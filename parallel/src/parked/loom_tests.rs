//! Loom models for the pool's publication, park/wake, and completion protocols.
//!
//! Each model constructs a real `Parked` pool inside `loom::model`, so loom explores the
//! shipped park/wake/pin transitions (the sync facade routes every primitive through loom
//! here). Every model overrides the planning parallelism to 2 with a SINGLE worker: the
//! policy's parallel arm engages (with the pool's own parallelism of 1, every operation
//! would take the Serial arm and the models would explore nothing), while the explored
//! thread count stays small.
//!
//! Race coverage (numbering per the plan):
//! - Races 1/2 (submit-vs-park, spurious wakes) and the sync-caller half of race 5 are
//!   interleavings of [`loom_map_completes`] and [`loom_concurrent_submitters`].
//! - Races 3/7 (wake claiming, registration withdrawal) require a nonzero wake budget and
//!   are exercised by [`loom_wake_dispatch`] (two workers, so `wake` runs its CAS loop).
//! - Race 4 (shutdown vs parked worker): [`loom_shutdown_with_parked_worker`].
//! - Race 6 (caller-only completion): explored within [`loom_map_completes`] whenever the
//!   scheduler never runs the worker.
//! - Race 8 (overflow never blocks) is deterministic logic, covered by
//!   `tests::test_nested_submission_and_overflow_inline`.
//! - Race 9 (pin acquisition vs unpublish): [`loom_slot_reuse_does_not_touch_dead_frame`].
//! - Close-vs-claim backout (the executing-before-claim protocol):
//!   [`loom_error_close_backout`].

use super::*;
use loom::sync::atomic::{AtomicBool as LoomBool, Ordering as LoomOrdering};

/// Runs a loom model with a preemption bound of 3. Unbounded exploration of the pool's
/// schedule space (worker scan loops over 4 slots x SeqCst ops x condvar parkers) is
/// intractable; bound 3 exceeds the preemption depth of both protocol bugs found to date
/// (the SeqCst-fence omission needed 2) while keeping each model in seconds.
fn model<F: Fn() + Sync + Send + 'static>(f: F) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(f);
}

/// One worker, parallelism 2: parallel arms engage, loom explores worker + caller.
fn parked() -> Parked {
    Parked::new(NonZeroUsize::new(1).unwrap()).with_parallelism(NonZeroUsize::new(2).unwrap())
}

#[test]
fn loom_map_completes() {
    model(|| {
        let strategy = parked();
        let out = strategy.manual().map_collect_vec(0..2u64, |i| i + 1);
        assert_eq!(out, vec![1, 2]);
        drop(strategy); // shutdown: parked worker must observe it and exit
    });
}

#[test]
fn loom_slot_reuse_does_not_touch_dead_frame() {
    model(|| {
        let strategy = parked();
        // Job 1's frame-liveness flag: the body asserts it; the flag is cleared as soon as
        // the scoped run returns. A worker that pinned the slot late (between observing it
        // and validating) must never execute job 1's body after that point.
        let alive = loom::sync::Arc::new(LoomBool::new(true));
        {
            let alive = loom::sync::Arc::clone(&alive);
            let manual = strategy.manual();
            let out = manual.map_collect_vec(0..1u64, move |i| {
                assert!(
                    alive.load(LoomOrdering::SeqCst),
                    "body ran after frame death"
                );
                i
            });
            assert_eq!(out, vec![0]);
        }
        alive.store(false, LoomOrdering::SeqCst);
        // Job 2 reuses the slot; a stale pin from job 1's era must not reach job 1's body.
        let out = strategy.manual().map_collect_vec(0..1u64, |i| i + 10);
        assert_eq!(out, vec![10]);
        drop(strategy);
    });
}

#[test]
fn loom_shutdown_with_parked_worker() {
    model(|| {
        // No jobs: the worker parks (search window is zero under loom); dropping the
        // strategy must wake it and let it exit, on every interleaving.
        let strategy = parked();
        drop(strategy);
    });
}

#[test]
fn loom_concurrent_submitters() {
    model(|| {
        let strategy = parked();
        let other = strategy.clone();
        let t = loom::thread::spawn(move || {
            let out = other.manual().map_collect_vec(0..1u64, |i| i + 100);
            assert_eq!(out, vec![100]);
        });
        let out = strategy.manual().map_collect_vec(0..1u64, |i| i + 200);
        assert_eq!(out, vec![200]);
        t.join().unwrap();
        drop(strategy);
    });
}

#[test]
fn loom_wake_dispatch() {
    model(|| {
        // Two workers and a two-chunk job (MIN_CHUNK=1 under loom): the wake budget is
        // nonzero, so the submitter's CAS claim of a REGISTERED worker, the claimant-side
        // idle_count decrement, the token deposit, and the failed-withdraw/stale-token
        // paths are all explored, together with two executors concurrently inside one
        // job (was_last arbitration, concurrent completed accumulation).
        let strategy = Parked::new(NonZeroUsize::new(2).unwrap());
        let out = strategy.manual().map_collect_vec(0..2u64, |i| i + 1);
        assert_eq!(out, vec![1, 2]);
        drop(strategy);
    });
}

#[test]
fn loom_spawn_completes_and_detached_runs() {
    model(|| {
        // Async-awaiter waiter type (race 5) + detached completion: one awaited spawn and
        // one dropped-future spawn must both execute, on every interleaving, and shutdown
        // must drain whatever the worker has not yet taken.
        let strategy = Parked::new(NonZeroUsize::new(2).unwrap());
        let ran = loom::sync::Arc::new(LoomBool::new(false));
        {
            let ran = loom::sync::Arc::clone(&ran);
            drop(strategy.spawn(move |_| ran.store(true, LoomOrdering::SeqCst)));
        }
        let out = futures::executor::block_on(strategy.spawn(|_| 5u8));
        assert_eq!(out, 5);
        drop(strategy); // shutdown drains the detached job if no worker took it
        assert!(ran.load(LoomOrdering::SeqCst));
    });
}

#[test]
fn loom_error_close_backout() {
    model(|| {
        // One item errors while the other may be claimed by the worker: the close must
        // prevent any post-close claim (executing-before-claim protocol), the latch must
        // wait for the in-flight chunk, and the caller must observe the error after full
        // quiescence, on every interleaving.
        let strategy = parked();
        let result: Result<Vec<u64>, &'static str> = strategy
            .manual()
            .try_map_collect_vec(0..2u64, |i| if i == 0 { Err("boom") } else { Ok(i) });
        assert_eq!(result.unwrap_err(), "boom");
        drop(strategy);
    });
}
