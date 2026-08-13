//! Loom models for the pool's publication, park/wake, and completion protocols.
//!
//! Each model constructs a real `Parked` pool inside `loom::model`, so loom explores the
//! shipped park/wake/pin transitions (the sync facade routes every primitive through loom
//! here). Models are kept tiny -- one or two workers, one or two items -- to bound the
//! state space.
//!
//! Race coverage (numbering per the plan):
//! - Races 1/2/3/7 (submit-vs-park, spurious wakes, wake claiming, registration
//!   withdrawal) and the sync-caller half of race 5 are all interleavings of
//!   [`loom_map_completes`] and [`loom_concurrent_submitters`].
//! - Race 4 (shutdown vs parked worker): [`loom_shutdown_with_parked_worker`].
//! - Race 6 (caller-only completion): explored within [`loom_map_completes`] whenever the
//!   scheduler never runs the worker.
//! - Race 8 (overflow never blocks) is deterministic logic and covered by unit tests.
//! - Race 9 (pin acquisition vs unpublish): [`loom_slot_reuse_does_not_touch_dead_frame`].

use super::*;
use loom::sync::atomic::{AtomicBool as LoomBool, Ordering as LoomOrdering};

fn parked(workers: usize) -> Parked {
    Parked::new(NonZeroUsize::new(workers).unwrap())
}

#[test]
fn loom_map_completes() {
    loom::model(|| {
        let strategy = parked(1);
        let out = strategy.manual().map_collect_vec(0..2u64, |i| i + 1);
        assert_eq!(out, vec![1, 2]);
        drop(strategy); // shutdown: parked worker must observe it and exit
    });
}

#[test]
fn loom_slot_reuse_does_not_touch_dead_frame() {
    loom::model(|| {
        let strategy = parked(1);
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
    loom::model(|| {
        // No jobs: the worker parks (search window is zero under loom); dropping the
        // strategy must wake it and let it exit, on every interleaving.
        let strategy = parked(1);
        drop(strategy);
    });
}

#[test]
fn loom_concurrent_submitters() {
    loom::model(|| {
        let strategy = parked(1);
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
