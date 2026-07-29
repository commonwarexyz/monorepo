use super::{ENTRY_CANCELED, ENTRY_FAILED, ENTRY_FIRED, ENTRY_WAITING};
use loom::{
    model,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    thread,
};

/// Latches one notification and records its false-to-true wake call.
fn notify(notified: &AtomicBool, edges: &AtomicUsize, wakes: &AtomicUsize) {
    if !notified.swap(true, Ordering::Release) {
        edges.fetch_add(1, Ordering::Relaxed);
        wakes.fetch_add(1, Ordering::Release);
    }
}

/// Runs the signal's consume, register, and consume wait protocol.
fn consume_notification(
    notified: &AtomicBool,
    registered: &AtomicBool,
    parked: &AtomicBool,
    wakes: &AtomicUsize,
) {
    if notified.swap(false, Ordering::AcqRel) {
        return;
    }
    let prior_wakes = wakes.load(Ordering::Acquire);
    registered.store(true, Ordering::Release);
    if notified.swap(false, Ordering::AcqRel) {
        registered.store(false, Ordering::Release);
        return;
    }

    // A real task returns pending here, then resumes after the registered wake.
    parked.store(true, Ordering::Release);
    while wakes.load(Ordering::Acquire) == prior_wakes {
        thread::yield_now();
    }
    assert!(notified.swap(false, Ordering::AcqRel));
    registered.store(false, Ordering::Release);
}

/// State protected by the production shard mutex during rearm.
struct RearmState {
    /// Deadline currently desired by the heap.
    desired: Option<u64>,
    /// Deadline last recorded as armed.
    armed: Option<u64>,
    /// Whether teardown invalidated ordinary driver work.
    stopped: bool,
}

/// Concurrent heap or lifecycle update explored by the rearm model.
#[derive(Clone, Copy)]
enum RearmUpdate {
    /// Remove the final entry.
    Disarm,
    /// Move 50 ns earlier within tolerance.
    Tolerated,
    /// Move 51 ns earlier beyond tolerance.
    Earlier,
    /// Move the minimum later.
    Later,
    /// Stop while an arm may be outside the lock.
    Stop,
}

/// Mirrors the service's one-sided 50 ns coverage rule.
fn arm_covers(armed: Option<u64>, desired: Option<u64>) -> bool {
    match (armed, desired) {
        (None, None) => true,
        (Some(armed), Some(desired)) if armed == desired => true,
        (Some(armed), Some(desired)) if desired < armed => armed - desired <= 50,
        _ => false,
    }
}

/// Performs one snapshot, native update, and convergence recheck.
fn rearm_once(state: &Mutex<RearmState>, native_arm: &Mutex<Option<u64>>) {
    let (armed, desired, stopped) = {
        let state = state.lock().unwrap();
        (state.armed, state.desired, state.stopped)
    };
    if stopped {
        *native_arm.lock().unwrap() = None;
        return;
    }
    if arm_covers(armed, desired) {
        return;
    }

    // The native update intentionally runs without the state mutex.
    *native_arm.lock().unwrap() = desired;
    thread::yield_now();
    let mut state = state.lock().unwrap();
    if state.stopped {
        state.armed = None;
        drop(state);
        *native_arm.lock().unwrap() = None;
    } else {
        state.armed = desired;
    }
}

#[test]
fn entry_poll_and_completion_cannot_lose_terminal_wake() {
    for terminal in [ENTRY_FIRED, ENTRY_FAILED] {
        model(move || {
            // Race one poll registration against each completion transition.
            let state = Arc::new(AtomicU8::new(ENTRY_WAITING));
            let registered = Arc::new(Mutex::new(false));
            let observed_terminal = Arc::new(AtomicBool::new(false));
            let wakes = Arc::new(AtomicUsize::new(0));
            let completer = {
                let state = Arc::clone(&state);
                let registered = Arc::clone(&registered);
                let wakes = Arc::clone(&wakes);
                thread::spawn(move || {
                    assert!(
                        state
                            .compare_exchange(
                                ENTRY_WAITING,
                                terminal,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                    );
                    let mut registered = registered.lock().unwrap();
                    if *registered {
                        *registered = false;
                        wakes.fetch_add(1, Ordering::Relaxed);
                    }
                })
            };

            // Model the future's check, register, and second-check sequence.
            if state.load(Ordering::Acquire) == ENTRY_WAITING {
                *registered.lock().unwrap() = true;
                if state.load(Ordering::Acquire) != ENTRY_WAITING {
                    *registered.lock().unwrap() = false;
                    observed_terminal.store(true, Ordering::Release);
                }
            } else {
                observed_terminal.store(true, Ordering::Release);
            }
            completer.join().unwrap();

            // Completion is visible either directly or through the registered wake.
            assert_eq!(state.load(Ordering::Acquire), terminal);
            assert!(
                observed_terminal.load(Ordering::Acquire) || wakes.load(Ordering::Acquire) == 1
            );
            assert!(!*registered.lock().unwrap());
        });
    }
}

#[test]
fn entry_has_exactly_one_fire_cancel_or_failure_winner() {
    model(|| {
        // Race every legal terminal transition against one WAITING entry.
        let state = Arc::new(AtomicU8::new(ENTRY_WAITING));
        let mut contenders = Vec::new();
        for terminal in [ENTRY_FIRED, ENTRY_CANCELED, ENTRY_FAILED] {
            let state = Arc::clone(&state);
            contenders.push(thread::spawn(move || {
                match state.compare_exchange(
                    ENTRY_WAITING,
                    terminal,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => (true, terminal),
                    Err(observed) => (false, observed),
                }
            }));
        }

        // One transition wins and both losers leave the terminal state unchanged.
        let outcomes: Vec<_> = contenders
            .into_iter()
            .map(|contender| contender.join().unwrap())
            .collect();
        let terminal = state.load(Ordering::Acquire);
        assert_eq!(outcomes.iter().filter(|(won, _)| *won).count(), 1);
        assert_eq!(outcomes.iter().filter(|(won, _)| !*won).count(), 2);
        assert!(
            outcomes
                .iter()
                .filter(|(won, _)| !*won)
                .all(|(_, observed)| *observed == terminal)
        );
        assert_ne!(terminal, ENTRY_WAITING);
    });
}

#[test]
fn signal_registration_races_coalescing_and_renotification_are_durable() {
    model(|| {
        // Start two concurrent producers before the driver consumes either signal.
        let notified = Arc::new(AtomicBool::new(false));
        let registered = Arc::new(AtomicBool::new(false));
        let published = Arc::new(AtomicUsize::new(0));
        let edges = Arc::new(AtomicUsize::new(0));
        let wakes = Arc::new(AtomicUsize::new(0));
        let mut producers = Vec::new();
        for publication in [1, 2] {
            let notified = Arc::clone(&notified);
            let published = Arc::clone(&published);
            let edges = Arc::clone(&edges);
            let wakes = Arc::clone(&wakes);
            producers.push(thread::spawn(move || {
                published.fetch_or(publication, Ordering::Relaxed);
                notify(&notified, &edges, &wakes);
            }));
        }
        for producer in producers {
            producer.join().unwrap();
        }

        // Both first-phase publications coalesce into one false-to-true edge.
        assert_eq!(published.load(Ordering::Acquire), 3);
        assert_eq!(edges.load(Ordering::Acquire), 1);
        assert_eq!(wakes.load(Ordering::Acquire), 1);
        let first_parked = AtomicBool::new(false);
        consume_notification(&notified, &registered, &first_parked, &wakes);
        assert!(!first_parked.load(Ordering::Acquire));

        // Race a new notification against the driver's full registration protocol.
        let post_producer = {
            let notified = Arc::clone(&notified);
            let published = Arc::clone(&published);
            let edges = Arc::clone(&edges);
            let wakes = Arc::clone(&wakes);
            thread::spawn(move || {
                published.fetch_or(4, Ordering::Relaxed);
                notify(&notified, &edges, &wakes);
            })
        };
        let second_parked = AtomicBool::new(false);
        consume_notification(&notified, &registered, &second_parked, &wakes);

        // Acquire consumption observes publication before thread join can synchronize it.
        assert_eq!(published.load(Ordering::Acquire), 7);
        post_producer.join().unwrap();

        // Re-notification creates one new edge and one new wake call.
        assert_eq!(edges.load(Ordering::Acquire), 2);
        assert_eq!(wakes.load(Ordering::Acquire), 2);

        // Re-notification leaves no stale signal or registered waiter.
        assert!(!notified.load(Ordering::Acquire));
        assert!(!registered.load(Ordering::Acquire));
    });
}

#[test]
fn rearm_converges_across_disarm_tolerance_and_shutdown() {
    for update in [
        RearmUpdate::Disarm,
        RearmUpdate::Tolerated,
        RearmUpdate::Earlier,
        RearmUpdate::Later,
        RearmUpdate::Stop,
    ] {
        model(move || {
            // Begin with 100 ns desired and an in-progress arm only for shutdown.
            let initial_arm = if matches!(update, RearmUpdate::Stop) {
                None
            } else {
                Some(100)
            };
            let state = Arc::new(Mutex::new(RearmState {
                desired: Some(100),
                armed: initial_arm,
                stopped: false,
            }));
            let native_arm = Arc::new(Mutex::new(initial_arm));
            let producer = {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    thread::yield_now();
                    let mut state = state.lock().unwrap();
                    match update {
                        RearmUpdate::Disarm => state.desired = None,
                        RearmUpdate::Tolerated => state.desired = Some(50),
                        RearmUpdate::Earlier => state.desired = Some(49),
                        RearmUpdate::Later => state.desired = Some(150),
                        RearmUpdate::Stop => {
                            state.desired = None;
                            state.armed = None;
                            state.stopped = true;
                        }
                    }
                })
            };

            // Race one rearm attempt with the update, then converge after it quiesces.
            rearm_once(&state, &native_arm);
            producer.join().unwrap();
            rearm_once(&state, &native_arm);

            // Every update must end in its precise covered or disarmed state.
            let state = state.lock().unwrap();
            match update {
                RearmUpdate::Disarm => {
                    assert_eq!(state.desired, None);
                    assert_eq!(state.armed, None);
                    assert_eq!(*native_arm.lock().unwrap(), None);
                }
                RearmUpdate::Tolerated => {
                    assert_eq!(state.desired, Some(50));
                    assert_eq!(state.armed, Some(100));
                    assert_eq!(*native_arm.lock().unwrap(), Some(100));
                }
                RearmUpdate::Earlier => {
                    assert_eq!(state.desired, Some(49));
                    assert_eq!(state.armed, Some(49));
                    assert_eq!(*native_arm.lock().unwrap(), Some(49));
                }
                RearmUpdate::Later => {
                    assert_eq!(state.desired, Some(150));
                    assert_eq!(state.armed, Some(150));
                    assert_eq!(*native_arm.lock().unwrap(), Some(150));
                }
                RearmUpdate::Stop => {
                    assert!(state.stopped);
                    assert_eq!(state.armed, None);
                    assert_eq!(*native_arm.lock().unwrap(), None);
                }
            }
        });
    }
}
