use super::{
    Alarm, AlarmInitError, Batch, Deadline, DriverFailure, DriverSignal, ENTRY_CANCELED,
    ENTRY_FAILED, ENTRY_FIRED, ENTRY_STOPPED, ENTRY_WAITING, Entry, NOT_IN_HEAP, Shard,
    ShardLifecycle,
};
use crate::utils::{Panicker, extract_panic_message};
use loom::{
    future::block_on,
    model,
    sync::{
        Arc as LoomArc, Mutex as LoomMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};
use std::{
    future::{Future, pending},
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

/// Future adapter that polls the production timer entry.
struct EntryFuture {
    /// Entry shared with the completing thread.
    entry: LoomArc<Entry>,
}

impl Future for EntryFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.entry.poll(context)
    }
}

/// Native-alarm state exposed to the forced rearm interleaving.
struct ModelAlarmState {
    /// Deadline most recently installed at the alarm boundary.
    armed: LoomMutex<Option<Deadline>>,
    /// Whether the first arm has reached the syscall boundary.
    first_arm_started: AtomicBool,
    /// Whether the concurrent shard update has completed.
    update_finished: AtomicBool,
}

impl ModelAlarmState {
    /// Creates an alarm that pauses its first arm until a producer updates the shard.
    fn new() -> Self {
        Self {
            armed: LoomMutex::new(None),
            first_arm_started: AtomicBool::new(false),
            update_finished: AtomicBool::new(false),
        }
    }

    /// Waits until rearm reaches its first native arm.
    fn wait_for_first_arm(&self) {
        while !self.first_arm_started.load(Ordering::Acquire) {
            thread::yield_now();
        }
    }

    /// Releases the first native arm after publishing the shard update.
    fn finish_update(&self) {
        self.update_finished.store(true, Ordering::Release);
    }

    /// Returns the deadline currently installed at the modeled native boundary.
    fn armed(&self) -> Option<Deadline> {
        *self.armed.lock().expect("modeled alarm mutex poisoned")
    }

    /// Installs a sentinel native state without exercising the arm protocol.
    fn set_armed(&self, deadline: Deadline) {
        *self.armed.lock().expect("modeled alarm mutex poisoned") = Some(deadline);
    }
}

/// Alarm stub that leaves all synchronization in the production shard code.
struct ModelAlarm {
    /// Narrow replacement for the native arm, disarm, and clock boundary.
    state: LoomArc<ModelAlarmState>,
}

impl Alarm for ModelAlarm {
    const PLATFORM: &'static str = "loom";

    fn new(_shard: usize) -> Result<Self, AlarmInitError> {
        unreachable!("Loom tests construct the modeled alarm directly")
    }

    fn max_deadline(&self) -> Deadline {
        deadline(u64::MAX)
    }

    fn now(&self) -> io::Result<Deadline> {
        Ok(deadline(0))
    }

    fn arm(&self, deadline: Deadline) -> io::Result<()> {
        *self
            .state
            .armed
            .lock()
            .expect("modeled alarm mutex poisoned") = Some(deadline);

        // Force the producer update into the real rearm syscall window. Later
        // convergence arms proceed without additional coordination.
        if !self.state.first_arm_started.swap(true, Ordering::AcqRel) {
            while !self.state.update_finished.load(Ordering::Acquire) {
                thread::yield_now();
            }
        }
        Ok(())
    }

    fn disarm(&self) -> io::Result<()> {
        *self
            .state
            .armed
            .lock()
            .expect("modeled alarm mutex poisoned") = None;
        Ok(())
    }

    fn wait(&self) -> impl Future<Output = io::Result<()>> + Send {
        pending()
    }
}

/// Concurrent update forced into one production rearm operation.
#[derive(Clone, Copy)]
enum RearmUpdate {
    /// Remove the final entry.
    Disarm,
    /// Move 50 nanoseconds earlier within the rearm tolerance.
    Tolerated,
    /// Move 51 nanoseconds earlier beyond the rearm tolerance.
    Earlier,
    /// Remove the minimum and expose a later entry.
    Later,
    /// Stop the shard while its native arm is in progress.
    Stop,
}

/// Constructs one compact monotonic deadline.
const fn deadline(nanoseconds: u64) -> Deadline {
    Deadline::from_duration(Duration::from_nanos(nanoseconds))
}

/// Extracts a successful driver result without requiring failure Debug output.
fn driver_ok<T>(result: Result<T, DriverFailure>) -> T {
    result.unwrap_or_else(|_| panic!("modeled timer driver operation failed"))
}

/// Constructs one production shard around the narrow modeled alarm boundary.
fn model_shard() -> (Arc<Shard<ModelAlarm>>, LoomArc<ModelAlarmState>) {
    let alarm_state = LoomArc::new(ModelAlarmState::new());
    let alarm = ModelAlarm {
        state: LoomArc::clone(&alarm_state),
    };
    let (panicker, _panicked) = Panicker::new(true);
    // Loom 0.7 has no Weak model, so shard lifetime remains in std Arc while
    // every state transition, mutex, waker, and heap entry is Loom-backed.
    (Arc::new(Shard::new(0, alarm, panicker)), alarm_state)
}

#[test]
fn production_entry_poll_cannot_lose_firing_wake() {
    model(|| {
        // Race the production Entry poll protocol against its firing transition.
        let entry = LoomArc::new(Entry::new());
        let completer = {
            let mut batch = Batch::new();
            batch.entries.push(LoomArc::clone(&entry));
            thread::spawn(move || {
                assert!(batch.complete(ENTRY_FIRED).is_none());
            })
        };
        block_on(EntryFuture {
            entry: LoomArc::clone(&entry),
        });
        completer.join().unwrap();

        // Either state check or the registered production AtomicWaker must
        // complete the future, with firing as the only terminal state.
        assert_eq!(entry.state.load(Ordering::Acquire), ENTRY_FIRED);
    });
}

#[test]
fn production_entry_poll_observes_failure_without_retaining_waker() {
    model(|| {
        // Race the production Entry poll protocol against failure completion.
        let entry = LoomArc::new(Entry::new());
        let completer = {
            let mut batch = Batch::new();
            batch.entries.push(LoomArc::clone(&entry));
            thread::spawn(move || {
                assert!(batch.complete(ENTRY_FAILED).is_none());
            })
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            block_on(EntryFuture {
                entry: LoomArc::clone(&entry),
            });
        }));
        completer.join().unwrap();

        // Every interleaving must observe failure as an unwind and release a
        // waker registered between the two production state checks.
        let panic = outcome.expect_err("modeled failed entry completed without unwinding");
        assert_eq!(
            extract_panic_message(&*panic),
            "high-resolution timer service failed"
        );
        assert_eq!(entry.state.load(Ordering::Acquire), ENTRY_FAILED);
        assert!(entry.take_waker().is_none());
    });
}

#[test]
fn production_entry_poll_observes_stop_without_retaining_waker() {
    model(|| {
        // Race one production poll against orderly shutdown completion.
        let entry = LoomArc::new(Entry::new());
        let poller = {
            let entry = LoomArc::clone(&entry);
            thread::spawn(move || {
                let waker = futures::task::noop_waker();
                let mut context = Context::from_waker(&waker);
                assert_eq!(entry.poll(&mut context), Poll::Pending);
            })
        };
        let completer = {
            let mut batch = Batch::new();
            batch.entries.push(LoomArc::clone(&entry));
            thread::spawn(move || {
                assert!(batch.complete(ENTRY_STOPPED).is_none());
            })
        };
        poller.join().unwrap();
        completer.join().unwrap();

        // Every interleaving leaves the stopped future quiescent and releases
        // a waker installed between the production state checks.
        assert_eq!(entry.state.load(Ordering::Acquire), ENTRY_STOPPED);
        assert!(entry.take_waker().is_none());
    });
}

#[test]
fn production_entry_has_exactly_one_terminal_winner() {
    model(|| {
        // Race every legal terminal transition through Entry::transition.
        let entry = LoomArc::new(Entry::new());
        let contenders: Vec<_> = [ENTRY_FIRED, ENTRY_CANCELED, ENTRY_FAILED]
            .into_iter()
            .map(|terminal| {
                let entry = LoomArc::clone(&entry);
                thread::spawn(move || (entry.transition(terminal), terminal))
            })
            .collect();
        let outcomes: Vec<_> = contenders
            .into_iter()
            .map(|contender| contender.join().unwrap())
            .collect();

        // One compare-exchange wins and both losing attempts preserve its state.
        let terminal = entry.state.load(Ordering::Acquire);
        assert_eq!(outcomes.iter().filter(|(won, _)| *won).count(), 1);
        assert!(
            outcomes
                .iter()
                .any(|(won, state)| *won && *state == terminal)
        );
        assert_ne!(terminal, ENTRY_WAITING);
    });
}

#[test]
fn production_stop_races_other_terminal_transitions() {
    for other in [ENTRY_FIRED, ENTRY_CANCELED, ENTRY_FAILED] {
        model(move || {
            // Race orderly stop against one other legal production transition.
            let entry = LoomArc::new(Entry::new());
            let stopper = {
                let entry = LoomArc::clone(&entry);
                thread::spawn(move || entry.transition(ENTRY_STOPPED))
            };
            let contender = {
                let entry = LoomArc::clone(&entry);
                thread::spawn(move || entry.transition(other))
            };
            let stopped = stopper.join().unwrap();
            let other_won = contender.join().unwrap();

            // Exactly one transition wins and its terminal value remains published.
            assert_ne!(stopped, other_won);
            let terminal = entry.state.load(Ordering::Acquire);
            assert_eq!(terminal, if stopped { ENTRY_STOPPED } else { other });
        });
    }
}

#[test]
fn production_registered_sleep_drop_races_driver_completion() {
    model(|| {
        // Setup: Register one immediately expired sleep through the production shard.
        let (shard, _alarm) = model_shard();
        let sleep = shard.register_after(Duration::ZERO);
        let entry = LoomArc::clone(&sleep.entry);

        // Action: Race RegisteredSleep::drop against the driver's production
        // heap-pop and batch-completion sequence.
        let dropper = thread::spawn(move || drop(sleep));
        let driver = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || {
                let mut batch = Batch::new();
                assert!(!driver_ok(shard.take_expired(&mut batch)));
                assert!(shard.complete_batch(&mut batch, ENTRY_FIRED).is_none());
            })
        };
        dropper.join().unwrap();
        driver.join().unwrap();

        // Assertion: Either legal terminal winner leaves no resident or
        // in-flight entry and publishes the nonresident heap index.
        assert!(matches!(
            entry.state.load(Ordering::Acquire),
            ENTRY_CANCELED | ENTRY_FIRED
        ));
        let state = shard.state.lock();
        assert_eq!(state.entries.len(), 0);
        assert!(state.in_flight.is_empty());
        assert_eq!(entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
    });
}

#[test]
fn production_driver_signal_coalesces_and_cannot_lose_registration_race() {
    model(|| {
        // Two notifications before a wait coalesce in the production signal.
        let signal = LoomArc::new(DriverSignal::new());
        signal.notify();
        signal.notify();
        assert!(signal.is_notified());
        block_on(signal.wait());
        assert!(!signal.is_notified());

        // Race a published payload and notification against the production
        // consume-register-consume wait protocol.
        let payload = LoomArc::new(AtomicUsize::new(0));
        let producer = {
            let signal = LoomArc::clone(&signal);
            let payload = LoomArc::clone(&payload);
            thread::spawn(move || {
                payload.store(7, Ordering::Relaxed);
                signal.notify();
            })
        };
        block_on(signal.wait());

        // The signal's Release and Acquire operations must publish producer
        // writes in addition to preventing a lost wake.
        assert_eq!(payload.load(Ordering::Relaxed), 7);
        producer.join().unwrap();
        assert!(!signal.is_notified());
    });
}

#[test]
fn production_rearm_does_not_touch_native_alarm_after_prior_stop() {
    model(|| {
        // Leave a sentinel native arm behind, then stop through the production
        // lifecycle path before rearm snapshots shard state.
        let (shard, alarm) = model_shard();
        let sentinel = deadline(777);
        alarm.set_armed(sentinel);
        let entry = LoomArc::new(Entry::new());
        shard.register(deadline(100), LoomArc::clone(&entry));
        shard.stop();
        assert_eq!(entry.state.load(Ordering::Acquire), ENTRY_STOPPED);

        // Teardown owns native resource cleanup once stop is already visible.
        // Rearm must return without issuing either an arm or disarm operation.
        assert!(shard.rearm().is_ok());
        assert_eq!(alarm.armed(), Some(sentinel));
    });
}

#[test]
fn production_rearm_converges_across_concurrent_shard_updates() {
    for update in [
        RearmUpdate::Disarm,
        RearmUpdate::Tolerated,
        RearmUpdate::Earlier,
        RearmUpdate::Later,
        RearmUpdate::Stop,
    ] {
        model(move || {
            // Register the initial minimum through the complete production path.
            let (shard, alarm) = model_shard();
            let first = shard.register_after(Duration::from_nanos(100));
            let first_entry = LoomArc::clone(&first.entry);
            if matches!(update, RearmUpdate::Later) {
                shard.register(deadline(150), LoomArc::new(Entry::new()));
            }

            // Force one heap or lifecycle update while rearm is outside the
            // production shard mutex in ModelAlarm::arm.
            let producer = {
                let shard = Arc::clone(&shard);
                let alarm = LoomArc::clone(&alarm);
                thread::spawn(move || {
                    alarm.wait_for_first_arm();
                    match update {
                        RearmUpdate::Disarm | RearmUpdate::Later => {}
                        RearmUpdate::Tolerated => {
                            shard.register(deadline(50), LoomArc::new(Entry::new()));
                        }
                        RearmUpdate::Earlier => {
                            shard.register(deadline(49), LoomArc::new(Entry::new()));
                        }
                        RearmUpdate::Stop => shard.stop(),
                    }
                    // Exercise RegisteredSleep::drop rather than reproducing its
                    // transition and shard-removal sequence in this model.
                    drop(first);
                    alarm.finish_update();
                })
            };
            assert!(shard.rearm().is_ok());
            producer.join().unwrap();

            // The single production rearm call must converge to the update
            // that raced its first native operation.
            let state = shard.state.lock();
            let desired = state.entries.peek().map(|item| item.deadline);
            match update {
                RearmUpdate::Disarm => {
                    assert_eq!(desired, None);
                    assert_eq!(state.armed_deadline, None);
                    assert_eq!(alarm.armed(), None);
                }
                RearmUpdate::Tolerated => {
                    assert_eq!(desired, Some(deadline(50)));
                    assert_eq!(state.armed_deadline, Some(deadline(100)));
                    assert_eq!(alarm.armed(), Some(deadline(100)));
                }
                RearmUpdate::Earlier => {
                    assert_eq!(desired, Some(deadline(49)));
                    assert_eq!(state.armed_deadline, Some(deadline(49)));
                    assert_eq!(alarm.armed(), Some(deadline(49)));
                }
                RearmUpdate::Later => {
                    assert_eq!(desired, Some(deadline(150)));
                    assert_eq!(state.armed_deadline, Some(deadline(150)));
                    assert_eq!(alarm.armed(), Some(deadline(150)));
                }
                RearmUpdate::Stop => {
                    assert_eq!(state.lifecycle, ShardLifecycle::Stopped);
                    assert_eq!(desired, None);
                    assert_eq!(state.armed_deadline, None);
                    assert_eq!(alarm.armed(), None);
                }
            }
            let expected = if matches!(update, RearmUpdate::Stop) {
                ENTRY_STOPPED
            } else {
                ENTRY_CANCELED
            };
            assert_eq!(first_entry.state.load(Ordering::Acquire), expected);
        });
    }
}
