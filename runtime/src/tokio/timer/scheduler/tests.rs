#[cfg(not(feature = "loom"))]
mod ordinary {
    use super::super::{
        Affinity, Alarm, AssignmentKind, Batch, Deadline, DriverFailure, DriverSignal,
        ENTRY_CANCELED, ENTRY_FAILED, ENTRY_FIRED, ENTRY_STOPPED, ENTRY_WAITING,
        EXPIRY_YIELD_BUDGET, Entry, NOT_IN_HEAP, RegisteredSleep, Shard, ShardLifecycle, Sleep,
        ThreadAssignment, ThreadAssignments, WAKE_BATCH, allocate_runtime_id, register_relative,
        run_driver, run_driver_loop,
    };
    use crate::{
        telemetry::traces::collector::{CollectingLayer, TraceStorage},
        utils::{Panicked, Panicker, extract_panic_message},
    };
    use commonware_utils::sync::Mutex as TestMutex;
    use futures::{
        FutureExt as _, future,
        task::{ArcWake, AtomicWaker, noop_waker, waker},
    };
    use std::{
        io,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc, Barrier, Weak,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
        },
        task::{Context, Poll},
        thread,
        time::{Duration, Instant},
    };
    use tracing_subscriber::{Registry, layer::SubscriberExt as _};

    /// One native alarm operation recorded by [`FakeAlarm`].
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AlarmOperation {
        /// An absolute arm request.
        Arm(Deadline),
        /// A disarm request.
        Disarm,
    }

    /// Shared state controlled by a test and observed by its fake alarm.
    struct FakeAlarmState {
        /// Manual monotonic time in nanoseconds.
        now: AtomicU64,
        /// Number of platform-limit queries made through the alarm.
        max_deadline_reads: AtomicUsize,
        /// Ordered native operations requested by the scheduler.
        operations: TestMutex<Vec<AlarmOperation>>,
        /// One latched readiness event.
        ready: AtomicBool,
        /// One injected monotonic clock failure.
        fail_now: AtomicBool,
        /// One injected arm failure.
        fail_arm: AtomicBool,
        /// One injected disarm failure.
        fail_disarm: AtomicBool,
        /// One injected readiness wait failure.
        fail_wait: AtomicBool,
        /// One injected panic from the readiness wait.
        panic_wait: AtomicBool,
        /// Waker registered by the fake readiness future.
        wait_waker: AtomicWaker,
        /// Number of readiness future polls.
        wait_polls: AtomicUsize,
        /// Whether the alarm owner has been dropped.
        shutdown: AtomicBool,
    }

    impl FakeAlarmState {
        /// Creates an idle fake at monotonic time zero.
        fn new() -> Self {
            Self {
                now: AtomicU64::new(0),
                max_deadline_reads: AtomicUsize::new(0),
                operations: TestMutex::new(Vec::new()),
                ready: AtomicBool::new(false),
                fail_now: AtomicBool::new(false),
                fail_arm: AtomicBool::new(false),
                fail_disarm: AtomicBool::new(false),
                fail_wait: AtomicBool::new(false),
                panic_wait: AtomicBool::new(false),
                wait_waker: AtomicWaker::new(),
                wait_polls: AtomicUsize::new(0),
                shutdown: AtomicBool::new(false),
            }
        }

        /// Consumes a failure or readiness event around waker registration.
        fn poll_wait(&self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.wait_polls.fetch_add(1, AtomicOrdering::Relaxed);
            if self.panic_wait.swap(false, AtomicOrdering::AcqRel) {
                panic!("injected fake alarm wait panic");
            }
            if self.fail_wait.swap(false, AtomicOrdering::AcqRel) {
                return Poll::Ready(Err(injected_error("wait")));
            }
            if self.ready.swap(false, AtomicOrdering::AcqRel) {
                return Poll::Ready(Ok(()));
            }

            self.wait_waker.register(context.waker());
            if self.fail_wait.swap(false, AtomicOrdering::AcqRel) {
                self.wait_waker.take();
                Poll::Ready(Err(injected_error("wait")))
            } else if self.ready.swap(false, AtomicOrdering::AcqRel) {
                self.wait_waker.take();
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    /// Statically dispatched alarm with test-controlled time and outcomes.
    struct FakeAlarm {
        /// State shared with the test control handle.
        state: Arc<FakeAlarmState>,
    }

    impl FakeAlarm {
        /// Creates one alarm and its independent control handle.
        fn controlled() -> (Self, FakeAlarmControl) {
            let state = Arc::new(FakeAlarmState::new());
            (
                Self {
                    state: Arc::clone(&state),
                },
                FakeAlarmControl { state },
            )
        }
    }

    impl Drop for FakeAlarm {
        fn drop(&mut self) {
            self.state.shutdown.store(true, AtomicOrdering::Release);
            self.state.wait_waker.wake();
        }
    }

    impl Alarm for FakeAlarm {
        fn max_deadline(&self) -> Deadline {
            self.state
                .max_deadline_reads
                .fetch_add(1, AtomicOrdering::Relaxed);
            Deadline::from_duration(Duration::from_nanos(u64::MAX))
        }

        fn now(&self) -> io::Result<Deadline> {
            if self.state.fail_now.swap(false, AtomicOrdering::AcqRel) {
                return Err(injected_error("now"));
            }
            Ok(Deadline::from_duration(Duration::from_nanos(
                self.state.now.load(AtomicOrdering::Acquire),
            )))
        }

        fn arm(&self, deadline: Deadline) -> io::Result<()> {
            self.state
                .operations
                .lock()
                .push(AlarmOperation::Arm(deadline));
            if self.state.fail_arm.swap(false, AtomicOrdering::AcqRel) {
                return Err(injected_error("arm"));
            }
            Ok(())
        }

        fn disarm(&self) -> io::Result<()> {
            self.state.operations.lock().push(AlarmOperation::Disarm);
            if self.state.fail_disarm.swap(false, AtomicOrdering::AcqRel) {
                return Err(injected_error("disarm"));
            }
            Ok(())
        }

        async fn wait(&self) -> io::Result<()> {
            future::poll_fn(|context| self.state.poll_wait(context)).await
        }
    }

    /// Test-side controls and observations for one [`FakeAlarm`].
    #[derive(Clone)]
    struct FakeAlarmControl {
        /// State shared with the alarm owned by the shard.
        state: Arc<FakeAlarmState>,
    }

    impl FakeAlarmControl {
        /// Returns the number of times the platform deadline limit was requested.
        fn max_deadline_reads(&self) -> usize {
            self.state.max_deadline_reads.load(AtomicOrdering::Relaxed)
        }

        /// Advances or rewinds the manual monotonic clock.
        fn set_now(&self, deadline: Deadline) {
            let nanoseconds = u64::try_from(deadline.as_duration().as_nanos()).unwrap();
            self.state.now.store(nanoseconds, AtomicOrdering::Release);
        }

        /// Returns all requested arms and disarms in call order.
        fn operations(&self) -> Vec<AlarmOperation> {
            self.state.operations.lock().clone()
        }

        /// Clears previously observed native operations.
        fn clear_operations(&self) {
            self.state.operations.lock().clear();
        }

        /// Injects one readiness event and wakes a pending wait.
        fn inject_readiness(&self) {
            self.state.ready.store(true, AtomicOrdering::Release);
            self.state.wait_waker.wake();
        }

        /// Causes the next clock read to fail.
        fn fail_next_now(&self) {
            self.state.fail_now.store(true, AtomicOrdering::Release);
        }

        /// Causes the next arm to fail.
        fn fail_next_arm(&self) {
            self.state.fail_arm.store(true, AtomicOrdering::Release);
        }

        /// Causes the next disarm to fail.
        fn fail_next_disarm(&self) {
            self.state.fail_disarm.store(true, AtomicOrdering::Release);
        }

        /// Causes the next readiness wait to fail.
        fn fail_next_wait(&self) {
            self.state.fail_wait.store(true, AtomicOrdering::Release);
            self.state.wait_waker.wake();
        }

        /// Causes the next readiness wait poll to panic.
        fn panic_next_wait(&self) {
            self.state.panic_wait.store(true, AtomicOrdering::Release);
            self.state.wait_waker.wake();
        }

        /// Waits cooperatively until the driver polls native readiness.
        async fn wait_until_wait_polled(&self) {
            for _ in 0..10_000 {
                if self.state.wait_polls.load(AtomicOrdering::Acquire) > 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("fake alarm readiness future was not polled");
        }

        /// Reports whether the shard-owned alarm has been dropped.
        fn is_shutdown(&self) -> bool {
            self.state.shutdown.load(AtomicOrdering::Acquire)
        }
    }

    /// Waker that deliberately unwinds when invoked.
    struct PanickingWaker;

    impl ArcWake for PanickingWaker {
        fn wake_by_ref(_arc_self: &Arc<Self>) {
            panic!("injected waker panic");
        }
    }

    /// Waker that records every invocation.
    struct CountingWaker {
        /// Number of wake callbacks observed.
        wakes: AtomicUsize,
    }

    impl ArcWake for CountingWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.wakes.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    /// Waker that simulates an awakened task reporting its generic failure panic.
    struct NotifyPanickerWaker {
        /// Root interruption handle used by the simulated task wrapper.
        panicker: Panicker,
        /// Whether failure cleanup invoked this callback.
        notified: AtomicBool,
    }

    impl ArcWake for NotifyPanickerWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.notified.store(true, AtomicOrdering::Release);
            arc_self
                .panicker
                .notify(Box::new("generic failed sleeper panic"));
        }
    }

    /// Waker that verifies the shard mutex is available during callbacks.
    struct LockCheckingWaker {
        /// Shard whose state lock must not be held.
        shard: Arc<Shard<FakeAlarm>>,
        /// Whether the callback acquired the state lock.
        acquired: AtomicBool,
    }

    impl ArcWake for LockCheckingWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            let acquired = arc_self.shard.state.try_lock().is_some();
            arc_self.acquired.store(acquired, AtomicOrdering::Release);
        }
    }

    /// Waker whose destructor tries to re-enter the shard state lock.
    struct ReentrantDropWaker {
        /// Shard revisited when the final waker reference is dropped.
        shard: Weak<Shard<FakeAlarm>>,
        /// Whether destructor re-entry acquired the shard lock.
        acquired: Arc<AtomicBool>,
    }

    impl ArcWake for ReentrantDropWaker {
        fn wake_by_ref(_arc_self: &Arc<Self>) {}
    }

    impl Drop for ReentrantDropWaker {
        fn drop(&mut self) {
            if let Some(shard) = self.shard.upgrade() {
                let acquired = shard.state.try_lock().is_some();
                self.acquired.store(acquired, AtomicOrdering::Release);
            }
        }
    }

    /// Waker whose destructor records its release and then unwinds.
    struct PanickingDropWaker {
        /// Number of final waker owners released.
        drops: Arc<AtomicUsize>,
        /// Whether final release should inject an unwind.
        panic_on_drop: Arc<AtomicBool>,
    }

    impl ArcWake for PanickingDropWaker {
        fn wake_by_ref(_arc_self: &Arc<Self>) {}
    }

    impl Drop for PanickingDropWaker {
        fn drop(&mut self) {
            self.drops.fetch_add(1, AtomicOrdering::AcqRel);
            if self.panic_on_drop.load(AtomicOrdering::Acquire) {
                panic!("injected waker destructor panic");
            }
        }
    }

    /// Final expiry waker that observes a cooperative driver yield.
    struct YieldCheckingWaker {
        /// Competing task scheduled before the driver starts draining.
        competitor_ran: Arc<AtomicBool>,
        /// Whether the competitor ran before this final callback.
        observed_after_yield: AtomicBool,
        /// Shard stopped after the observation so the driver can return.
        shard: Arc<Shard<FakeAlarm>>,
    }

    impl ArcWake for YieldCheckingWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            let competitor_ran = arc_self.competitor_ran.load(AtomicOrdering::Acquire);
            arc_self
                .observed_after_yield
                .store(competitor_ran, AtomicOrdering::Release);
            arc_self.shard.stop();
        }
    }

    /// Constructs a compact deadline for fake-clock tests.
    const fn at(nanoseconds: u64) -> Deadline {
        Deadline::from_duration(Duration::from_nanos(nanoseconds))
    }

    /// Constructs a stable injected I/O error for fake operations.
    fn injected_error(operation: &'static str) -> io::Error {
        io::Error::other(format!("injected fake alarm {operation} failure"))
    }

    /// Extracts a successful driver helper result without requiring `Debug`.
    fn driver_ok<T>(result: Result<T, DriverFailure>) -> T {
        match result {
            Ok(value) => value,
            Err(failure) => panic!(
                "unexpected driver failure during {}: {}",
                failure.operation, failure.cause
            ),
        }
    }

    /// Constructs one fake-backed shard without retaining its fatal receiver.
    fn fake_shard() -> (Arc<Shard<FakeAlarm>>, FakeAlarmControl) {
        let (alarm, control) = FakeAlarm::controlled();
        let (panicker, _panicked) = Panicker::new(true);
        (Arc::new(Shard::new(0, alarm, panicker)), control)
    }

    /// Constructs one fake-backed shard and retains its fatal receiver.
    fn observed_fake_shard() -> (Arc<Shard<FakeAlarm>>, FakeAlarmControl, Panicked) {
        let (alarm, control) = FakeAlarm::controlled();
        let (panicker, panicked) = Panicker::new(true);
        (Arc::new(Shard::new(0, alarm, panicker)), control, panicked)
    }

    /// Inserts one entry and returns the future-side owner used for cancellation.
    fn register(
        shard: &Arc<Shard<FakeAlarm>>,
        deadline: Deadline,
    ) -> (Arc<Entry>, RegisteredSleep<FakeAlarm>) {
        let entry = Arc::new(Entry::new());
        shard.register(deadline, Arc::clone(&entry));
        let sleep = RegisteredSleep {
            shard: Arc::downgrade(shard),
            entry: Arc::clone(&entry),
        };
        (entry, sleep)
    }

    /// Builds a fired batch whose final waker releases will unwind.
    fn panicking_waker_batch() -> (Batch, Arc<AtomicUsize>) {
        let (shard, control) = fake_shard();
        let drops = Arc::new(AtomicUsize::new(0));
        let panic_on_drop = Arc::new(AtomicBool::new(false));
        let mut entries = Vec::new();
        let mut registered = Vec::new();
        for _ in 0..2 {
            let (entry, sleep) = register(&shard, at(10));
            let panic_waker = waker(Arc::new(PanickingDropWaker {
                drops: Arc::clone(&drops),
                panic_on_drop: Arc::clone(&panic_on_drop),
            }));
            let mut context = Context::from_waker(&panic_waker);
            assert_eq!(entry.poll(&mut context), Poll::Pending);
            drop(panic_waker);
            entries.push(entry);
            registered.push(sleep);
        }
        control.set_now(at(10));
        let mut batch = Batch::new();
        assert!(!driver_ok(shard.take_expired(&mut batch)));
        drop(registered);
        drop(entries);

        // Arm destructor panics only after setup can no longer unwind through them.
        panic_on_drop.store(true, AtomicOrdering::Release);
        (batch, drops)
    }

    /// Consumes one expected producer notification.
    fn consume_signal(shard: &Shard<FakeAlarm>) {
        assert!(shard.signal.wait().now_or_never().is_some());
        assert!(!shard.signal.is_notified());
    }

    /// Polls an entry once and reports whether failure caused an unwind.
    fn failed_poll_unwinds(entry: &Entry) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let _ = entry.poll(&mut context);
        }))
        .is_err()
    }

    /// Observes and extracts one fatal runtime interruption.
    async fn fatal_message(panicked: Panicked) -> String {
        let panic = AssertUnwindSafe(panicked.interrupt(future::pending::<()>()))
            .catch_unwind()
            .await
            .expect_err("timer failure did not interrupt the runtime");
        extract_panic_message(&*panic)
    }

    /// Reports whether another ready task ran before the final expiry callback.
    async fn final_expiry_observes_competitor(entry_count: usize) -> bool {
        assert!(entry_count > 0);
        let (shard, control) = fake_shard();
        for _ in 1..entry_count {
            shard.register(at(10), Arc::new(Entry::new()));
        }
        let final_entry = Arc::new(Entry::new());
        shard.register(at(10), Arc::clone(&final_entry));

        let competitor_ran = Arc::new(AtomicBool::new(false));
        let checking = Arc::new(YieldCheckingWaker {
            competitor_ran: Arc::clone(&competitor_ran),
            observed_after_yield: AtomicBool::new(false),
            shard: Arc::clone(&shard),
        });
        let checking_waker = waker(Arc::clone(&checking));
        let mut context = Context::from_waker(&checking_waker);
        assert_eq!(final_entry.poll(&mut context), Poll::Pending);

        let competitor = {
            let competitor_ran = Arc::clone(&competitor_ran);
            tokio::spawn(async move {
                competitor_ran.store(true, AtomicOrdering::Release);
            })
        };
        control.set_now(at(10));
        control.inject_readiness();
        let mut batch = Batch::new();
        driver_ok(run_driver_loop(&shard, &mut batch).await);
        competitor.await.unwrap();
        assert_eq!(final_entry.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        checking.observed_after_yield.load(AtomicOrdering::Acquire)
    }

    /// Constructs an affinity allocator with a fresh runtime identity.
    fn affinity(worker_threads: usize) -> Affinity {
        Affinity {
            runtime_id: allocate_runtime_id(),
            lifetime: Arc::new(()),
            worker_threads,
            next_worker: super::super::AtomicUsize::new(0),
            next_fallback: super::super::AtomicUsize::new(0),
        }
    }

    /// Concurrently claims shard indices from fresh worker-like or fallback threads.
    fn claim_affinity_indices(affinity: &Arc<Affinity>, claims: usize, worker: bool) -> Vec<usize> {
        let barrier = Arc::new(Barrier::new(claims));
        let threads: Vec<_> = (0..claims)
            .map(|_| {
                let affinity = Arc::clone(affinity);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    if worker {
                        affinity.assign_worker();
                    }
                    affinity.select()
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect()
    }

    #[test]
    fn registration_is_eager_and_cancellation_is_immediate() {
        // Create an idle shard and request a sleep without polling its future.
        let (shard, control) = fake_shard();
        assert_eq!(control.max_deadline_reads(), 1);
        let registered = shard.register_after(Duration::from_nanos(100));
        let entry = Arc::clone(&registered.entry);

        // Registration must publish the heap entry and notify the driver eagerly.
        assert_eq!(control.max_deadline_reads(), 1);
        assert_eq!(shard.state.lock().entries.len(), 1);
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_WAITING);
        assert!(shard.signal.is_notified());

        // Dropping the unpolled future must cancel and remove the exact entry.
        drop(registered);
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_CANCELED);
        assert_eq!(entry.heap_index.load(AtomicOrdering::Acquire), NOT_IN_HEAP);
        assert_eq!(shard.state.lock().entries.len(), 0);
    }

    #[test]
    fn relative_deadline_precedes_shard_selection_work() {
        // Advance the selected shard's fake clock after construction captures
        // the relative deadline from the scheduler's shared clock shard.
        let (clock_shard, clock_control) = fake_shard();
        let (selected_shard, selected_control) = fake_shard();
        clock_control.set_now(at(100));
        let shards = [Arc::clone(&clock_shard), Arc::clone(&selected_shard)];
        let registered = register_relative(
            &shards,
            Duration::from_nanos(25),
            || {
                selected_control.set_now(at(1_000));
                1
            },
        );
        let entry = Arc::clone(&registered.entry);

        // Selection time must not shift the captured 125 ns deadline to 1,025 ns.
        assert_eq!(clock_shard.state.lock().entries.len(), 0);
        assert_eq!(selected_shard.state.lock().entries.peek(), Some(at(125)));
        let mut batch = Batch::new();
        assert!(!driver_ok(selected_shard.take_expired(&mut batch)));
        assert_eq!(batch.entries.len(), 1);
        assert!(batch.complete(ENTRY_FIRED).is_none());
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
    }

    #[test]
    fn registration_notifications_respect_current_arm_and_tolerance() {
        // Register and arm the initial minimum, then discard setup observations.
        let (shard, control) = fake_shard();
        let (initial, _initial_sleep) = register(&shard, at(1_000));
        consume_signal(&shard);
        driver_ok(shard.rearm());
        control.clear_operations();

        // A later nonminimum and an exactly 50 ns earlier minimum are both covered.
        let (_later, _later_sleep) = register(&shard, at(2_000));
        assert!(!shard.signal.is_notified());
        let (_covered, _covered_sleep) = register(&shard, at(950));
        assert!(!shard.signal.is_notified());
        assert!(control.operations().is_empty());

        // An earlier minimum 51 ns before the current arm must notify the driver.
        let (_uncovered, _uncovered_sleep) = register(&shard, at(949));
        assert!(shard.signal.is_notified());
        assert!(Arc::strong_count(&initial) >= 2);
    }

    #[test]
    fn moving_minimum_later_rearms_and_removing_final_entry_disarms() {
        // Arm a head entry and add one later entry that does not change the minimum.
        let (shard, control) = fake_shard();
        let (head, head_sleep) = register(&shard, at(1_000));
        consume_signal(&shard);
        driver_ok(shard.rearm());
        let (tail, tail_sleep) = register(&shard, at(2_000));
        assert!(!shard.signal.is_notified());
        control.clear_operations();

        // Canceling the head moves the minimum later and requests a new arm.
        drop(head_sleep);
        assert_eq!(head.state.load(AtomicOrdering::Acquire), ENTRY_CANCELED);
        assert!(shard.signal.is_notified());
        consume_signal(&shard);
        driver_ok(shard.rearm());
        assert_eq!(control.operations(), vec![AlarmOperation::Arm(at(2_000))]);

        // Canceling the final entry requests and performs a disarm.
        drop(tail_sleep);
        assert_eq!(tail.state.load(AtomicOrdering::Acquire), ENTRY_CANCELED);
        assert!(shard.signal.is_notified());
        consume_signal(&shard);
        driver_ok(shard.rearm());
        assert_eq!(
            control.operations(),
            vec![AlarmOperation::Arm(at(2_000)), AlarmOperation::Disarm]
        );
        assert_eq!(shard.state.lock().armed_deadline, None);
    }

    #[tokio::test]
    async fn injected_readiness_fires_a_registered_sleep() {
        // Register one future and run its driver against a pending fake readiness wait.
        let (shard, control, panicked) = observed_fake_shard();
        let registered = shard.register_after(Duration::from_nanos(20));
        let entry = Arc::clone(&registered.entry);
        let driver = tokio::spawn(run_driver(Arc::clone(&shard)));
        control.wait_until_wait_polled().await;

        // Advance through the deadline and inject the native readiness edge.
        control.set_now(at(20));
        control.inject_readiness();
        future::poll_fn(|context| entry.poll(context)).await;
        drop(registered);

        // The driver must fire and remove the entry before stopping normally.
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        assert_eq!(entry.heap_index.load(AtomicOrdering::Acquire), NOT_IN_HEAP);
        assert_eq!(shard.state.lock().entries.len(), 0);
        shard.stop();
        driver.await.unwrap();
        assert_eq!(shard.state.lock().lifecycle, ShardLifecycle::Stopped);

        // Orderly shutdown must leave root execution uninterrupted.
        assert_eq!(panicked.interrupt(future::ready(7)).await, 7);
    }

    #[test]
    fn expiry_removes_only_elapsed_entries_in_deadline_and_sequence_order() {
        // Queue one earliest entry, two equal entries, and one future entry out of order.
        let (shard, control) = fake_shard();
        let (equal_first, _equal_first_sleep) = register(&shard, at(50));
        let (future, _future_sleep) = register(&shard, at(150));
        let (equal_second, _equal_second_sleep) = register(&shard, at(50));
        let (earliest, _earliest_sleep) = register(&shard, at(25));
        control.set_now(at(50));
        let mut batch = Batch::new();

        // Expiry must remove the elapsed prefix and leave the future entry resident.
        assert!(!driver_ok(shard.take_expired(&mut batch)));
        assert_eq!(batch.entries.len(), 3);
        assert!(Arc::ptr_eq(&batch.entries[0], &earliest));
        assert!(Arc::ptr_eq(&batch.entries[1], &equal_first));
        assert!(Arc::ptr_eq(&batch.entries[2], &equal_second));
        assert_eq!(shard.state.lock().entries.len(), 1);
        assert_ne!(future.heap_index.load(AtomicOrdering::Acquire), NOT_IN_HEAP);

        // Heap removal commits only the elapsed entries before callbacks run.
        assert_eq!(earliest.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        assert_eq!(equal_first.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        assert_eq!(
            equal_second.state.load(AtomicOrdering::Acquire),
            ENTRY_FIRED
        );
        assert_eq!(future.state.load(AtomicOrdering::Acquire), ENTRY_WAITING);
        assert!(batch.complete(ENTRY_FIRED).is_none());
    }

    #[test]
    fn expiry_clock_failure_preserves_queue_and_operation_context() {
        // Queue one entry and inject failure into the expiry-specific clock read.
        let (shard, control) = fake_shard();
        let (entry, _registered) = register(&shard, at(10));
        control.fail_next_now();
        let mut batch = Batch::new();

        // Expiry must return precise driver context without changing authoritative state.
        let failure = match shard.take_expired(&mut batch) {
            Ok(_) => panic!("expiry clock read unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert_eq!(failure.operation, "read monotonic clock during expiry");
        assert_eq!(failure.cause.to_string(), "injected fake alarm now failure");
        assert_eq!(shard.state.lock().entries.len(), 1);
        assert!(batch.entries.is_empty());
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_WAITING);
    }

    #[test]
    fn expiry_removes_at_most_thirty_two_entries_per_lock_batch() {
        // Queue one more expired entry than the fixed lock-batch limit.
        let (shard, control) = fake_shard();
        control.set_now(at(100));
        let entries: Vec<_> = (0..=WAKE_BATCH)
            .map(|index| {
                let entry = Arc::new(Entry::new());
                shard.register(at(index as u64), Arc::clone(&entry));
                entry
            })
            .collect();
        let mut batch = Batch::new();

        // The first acquisition must remove exactly 32 entries and report more work.
        assert!(driver_ok(shard.take_expired(&mut batch)));
        assert_eq!(batch.entries.len(), WAKE_BATCH);
        assert_eq!(shard.state.lock().entries.len(), 1);
        assert!(batch.complete(ENTRY_FIRED).is_none());

        // A second acquisition removes the final entry and completes the drain.
        assert!(!driver_ok(shard.take_expired(&mut batch)));
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(shard.state.lock().entries.len(), 0);
        assert!(batch.complete(ENTRY_FIRED).is_none());
        assert!(entries.iter().all(|entry| {
            entry.state.load(AtomicOrdering::Acquire) == ENTRY_FIRED
                && entry.heap_index.load(AtomicOrdering::Acquire) == NOT_IN_HEAP
        }));
    }

    #[test]
    fn expiry_callbacks_run_after_releasing_the_shard_lock() {
        // Register a waker that attempts to acquire the shard lock from its callback.
        let (shard, control) = fake_shard();
        let (entry, _registered) = register(&shard, at(10));
        let checking = Arc::new(LockCheckingWaker {
            shard: Arc::clone(&shard),
            acquired: AtomicBool::new(false),
        });
        let checking_waker = waker(Arc::clone(&checking));
        let mut context = Context::from_waker(&checking_waker);
        assert_eq!(entry.poll(&mut context), Poll::Pending);
        control.set_now(at(10));

        // Pop under the lock, then invoke the callback through batch completion.
        let mut batch = Batch::new();
        assert!(!driver_ok(shard.take_expired(&mut batch)));
        assert!(batch.complete(ENTRY_FIRED).is_none());

        // Successful acquisition proves callback execution happened outside the lock.
        assert!(checking.acquired.load(AtomicOrdering::Acquire));
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
    }

    #[test]
    fn batch_completion_drops_reentrant_waker_outside_shard_lock() {
        // Register a polled entry whose final waker destructor re-enters the shard lock.
        let (shard, control) = fake_shard();
        let (entry, registered) = register(&shard, at(10));
        let acquired = Arc::new(AtomicBool::new(false));
        let reentrant_waker = waker(Arc::new(ReentrantDropWaker {
            shard: Arc::downgrade(&shard),
            acquired: Arc::clone(&acquired),
        }));
        let mut context = Context::from_waker(&reentrant_waker);
        assert_eq!(entry.poll(&mut context), Poll::Pending);
        drop(reentrant_waker);
        control.set_now(at(10));
        let mut batch = Batch::new();
        assert!(!driver_ok(shard.take_expired(&mut batch)));

        // Release every owner except the driver batch after expiry commits.
        drop(registered);
        drop(entry);
        assert!(!acquired.load(AtomicOrdering::Acquire));

        // Completion must release the final owner outside the shard lock.
        assert!(batch.complete(ENTRY_FIRED).is_none());
        assert!(acquired.load(AtomicOrdering::Acquire));
        assert!(batch.entries.is_empty());
        assert!(batch.entries.capacity() >= WAKE_BATCH);
    }

    #[test]
    fn batch_completion_and_drop_contain_every_panicking_waker_destructor() {
        {
            // Retain two fired entries whose final waker releases each unwind.
            let (mut batch, drops) = panicking_waker_batch();

            // Explicit completion retains one panic while releasing the entire batch.
            let panic = batch.complete(ENTRY_FIRED);

            // Both final waker owners are released despite their independent unwinds.
            assert!(panic.is_some());
            assert_eq!(drops.load(AtomicOrdering::Acquire), 2);
            assert!(batch.entries.is_empty());
        }

        {
            // Build the same panicking batch for implicit abortion cleanup.
            let (batch, drops) = panicking_waker_batch();

            drop(batch);

            // Drop contains both unwinds and releases every final waker owner.
            assert_eq!(drops.load(AtomicOrdering::Acquire), 2);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn driver_yields_only_when_budget_is_exhausted_with_more_ready() {
        // Drain exactly the budget while a competing task is ready.
        let at_budget = final_expiry_observes_competitor(EXPIRY_YIELD_BUDGET).await;

        // With no remaining entry, the final callback must run before the competitor.
        assert!(!at_budget);

        // Add one more expired entry so work remains after the budget boundary.
        let over_budget = final_expiry_observes_competitor(EXPIRY_YIELD_BUDGET + 1).await;

        // The explicit cooperative yield must run the competitor before the last callback.
        assert!(over_budget);
    }

    #[test]
    fn head_nonhead_and_cross_thread_cancellation_preserve_exact_live_count() {
        // Register five ordered sleeps and retain every future-side owner.
        let (shard, _control) = fake_shard();
        let mut sleeps: Vec<_> = (1..=5)
            .map(|index| {
                let (entry, sleep) = register(&shard, at(index * 10));
                (entry, Some(sleep))
            })
            .collect();
        assert_eq!(shard.state.lock().entries.len(), 5);

        // Cancel a nonhead entry, then the head, and check the count after each removal.
        drop(sleeps[3].1.take());
        assert_eq!(
            sleeps[3].0.state.load(AtomicOrdering::Acquire),
            ENTRY_CANCELED
        );
        assert_eq!(shard.state.lock().entries.len(), 4);
        drop(sleeps[0].1.take());
        assert_eq!(
            sleeps[0].0.state.load(AtomicOrdering::Acquire),
            ENTRY_CANCELED
        );
        assert_eq!(shard.state.lock().entries.len(), 3);

        // Move one future to another thread and cancel it against the original shard.
        let cross_thread = sleeps[2].1.take().unwrap();
        thread::spawn(move || drop(cross_thread)).join().unwrap();
        assert_eq!(
            sleeps[2].0.state.load(AtomicOrdering::Acquire),
            ENTRY_CANCELED
        );
        assert_eq!(shard.state.lock().entries.len(), 2);

        // Cancel the remaining owners and require the heap count to track live entries exactly.
        let mut live = 2;
        for (entry, sleep) in &mut sleeps {
            let Some(sleep) = sleep.take() else {
                continue;
            };
            drop(sleep);
            live -= 1;
            assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_CANCELED);
            assert_eq!(entry.heap_index.load(AtomicOrdering::Acquire), NOT_IN_HEAP);
            assert_eq!(shard.state.lock().entries.len(), live);
        }
        assert_eq!(live, 0);
    }

    #[test]
    fn stop_quiesces_queued_sleeps_without_retaining_wakers_or_alarm() {
        // Queue two sleeps, including one that has installed a task waker.
        let (shard, control) = fake_shard();
        let first = shard.register_after(Duration::from_nanos(10));
        let first_entry = Arc::clone(&first.entry);
        let second = shard.register_after(Duration::from_nanos(20));
        let second_entry = Arc::clone(&second.entry);
        let counter = Arc::new(CountingWaker {
            wakes: AtomicUsize::new(0),
        });
        let waker = waker(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        assert_eq!(first_entry.poll(&mut context), Poll::Pending);
        consume_signal(&shard);

        // Normal scheduler stop drains every queued sleep without waking tasks.
        shard.stop();

        // The first stop reaches the driver and quiesces all resident state.
        consume_signal(&shard);
        assert_eq!(shard.state.lock().entries.len(), 0);
        assert_eq!(
            first_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_STOPPED
        );
        assert_eq!(
            second_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_STOPPED
        );
        assert_eq!(counter.wakes.load(AtomicOrdering::Relaxed), 0);
        assert!(first_entry.take_waker().is_none());

        // A later poll remains pending and cannot retain another task waker.
        assert_eq!(first_entry.poll(&mut context), Poll::Pending);
        assert_eq!(second_entry.poll(&mut context), Poll::Pending);
        assert!(first_entry.take_waker().is_none());
        assert!(second_entry.take_waker().is_none());

        shard.stop();

        // Repeated stop is idempotent and does not renotify the driver.
        assert_eq!(
            first_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_STOPPED
        );
        assert_eq!(
            second_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_STOPPED
        );
        assert_eq!(shard.state.lock().entries.len(), 0);
        assert!(!shard.signal.is_notified());

        // Outliving sleeps hold weak cancellation owners and cannot retain the alarm.
        drop(shard);
        assert!(control.is_shutdown());

        drop(first);
        drop(second);

        // Their weak cancellation owners cannot revive the alarm.
        assert!(control.is_shutdown());
    }

    #[test]
    fn clean_runtime_shutdown_does_not_report_pending_sleeps() {
        const CHILD_ENV: &str = "_COMMONWARE_RUNTIME_TIMER_CLEAN_SHUTDOWN_CHILD";
        const TEST_NAME: &str = "tokio::timer::scheduler::tests::ordinary::clean_runtime_shutdown_does_not_report_pending_sleeps";

        // Isolate the global tracing subscriber in a child test process.
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("current test executable must be available"),
            )
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("clean-shutdown child test must start");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // The isolated regression completed without a task panic.
            assert!(
                output.status.success(),
                "clean-shutdown child failed\nstdout:\n{}\nstderr:\n{}",
                stdout,
                stderr
            );
            assert!(
                stdout.contains(&format!("test {TEST_NAME} ... ok")),
                "clean-shutdown child did not execute the regression\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            assert!(
                !stderr.contains("high-resolution timer scheduler failed"),
                "clean-shutdown child reported a timer failure panic\nstderr:\n{stderr}"
            );
            return;
        }

        use crate::{Clock as _, Runner as _, Spawner as _, Supervisor as _};

        let storage = TraceStorage::default();
        let subscriber = Registry::default().with(CollectingLayer::new(storage.clone()));
        tracing::subscriber::set_global_default(subscriber)
            .expect("child process must install its tracing subscriber");
        let runner =
            crate::tokio::Runner::new(crate::tokio::Config::default().with_worker_threads(1));

        // Return the root while polled tasks retain only pending sleep futures.
        runner.start(|context| async move {
            const TASKS: usize = 256;
            let started = Arc::new(AtomicUsize::new(0));
            for _ in 0..TASKS {
                let sleep = context.sleep(Duration::from_secs(60));
                let task_started = Arc::clone(&started);
                let _handle = context.child("pending_timer").spawn(move |_| async move {
                    task_started.fetch_add(1, AtomicOrdering::Release);
                    sleep.await;
                });
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while started.load(AtomicOrdering::Acquire) != TASKS {
                assert!(
                    Instant::now() < deadline,
                    "pending timer tasks did not all start"
                );
                tokio::task::yield_now().await;
            }
        });

        // Orderly timer teardown emits no generic task-panic diagnostic.
        assert!(
            storage
                .get_all()
                .iter()
                .all(|event| event.metadata.content != "task panicked")
        );
    }

    #[test]
    fn registration_after_stop_or_failure_returns_matching_nonresident_entry() {
        // Stop one shard and consume its teardown notification before registering again.
        let (stopped, _stopped_control) = fake_shard();
        stopped.stop();
        consume_signal(&stopped);
        let stopped_entry = Arc::new(Entry::new());
        stopped.register(at(10), Arc::clone(&stopped_entry));

        // A stopped shard must reject registration without mutating its heap or signal.
        assert_eq!(
            stopped_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_STOPPED
        );
        assert_eq!(
            stopped_entry.heap_index.load(AtomicOrdering::Acquire),
            NOT_IN_HEAP
        );
        assert_eq!(stopped.state.lock().entries.len(), 0);
        assert!(!stopped.signal.is_notified());

        // Fail another shard and consume its failure notification before registering again.
        let (failed, _failed_control) = fake_shard();
        failed.fail(DriverFailure::io("first failure", injected_error("first")));
        consume_signal(&failed);
        let failed_entry = Arc::new(Entry::new());
        failed.register(at(20), Arc::clone(&failed_entry));

        // A failed shard rejects registration with the distinct failure terminal.
        assert_eq!(
            failed_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_FAILED
        );
        assert_eq!(
            failed_entry.heap_index.load(AtomicOrdering::Acquire),
            NOT_IN_HEAP
        );
        assert_eq!(failed.state.lock().entries.len(), 0);
        assert!(!failed.signal.is_notified());
    }

    #[tokio::test]
    async fn duplicate_failure_and_failure_after_stop_are_ignored() {
        // Report two failures to one running shard before observing its fatal message.
        let (failed, _failed_control, panicked) = observed_fake_shard();
        failed.fail(DriverFailure::io(
            "first operation",
            injected_error("first"),
        ));
        failed.fail(DriverFailure::io(
            "duplicate operation",
            injected_error("duplicate"),
        ));

        // Only the first failure may own fatal diagnostics and lifecycle transition.
        let message = fatal_message(panicked).await;
        assert!(message.contains("first operation"));
        assert!(message.contains("injected fake alarm first failure"));
        assert!(!message.contains("duplicate operation"));
        {
            let state = failed.state.lock();
            assert_eq!(state.lifecycle, ShardLifecycle::Failed);
        }

        // Stop a fresh shard before reporting a failure and retain its fatal receiver.
        let (stopped, _stopped_control, panicked) = observed_fake_shard();
        stopped.stop();
        consume_signal(&stopped);
        stopped.fail(DriverFailure::io(
            "post-stop operation",
            injected_error("post-stop"),
        ));

        // Failure after normal stop must neither reclassify nor interrupt the runtime.
        {
            let state = stopped.state.lock();
            assert_eq!(state.lifecycle, ShardLifecycle::Stopped);
        }
        assert!(!stopped.signal.is_notified());
        assert_eq!(panicked.interrupt(future::ready(7)).await, 7);
    }

    #[test]
    fn every_failed_shard_logs_when_root_notification_is_closed() {
        // Close the shared interruption receiver and capture structured diagnostics.
        let (panicker, panicked) = Panicker::new(false);
        drop(panicked);
        let (first_alarm, _first_control) = FakeAlarm::controlled();
        let first = Shard::new(0, first_alarm, panicker.clone());
        let (second_alarm, _second_control) = FakeAlarm::controlled();
        let second = Shard::new(1, second_alarm, panicker);
        let storage = TraceStorage::default();
        let subscriber = Registry::default().with(CollectingLayer::new(storage.clone()));
        let first_error = io::Error::from_raw_os_error(libc::EINVAL);
        let first_error_kind = format!("{:?}", Some(first_error.kind()));
        let first_raw_os_error = format!("{:?}", first_error.raw_os_error());

        // Fail two shards after neither can publish a root interruption.
        tracing::subscriber::with_default(subscriber, || {
            first.fail(DriverFailure::io("first injected operation", first_error));
            second.fail(DriverFailure::io(
                "second injected operation",
                injected_error("second"),
            ));
        });

        // Each shard emits one independently actionable diagnostic.
        let events = storage.get_all();
        let diagnostics: Vec<_> = events
            .iter()
            .filter(|event| event.metadata.content == "timer infrastructure failed")
            .collect();
        assert_eq!(diagnostics.len(), 2);
        for (shard, operation) in [
            ("0", "first injected operation"),
            ("1", "second injected operation"),
        ] {
            assert!(diagnostics.iter().any(|event| {
                event
                    .metadata
                    .fields
                    .iter()
                    .any(|(name, value)| name == "shard" && value == shard)
                    && event
                        .metadata
                        .fields
                        .iter()
                        .any(|(name, value)| name == "operation" && value == operation)
            }));
        }
        let first_diagnostic = diagnostics
            .iter()
            .find(|event| {
                event
                    .metadata
                    .fields
                    .iter()
                    .any(|(name, value)| name == "shard" && value == "0")
            })
            .expect("first shard diagnostic must be recorded");
        first_diagnostic
            .metadata
            .expect_field_exact("error_kind", &first_error_kind)
            .unwrap();
        first_diagnostic
            .metadata
            .expect_field_exact("raw_os_error", &first_raw_os_error)
            .unwrap();
    }

    #[tokio::test]
    async fn fatal_failure_precedes_failed_sleeper_notification() {
        // Use the default panic policy and install a sleeper waker that reports an
        // ordinary task panic as soon as failure cleanup invokes it.
        let (alarm, _control) = FakeAlarm::controlled();
        let (panicker, panicked) = Panicker::new(false);
        let notifying = Arc::new(NotifyPanickerWaker {
            panicker: panicker.clone(),
            notified: AtomicBool::new(false),
        });
        let shard = Arc::new(Shard::new(0, alarm, panicker));
        let (entry, _registered) = register(&shard, at(10));
        let task_waker = waker(Arc::clone(&notifying));
        let mut context = Context::from_waker(&task_waker);
        assert_eq!(entry.poll(&mut context), Poll::Pending);

        // The infrastructure payload must claim root interruption before waking the
        // failed sleeper, so its generic task panic cannot replace diagnostics.
        shard.fail(DriverFailure::io(
            "injected operation",
            injected_error("root cause"),
        ));
        assert!(notifying.notified.load(AtomicOrdering::Acquire));
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_FAILED);
        let message = fatal_message(panicked).await;
        assert!(message.contains("injected operation"));
        assert!(message.contains("injected fake alarm root cause failure"));
        assert!(!message.contains("generic failed sleeper panic"));
    }

    #[tokio::test]
    async fn registration_clock_failure_preserves_a_committed_expiry_batch() {
        // Commit two expired entries without invoking their callbacks.
        let (shard, control, panicked) = observed_fake_shard();
        control.set_now(at(10));
        let (first, _first_sleep) = register(&shard, at(10));
        let (second, _second_sleep) = register(&shard, at(10));
        let mut batch = Batch::new();
        assert!(!driver_ok(shard.take_expired(&mut batch)));

        // Fail a producer clock read before completing the committed batch.
        control.fail_next_now();
        let failed_registration = register_relative(
            std::slice::from_ref(&shard),
            Duration::from_nanos(1),
            || 0,
        );

        // Failure covers the new entry but cannot overwrite committed expirations.
        {
            let state = shard.state.lock();
            assert_eq!(state.lifecycle, ShardLifecycle::Failed);
            assert_eq!(state.entries.len(), 0);
        }
        assert_eq!(first.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        assert_eq!(second.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        assert_eq!(
            failed_registration
                .entry
                .state
                .load(AtomicOrdering::Acquire),
            ENTRY_FAILED
        );
        assert_eq!(
            failed_registration
                .entry
                .heap_index
                .load(AtomicOrdering::Acquire),
            NOT_IN_HEAP
        );
        assert!(failed_poll_unwinds(&failed_registration.entry));
        assert!(batch.complete(ENTRY_FIRED).is_none());

        // Fatal propagation still preserves the operation that failed.
        let message = fatal_message(panicked).await;
        assert!(message.contains("read monotonic clock during registration"));
    }

    #[tokio::test]
    async fn arm_failure_fails_every_pending_sleep_and_reports_snapshot() {
        // Queue two pending sleeps and make the driver's first arm fail.
        let (shard, control, panicked) = observed_fake_shard();
        let first = shard.register_after(Duration::from_nanos(10));
        let first_entry = Arc::clone(&first.entry);
        let second = shard.register_after(Duration::from_nanos(20));
        let second_entry = Arc::clone(&second.entry);
        control.fail_next_arm();
        run_driver(Arc::clone(&shard)).await;

        // Failure cleanup must empty the heap and mark every sleep failed.
        {
            let state = shard.state.lock();
            assert_eq!(state.lifecycle, ShardLifecycle::Failed);
            assert_eq!(state.entries.len(), 0);
        }
        assert_eq!(
            first_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_FAILED
        );
        assert_eq!(
            second_entry.state.load(AtomicOrdering::Acquire),
            ENTRY_FAILED
        );

        // Fatal diagnostics must name the operation and preserve the pre-cleanup count.
        let message = fatal_message(panicked).await;
        assert!(message.contains("arm native alarm"));
        assert!(message.contains("queued: 2"));
    }

    #[tokio::test]
    async fn wait_error_and_panic_fail_pending_sleep_with_precise_diagnostics() {
        type WaitCase = (fn(&FakeAlarmControl), &'static [&'static str]);

        let cases: [WaitCase; 2] = [
            (FakeAlarmControl::fail_next_wait, &["wait for native alarm"]),
            (
                FakeAlarmControl::panic_next_wait,
                &["driver panic", "injected fake alarm wait panic"],
            ),
        ];

        for (inject, expected_diagnostics) in cases {
            // Queue one sleep and consume its producer notification.
            let (shard, control, panicked) = observed_fake_shard();
            let registered = shard.register_after(Duration::from_nanos(10));
            let entry = Arc::clone(&registered.entry);
            consume_signal(&shard);
            inject(&control);

            // Run the driver through the injected wait error or panic.
            run_driver(Arc::clone(&shard)).await;

            // Containment fails the resident sleep and clears the shard.
            assert_eq!(shard.state.lock().lifecycle, ShardLifecycle::Failed);
            assert_eq!(shard.state.lock().entries.len(), 0);
            assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_FAILED);
            assert!(failed_poll_unwinds(&entry));

            // Fatal propagation retains each path's precise classification.
            let message = fatal_message(panicked).await;
            for expected in expected_diagnostics {
                assert!(
                    message.contains(expected),
                    "fatal diagnostic {message:?} omitted {expected:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn expiry_waker_panic_propagates_through_driver_and_fails_shard() {
        // Register an expired entry and install a waker that unwinds when the driver fires it.
        let (shard, control, panicked) = observed_fake_shard();
        let (entry, _registered) = register(&shard, at(10));
        let panic_waker = waker(Arc::new(PanickingWaker));
        let mut context = Context::from_waker(&panic_waker);
        assert_eq!(entry.poll(&mut context), Poll::Pending);
        control.set_now(at(10));
        control.inject_readiness();

        // Run the complete driver wrapper so callback failure reaches fatal cleanup.
        run_driver(Arc::clone(&shard)).await;

        // The expiry transition wins before the callback panic, then the shard fails.
        assert_eq!(entry.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        {
            let state = shard.state.lock();
            assert_eq!(state.lifecycle, ShardLifecycle::Failed);
            assert_eq!(state.entries.len(), 0);
        }
        let message = fatal_message(panicked).await;
        assert!(message.contains("driver panic"));
        assert!(message.contains("injected waker panic"));
    }

    #[tokio::test]
    async fn disarm_failure_fails_the_running_scheduler() {
        // Arm one entry, cancel it, and inject failure in the requested disarm.
        let (shard, control, panicked) = observed_fake_shard();
        let (_entry, registered) = register(&shard, at(10));
        consume_signal(&shard);
        driver_ok(shard.rearm());
        drop(registered);
        consume_signal(&shard);
        control.fail_next_disarm();
        run_driver(Arc::clone(&shard)).await;

        // The disarm error must stop the shard and identify its native operation.
        assert_eq!(shard.state.lock().lifecycle, ShardLifecycle::Failed);
        let message = fatal_message(panicked).await;
        assert!(message.contains("disarm native alarm"));
    }

    #[test]
    fn waker_unwind_does_not_strand_the_rest_of_a_batch() {
        // Register a panicking waker before a counting waker in one local batch.
        let panicking = Arc::new(Entry::new());
        let panic_waker = waker(Arc::new(PanickingWaker));
        let mut panic_context = Context::from_waker(&panic_waker);
        assert_eq!(panicking.poll(&mut panic_context), Poll::Pending);
        let following = Arc::new(Entry::new());
        let counter = Arc::new(CountingWaker {
            wakes: AtomicUsize::new(0),
        });
        let counting_waker = waker(Arc::clone(&counter));
        let mut counting_context = Context::from_waker(&counting_waker);
        assert_eq!(following.poll(&mut counting_context), Poll::Pending);
        let mut batch = Batch {
            entries: vec![Arc::clone(&panicking), Arc::clone(&following)],
        };

        // Completion must contain the first unwind and continue invoking callbacks.
        let panic = batch.complete(ENTRY_FIRED);
        assert!(panic.is_some());
        assert!(batch.entries.is_empty());

        // Both entries must reach FIRED and the later callback must run once.
        assert_eq!(panicking.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        assert_eq!(following.state.load(AtomicOrdering::Acquire), ENTRY_FIRED);
        assert_eq!(counter.wakes.load(AtomicOrdering::Relaxed), 1);
    }

    #[test]
    fn deadline_add_saturates_at_platform_limit() {
        let limit = Deadline::from_duration(Duration::from_secs(10));
        let saturated = Deadline::from_duration(Duration::from_secs(9))
            .saturating_add(Duration::from_secs(2), limit);
        let exact = Deadline::from_duration(Duration::from_secs(2))
            .saturating_add(Duration::from_secs(3), limit);

        // The crossing addition clamps while the representable addition stays exact.
        assert_eq!(saturated, limit);
        assert_eq!(exact, Deadline::from_duration(Duration::from_secs(5)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_sleep_loop_cooperates_with_other_tasks() {
        // Queue a peer behind a task that repeatedly awaits immediate sleeps.
        let peer_ran = Arc::new(AtomicBool::new(false));
        let peer_flag = Arc::clone(&peer_ran);
        let peer = tokio::spawn(async move {
            peer_flag.store(true, AtomicOrdering::Release);
        });

        // Await more immediate sleeps than one Tokio cooperative budget.
        for _ in 0..1_024 {
            Sleep::Ready.await;
            if peer_ran.load(AtomicOrdering::Acquire) {
                break;
            }
        }

        // Budget exhaustion yields to the already-runnable peer.
        assert!(peer_ran.load(AtomicOrdering::Acquire));
        peer.await.unwrap();
    }

    #[test]
    fn entry_poll_replaces_waker_and_reports_terminal_outcomes() {
        // Poll repeatedly with one task waker, then migrate polling to another task.
        let entry = Entry::new();
        let first = Arc::new(CountingWaker {
            wakes: AtomicUsize::new(0),
        });
        let first_waker = waker(Arc::clone(&first));
        let mut first_context = Context::from_waker(&first_waker);
        for _ in 0..3 {
            assert_eq!(entry.poll(&mut first_context), Poll::Pending);
        }
        let second = Arc::new(CountingWaker {
            wakes: AtomicUsize::new(0),
        });
        let second_waker = waker(Arc::clone(&second));
        let mut second_context = Context::from_waker(&second_waker);
        assert_eq!(entry.poll(&mut second_context), Poll::Pending);

        // Fire once and invoke the single waker retained by the entry.
        assert!(entry.transition(ENTRY_FIRED));
        entry.take_waker().unwrap().wake();

        // Repeated polls do not duplicate callbacks, replacement targets
        // only the latest task, and a fired entry completes.
        assert_eq!(first.wakes.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(second.wakes.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(entry.poll(&mut second_context), Poll::Ready(()));

        // Prepare the other externally visible terminal outcome.
        let failed = Entry::new();

        assert!(failed.transition(ENTRY_FAILED));

        // A failed entry unwinds instead of hanging.
        assert!(failed_poll_unwinds(&failed));
    }

    #[test]
    fn signal_latches_and_coalesces() {
        // Notify twice before the single driver has a chance to consume either edge.
        let signal = DriverSignal::new();
        signal.notify();
        signal.notify();

        // One durable notification must be sufficient and leave no stale signal.
        assert!(signal.is_notified());
        assert!(signal.wait().now_or_never().is_some());
        assert!(!signal.is_notified());
    }

    #[test]
    fn affinity_caches_fallback_and_upgrades_worker() {
        // Select twice before a park callback assigns this thread as a worker.
        let affinity = affinity(2);
        let provisional = affinity.select();
        assert_eq!(provisional, affinity.select());
        assert_eq!(affinity.next_fallback.load(AtomicOrdering::Relaxed), 1);

        // The callback upgrades once and then preserves the stable worker claim.
        affinity.assign_worker();
        assert_eq!(affinity.select(), 0);
        assert_eq!(affinity.next_worker.load(AtomicOrdering::Relaxed), 1);
        affinity.assign_worker();
        assert_eq!(affinity.next_worker.load(AtomicOrdering::Relaxed), 1);
    }

    #[test]
    fn affinity_distributes_worker_and_fallback_claims() {
        // Create independent four-shard allocators for worker and fallback claims.
        let workers = Arc::new(affinity(4));
        let fallbacks = Arc::new(affinity(4));

        // Concurrently claim every worker index once and two fallback rounds.
        let mut worker_indices = claim_affinity_indices(&workers, 4, true);
        let mut fallback_indices = claim_affinity_indices(&fallbacks, 8, false);
        worker_indices.sort_unstable();
        fallback_indices.sort_unstable();

        // Workers are distinct and fallback claims balance round-robin.
        assert_eq!(worker_indices, vec![0, 1, 2, 3]);
        assert_eq!(fallback_indices, vec![0, 0, 1, 1, 2, 2, 3, 3]);
        assert_eq!(workers.next_worker.load(AtomicOrdering::Relaxed), 4);
        assert_eq!(workers.next_fallback.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(fallbacks.next_worker.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(fallbacks.next_fallback.load(AtomicOrdering::Relaxed), 8);
    }

    #[test]
    fn thread_assignment_cache_prunes_dropped_runtimes_on_cold_paths() {
        // Cache two live runtimes, leaving the first assignment inactive.
        let mut assignments = ThreadAssignments::new();
        let first_lifetime = Arc::new(());
        assignments.install(ThreadAssignment {
            runtime_id: 1,
            lifetime: Arc::downgrade(&first_lifetime),
            kind: AssignmentKind::Provisional,
            index: 3,
        });
        let second_lifetime = Arc::new(());
        assignments.install(ThreadAssignment {
            runtime_id: 2,
            lifetime: Arc::downgrade(&second_lifetime),
            kind: AssignmentKind::Worker,
            index: 4,
        });
        assert_eq!(assignments.get(1), Some((3, AssignmentKind::Provisional)));
        assert_eq!(assignments.inactive.len(), 1);

        // A cache miss prunes the inactive assignment after its runtime ends.
        drop(first_lifetime);
        assert_eq!(assignments.activate(3), None);
        assert!(assignments.inactive.is_empty());
        assert_eq!(assignments.get(2), Some((4, AssignmentKind::Worker)));

        // Replacing a dead current assignment does not preserve it as inactive.
        drop(second_lifetime);
        let third_lifetime = Arc::new(());
        assignments.install(ThreadAssignment {
            runtime_id: 3,
            lifetime: Arc::downgrade(&third_lifetime),
            kind: AssignmentKind::Provisional,
            index: 5,
        });
        assert!(assignments.inactive.is_empty());
        assert_eq!(assignments.get(3), Some((5, AssignmentKind::Provisional)));
    }

    #[test]
    fn cross_runtime_clock_use_preserves_worker_assignment() {
        // Claim runtime one's only worker index, then use runtime two on that worker.
        let first = affinity(1);
        let second = affinity(1);
        first.assign_worker();
        assert_eq!(first.select(), 0);
        assert_eq!(second.select(), 0);
        assert_eq!(second.next_fallback.load(AtomicOrdering::Relaxed), 1);

        // Returning to runtime one must recover its worker assignment without a fallback claim.
        assert_eq!(first.select(), 0);
        first.assign_worker();
        assert_eq!(first.next_worker.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(first.next_fallback.load(AtomicOrdering::Relaxed), 0);

        // Runtime two must also retain its provisional assignment across another switch.
        assert_eq!(second.select(), 0);
        assert_eq!(second.next_fallback.load(AtomicOrdering::Relaxed), 1);
    }

    #[test]
    fn block_in_place_replacement_worker_retains_runtime_progress() {
        const REPETITIONS: usize = 4;

        // Start a one-worker Tokio runtime and let its original worker
        // consume the sole unique affinity claim before any blocking handoff.
        let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
        runtime_builder.worker_threads(1).enable_all();
        let timer_builder = super::super::Builder::install(&mut runtime_builder, 1);
        let affinity = Arc::clone(&timer_builder.affinity);
        let runtime = runtime_builder.build().expect("Tokio runtime must build");
        let claim_deadline = Instant::now() + Duration::from_secs(5);
        while affinity.next_worker.load(AtomicOrdering::Relaxed) != 1 {
            assert!(
                Instant::now() < claim_deadline,
                "original worker did not claim its affinity"
            );
            thread::yield_now();
        }

        // Repeatedly block the original worker while its replacement
        // runs another task and reaches the production park callback.
        runtime.block_on(async {
            for iteration in 0..REPETITIONS {
                let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
                let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
                let blocker = tokio::spawn(async move {
                    tokio::task::block_in_place(move || {
                        entered_tx
                            .send(())
                            .expect("test must observe the blocking handoff");
                        release_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("test must release the blocked worker");
                    });
                });
                entered_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("worker did not enter block_in_place");

                // The first fresh replacement must park and install a provisional
                // assignment before any probe task makes its own fallback choice.
                if iteration == 0 {
                    let park_deadline = Instant::now() + Duration::from_secs(5);
                    while affinity.next_fallback.load(AtomicOrdering::Relaxed) == 0
                        && Instant::now() < park_deadline
                    {
                        thread::yield_now();
                    }
                }

                let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel(1);
                let probe_affinity = Arc::clone(&affinity);
                let probe = tokio::spawn(async move {
                    let index = probe_affinity.select();
                    let assignment = super::super::THREAD_ASSIGNMENTS.with(|assignments| {
                        assignments
                            .borrow()
                            .get(probe_affinity.runtime_id)
                            .expect("replacement worker must retain an assignment")
                    });
                    progress_tx
                        .send((index, assignment))
                        .expect("test must observe replacement-worker progress");
                });
                let progress = progress_rx.recv_timeout(Duration::from_secs(5));

                // Always unblock the original worker before asserting so a failed
                // progress probe cannot strand runtime teardown.
                release_tx
                    .send(())
                    .expect("blocked worker must still be waiting");
                blocker.await.expect("blocking task must complete");
                probe.await.expect("replacement-worker probe must complete");

                let (index, assignment) =
                    progress.expect("replacement worker did not run the probe task");
                assert_eq!(index, assignment.0);
                assert!(index < affinity.worker_threads);
                if iteration == 0 {
                    assert_eq!(assignment.1, AssignmentKind::Provisional);
                }
            }
        });

        // Every handoff completed, all selections stayed in range, and
        // temporary replacement threads never consumed another worker identity.
        assert_eq!(affinity.next_worker.load(AtomicOrdering::Relaxed), 1);
        assert!((1..=REPETITIONS).contains(&affinity.next_fallback.load(AtomicOrdering::Relaxed)));
    }
}

#[cfg(feature = "loom")]
mod loom_tests {
    use super::super::{
        Alarm, Batch, Deadline, DriverFailure, DriverSignal, ENTRY_CANCELED, ENTRY_FAILED,
        ENTRY_FIRED, ENTRY_STOPPED, ENTRY_WAITING, Entry, NOT_IN_HEAP, Shard, ShardLifecycle,
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
            // Register one already-expired entry through the production shard.
            let (shard, _alarm) = model_shard();
            let entry = LoomArc::new(Entry::new());
            shard.register(deadline(0), LoomArc::clone(&entry));

            // Race polling against the production split expiry and callback path.
            let completer = {
                let shard = Arc::clone(&shard);
                thread::spawn(move || {
                    let mut batch = Batch::new();
                    assert!(!driver_ok(shard.take_expired(&mut batch)));
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
                "high-resolution timer scheduler failed"
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
    fn production_stop_races_expiry_commit_under_the_shard_lock() {
        model(|| {
            // Register one expired entry through the production shard.
            let (shard, _alarm) = model_shard();
            let entry = LoomArc::new(Entry::new());
            shard.register(deadline(0), LoomArc::clone(&entry));

            // Race synchronous stop against the driver's pop and callback path.
            let stopper = {
                let shard = Arc::clone(&shard);
                thread::spawn(move || shard.stop())
            };
            let expirer = {
                let shard = Arc::clone(&shard);
                thread::spawn(move || {
                    let mut batch = Batch::new();
                    assert!(!driver_ok(shard.take_expired(&mut batch)));
                    assert!(batch.complete(ENTRY_FIRED).is_none());
                })
            };
            stopper.join().unwrap();
            expirer.join().unwrap();

            // The lock winner commits one terminal state and removes the entry.
            assert!(matches!(
                entry.state.load(Ordering::Acquire),
                ENTRY_FIRED | ENTRY_STOPPED
            ));
            let state = shard.state.lock();
            assert_eq!(state.lifecycle, ShardLifecycle::Stopped);
            assert_eq!(state.entries.len(), 0);
            assert_eq!(entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
        });
    }

    #[test]
    fn production_registered_sleep_drop_races_driver_completion() {
        model(|| {
            // Register one immediately expired sleep through the production shard.
            let (shard, _alarm) = model_shard();
            let sleep = shard.register_after(Duration::ZERO);
            let entry = LoomArc::clone(&sleep.entry);

            // Race RegisteredSleep::drop against the driver's production
            // heap-pop and batch-completion sequence.
            let dropper = thread::spawn(move || drop(sleep));
            let driver = {
                let shard = Arc::clone(&shard);
                thread::spawn(move || {
                    let mut batch = Batch::new();
                    assert!(!driver_ok(shard.take_expired(&mut batch)));
                    assert!(batch.complete(ENTRY_FIRED).is_none());
                })
            };
            dropper.join().unwrap();
            driver.join().unwrap();

            // Either legal terminal winner leaves no resident entry
            // and publishes the nonresident heap index.
            assert!(matches!(
                entry.state.load(Ordering::Acquire),
                ENTRY_CANCELED | ENTRY_FIRED
            ));
            let state = shard.state.lock();
            assert_eq!(state.entries.len(), 0);
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
                let desired = state.entries.peek();
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
}
