use super::{
    super::{EVENT_READY_TASKS_PER_TURN, READY_TASKS_PER_TURN, Runner},
    *,
};
use crate::{Clock as _, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::channel::oneshot;
use std::{sync::atomic::AtomicUsize, task::Waker, time::Duration};

/// Build an unregistered pending task cell for ready-lane tests.
fn pending_cell(
    tasks: &Arc<Tasks>,
    slot: usize,
    queued: bool,
) -> Arc<TaskCell<std::future::Pending<()>>> {
    Arc::new(TaskCell {
        slot,
        tasks: Arc::downgrade(tasks),
        state: if queued {
            TaskState::queued()
        } else {
            TaskState::idle()
        },
        future: Affine::pinned(
            std::thread::current().id(),
            RefCell::new(Some(std::future::pending())),
        ),
    })
}

/// Build an unregistered ready task cell for ready-lane order tests.
fn ready_cell(tasks: &Arc<Tasks>, slot: usize) -> Arc<TaskCell<std::future::Ready<()>>> {
    Arc::new(TaskCell {
        slot,
        tasks: Arc::downgrade(tasks),
        state: TaskState::queued(),
        future: Affine::pinned(
            std::thread::current().id(),
            RefCell::new(Some(std::future::ready(()))),
        ),
    })
}

/// Poll a drained batch of ready tokens and return their completion slots.
fn completed_slots(owner: &Tasks, tasks: &mut Vec<Arc<dyn ErasedTask>>) -> Vec<usize> {
    tasks
        .drain(..)
        .map(|task| task.poll(owner).expect("ready token must complete"))
        .collect()
}

/// Append an unregistered token to one ready lane without unparking.
fn queue_token(tasks: &Tasks, task: Arc<dyn ErasedTask>, lane: ReadyLane) {
    let mut ready = tasks.ready.lock();
    match lane {
        ReadyLane::Normal => ready.normal.push_back(task),
        ReadyLane::Event => ready.event.push_back(task),
    }
}

/// Separately constructed wakers for one task must retain the task's
/// pointer identity so callers can use `Waker::will_wake`.
#[test]
fn test_task_wakers_will_wake_same_cell() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    let cell = Arc::new(TaskCell {
        slot: 0,
        tasks: Arc::downgrade(&tasks),
        state: TaskState::queued(),
        future: Affine::pinned(
            std::thread::current().id(),
            RefCell::new(Some(std::future::pending::<()>())),
        ),
    });

    let first = waker(Arc::clone(&cell));
    let second = waker(Arc::clone(&cell));
    assert!(first.will_wake(&second));
}

/// The initial event quota is drained first, a normal token present in the
/// snapshot is reserved, and unused normal capacity is filled from the
/// event lane without crossing the combined limit.
#[test]
fn test_event_drain_prioritizes_quota_and_reserves_normal() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    for slot in 0..2 {
        queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Normal);
    }
    for slot in 10..14 {
        queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Event);
    }

    let mut scratch = Vec::new();
    tasks.drain_into(&mut scratch, 4, 1);
    assert_eq!(scratch.len(), 4);
    assert_eq!(completed_slots(&tasks, &mut scratch), vec![10, 0, 1, 11]);

    tasks.drain_into(&mut scratch, 4, 1);
    assert_eq!(completed_slots(&tasks, &mut scratch), vec![12, 13]);
    assert!(!tasks.has_ready());
}

/// Multiple drains may interleave the lanes, but tokens from each lane
/// retain their own arrival order.
#[test]
fn test_ready_lanes_preserve_fifo_order() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    for slot in 0..3 {
        queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Normal);
    }
    for slot in 10..13 {
        queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Event);
    }

    let mut scratch = Vec::new();
    tasks.drain_into(&mut scratch, 4, 2);
    assert_eq!(completed_slots(&tasks, &mut scratch), vec![10, 11, 0, 1]);
    tasks.drain_into(&mut scratch, 4, 2);
    assert_eq!(completed_slots(&tasks, &mut scratch), vec![12, 2]);
    assert!(!tasks.has_ready());
}

/// The production half-turn event quota drains a 64-event burst in two
/// snapshots while an older normal backlog advances by the other half of
/// each snapshot. This is the burst-tail and starvation contract selected
/// by the scheduler benchmark.
#[test]
fn test_production_event_quota_balances_burst_and_normal_progress() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    for slot in 0..READY_TASKS_PER_TURN * 2 {
        queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Normal);
    }
    for slot in 0..READY_TASKS_PER_TURN {
        queue_token(&tasks, ready_cell(&tasks, 1_000 + slot), ReadyLane::Event);
    }

    let mut scratch = Vec::with_capacity(READY_TASKS_PER_TURN);
    tasks.drain_into(
        &mut scratch,
        READY_TASKS_PER_TURN,
        EVENT_READY_TASKS_PER_TURN,
    );
    assert_eq!(
        completed_slots(&tasks, &mut scratch),
        (1_000..1_000 + EVENT_READY_TASKS_PER_TURN)
            .chain(0..READY_TASKS_PER_TURN - EVENT_READY_TASKS_PER_TURN)
            .collect::<Vec<_>>()
    );

    tasks.drain_into(
        &mut scratch,
        READY_TASKS_PER_TURN,
        EVENT_READY_TASKS_PER_TURN,
    );
    assert_eq!(
        completed_slots(&tasks, &mut scratch),
        (1_000 + EVENT_READY_TASKS_PER_TURN..1_000 + READY_TASKS_PER_TURN)
            .chain(
                READY_TASKS_PER_TURN - EVENT_READY_TASKS_PER_TURN
                    ..2 * (READY_TASKS_PER_TURN - EVENT_READY_TASKS_PER_TURN),
            )
            .collect::<Vec<_>>()
    );

    scratch.clear();
    let ready = tasks.ready.lock();
    assert!(ready.event.is_empty());
    assert_eq!(ready.normal.len(), READY_TASKS_PER_TURN);
}

/// An event wake cannot promote a token already latched in the normal
/// lane because lane selection happens only on the first latch transition.
#[test]
fn test_event_wake_does_not_promote_queued_normal_token() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    let cell = pending_cell(&tasks, 7, true);
    let task_waker = waker(Arc::clone(&cell));
    queue_token(&tasks, cell as Arc<dyn ErasedTask>, ReadyLane::Normal);

    {
        let _event_delivery = tasks.event_delivery();
        task_waker.wake_by_ref();
    }

    let ready = tasks.ready.lock();
    assert_eq!(ready.normal.len(), 1);
    assert!(ready.event.is_empty());
    drop(ready);
    tasks.clear();
}

/// A self-wake published while a spawned task is being polled uses the
/// normal lane because task polling is outside event-delivery phases.
#[test]
fn test_task_poll_self_wake_uses_normal_lane() {
    struct WakePending;

    impl Future for WakePending {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    let cell = Arc::new(TaskCell {
        slot: 5,
        tasks: Arc::downgrade(&tasks),
        state: TaskState::queued(),
        future: Affine::pinned(std::thread::current().id(), RefCell::new(Some(WakePending))),
    });
    queue_token(&tasks, cell as Arc<dyn ErasedTask>, ReadyLane::Normal);

    let mut scratch = Vec::new();
    tasks.drain_into(&mut scratch, 1, 1);
    assert_eq!(scratch.pop().unwrap().poll(&tasks), None);

    let ready = tasks.ready.lock();
    assert_eq!(ready.normal.len(), 1);
    assert!(ready.event.is_empty());
    drop(ready);
    tasks.clear();
}

/// A by-value wake racing a poll is retained only when that poll returns
/// `Pending`. The polling thread publishes the successor token after
/// releasing the future borrow, while a final poll discards the wake.
#[test]
fn test_foreign_wake_during_poll_follows_poll_result() {
    struct ForeignWake {
        waker: Option<std::sync::mpsc::SyncSender<Waker>>,
        acknowledged: std::sync::mpsc::Receiver<()>,
        ready: bool,
    }

    impl Future for ForeignWake {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
            self.waker.take().unwrap().send(cx.waker().clone()).unwrap();
            self.acknowledged.recv().unwrap();
            if self.ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    for ready in [false, true] {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        let (waker_send, waker_recv) = std::sync::mpsc::sync_channel(0);
        let (acknowledged_send, acknowledged_recv) = std::sync::mpsc::sync_channel(0);
        let cell = Arc::new(TaskCell {
            slot: 12,
            tasks: Arc::downgrade(&tasks),
            state: TaskState::queued(),
            future: Affine::pinned(
                std::thread::current().id(),
                RefCell::new(Some(ForeignWake {
                    waker: Some(waker_send),
                    acknowledged: acknowledged_recv,
                    ready,
                })),
            ),
        });
        queue_token(&tasks, cell as Arc<dyn ErasedTask>, ReadyLane::Normal);

        let foreign = std::thread::spawn(move || {
            waker_recv.recv().unwrap().wake();
            acknowledged_send.send(()).unwrap();
        });
        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, 1, 1);
        let result = scratch.pop().unwrap().poll(&tasks);
        foreign.join().unwrap();

        if ready {
            assert_eq!(result, Some(12));
            assert!(!tasks.has_ready());
        } else {
            assert_eq!(result, None);
            let queued = tasks.ready.lock();
            assert_eq!(queued.normal.len(), 1);
            assert!(queued.event.is_empty());
            drop(queued);
        }
        tasks.clear();
    }
}

/// A foreign-thread wake remains normal even while the owner holds an
/// event-delivery guard.
#[test]
fn test_foreign_wake_during_event_delivery_uses_normal_lane() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    let cell = pending_cell(&tasks, 3, false);
    let task_waker = waker(Arc::clone(&cell));

    {
        let _event_delivery = tasks.event_delivery();
        std::thread::spawn(move || task_waker.wake())
            .join()
            .unwrap();
    }

    let ready = tasks.ready.lock();
    assert_eq!(ready.normal.len(), 1);
    assert!(ready.event.is_empty());
    drop(ready);
    tasks.clear();
}

/// Dropping an event-delivery guard during unwinding resets the phase so
/// the next owner-thread wake returns to the normal lane.
#[test]
fn test_event_delivery_phase_resets_after_unwind() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _event_delivery = tasks.event_delivery();
        panic!("event delivery panic");
    }));
    assert!(result.is_err());

    let cell = pending_cell(&tasks, 4, false);
    ArcWake::wake_by_ref(&cell);
    let ready = tasks.ready.lock();
    assert_eq!(ready.normal.len(), 1);
    assert!(ready.event.is_empty());
    drop(ready);
    tasks.clear();
}

/// Repeated direct wakes before a poll coalesce into one token in both
/// the normal and event lanes.
#[test]
fn test_repeated_direct_wakes_coalesce() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    let normal = pending_cell(&tasks, 5, false);
    let event = pending_cell(&tasks, 6, false);

    for _ in 0..5 {
        ArcWake::wake_by_ref(&normal);
    }

    {
        let _event_delivery = tasks.event_delivery();
        for _ in 0..5 {
            ArcWake::wake_by_ref(&event);
        }
    }

    let ready = tasks.ready.lock();
    assert_eq!(ready.normal.len(), 1);
    assert_eq!(ready.event.len(), 1);
    drop(ready);
    tasks.clear();
}

/// Teardown clears both spawned-task lanes and removes their readiness.
#[test]
fn test_clear_covers_both_ready_lanes() {
    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    queue_token(&tasks, pending_cell(&tasks, 0, true), ReadyLane::Normal);
    queue_token(&tasks, pending_cell(&tasks, 1, true), ReadyLane::Event);
    assert!(tasks.has_ready());

    tasks.clear();
    let ready = tasks.ready.lock();
    assert!(ready.normal.is_empty());
    assert!(ready.event.is_empty());
    drop(ready);
    assert!(!tasks.has_ready());
}

/// A ready future's destructor may wake its own task and panic. The task
/// is terminal before that destructor runs, and later teardown neither
/// queues the wake nor invokes the destructor a second time.
#[test]
fn test_ready_drop_panic_is_terminal_and_dropped_once() {
    struct WakeAndPanicOnDrop {
        waker: Option<Waker>,
        drops: Arc<AtomicUsize>,
    }

    impl Future for WakeAndPanicOnDrop {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
            self.waker = Some(cx.waker().clone());
            Poll::Ready(())
        }
    }

    impl Drop for WakeAndPanicOnDrop {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
            self.waker.take().unwrap().wake();
            panic!("ready future drop panic");
        }
    }

    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    let drops = Arc::new(AtomicUsize::new(0));
    assert!(Tasks::register(
        &tasks,
        WakeAndPanicOnDrop {
            waker: None,
            drops: Arc::clone(&drops),
        }
    ));

    let mut scratch = Vec::new();
    tasks.drain_into(&mut scratch, 1, 1);
    let task = scratch.pop().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| task.poll(&tasks)));
    let payload = result.expect_err("ready future drop must panic");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"ready future drop panic")
    );
    assert_eq!(drops.load(Ordering::Acquire), 1);
    {
        let ready = tasks.ready.lock();
        assert!(ready.normal.is_empty());
        assert!(ready.event.is_empty());
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tasks.clear()));
    assert!(result.is_ok(), "teardown must not drop the future again");
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

/// A panic from one task destructor must not skip later task destructors,
/// and the earliest payload remains the one propagated by teardown.
#[test]
fn test_clear_continues_after_multiple_task_drop_panics() {
    struct PanicOnDrop {
        message: &'static str,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PanicOnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
            panic!("{}", self.message);
        }
    }

    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    let drops = Arc::new(AtomicUsize::new(0));
    assert!(Tasks::register(
        &tasks,
        PanicOnDrop {
            message: "first task drop panic",
            drops: Arc::clone(&drops),
        }
    ));
    assert!(Tasks::register(
        &tasks,
        PanicOnDrop {
            message: "second task drop panic",
            drops: Arc::clone(&drops),
        }
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tasks.clear()));
    let payload = result.expect_err("task teardown should propagate the first panic");
    assert_eq!(
        payload.downcast_ref::<String>().map(String::as_str),
        Some("first task drop panic")
    );
    assert_eq!(drops.load(Ordering::Acquire), 2);
}

/// A bounded drain preserves FIFO order and leaves every token beyond the
/// limit in the shared queue, where [Tasks::has_ready] keeps the worker
/// from parking. A second drain observes the remainder without loss.
#[test]
fn test_bounded_fifo_drain_is_lossless_and_remains_ready() {
    const LIMIT: usize = 64;

    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    for _ in 0..=LIMIT {
        assert!(Tasks::register(&tasks, std::future::ready(())));
    }

    let mut scratch = Vec::new();
    tasks.drain_into(&mut scratch, LIMIT, 1);
    assert_eq!(scratch.len(), LIMIT);
    let first = completed_slots(&tasks, &mut scratch);
    assert_eq!(first, (0..LIMIT).collect::<Vec<_>>());
    for slot in first {
        tasks.remove(slot);
    }
    assert_eq!(tasks.ready.lock().normal.len(), 1);
    assert!(tasks.has_ready(), "shared remainder must prevent parking");

    tasks.drain_into(&mut scratch, LIMIT, 1);
    assert_eq!(scratch.len(), 1);
    assert_eq!(completed_slots(&tasks, &mut scratch), vec![LIMIT]);
    tasks.remove(LIMIT);
    assert!(!tasks.has_ready());

    tasks.clear();
}

/// A task that wakes itself and then completes must discard that
/// notification, leaving the full next batch available to a replacement
/// that immediately reuses its arena slot.
#[test]
fn test_self_wake_then_ready_leaves_no_stale_token() {
    struct WakeThenReady;

    impl Future for WakeThenReady {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
            cx.waker().wake_by_ref();
            Poll::Ready(())
        }
    }

    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    assert!(tasks.take_root_ready());
    assert!(Tasks::register(&tasks, WakeThenReady));

    let mut scratch = Vec::new();
    tasks.drain_into(&mut scratch, 1, 1);
    let task = scratch.pop().unwrap();
    let slot = task.poll(&tasks).expect("live task must complete");
    tasks.remove(slot);

    // The completed task's arena slot is immediately reused, without a
    // stale self-wake token preceding its replacement.
    assert!(Tasks::register(&tasks, std::future::ready(())));
    assert_eq!(tasks.ready.lock().normal.len(), 1);

    tasks.drain_into(&mut scratch, 1, 1);
    let replacement = scratch.pop().unwrap();
    assert_eq!(replacement.poll(&tasks), Some(slot));
    tasks.remove(slot);
    assert!(!tasks.has_ready());
    tasks.clear();
}

/// A task that wakes itself multiple times per poll (by ref and by value)
/// must complete exactly once, coalesce to one successor after each
/// pending poll, and leave its immediately reused arena slot intact.
#[test]
// The by-value wake is deliberate: it exercises the consuming waker
// vtable path alongside `wake_by_ref`.
#[allow(clippy::waker_clone_wake)]
fn test_self_wake_storm_and_slot_reuse() {
    struct SelfWakeStorm {
        polls: usize,
    }
    impl Future for SelfWakeStorm {
        type Output = usize;
        fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<usize> {
            self.polls += 1;
            if self.polls >= 4 {
                return Poll::Ready(self.polls);
            }
            cx.waker().wake_by_ref();
            cx.waker().wake_by_ref();
            cx.waker().clone().wake();
            Poll::Pending
        }
    }

    Runner::default().start(|context| async move {
        let storm = context.child("storm").spawn(|_| SelfWakeStorm { polls: 0 });
        assert_eq!(storm.await.unwrap(), 4);

        // Repeated self-wakes must not corrupt immediately reused slots.
        for i in 0..32u32 {
            let handle = context.child("reuse").spawn(move |_| async move { i });
            assert_eq!(handle.await.unwrap(), i);
        }
    });
}

/// A waker captured from a completed task must be inert: waking it (from
/// the runtime thread and from a foreign thread) after its arena slot was
/// freed and reused must neither double-free the slot nor disturb the
/// tasks that reused it.
#[test]
fn test_stale_waker_after_completion_and_slot_reuse() {
    struct CaptureWaker(Arc<Mutex<Option<Waker>>>);
    impl Future for CaptureWaker {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
            *self.0.lock() = Some(cx.waker().clone());
            Poll::Ready(())
        }
    }

    Runner::default().start(|context| async move {
        let slot = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&slot);
        context
            .child("victim")
            .spawn(move |_| CaptureWaker(captured))
            .await
            .unwrap();

        // The victim completed and freed its slot. Fire the stale waker
        // repeatedly (cross-thread too) while replacements reuse it.
        let waker = slot.lock().take().unwrap();
        waker.wake_by_ref();
        let cross = waker.clone();
        std::thread::spawn(move || cross.wake()).join().unwrap();
        for i in 0..8u32 {
            let handle = context.child("reuse").spawn(move |_| async move { i });
            assert_eq!(handle.await.unwrap(), i);
            waker.wake_by_ref();
        }
    });
}

/// A waker that outlives the runtime must be inert: waking and dropping
/// it after `start` returned must not touch freed executor state.
#[test]
// The by-value wake is deliberate: it exercises the consuming waker
// vtable path alongside `wake_by_ref`.
#[allow(clippy::waker_clone_wake)]
fn test_waker_outlives_runtime() {
    struct CaptureWaker(Arc<Mutex<Option<Waker>>>);
    impl Future for CaptureWaker {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
            *self.0.lock() = Some(cx.waker().clone());
            Poll::Ready(())
        }
    }

    let slot = Arc::new(Mutex::new(None::<Waker>));
    let captured = Arc::clone(&slot);
    Runner::default().start(|context| async move {
        context
            .child("victim")
            .spawn(move |_| CaptureWaker(captured))
            .await
            .unwrap();
    });

    let waker = slot.lock().take().unwrap();
    waker.wake_by_ref();
    waker.clone().wake();
    drop(waker);
}

#[test]
#[allow(clippy::waker_clone_wake)]
fn test_root_waker_outlives_runtime() {
    let slot = Arc::new(Mutex::new(None::<Waker>));
    let captured = Arc::clone(&slot);
    let task_slot = Arc::new(Mutex::new(None::<std::sync::Weak<Tasks>>));
    let captured_tasks = Arc::clone(&task_slot);
    Runner::default().start(move |context| {
        let executor = context.executor.upgrade().unwrap();
        *captured_tasks.lock() = Some(Arc::downgrade(&executor.tasks));
        std::future::poll_fn(move |cx| {
            *captured.lock() = Some(cx.waker().clone());
            Poll::Ready(())
        })
    });

    // The retained waker must not keep the task arena or ring wake fd alive.
    assert!(task_slot.lock().take().unwrap().upgrade().is_none());
    let waker = slot.lock().take().unwrap();
    waker.wake_by_ref();
    waker.clone().wake();
    drop(waker);
}

/// Spawns registered from a dedicated worker onto a worker that is
/// paused immediately before registration must be rejected when the
/// target worker closes its arena in the interim.
#[test]
fn test_cross_worker_spawn_rejected_after_arena_closes() {
    let polled = Arc::new(AtomicBool::new(false));
    let polled_by_task = Arc::clone(&polled);
    let (result_send, result_recv) = std::sync::mpsc::channel();

    Runner::default().start(move |context| async move {
        let tasks = context.executor().tasks.clone();
        let target = context.child("target");
        let (paused_send, paused_recv) = oneshot::channel();
        let observed_tasks = Arc::downgrade(&tasks);
        tasks.hook_register_once(move || {
            paused_send
                .send(())
                .expect("root worker dropped pause signal");
            let tasks = observed_tasks
                .upgrade()
                .expect("task arena dropped during registration");
            while !tasks.is_closed() {
                std::thread::yield_now();
            }
        });

        let _dedicated = context
            .child("dedicated")
            .dedicated()
            .spawn(move |_| async move {
                let handle = target.spawn(move |_| {
                    std::future::poll_fn(move |_| {
                        polled_by_task.store(true, Ordering::Release);
                        Poll::Ready(())
                    })
                });
                let result = handle.await;
                result_send
                    .send(result)
                    .expect("test dropped spawn result receiver");
            });

        paused_recv.await.expect("registration did not reach hook");
    });

    let result = result_recv.recv().expect("dedicated worker dropped");
    assert!(
        matches!(&result, Err(Error::Closed)),
        "spawn returned an unexpected result: {result:?}"
    );
    assert!(
        !polled.load(Ordering::Acquire),
        "rejected task must not be polled"
    );
}

/// Spawns registered from a dedicated worker onto a worker that is
/// concurrently tearing down must either run or resolve with
/// [Error::Closed], and never hang, panic, or leave a task polled after
/// teardown.
#[test]
fn test_cross_worker_spawn_races_teardown() {
    for _ in 0..8 {
        Runner::default().start(|context| async move {
            let root_spawner = context.child("target");
            let (entered_send, entered_recv) = oneshot::channel();
            let _dedicated = context.child("ded").dedicated().spawn(move |_| async move {
                // Register onto the root worker from this thread
                // while the root races into teardown.
                let mut entered = Some(entered_send);
                for i in 0..1024u32 {
                    let handle = root_spawner.child("race").spawn(move |_| async move { i });
                    // Prove the loop started (first spawn issued) before
                    // the root is allowed to tear down.
                    if let Some(entered) = entered.take() {
                        let _ = entered.send(());
                    }
                    match handle.await {
                        Ok(value) => assert_eq!(value, i),
                        Err(Error::Closed) => break,
                        Err(err) => panic!("unexpected spawn error: {err}"),
                    }
                }
            });
            // Return as soon as the dedicated worker has provably entered
            // its spawn loop: teardown races the remaining spawns.
            let _ = entered_recv.await;
        });
    }
}

/// A context moved to a raw thread can spawn a task back onto its origin
/// worker: the task cell is pinned to the worker that polls it, not to
/// the registering thread.
#[test]
fn test_spawn_from_foreign_thread() {
    Runner::default().start(|context| async move {
        let (send, recv) = oneshot::channel();
        let spawner = context.child("foreign");
        std::thread::spawn(move || {
            let handle = spawner.spawn(|context| async move {
                context.sleep(Duration::from_millis(10)).await;
                42
            });
            let _ = send.send(handle);
        });
        assert_eq!(recv.await.unwrap().await.unwrap(), 42);
    });
}

/// A dedicated task can spawn onto another worker through a moved
/// context, and the spawned task runs on the context's origin worker.
#[test]
fn test_cross_worker_spawn() {
    Runner::default().start(|context| async move {
        let root_spawner = context.child("sibling");
        let dedicated = context
            .child("dedicated")
            .dedicated()
            .spawn(move |_| async move {
                // Register onto the root worker from this worker's
                // thread, then await the result across threads.
                root_spawner.spawn(|_| async move { 7 }).await.unwrap()
            });
        assert_eq!(dedicated.await.unwrap(), 7);
    });
}

/// Property: a cleared arena rejects registration and drops the supplied
/// future without polling it. Setup: create [Tasks] directly and close
/// the arena with [Tasks::clear]. Action: register a future holding a
/// drop probe, then perform a late remove. Expected: register returns
/// false, the probe reports the future dropped unpolled, and the late
/// remove is harmless.
#[test]
fn test_clear_rejects_registration_and_drops_future() {
    struct Probe {
        polled: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }
    impl Future for Probe {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<()> {
            self.polled.store(true, Ordering::Release);
            Poll::Ready(())
        }
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
    tasks.clear();

    let polled = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let future = Probe {
        polled: Arc::clone(&polled),
        dropped: Arc::clone(&dropped),
    };
    assert!(
        !Tasks::register(&tasks, future),
        "closed arena must reject registration"
    );
    assert!(dropped.load(Ordering::Acquire), "future must drop unpolled");
    assert!(!polled.load(Ordering::Acquire), "future must not be polled");

    // A late remove after clear is harmless.
    tasks.remove(0);
}
