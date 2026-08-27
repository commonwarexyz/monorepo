use super::*;
use crate::iouring::driver::{request::RecvRequest, waiter::StageOutcome};
use futures::task::{ArcWake, waker as arc_waker};
use std::{
    cell::Cell,
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{RawWaker, RawWakerVTable},
};

struct LogWaker {
    id: usize,
    log: Arc<Mutex<Vec<usize>>>,
}

impl ArcWake for LogWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.log.lock().push(arc_self.id);
    }
}

struct CountWaker(AtomicUsize);

impl ArcWake for CountWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::AcqRel);
    }
}

struct PanicWaker;

impl ArcWake for PanicWaker {
    fn wake_by_ref(_: &Arc<Self>) {
        panic!("waker panic");
    }
}

#[test]
fn test_wake_batch_finishes_committed_actions_before_panicking() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let result = catch_unwind(AssertUnwindSafe(|| {
        wake_batch([
            WakerAction::Wake(arc_waker(Arc::new(PanicWaker))),
            WakerAction::Wake(log_waker(1, &log)),
        ]);
    }));
    assert!(result.is_err());
    assert_eq!(*log.lock(), [1]);
}

fn log_waker(id: usize, log: &Arc<Mutex<Vec<usize>>>) -> Waker {
    arc_waker(Arc::new(LogWaker {
        id,
        log: Arc::clone(log),
    }))
}

fn poll_capacity(
    capacity: &mut CapacityWaiters,
    registration: &mut Option<CapacityId>,
    free_len: usize,
    waker: &Waker,
) -> CapacityAdmission {
    poll_capacity_with_deadline(capacity, registration, free_len, None, waker)
}

fn poll_capacity_with_deadline(
    capacity: &mut CapacityWaiters,
    registration: &mut Option<CapacityId>,
    free_len: usize,
    deadline: Option<Instant>,
    waker: &Waker,
) -> CapacityAdmission {
    let mut actions = Vec::new();
    let mut incoming = Some(waker.clone());
    let admission = capacity.poll(
        registration,
        free_len,
        deadline,
        &mut incoming,
        &mut actions,
    );
    actions.extend(incoming.map(WakerAction::Drop));
    wake_batch(actions);
    admission
}

fn reconcile_capacity(capacity: &mut CapacityWaiters, free_len: usize) {
    let mut actions = Vec::new();
    capacity.reconcile(free_len, &mut actions);
    wake_batch(actions);
}

fn cancel_capacity(capacity: &mut CapacityWaiters, id: CapacityId, free_len: usize) {
    let mut actions = Vec::new();
    capacity.cancel(id, free_len, &mut actions);
    wake_batch(actions);
}

fn recv_request() -> Request {
    let (left, _right) = UnixStream::pair().unwrap();
    Request::Recv(RecvRequest {
        fd: Arc::new(left.into()),
        buf: IoBufMut::with_capacity(1),
        offset: 0,
        len: 1,
        exact: false,
        deadline: None,
    })
}

#[test]
fn test_capacity_fifo_prevents_fresh_admission_barging() {
    let mut capacity = CapacityWaiters::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let wakers = [log_waker(0, &log), log_waker(1, &log), log_waker(2, &log)];
    let mut registrations = [None, None, None];

    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[0], 0, &wakers[0]),
        CapacityAdmission::Queued
    );
    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[1], 0, &wakers[1]),
        CapacityAdmission::Queued
    );
    reconcile_capacity(&mut capacity, 1);
    assert_eq!(capacity.reserved(), 1);

    // One free slot is already reserved for the oldest waiter. A new poll
    // joins behind the remaining queued waiter instead of taking it.
    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[2], 1, &wakers[2]),
        CapacityAdmission::Queued
    );
    assert_eq!(capacity.queued(), 2);
    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[0], 1, &wakers[0]),
        CapacityAdmission::Granted
    );

    // Simulate insertion consuming the free waiter, then two terminal
    // removals. The older queued registration is always granted first.
    reconcile_capacity(&mut capacity, 1);
    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[1], 1, &wakers[1]),
        CapacityAdmission::Granted
    );
    reconcile_capacity(&mut capacity, 1);
    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[2], 1, &wakers[2]),
        CapacityAdmission::Granted
    );
    assert_eq!(*log.lock(), vec![0, 1, 2]);
    assert_eq!(capacity.registered(), 0);
    assert_eq!(capacity.reserved(), 0);
}

#[test]
fn test_capacity_reconcile_wakes_exactly_k_fifo_heads() {
    let mut capacity = CapacityWaiters::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut registrations = [None, None, None, None, None];
    let wakers: Vec<_> = (0..registrations.len())
        .map(|id| log_waker(id, &log))
        .collect();
    for (registration, waker) in registrations.iter_mut().zip(&wakers) {
        assert_eq!(
            poll_capacity(&mut capacity, registration, 0, waker),
            CapacityAdmission::Queued
        );
    }

    reconcile_capacity(&mut capacity, 3);
    assert_eq!(*log.lock(), vec![0, 1, 2]);
    assert_eq!(capacity.reserved(), 3);
    assert_eq!(capacity.queued(), 2);
    assert_eq!(capacity.registered(), 5);
}

#[test]
fn test_capacity_granted_deadline_transfers_permit_to_fifo_survivor() {
    let now = Instant::now();
    let mut capacity = CapacityWaiters::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let wakers = [log_waker(0, &log), log_waker(1, &log), log_waker(2, &log)];
    let mut registrations = [None, None, None];
    assert_eq!(
        poll_capacity_with_deadline(
            &mut capacity,
            &mut registrations[0],
            0,
            Some(now + Duration::from_millis(10)),
            &wakers[0],
        ),
        CapacityAdmission::Queued
    );
    assert_eq!(
        poll_capacity_with_deadline(
            &mut capacity,
            &mut registrations[1],
            0,
            Some(now + Duration::from_millis(20)),
            &wakers[1],
        ),
        CapacityAdmission::Queued
    );
    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[2], 0, &wakers[2],),
        CapacityAdmission::Queued
    );

    reconcile_capacity(&mut capacity, 1);
    assert_eq!(*log.lock(), vec![0]);
    assert_eq!(capacity.reserved(), 1);
    assert_eq!(capacity.next_deadline(now), Some(Duration::from_millis(10)));

    let mut actions = Vec::new();
    capacity.expire(now + Duration::from_millis(15), 1, &mut actions);
    wake_batch(actions);
    assert_eq!(*log.lock(), vec![0, 1]);
    assert!(capacity.live_state(registrations[0].unwrap()).is_none());
    assert!(matches!(
        capacity.live_state(registrations[1].unwrap()),
        Some(CapacityState::Granted { .. })
    ));
    assert_eq!(capacity.registered(), 2);
    assert_eq!(capacity.queued(), 1);
    assert_eq!(capacity.reserved(), 1);
    assert_eq!(
        capacity.next_deadline(now + Duration::from_millis(15)),
        Some(Duration::from_millis(5))
    );

    cancel_capacity(&mut capacity, registrations[0].unwrap(), 1);
    assert_eq!(capacity.registered(), 2);
    assert_eq!(capacity.reserved(), 1);
    assert_eq!(
        poll_capacity_with_deadline(
            &mut capacity,
            &mut registrations[1],
            1,
            Some(now + Duration::from_millis(20)),
            &wakers[1],
        ),
        CapacityAdmission::Granted
    );
    reconcile_capacity(&mut capacity, 1);
    assert_eq!(
        poll_capacity(&mut capacity, &mut registrations[2], 1, &wakers[2]),
        CapacityAdmission::Granted
    );
    assert_eq!(*log.lock(), vec![0, 1, 2]);
    assert_eq!(capacity.registered(), 0);
}

#[test]
fn test_capacity_deadline_tombstones_compact_behind_live_root() {
    let now = Instant::now();
    let mut capacity = CapacityWaiters::new();
    let waker = futures::task::noop_waker();
    let mut anchor = None;
    assert_eq!(
        poll_capacity_with_deadline(
            &mut capacity,
            &mut anchor,
            0,
            Some(now + Duration::from_secs(1)),
            &waker,
        ),
        CapacityAdmission::Queued
    );

    for offset in 0..256 {
        let mut churn = None;
        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut churn,
                0,
                Some(now + Duration::from_secs(2) + Duration::from_millis(offset)),
                &waker,
            ),
            CapacityAdmission::Queued
        );
        cancel_capacity(&mut capacity, churn.unwrap(), 0);
    }

    assert!(capacity.deadlines.len() < 64);
    assert!(capacity.deadline_tombstones < 64);
    assert_eq!(capacity.registered(), 1);
    assert_eq!(capacity.arena_len(), 2);
    cancel_capacity(&mut capacity, anchor.unwrap(), 0);
    assert_eq!(capacity.next_deadline(now), None);
    assert!(capacity.deadlines.is_empty());
}

#[test]
fn test_capacity_close_wins_after_unobserved_expiry() {
    let handle = Handle::new(1, RingWaker::new().unwrap());
    let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(3600),
    ));
    let deadline = Instant::now() + Duration::from_secs(1);
    let (expired_left, _expired_right) = UnixStream::pair().unwrap();
    let mut expired = Box::pin(handle.recv(
        Arc::new(expired_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        deadline,
    ));
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(blocker.as_mut().poll(&mut cx).is_pending());
    assert!(expired.as_mut().poll(&mut cx).is_pending());

    let actions = handle.with(|ops| {
        let mut actions = Vec::new();
        ops.capacity
            .expire(deadline, ops.waiters.free_len(), &mut actions);
        assert_eq!(ops.capacity.registered(), 0);
        actions
    });
    wake_batch(actions);
    assert!(handle.close().is_empty());

    assert!(matches!(
        expired.as_mut().poll(&mut cx),
        Poll::Ready(Err((_, Error::RecvFailed)))
    ));
}

unsafe fn count_clone(data: *const ()) -> RawWaker {
    // SAFETY: the test keeps the referenced atomic alive until every
    // waker using this static vtable has been dropped.
    let clones = unsafe { &*data.cast::<AtomicUsize>() };
    clones.fetch_add(1, Ordering::AcqRel);
    RawWaker::new(data, &COUNT_CLONE_VTABLE)
}

static COUNT_CLONE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(count_clone, noop_wake, noop_wake_by_ref, noop_drop);

#[test]
fn test_capacity_granted_cancellation_hands_permit_to_fifo_head() {
    let mut capacity = CapacityWaiters::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let first_waker = log_waker(0, &log);
    let second_waker = log_waker(1, &log);
    let mut first = None;
    let mut second = None;
    assert_eq!(
        poll_capacity(&mut capacity, &mut first, 0, &first_waker),
        CapacityAdmission::Queued
    );
    assert_eq!(
        poll_capacity(&mut capacity, &mut second, 0, &second_waker),
        CapacityAdmission::Queued
    );

    reconcile_capacity(&mut capacity, 1);
    cancel_capacity(&mut capacity, first.unwrap(), 1);
    assert_eq!(*log.lock(), vec![0, 1]);
    assert_eq!(capacity.reserved(), 1);
    assert_eq!(capacity.queued(), 0);
    assert_eq!(capacity.registered(), 1);
    assert_eq!(
        poll_capacity(&mut capacity, &mut second, 1, &second_waker),
        CapacityAdmission::Granted
    );
}

#[test]
fn test_capacity_queued_head_middle_tail_cancellation_preserves_links() {
    let mut capacity = CapacityWaiters::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut registrations = [None, None, None, None, None];
    let wakers: Vec<_> = (0..registrations.len())
        .map(|id| log_waker(id, &log))
        .collect();
    for (registration, waker) in registrations.iter_mut().zip(&wakers) {
        assert_eq!(
            poll_capacity(&mut capacity, registration, 0, waker),
            CapacityAdmission::Queued
        );
    }

    cancel_capacity(&mut capacity, registrations[0].unwrap(), 0);
    cancel_capacity(&mut capacity, registrations[2].unwrap(), 0);
    cancel_capacity(&mut capacity, registrations[4].unwrap(), 0);
    assert_eq!(capacity.queued(), 2);
    reconcile_capacity(&mut capacity, 2);
    assert_eq!(*log.lock(), vec![1, 3]);
    assert_eq!(capacity.reserved(), 2);
}

#[test]
fn test_capacity_queued_repoll_replaces_waker_without_reordering() {
    let mut capacity = CapacityWaiters::new();
    let old = Arc::new(CountWaker(AtomicUsize::new(0)));
    let new = Arc::new(CountWaker(AtomicUsize::new(0)));
    let old_waker = arc_waker(Arc::clone(&old));
    let new_waker = arc_waker(Arc::clone(&new));
    let mut registration = None;
    assert_eq!(
        poll_capacity(&mut capacity, &mut registration, 0, &old_waker),
        CapacityAdmission::Queued
    );
    assert_eq!(
        poll_capacity(&mut capacity, &mut registration, 0, &new_waker),
        CapacityAdmission::Queued
    );
    assert_eq!(capacity.queued(), 1);
    reconcile_capacity(&mut capacity, 1);
    assert_eq!(old.0.load(Ordering::Acquire), 0);
    assert_eq!(new.0.load(Ordering::Acquire), 1);
}

#[test]
fn test_capacity_queued_repoll_with_same_waker_retains_registration() {
    let mut capacity = CapacityWaiters::new();
    let clone_count = AtomicUsize::new(0);
    // SAFETY: clone_count outlives the waker and the capacity arena. The
    // vtable treats its pointer as an AtomicUsize and never owns it.
    let waker = unsafe {
        Waker::from_raw(RawWaker::new(
            std::ptr::from_ref(&clone_count).cast(),
            &COUNT_CLONE_VTABLE,
        ))
    };
    let mut registration = None;
    assert_eq!(
        poll_capacity(&mut capacity, &mut registration, 0, &waker),
        CapacityAdmission::Queued
    );
    let clones = clone_count.load(Ordering::Acquire);

    assert_eq!(
        poll_capacity(&mut capacity, &mut registration, 0, &waker),
        CapacityAdmission::Queued
    );
    // Polling clones before entering the affine Ops borrow. The arena
    // recognizes the equivalent waker and defers that clone's drop rather
    // than replacing the stored registration.
    assert_eq!(clone_count.load(Ordering::Acquire), clones + 1);
    assert_eq!(capacity.queued(), 1);

    cancel_capacity(
        &mut capacity,
        registration.expect("capacity registration missing"),
        0,
    );
}

#[test]
fn test_capacity_close_recycles_terminal_registrations() {
    let mut capacity = CapacityWaiters::new();
    let counts: Vec<_> = (0..3)
        .map(|_| Arc::new(CountWaker(AtomicUsize::new(0))))
        .collect();
    let wakers: Vec<_> = counts.iter().cloned().map(arc_waker).collect();
    let mut registrations = [None, None, None];
    for (registration, waker) in registrations.iter_mut().zip(&wakers) {
        assert_eq!(
            poll_capacity(&mut capacity, registration, 0, waker),
            CapacityAdmission::Queued
        );
    }
    let mut grant_actions = Vec::new();
    capacity.reconcile(2, &mut grant_actions);
    wake_batch(grant_actions);
    assert_eq!(capacity.reserved(), 2);
    assert_eq!(capacity.queued(), 1);

    let closed = capacity.close();
    assert_eq!(closed.len(), 1);
    assert!(closed[0].will_wake(&wakers[2]));
    assert_eq!(capacity.registered(), 0);
    assert_eq!(capacity.reserved(), 0);
    assert_eq!(capacity.queued(), 0);
    assert_eq!(capacity.arena_len(), 3);
    assert!(
        registrations
            .iter()
            .flatten()
            .all(|id| capacity.live_state(*id).is_none())
    );
    for waker in closed {
        waker.wake();
    }
    assert!(
        counts
            .iter()
            .all(|count| count.0.load(Ordering::Acquire) == 1)
    );

    // Stale owner or mailbox cancellation cannot affect a recycled slot.
    let stale = registrations[0].unwrap();
    for id in registrations.iter().flatten().copied() {
        cancel_capacity(&mut capacity, id, 2);
    }
    assert_eq!(capacity.registered(), 0);

    let mut replacement = None;
    assert_eq!(
        poll_capacity(&mut capacity, &mut replacement, 0, &wakers[0]),
        CapacityAdmission::Queued
    );
    let replacement = replacement.unwrap();
    assert_eq!(replacement.index, stale.index);
    assert_ne!(replacement.generation, stale.generation);
    assert_eq!(capacity.arena_len(), 3);
    cancel_capacity(&mut capacity, replacement, 0);
}

#[test]
fn test_capacity_wake_count_is_linear_in_waiter_count() {
    const WAITERS: usize = 128;
    let mut capacity = CapacityWaiters::new();
    let count = Arc::new(CountWaker(AtomicUsize::new(0)));
    let waker = arc_waker(Arc::clone(&count));
    let mut registrations = vec![None; WAITERS];
    for registration in &mut registrations {
        assert_eq!(
            poll_capacity(&mut capacity, registration, 0, &waker),
            CapacityAdmission::Queued
        );
    }

    for registration in &mut registrations {
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(
            poll_capacity(&mut capacity, registration, 1, &waker),
            CapacityAdmission::Granted
        );
    }
    assert_eq!(count.0.load(Ordering::Acquire), WAITERS);
    assert_eq!(capacity.registered(), 0);
    assert_eq!(capacity.arena_len(), WAITERS);
}

unsafe fn panic_clone(_: *const ()) -> RawWaker {
    panic!("waker clone panic");
}

unsafe fn noop_wake(_: *const ()) {}

unsafe fn noop_wake_by_ref(_: *const ()) {}

unsafe fn noop_drop(_: *const ()) {}

static PANIC_CLONE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(panic_clone, noop_wake, noop_wake_by_ref, noop_drop);

fn panic_clone_waker() -> Waker {
    // SAFETY: the vtable never dereferences the null data pointer. Clone
    // panics deliberately, and wake and drop are no-ops.
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &PANIC_CLONE_VTABLE)) }
}

/// RawWaker state that orphans one waiter from its drop callback.
struct ReentrantOrphan {
    handle: Handle,
    waiter: Cell<Option<WaiterId>>,
}

unsafe fn clone_reentrant_orphan(data: *const ()) -> RawWaker {
    RawWaker::new(data, &REENTRANT_ORPHAN_VTABLE)
}

unsafe fn wake_reentrant_orphan(data: *const ()) {
    // SAFETY: every waker built by `reentrant_orphan_waker` points to a
    // ReentrantOrphan that outlives all of its raw waker clones.
    unsafe { drop_reentrant_orphan(data) };
}

unsafe fn wake_by_ref_reentrant_orphan(_: *const ()) {}

unsafe fn drop_reentrant_orphan(data: *const ()) {
    // SAFETY: every waker built by `reentrant_orphan_waker` points to a
    // ReentrantOrphan that outlives all of its raw waker clones.
    let state = unsafe { &*data.cast::<ReentrantOrphan>() };
    if let Some(waiter_id) = state.waiter.take() {
        orphan_waiter(&state.handle, waiter_id);
    }
}

static REENTRANT_ORPHAN_VTABLE: RawWakerVTable = RawWakerVTable::new(
    clone_reentrant_orphan,
    wake_reentrant_orphan,
    wake_by_ref_reentrant_orphan,
    drop_reentrant_orphan,
);

fn reentrant_orphan_waker(state: &ReentrantOrphan) -> Waker {
    // SAFETY: the test keeps `state` alive until the original waker and
    // every clone stored in driver state have been dropped.
    unsafe {
        Waker::from_raw(RawWaker::new(
            std::ptr::from_ref(state).cast(),
            &REENTRANT_ORPHAN_VTABLE,
        ))
    }
}

#[test]
fn test_op_waker_reentrant_drop_runs_after_ops_borrow() {
    let handle = Handle::new(2, RingWaker::new().unwrap());
    let target = handle.with(|ops| {
        ops.waiters
            .insert(recv_request(), futures::task::noop_waker())
    });
    let state = ReentrantOrphan {
        handle: handle.clone(),
        waiter: Cell::new(Some(target)),
    };
    let reentrant = reentrant_orphan_waker(&state);
    let mut reentrant_cx = Context::from_waker(&reentrant);
    let mut op = Op::new(&handle, recv_request());
    assert!(Pin::new(&mut op).poll(&mut reentrant_cx).is_pending());

    let noop = futures::task::noop_waker();
    let mut noop_cx = Context::from_waker(&noop);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Pin::new(&mut op).poll(&mut noop_cx)
    }));
    assert!(matches!(result, Ok(Poll::Pending)));
    assert!(state.waiter.get().is_none());
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(target),
            StageOutcome::Complete { freed: true, .. }
        ));
    });

    let op_id = match op.state {
        OpState::Waiting(id) => id,
        _ => panic!("op did not retain its waiter"),
    };
    drop(op);
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(op_id),
            StageOutcome::Complete { freed: true, .. }
        ));
        assert!(ops.waiters.is_empty());
    });
}

#[test]
fn test_ticket_waker_reentrant_drop_runs_after_ops_borrow() {
    let handle = Handle::new(2, RingWaker::new().unwrap());
    let target = handle.with(|ops| {
        ops.waiters
            .insert(recv_request(), futures::task::noop_waker())
    });
    let state = ReentrantOrphan {
        handle: handle.clone(),
        waiter: Cell::new(Some(target)),
    };
    let reentrant = reentrant_orphan_waker(&state);
    let (completion_id, ticket_waiter) = handle.with(|ops| {
        let mut incoming = Some(reentrant.clone());
        let (completions, waiters) = (&mut ops.completions, &mut ops.waiters);
        completions.insert_pending_deferred(&mut incoming, |completion_id| {
            waiters.insert_ticket(recv_request(), completion_id)
        })
    });

    let noop = futures::task::noop_waker();
    let mut cx = Context::from_waker(&noop);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_ticket_completion(&handle, completion_id, &mut cx)
    }));
    assert!(matches!(result, Ok(Poll::Pending)));
    assert!(state.waiter.get().is_none());
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(target),
            StageOutcome::Complete { freed: true, .. }
        ));
    });

    drop(Ticket {
        handle: handle.clone(),
        state: TicketState::Waiting(completion_id),
    });
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(ticket_waiter),
            StageOutcome::Complete { freed: true, .. }
        ));
        assert!(ops.waiters.is_empty());
        assert!(ops.completions.is_empty());
    });
}

#[test]
fn test_pending_op_clone_panic_preserves_observer() {
    let handle = Handle::new(1, RingWaker::new().unwrap());
    let noop = futures::task::noop_waker();
    let mut noop_cx = Context::from_waker(&noop);
    let mut op = Op::new(&handle, recv_request());
    assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());

    let panicking = panic_clone_waker();
    let mut panic_cx = Context::from_waker(&panicking);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Pin::new(&mut op).poll(&mut panic_cx)
    }));
    assert!(result.is_err());
    assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());

    let waiter_id = match op.state {
        OpState::Waiting(id) => id,
        _ => panic!("op lost its waiter after clone panic"),
    };
    drop(op);
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(waiter_id),
            StageOutcome::Complete { freed: true, .. }
        ));
    });
}

#[test]
fn test_pending_ticket_clone_panic_preserves_observer() {
    let handle = Handle::new(1, RingWaker::new().unwrap());
    let noop = futures::task::noop_waker();
    let (completion_id, waiter_id) = handle.with(|ops| {
        let mut incoming = Some(noop.clone());
        let (completions, waiters) = (&mut ops.completions, &mut ops.waiters);
        completions.insert_pending_deferred(&mut incoming, |completion_id| {
            waiters.insert_ticket(recv_request(), completion_id)
        })
    });

    let panicking = panic_clone_waker();
    let mut panic_cx = Context::from_waker(&panicking);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_ticket_completion(&handle, completion_id, &mut panic_cx)
    }));
    assert!(result.is_err());
    let mut noop_cx = Context::from_waker(&noop);
    assert!(poll_ticket_completion(&handle, completion_id, &mut noop_cx).is_pending());

    drop(Ticket {
        handle: handle.clone(),
        state: TicketState::Waiting(completion_id),
    });
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(waiter_id),
            StageOutcome::Complete { freed: true, .. }
        ));
        assert!(ops.completions.is_empty());
    });
}

#[test]
fn test_granted_admission_clone_panic_preserves_reservation_for_retry() {
    let handle = Handle::new(1, RingWaker::new().unwrap());
    let blocker = handle.with(|ops| {
        ops.waiters
            .insert(recv_request(), futures::task::noop_waker())
    });
    let mut op = Op::new(&handle, recv_request());
    let noop = futures::task::noop_waker();
    let mut noop_cx = Context::from_waker(&noop);
    assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());
    handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 0);
    });

    let actions = handle.with(|ops| {
        let outcome = ops.waiters.classify_orphan(blocker);
        assert!(matches!(
            &outcome,
            DropOutcome::Cancel {
                needs_sqe: false,
                ..
            }
        ));
        let _ = ops.waiters.mark_orphaned(blocker, &outcome);
        assert!(matches!(
            ops.waiters.stage(blocker),
            StageOutcome::Complete { freed: true, .. }
        ));
        let mut actions = Vec::new();
        ops.capacity.reconcile(ops.waiters.free_len(), &mut actions);
        actions
    });
    wake_batch(actions);
    handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    let panicking = panic_clone_waker();
    let mut panic_cx = Context::from_waker(&panicking);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = Pin::new(&mut op).poll(&mut panic_cx);
    }));
    assert!(result.is_err());
    handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    // The same Op can consume its original grant on a later valid poll.
    assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());
    let waiter_id = match op.state {
        OpState::Waiting(id) => id,
        _ => panic!("retried op did not publish waiter ownership"),
    };
    handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.capacity.registered(), 0);
        assert_eq!(ops.capacity.reserved(), 0);
    });
    drop(op);
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(waiter_id),
            StageOutcome::Complete { freed: true, .. }
        ));
        assert_eq!(ops.waiters.len(), 0);
    });
}

#[test]
fn test_queued_ticket_admission_fails_after_close() {
    let handle = Handle::new(1, RingWaker::new().unwrap());
    let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(3600),
    ));
    let (left, _right) = UnixStream::pair().unwrap();
    let file = Arc::new(File::from(OwnedFd::from(left)));
    let mut admission = Box::pin(handle.start_sync(file));
    let noop = futures::task::noop_waker();
    let mut cx = Context::from_waker(&noop);
    assert!(blocker.as_mut().poll(&mut cx).is_pending());
    assert!(admission.as_mut().poll(&mut cx).is_pending());
    handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.backlog.len(), 1);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 1);
    });

    for waker in handle.close() {
        waker.wake();
    }
    let Poll::Ready(mut ticket) = admission.as_mut().poll(&mut cx) else {
        panic!("closed ticket admission remained pending");
    };
    assert!(matches!(
        Pin::new(&mut ticket).poll(&mut cx),
        Poll::Ready(Err(Error::Closed))
    ));
    handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 0);
        assert_eq!(ops.capacity.reserved(), 0);
    });
}
