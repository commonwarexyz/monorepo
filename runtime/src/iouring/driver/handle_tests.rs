use super::*;
use crate::iouring::driver::{request::RecvRequest, waiter::StageOutcome};
use futures::task::{ArcWake, waker as arc_waker};
use std::{
    cell::Cell,
    os::unix::net::UnixStream,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    task::{RawWaker, RawWakerVTable},
    time::{Duration, Instant},
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
            StageOutcome::Freed
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
            StageOutcome::Freed
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
            StageOutcome::Freed
        ));
    });

    drop(Ticket {
        handle: handle.clone(),
        state: TicketState::Waiting(completion_id),
    });
    handle.with(|ops| {
        assert!(matches!(
            ops.waiters.stage(ticket_waiter),
            StageOutcome::Freed
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
            StageOutcome::Freed
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
            StageOutcome::Freed
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
            StageOutcome::Freed
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
            StageOutcome::Freed
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
