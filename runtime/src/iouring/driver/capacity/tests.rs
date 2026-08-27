use super::*;
use crate::iouring::driver::callbacks::{WakerAction, wake_batch};
use commonware_utils::sync::Mutex;
use futures::task::{ArcWake, waker as arc_waker};
use std::{
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

unsafe fn count_clone(data: *const ()) -> RawWaker {
    // SAFETY: the test keeps the referenced atomic alive until every
    // waker using this static vtable has been dropped.
    let clones = unsafe { &*data.cast::<AtomicUsize>() };
    clones.fetch_add(1, Ordering::AcqRel);
    RawWaker::new(data, &COUNT_CLONE_VTABLE)
}

static COUNT_CLONE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(count_clone, noop_wake, noop_wake_by_ref, noop_drop);

unsafe fn noop_wake(_: *const ()) {}

unsafe fn noop_wake_by_ref(_: *const ()) {}

unsafe fn noop_drop(_: *const ()) {}

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

