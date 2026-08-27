use super::*;
use crate::{
    IoBuf, IoBufMut, IoBufs,
    iouring::driver::request::{
        Cache, ReadAtRequest, RecvRequest, SendRequest, SyncRequest, WriteAtRequest, WriteAtState,
    },
};
use futures::task::noop_waker;
use std::{
    os::fd::OwnedFd,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

/// Build a `Sync` request backed by a socket fd so waiter tests can
/// exercise slot lifecycle without touching the filesystem.
fn make_sync_request() -> Request {
    let (sock_left, _sock_right) =
        std::os::unix::net::UnixStream::pair().expect("failed to create unix socket pair");
    let file = std::fs::File::from(OwnedFd::from(sock_left));
    Request::Sync(SyncRequest {
        file: Arc::new(file),
    })
}

fn make_send_request() -> Request {
    Request::Send(SendRequest {
        fd: Arc::new(std::os::unix::net::UnixStream::pair().unwrap().0.into()),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    })
}

fn make_recv_request() -> Request {
    make_recv_request_with_deadline(None)
}

fn make_recv_request_with_deadline(deadline: Option<std::time::Instant>) -> Request {
    Request::Recv(RecvRequest {
        fd: Arc::new(std::os::unix::net::UnixStream::pair().unwrap().0.into()),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline,
    })
}

fn make_read_at_request() -> Request {
    let (sock_left, _sock_right) =
        std::os::unix::net::UnixStream::pair().expect("failed to create unix socket pair");
    let file = std::fs::File::from(OwnedFd::from(sock_left));
    Request::ReadAt(ReadAtRequest {
        file: Arc::new(file),
        offset: 0,
        len: 8,
        read: 0,
        buf: IoBufMut::with_capacity(8),
        cache: Cache::Enabled,
    })
}

fn make_write_at_request() -> Request {
    let (sock_left, _sock_right) =
        std::os::unix::net::UnixStream::pair().expect("failed to create unix socket pair");
    let file = std::fs::File::from(OwnedFd::from(sock_left));
    Request::WriteAt(WriteAtRequest {
        file: Arc::new(file),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    })
}

fn insert(waiters: &mut Waiters, request: Request, tick: Option<Tick>) -> WaiterId {
    let id = waiters.insert(request, noop_waker());
    if let Some(tick) = tick {
        waiters.set_target_tick(id, tick);
    }
    id
}

fn waiter_state(waiters: &Waiters, waiter_id: WaiterId) -> Option<WaiterState> {
    let index = waiter_id.index() as usize;
    let slot = waiters.entries.get(index)?.as_ref()?;
    (slot.id == waiter_id).then_some(slot.state)
}

fn mark_orphaned(waiters: &mut Waiters, waiter_id: WaiterId) -> DropOutcome {
    let outcome = waiters.classify_orphan(waiter_id);
    drop(waiters.mark_orphaned(waiter_id, &outcome));
    outcome
}

fn remove_waiter(waiters: &mut Waiters, waiter_id: WaiterId) -> Lifecycle {
    let index = waiter_id.index() as usize;
    let slot = waiters
        .entries
        .get(index)
        .and_then(Option::as_ref)
        .expect("remove_waiter called for untracked waiter");
    assert_eq!(
        slot.id, waiter_id,
        "remove_waiter called with stale waiter id"
    );
    waiters.take(index)
}

fn insert_ticket(
    completions: &mut TicketCompletions,
    waiters: &mut Waiters,
    request: Request,
) -> (CompletionId, WaiterId) {
    completions.insert_pending(noop_waker(), |completion_id| {
        waiters.insert_ticket(request, completion_id)
    })
}

#[test]
fn test_ticket_output_survives_waiter_reuse() {
    let mut waiters = Waiters::new(1);
    let mut completions = TicketCompletions::new();
    let (completion_id, waiter_id) =
        insert_ticket(&mut completions, &mut waiters, make_sync_request());
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    let CompletionOutcome::Ticket {
        waiter_id: completed_waiter,
        completion_id: completed_completion,
        output,
        target_tick: None,
    } = waiters.on_completion(waiter_id.user_data(), 0)
    else {
        panic!("sync ticket did not produce detached output");
    };

    let _ = completions.publish_ready(completed_completion, completed_waiter, output);
    waiters.finish_ticket(completed_waiter, completed_completion);
    assert_eq!(waiters.len(), 0);
    assert_eq!(completions.ready(), 1);

    // Reuse the only waiter before consuming the first ticket. The Ready
    // output remains addressed solely by its independent completion ID.
    let (second_completion, second_waiter) =
        insert_ticket(&mut completions, &mut waiters, make_sync_request());
    assert_eq!(second_waiter.index(), waiter_id.index());
    assert_ne!(second_waiter, waiter_id);
    assert_ne!(second_completion, completion_id);
    assert!(matches!(
        completions.poll_take(completion_id, &noop_waker()),
        Some(Output::Sync(Ok(())))
    ));

    assert!(matches!(
        completions.mark_orphaned(second_completion),
        CompletionDropOutcome::Pending { waiter_id, .. } if waiter_id == second_waiter
    ));
    let _ = remove_waiter(&mut waiters, second_waiter);
}

#[test]
fn test_completion_slot_reuses_after_ticket_drop() {
    let mut waiters = Waiters::new(1);
    let mut completions = TicketCompletions::new();
    let (first, first_waiter) = insert_ticket(&mut completions, &mut waiters, make_sync_request());
    assert!(matches!(
        completions.mark_orphaned(first),
        CompletionDropOutcome::Pending { waiter_id, .. } if waiter_id == first_waiter
    ));
    let _ = remove_waiter(&mut waiters, first_waiter);

    let (reused, reused_waiter) =
        insert_ticket(&mut completions, &mut waiters, make_sync_request());
    assert_eq!(reused, first);
    assert_eq!(completions.arena_len(), 1);

    assert!(matches!(
        completions.mark_orphaned(reused),
        CompletionDropOutcome::Pending { waiter_id, .. } if waiter_id == reused_waiter
    ));
    let _ = remove_waiter(&mut waiters, reused_waiter);
}

#[test]
fn test_ticket_local_timeout_publishes_then_recycles_waiter() {
    let mut waiters = Waiters::new(1);
    let mut completions = TicketCompletions::new();
    let (completion_id, waiter_id) =
        insert_ticket(&mut completions, &mut waiters, make_recv_request());
    assert!(waiters.expire(waiter_id));
    let StageOutcome::Ticket {
        waiter_id: completed_waiter,
        completion_id: completed_completion,
        output,
    } = waiters.stage(waiter_id)
    else {
        panic!("locally timed out ticket did not produce detached output");
    };
    assert_eq!(completed_waiter, waiter_id);
    assert_eq!(completed_completion, completion_id);

    let _ = completions.publish_ready(completed_completion, completed_waiter, output);
    waiters.finish_ticket(completed_waiter, completed_completion);
    assert!(waiters.is_empty());
    let Some(Output::Recv(Err(error))) = completions.poll_take(completion_id, &noop_waker()) else {
        panic!("locally timed out ticket did not retain recv failure");
    };
    let (_, error) = *error;
    assert!(matches!(error, Error::Timeout));
}

#[test]
fn test_pending_sync_ticket_drop_detaches_through_completion_id() {
    let mut waiters = Waiters::new(1);
    let mut completions = TicketCompletions::new();
    let (completion_id, waiter_id) =
        insert_ticket(&mut completions, &mut waiters, make_sync_request());
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(matches!(
        completions.mark_orphaned(completion_id),
        CompletionDropOutcome::Pending {
            waiter_id: pending_waiter,
            ..
        } if pending_waiter == waiter_id
    ));
    assert!(matches!(
        mark_orphaned(&mut waiters, waiter_id),
        DropOutcome::Detached
    ));
    assert_eq!(completions.ready(), 0);
    assert_eq!(waiters.pending(), 1);

    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 0),
        CompletionOutcome::Freed { .. }
    ));
    assert!(waiters.is_empty());
}

#[test]
fn test_waiter_id_encoding_and_generation_wrap() {
    // Verify waiter ids round-trip through user_data encoding and wrap their generation field
    // without corrupting the slot index bits.
    let wrapped = WaiterId::new(7, (WaiterId::GENERATION_MASK as u32).wrapping_add(5));
    assert_eq!(wrapped.generation(), 4);

    let max = WaiterId::new(7, WaiterId::GENERATION_MASK as u32);
    assert_eq!(max.next_generation().generation(), 0);

    let waiter_id = WaiterId::new(7, 3);
    assert_eq!(waiter_id.index(), 7);
    assert_eq!(waiter_id.generation(), 3);

    let (decoded_op, is_cancel_op) = WaiterId::from_user_data(waiter_id.user_data());
    assert_eq!(decoded_op, waiter_id);
    assert!(!is_cancel_op);

    let (decoded_cancel, is_cancel) = WaiterId::from_user_data(waiter_id.cancel_user_data());
    assert_eq!(decoded_cancel, waiter_id);
    assert!(is_cancel);
}

#[test]
fn test_waiters_lifecycle_and_slot_reuse() {
    // Verify waiter insertion, completion, removal, and slot reuse all preserve generations.
    let mut waiters = Waiters::new(3);
    assert_eq!(waiters.entries.len(), 3);
    assert_eq!(waiters.len(), 0);
    assert!(waiters.is_empty());

    // Populate two slots so the test can later free and reuse one of them.
    let id0 = insert(&mut waiters, make_sync_request(), Some(5));
    let id1 = insert(&mut waiters, make_sync_request(), Some(9));
    assert_eq!((id0.index(), id1.index()), (0, 1));
    assert_eq!(waiters.len(), 2);
    assert_eq!(waiters.pending(), 2);
    assert!(!waiters.is_full());

    // A stale operation CQE should panic because only cancel CQEs are
    // expected to arrive after slot reuse.
    let stale = WaiterId::new(id1.index(), id1.generation().wrapping_add(1));
    let stale_completion = catch_unwind(AssertUnwindSafe(|| {
        let _ = waiters.on_completion(stale.user_data(), 0);
    }));
    assert!(stale_completion.is_err());

    // Complete id1: the result parks in the slot until taken.
    assert!(matches!(waiters.stage(id1), StageOutcome::Submit(_)));
    assert!(matches!(
        waiters.on_completion(id1.user_data(), 0),
        CompletionOutcome::Ready {
            target_tick: Some(9),
            ..
        }
    ));
    assert_eq!(waiters.len(), 2);
    assert_eq!(waiters.pending(), 1);
    assert!(matches!(
        waiters.poll_take(id1, &noop_waker()),
        Some(Output::Sync(Ok(())))
    ));
    assert_eq!(waiters.len(), 1);

    // Next allocation reuses the freed slot with incremented generation.
    let id2 = insert(&mut waiters, make_sync_request(), Some(11));
    assert_eq!(id2.index(), id1.index());
    assert_eq!(
        id2.generation(),
        id1.generation().wrapping_add(1) & (WaiterId::GENERATION_MASK as u32)
    );

    // All live waiters should still complete and remove cleanly after slot reuse.
    assert!(matches!(waiters.stage(id0), StageOutcome::Submit(_)));
    let _ = waiters.on_completion(id0.user_data(), 0);
    assert!(waiters.poll_take(id0, &noop_waker()).is_some());
    assert!(matches!(waiters.stage(id2), StageOutcome::Submit(_)));
    let _ = waiters.on_completion(id2.user_data(), 0);
    assert!(waiters.poll_take(id2, &noop_waker()).is_some());
    assert!(waiters.is_empty());
}

#[test]
fn test_waiters_expire_paths() {
    // Verify cancel requests transition waiter state, ignore cancel CQEs for completion, and
    // discard late cancel CQEs once the original operation has already completed.
    let mut waiters = Waiters::new(3);

    let waiter_id = insert(&mut waiters, make_sync_request(), Some(2));

    let stale = WaiterId::new(waiter_id.index(), waiter_id.generation().wrapping_add(1));
    assert!(!waiters.expire(stale));

    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(
        waiters.expire(waiter_id),
        "cancel should transition active waiter"
    );

    // Cancel CQE does not complete the waiter.
    assert!(matches!(
        waiters.on_completion(waiter_id.cancel_user_data(), -libc::ECANCELED),
        CompletionOutcome::Cancel
    ));

    // Op CQE completes the waiter.
    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 0),
        CompletionOutcome::Ready {
            target_tick: None,
            ..
        }
    ));
    assert_eq!(waiters.pending(), 0);
    assert!(waiters.poll_take(waiter_id, &noop_waker()).is_some());
    assert!(waiters.is_empty());

    // Late cancel CQE for the already-completed waiter should be ignored.
    assert!(matches!(
        waiters.on_completion(waiter_id.cancel_user_data(), -libc::ECANCELED),
        CompletionOutcome::Cancel
    ));
    let missing_op_cqe = catch_unwind(AssertUnwindSafe(|| {
        let _ = waiters.on_completion(0, 1);
    }));
    assert!(missing_op_cqe.is_err());
}

#[test]
fn test_waiters_stale_cancel_after_slot_reuse() {
    // Property: a cancel-tagged CQE carrying a stale generation is
    // tolerated after its slot index was reused by a new waiter, leaving
    // the new waiter untouched. This is the documented late-cancel race
    // the generation field exists for (only the empty-slot half was
    // covered before).
    // Setup: complete and take a waiter so its slot frees, then insert a
    // new waiter that reuses the same index with a new generation and
    // stage it.
    // Action: feed the old generation's cancel user_data with ECANCELED.
    // Expected: CompletionOutcome::Cancel, and the new waiter keeps its
    // identity, active state, and in-flight marker.
    let mut waiters = Waiters::new(1);

    // Insert, stage, complete, and take the first waiter.
    let old = insert(&mut waiters, make_sync_request(), None);
    assert!(matches!(waiters.stage(old), StageOutcome::Submit(_)));
    assert!(matches!(
        waiters.on_completion(old.user_data(), 0),
        CompletionOutcome::Ready { .. }
    ));
    assert!(waiters.poll_take(old, &noop_waker()).is_some());
    assert!(waiters.is_empty());

    // Reuse the slot index under a new generation and stage the waiter.
    let new = insert(&mut waiters, make_sync_request(), None);
    assert_eq!(new.index(), old.index(), "slot index must be reused");
    assert_ne!(new, old, "reused slot must carry a new generation");
    assert!(matches!(waiters.stage(new), StageOutcome::Submit(_)));

    // The old generation's late cancel CQE is tolerated and changes
    // nothing about the new waiter.
    assert!(matches!(
        waiters.on_completion(old.cancel_user_data(), -libc::ECANCELED),
        CompletionOutcome::Cancel
    ));
    assert!(matches!(
        waiter_state(&waiters, new),
        Some(WaiterState::Active { .. })
    ));
    assert!(waiters.is_in_flight(new), "in-flight marker must survive");
}

#[test]
fn test_waiters_track_in_flight_state() {
    // Verify `stage` tracks a staged operation and that the bit is
    // cleared again when the matching op CQE is processed.
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_sync_request(), Some(4));

    assert!(waiters.is_full());
    assert!(!waiters.is_in_flight(waiter_id));
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(waiters.is_in_flight(waiter_id));

    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 0),
        CompletionOutcome::Ready { .. }
    ));
    assert!(!waiters.is_in_flight(waiter_id));
}

#[test]
fn test_waiters_reject_stale_in_flight_queries() {
    // Verify stale waiter ids cannot observe in-flight state after
    // their slot has been recycled to a new generation.
    let mut waiters = Waiters::new(1);
    let stale_id = insert(&mut waiters, make_sync_request(), Some(1));
    let _ = remove_waiter(&mut waiters, stale_id);

    let deadline = std::time::Instant::now();
    let active_id = insert(
        &mut waiters,
        Request::Send(SendRequest {
            fd: Arc::new(std::os::unix::net::UnixStream::pair().unwrap().0.into()),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: Some(deadline),
        }),
        None,
    );
    assert_ne!(active_id, stale_id);

    assert!(!waiters.is_in_flight(stale_id));
    assert!(waiters.deadline_to_schedule(stale_id).is_none());
    assert_eq!(waiters.deadline_to_schedule(active_id), Some(deadline));
    assert!(matches!(waiters.stage(active_id), StageOutcome::Submit(_)));
    assert!(waiters.is_in_flight(active_id));
}

#[test]
fn test_waiters_expire_and_in_flight_reject_out_of_range_and_empty_slots() {
    // Verify cancel and in-flight tracking reject waiter ids that point
    // outside the table or at currently empty slots.
    let mut waiters = Waiters::new(1);
    let out_of_range = WaiterId::new(7, 0);
    assert!(!waiters.expire(out_of_range));
    assert!(!waiters.is_in_flight(out_of_range));

    let empty_slot = WaiterId::new(0, 0);
    assert!(!waiters.expire(empty_slot));
    assert!(!waiters.is_in_flight(empty_slot));
}

#[test]
fn test_waiters_expiration_stages_cancel_only_when_in_flight() {
    // Verify timeout processing can distinguish between:
    // - a waiter whose current SQE is still in flight
    // - a waiter that is only parked in the backlog
    let mut waiters = Waiters::new(2);

    // First build a waiter that still has an operation SQE outstanding.
    let active = insert(&mut waiters, make_sync_request(), Some(2));
    assert!(matches!(waiters.stage(active), StageOutcome::Submit(_)));
    assert!(waiters.expire(active));
    assert!(waiters.is_in_flight(active));
    let active_state = waiter_state(&waiters, active).expect("active waiter missing");
    assert!(matches!(active_state, WaiterState::CancelRequested { .. }));

    // Then build a waiter that has been canceled before any SQE was staged.
    let ready = insert(&mut waiters, make_sync_request(), Some(3));
    assert!(waiters.expire(ready));
    assert!(!waiters.is_in_flight(ready));
    let ready_state = waiter_state(&waiters, ready).expect("ready waiter missing");
    assert!(matches!(ready_state, WaiterState::CancelRequested { .. }));
}

#[test]
fn test_waiters_stage_orphans_dropped_ops() {
    // Verify orphaned send and read-at requests are removed locally before
    // their first SQE is ever staged.
    for (request, tick) in [(make_send_request(), 7), (make_read_at_request(), 8)] {
        let mut waiters = Waiters::new(1);
        let waiter_id = insert(&mut waiters, request, Some(tick));
        assert!(matches!(
            mark_orphaned(&mut waiters, waiter_id),
            DropOutcome::Cancel {
                needs_sqe: false,
                target_tick: Some(_),
            }
        ));

        match waiters.stage(waiter_id) {
            StageOutcome::Freed => {}
            _ => panic!("orphaned waiter should be retired before staging"),
        }
        assert!(waiters.is_empty());
    }
}

#[test]
fn test_waiters_orphan_dropped_ops_after_nonterminal_completion() {
    // Verify retryable and partial-progress send, recv, and read-at CQEs
    // remove the waiter instead of requeueing once the op is gone.
    for (request, tick, result) in [
        // Retryable CQE.
        (make_send_request(), 5, -libc::EAGAIN),
        // Partial-progress CQE.
        (make_send_request(), 5, 2),
        (make_recv_request(), 6, -libc::EAGAIN),
        (make_recv_request(), 6, 3),
        (make_read_at_request(), 9, 3),
    ] {
        let mut waiters = Waiters::new(1);
        let waiter_id = insert(&mut waiters, request, Some(tick));
        assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
        assert!(matches!(
            mark_orphaned(&mut waiters, waiter_id),
            DropOutcome::Cancel {
                needs_sqe: true,
                ..
            }
        ));

        match waiters.on_completion(waiter_id.user_data(), result) {
            CompletionOutcome::Freed {
                // Cancellation transitioned the waiter, so deadline
                // tracking was already released.
                target_tick: None,
            } => {}
            _ => panic!("orphaned waiter should be freed after CQE"),
        }
        assert!(waiters.is_empty());
    }
}

#[test]
fn test_waiters_detach_write_and_sync_on_drop() {
    // Verify write/sync requests keep progressing after their op is
    // dropped and free their slot at the terminal CQE.
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_sync_request(), None);
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(matches!(
        mark_orphaned(&mut waiters, waiter_id),
        DropOutcome::Detached
    ));

    // The waiter is still active: no cancellation was requested.
    let state = waiter_state(&waiters, waiter_id).expect("waiter should remain tracked");
    assert!(matches!(state, WaiterState::Active { .. }));

    // The terminal CQE frees the slot without parking a result.
    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 0),
        CompletionOutcome::Freed { .. }
    ));
    assert!(waiters.is_empty());
}

#[test]
fn test_waiters_requeue_partial_detached_write() {
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_write_at_request(), None);
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(matches!(
        mark_orphaned(&mut waiters, waiter_id),
        DropOutcome::Detached
    ));

    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 2),
        CompletionOutcome::Requeue(id) if id == waiter_id
    ));
    assert!(!waiters.is_in_flight(waiter_id));
    assert_eq!(waiters.pending(), 1);

    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 3),
        CompletionOutcome::Freed { .. }
    ));
    assert!(waiters.is_empty());
}

#[test]
fn test_waiters_drop_after_completion_frees_slot() {
    // Verify dropping an op whose result is already parked frees the
    // slot and drops the output.
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_sync_request(), None);
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 0),
        CompletionOutcome::Ready { .. }
    ));
    assert_eq!(waiters.pending(), 0);
    assert_eq!(waiters.len(), 1);

    assert!(matches!(
        mark_orphaned(&mut waiters, waiter_id),
        DropOutcome::Freed
    ));
    assert!(waiters.is_empty());
}

#[test]
fn test_waiters_deadline_scheduling() {
    // Verify deadline bookkeeping: only unscheduled deadlines are
    // reported, and recording a tick transitions the waiter.
    let mut waiters = Waiters::new(2);

    // Sync requests carry no deadline.
    let sync_id = waiters.insert(make_sync_request(), noop_waker());
    assert!(waiters.deadline_to_schedule(sync_id).is_none());

    // Send requests with a deadline report it exactly once.
    let deadline = std::time::Instant::now();
    let send_id = waiters.insert(
        Request::Send(SendRequest {
            fd: Arc::new(std::os::unix::net::UnixStream::pair().unwrap().0.into()),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: Some(deadline),
        }),
        noop_waker(),
    );
    assert_eq!(waiters.deadline_to_schedule(send_id), Some(deadline));
    waiters.set_target_tick(send_id, 3);
    assert!(waiters.deadline_to_schedule(send_id).is_none());
    assert!(matches!(
        waiter_state(&waiters, send_id),
        Some(WaiterState::Active {
            target_tick: Some(3)
        })
    ));

    // Rescheduling a scheduled waiter is an invariant violation.
    let double_schedule = catch_unwind(AssertUnwindSafe(|| {
        waiters.set_target_tick(send_id, 4);
    }));
    assert!(double_schedule.is_err());
}

#[test]
fn test_waiters_poll_take_refreshes_waker() {
    // Verify pending polls refresh the stored waker rather than taking
    // the slot.
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_sync_request(), None);
    assert!(waiters.poll_take(waiter_id, &noop_waker()).is_none());
    assert_eq!(waiters.pending(), 1);

    // Stale ids panic rather than observing a reused slot.
    let _ = remove_waiter(&mut waiters, waiter_id);
    let stale_take = catch_unwind(AssertUnwindSafe(|| {
        let _ = waiters.poll_take(waiter_id, &noop_waker());
    }));
    assert!(stale_take.is_err());
}

#[test]
fn test_waiters_accept_expected_cancel_cqe_results() {
    // Verify the expected kernel cancel CQE results leave the waiter alive
    // for the original operation CQE to finish it later.
    for result in [0, -libc::EALREADY, -libc::ENOENT] {
        let mut waiters = Waiters::new(1);
        let waiter_id = insert(&mut waiters, make_sync_request(), Some(2));
        assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
        assert!(waiters.expire(waiter_id));

        assert!(matches!(
            waiters.on_completion(waiter_id.cancel_user_data(), result),
            CompletionOutcome::Cancel
        ));
        let state = waiter_state(&waiters, waiter_id).expect("waiter should remain tracked");
        assert!(matches!(state, WaiterState::CancelRequested { .. }));
    }
}

#[test]
fn test_waiters_tolerate_unexpected_negative_cancel_result() {
    // Verify unexpected negative cancel CQEs are ignored rather than
    // corrupting waiter state.
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_sync_request(), Some(2));
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(waiters.expire(waiter_id));

    assert!(matches!(
        waiters.on_completion(waiter_id.cancel_user_data(), -libc::EPERM),
        CompletionOutcome::Cancel
    ));
    let state = waiter_state(&waiters, waiter_id).expect("waiter should remain tracked");
    assert!(matches!(state, WaiterState::CancelRequested { .. }));
}

#[test]
fn test_waiters_cancel_cqe_einval_panics() {
    // Verify `EINVAL` remains a hard invariant failure because the kernel
    // rejected our async cancel SQE.
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_sync_request(), Some(2));
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(waiters.expire(waiter_id));

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = waiters.on_completion(waiter_id.cancel_user_data(), -libc::EINVAL);
    }));
    assert!(result.is_err());
}

#[test]
fn test_waiters_expire_rejects_parked_results() {
    // Verify parked results can no longer transition to cancellation
    // (e.g. from a stale timeout-wheel entry).
    let mut waiters = Waiters::new(1);
    let waiter_id = insert(&mut waiters, make_sync_request(), None);
    assert!(matches!(waiters.stage(waiter_id), StageOutcome::Submit(_)));
    assert!(matches!(
        waiters.on_completion(waiter_id.user_data(), 0),
        CompletionOutcome::Ready { .. }
    ));
    assert!(!waiters.expire(waiter_id));
    assert!(waiters.poll_take(waiter_id, &noop_waker()).is_some());
}

#[test]
fn test_waiters_insert_and_expire_invariants() {
    // Verify waiter capacity is enforced and that cancel remains valid even for waiters that
    // were inserted without a deadline.
    let mut waiters = Waiters::new(2);

    // Inserting beyond configured capacity should panic.
    let _ = waiters.insert(make_sync_request(), noop_waker());
    let _ = waiters.insert(make_sync_request(), noop_waker());
    assert!(waiters.is_full());
    let insert_overflow = catch_unwind(AssertUnwindSafe(|| {
        let _ = waiters.insert(make_sync_request(), noop_waker());
    }));
    assert!(insert_overflow.is_err());

    // Cancellation is allowed even when no deadline is tracked.
    let mut waiters = Waiters::new(2);
    let no_deadline = waiters.insert(make_sync_request(), noop_waker());
    assert!(
        waiters.expire(no_deadline),
        "cancel should support active waiter without deadline"
    );

    // Repeated cancel on the same waiter must be ignored.
    let active = insert(&mut waiters, make_sync_request(), Some(3));
    assert!(waiters.expire(active));
    assert!(!waiters.expire(active));
}

#[test]
fn test_waiters_cancel_for_shutdown_skips_parked_results() {
    // Verify shutdown-time cancel-all only transitions progressing
    // waiters.
    let mut waiters = Waiters::new(3);

    // One parked result, one in-flight waiter, one already cancelled.
    let parked = insert(&mut waiters, make_sync_request(), None);
    assert!(matches!(waiters.stage(parked), StageOutcome::Submit(_)));
    assert!(matches!(
        waiters.on_completion(parked.user_data(), 0),
        CompletionOutcome::Ready { .. }
    ));

    let in_flight = insert(&mut waiters, make_sync_request(), Some(2));
    assert!(matches!(waiters.stage(in_flight), StageOutcome::Submit(_)));

    let cancelled = insert(&mut waiters, make_sync_request(), Some(3));
    assert!(waiters.expire(cancelled));

    let transitioned = waiters.cancel_for_shutdown();
    assert_eq!(transitioned.len(), 1);
    assert_eq!(transitioned[0].id, in_flight);
    assert_eq!(transitioned[0].target_tick, Some(2));
    assert!(transitioned[0].needs_cancel_sqe);
}
