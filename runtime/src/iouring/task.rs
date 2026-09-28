//! Worker-local tasks, each one allocation.
//!
//! A spawned task is one [`Cell`]: a type-erased [`Header`] followed by the
//! concrete future. The header holds the task's [`State`], a vtable for the
//! erased future, and the mailbox of the worker that owns the task. A [`Task`]
//! and a task's [`Waker`] are each a thin pointer to that header holding one
//! reference, so cloning either counts a reference, and a wake is an atomic
//! transition on the state, plus a queue push when it publishes a ready token.
//!
//! # Lifecycle
//!
//! A ready token is the reference that entitles its holder to poll the task
//! once. It waits in the owning worker's ready queue, or travels there through
//! the worker's mailbox, and a task has at most one. A wake publishes a token
//! only when the task has none, so duplicate wakes coalesce. A wake that
//! arrives during a poll is recorded in the state and becomes the next token
//! only if that poll returns pending. That token joins the tail of the ready
//! queue, so a self-waking task cannot skip other ready work. Completion is
//! terminal, so a late wake of a finished task is a no-op.
//!
//! ```text
//! Wakers, from any thread (`notify_by_ref`, `notify_by_value`):
//!   Idle              -> Queued       publishes a ready token
//!   Running           -> Notified     the poll will end in a requeue
//!   Queued, Notified  -> unchanged    coalesced, still a releasing exchange
//!   Complete          -> unchanged    ignored
//!
//! The poller, holding the token:
//!   Queued            -> Running      `start_poll`
//!   Running           -> Idle         `finish_pending`, no wake arrived
//!   Notified          -> Queued       `finish_pending`, the token is reused
//!   Running, Notified -> Complete     `complete`, then the future drops
//!
//! Teardown, through `clear`:
//!   Idle, Queued      -> Complete     the caller drops the future
//!   Running, Notified -> + CANCELLED  the poller completes instead of idling
//! ```
//!
//! # Ownership
//!
//! Every ready token, cloned waker, and arena entry holds one reference,
//! counted in the state word above the lifecycle bits. Transitions that create
//! or consume a reference change the count in the same exchange: a wake by
//! reference that publishes counts the token's, a wake by value hands its
//! reference to the token it publishes or releases it, and a poll that ends
//! idle releases its token's. The waker passed to a poll borrows its token's.
//!
//! The owning worker's arena retains every registered task so teardown can drop
//! its future. A future is dropped in place when its task completes or is
//! cleared, and freeing a cell whose future is still present panics, so
//! releasing a reference runs no user code. A stale waker keeps the cell's
//! allocation, not its future, alive.
//!
//! Wakes on the owning worker queue the token directly. Wakes and spawns from
//! other threads travel through its mailbox.

use super::{
    mailbox::{Mailbox, Message},
    runtime::{Local, Panics},
};
use crossbeam_utils::CachePadded;
use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    future::Future,
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    ops::Deref,
    pin::Pin,
    ptr::NonNull,
    sync::{Arc, Weak},
    task::{Context, Poll, RawWaker, RawWakerVTable, Wake, Waker},
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::atomic::{AtomicU32, AtomicUsize, Ordering, fence};
    } else {
        use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering, fence};
    }
}

/// Pending without a ready token. The next wake publishes one.
const IDLE: usize = 0;
/// One ready token exists, and no poll is running.
const QUEUED: usize = 1;
/// The token's holder is polling the future.
const RUNNING: usize = 2;
/// Polling, and a wake arrived during the poll, so a pending poll requeues
/// its token.
const NOTIFIED: usize = 3;
/// Terminal. The future is gone or being dropped, and wakes are ignored.
const COMPLETE: usize = 4;
/// Mask of the lifecycle values above.
const LIFECYCLE: usize = 0b111;
/// Teardown asked the running poller to drop the future when its poll ends.
const CANCELLED: usize = 0b1000;
/// One reference. The low byte holds the lifecycle and flags, and the bits
/// above it count references.
const REF_ONE: usize = 1 << 8;
/// Mask of the reference count.
const REFS: usize = !(REF_ONE - 1);

/// How a pending poll ends.
enum Finish {
    /// No wake arrived, so the task is idle. The exchange released the polled
    /// token's reference, and the poller forgets the token.
    Idle,
    /// A wake arrived during the poll. The polled token becomes the next one,
    /// keeping its reference, and the poller queues it again.
    Requeue,
    /// Teardown cleared the task during the poll. The poller completes it and
    /// drops the future.
    Cancelled,
}

/// How a wake that gives up its reference ends.
enum Notify {
    /// The task was idle. The waker's reference is now the ready token, which
    /// the waker schedules.
    Schedule,
    /// The task had a token, was running, or was complete. The exchange
    /// released the waker's reference, and others remain.
    DoNothing,
    /// As `DoNothing`, but the released reference was the last, so the waker
    /// frees the cell.
    Dealloc,
}

/// Scheduling state and reference count of one task, in one word.
///
/// The low three bits hold the lifecycle, the next one the `CANCELLED` flag,
/// and the bits from `REF_ONE` up the reference count. Each lifecycle
/// transition is a compare-exchange loop over the whole word, retried while
/// references come and go, so a lifecycle change and the reference change it
/// implies land together.
///
/// A ready token owns the right to poll while the lifecycle is `QUEUED`.
/// Polling moves to `RUNNING`, a concurrent wake moves to `NOTIFIED` without a
/// second token, and the poller requeues its token only after observing
/// pending. `COMPLETE` is terminal.
///
/// Transitions exchange with acquire-release ordering, so writes made before a
/// wake are visible to the poll it causes, and a poll's writes are visible to
/// the next poll and to teardown.
struct State(AtomicUsize);

impl State {
    /// State of a new task whose first poll is queued, holding that token's
    /// reference.
    // Loom's atomics have no const constructor.
    #[allow(clippy::missing_const_for_fn)]
    fn queued() -> Self {
        Self(AtomicUsize::new(QUEUED | REF_ONE))
    }

    /// `state` with its lifecycle replaced by `lifecycle`, keeping the flags
    /// and the reference count.
    #[inline]
    const fn with_lifecycle(state: usize, lifecycle: usize) -> usize {
        (state & !LIFECYCLE) | lifecycle
    }

    /// Count one more reference.
    ///
    /// Like `Arc`, the process aborts before the count can wrap, which takes a
    /// leak of about `isize::MAX / REF_ONE` references.
    #[inline]
    fn retain(&self) {
        // The new reference is made from one the caller holds, which keeps
        // the cell alive, so the increment needs no ordering.
        if self.0.fetch_add(REF_ONE, Ordering::Relaxed) > isize::MAX as usize {
            std::process::abort();
        }
    }

    /// Release one reference, returning whether it was the last.
    ///
    /// The caller that releases the last reference acquires before freeing
    /// the cell, so every earlier holder's writes happen before the free.
    #[inline]
    fn release(&self) -> bool {
        self.0.fetch_sub(REF_ONE, Ordering::Release) & REFS == REF_ONE
    }

    /// Record a wake that keeps its reference, as `Waker::wake_by_ref` does.
    /// Returns whether the caller must schedule a ready token, whose
    /// reference the exchange counted.
    #[inline]
    fn notify_by_ref(&self) -> bool {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, publish) = match state & LIFECYCLE {
                // No token exists, so this wake publishes one. The waker keeps
                // its own reference, so the token's is counted here.
                IDLE => {
                    // Guarded as in `retain`.
                    if state > isize::MAX as usize {
                        std::process::abort();
                    }
                    (Self::with_lifecycle(state, QUEUED) + REF_ONE, true)
                }
                // A token already waits to poll the task. Coalesced wakes
                // still exchange, so writes made before them are published to
                // the poller's next acquiring transition.
                QUEUED => (state, false),
                // A poll is running. The wake is recorded so that poll
                // requeues its token if it returns pending, and wakes during
                // one poll coalesce into that requeue.
                RUNNING | NOTIFIED => (Self::with_lifecycle(state, NOTIFIED), false),
                // Nothing will poll the task again.
                COMPLETE => return false,
                other => unreachable!("invalid task state {other}"),
            };
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return publish,
                Err(actual) => state = actual,
            }
        }
    }

    /// Record a wake that gives up its reference, as `Waker::wake` does. A
    /// published token takes the reference over, and otherwise the exchange
    /// releases it.
    ///
    /// The transitions match [`notify_by_ref`](Self::notify_by_ref), except
    /// for whose reference a published token holds. Folding the release of an
    /// unused reference into the exchange saves a separate decrement on every
    /// coalesced wake.
    #[inline]
    fn notify_by_value(&self) -> Notify {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, publish) = match state & LIFECYCLE {
                // No token exists, so the waker's reference becomes one, and
                // the count is unchanged.
                IDLE => (Self::with_lifecycle(state, QUEUED), true),
                // A token already waits, or nothing will poll again, so the
                // waker's reference is released. The exchange still publishes
                // earlier writes, as in `notify_by_ref`.
                QUEUED | COMPLETE => (state - REF_ONE, false),
                // The wake is recorded for the running poll, as in
                // `notify_by_ref`, and the waker's reference is released.
                RUNNING | NOTIFIED => (Self::with_lifecycle(state, NOTIFIED) - REF_ONE, false),
                other => unreachable!("invalid task state {other}"),
            };
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) if publish => return Notify::Schedule,
                // Only a completed task can lose its last reference here,
                // since a token or a poll holds one otherwise. The acquiring
                // exchange orders every earlier release before the free.
                Ok(_) if next & REFS == 0 => return Notify::Dealloc,
                Ok(_) => return Notify::DoNothing,
                Err(actual) => state = actual,
            }
        }
    }

    /// Claim a poll with the ready token, whose reference the poll then
    /// holds. Fails for a token of a task teardown cleared while the token
    /// waited.
    #[inline]
    fn start_poll(&self) -> bool {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            // Only a queued task has a token to claim. A token that finds the
            // task complete is stale.
            if state & LIFECYCLE != QUEUED {
                return false;
            }
            // Acquiring makes the writes of the previous poll and of every
            // wake since then visible to this poll.
            match self.0.compare_exchange_weak(
                state,
                Self::with_lifecycle(state, RUNNING),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => state = actual,
            }
        }
    }

    /// End a poll that returned pending. Going idle releases the polled
    /// token's reference in the same exchange.
    #[inline]
    fn finish_pending(&self) -> Finish {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            // Teardown cleared the task mid-poll and left the future to this
            // poller. The lifecycle stays running until `complete`, so wakes
            // meanwhile publish nothing.
            if state & CANCELLED != 0 {
                return Finish::Cancelled;
            }
            let (next, result) = match state & LIFECYCLE {
                // No wake arrived. The next wake publishes a new token, so
                // this one is released in the same exchange.
                RUNNING => {
                    // The arena holds a reference to every task that can go
                    // idle, so the token's is never the last.
                    assert!(
                        state & REFS > REF_ONE,
                        "idle task would release its last reference"
                    );
                    (Self::with_lifecycle(state, IDLE) - REF_ONE, Finish::Idle)
                }
                // A wake arrived and published nothing, so the polled token
                // becomes the next one, keeping its reference.
                NOTIFIED => (Self::with_lifecycle(state, QUEUED), Finish::Requeue),
                other => unreachable!("task left poll in invalid state {other}"),
            };
            // Releasing publishes the poll's writes to the next poll, or to
            // teardown if the task is cleared while idle.
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return result,
                Err(actual) => state = actual,
            }
        }
    }

    /// Mark the task terminal after its final poll, keeping every reference.
    ///
    /// The poller keeps exclusive access to the future afterwards, since no
    /// transition leaves `COMPLETE`, and drops it next.
    #[inline]
    fn complete(&self) {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            // Only the poller completes a task, and only while its poll runs.
            assert!(
                matches!(state & LIFECYCLE, RUNNING | NOTIFIED),
                "completed task was not running"
            );
            // A pending wake and the `CANCELLED` flag mean nothing once the
            // task is terminal, so only the count survives. Later wakes
            // publish nothing, and `start_poll` and `clear` do nothing.
            match self.0.compare_exchange_weak(
                state,
                (state & REFS) | COMPLETE,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => state = actual,
            }
        }
    }

    /// Mark the task terminal for teardown, keeping every reference. Returns
    /// whether the caller drops the future now. A running task is marked
    /// cancelled instead, and its poller drops the future.
    fn clear(&self) -> bool {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, drop_now) = match state & LIFECYCLE {
                // No poll is running, and once the task is terminal none can
                // start, so the caller has exclusive access to the future. A
                // token still queued is found stale when taken.
                IDLE | QUEUED => ((state & REFS) | COMPLETE, true),
                // The running poll owns the future. The flag makes the poller
                // complete the task and drop the future when the poll returns,
                // instead of idling or requeueing.
                RUNNING | NOTIFIED => (state | CANCELLED, false),
                // The future is gone, or its poller is dropping it.
                COMPLETE => return false,
                other => unreachable!("invalid task state {other}"),
            };
            // Acquiring makes the last poll's writes visible before the caller
            // drops the future.
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return drop_now,
                Err(actual) => state = actual,
            }
        }
    }
}

/// Result of polling a ready token.
pub enum Outcome {
    /// Pending, with no wake during the poll. The token is gone, and the next
    /// wake publishes a new one.
    Idle,
    /// Pending, and a wake during the poll requires another poll. Carries the
    /// token for the caller to queue again.
    Requeue(Task),
    /// The future returned ready, panicked, or was cleared during the poll,
    /// and has been dropped. Carries the token for the caller to pass to
    /// [`Tasks::retire`].
    Complete(Task),
    /// The token belonged to a task teardown already cleared, and has been
    /// released.
    Stale,
}

/// Operations that need the concrete future type behind a header, one table
/// per future type.
///
/// Each takes a header pointer that carries the whole allocation's
/// provenance, as described on [`Header`].
struct Vtable {
    /// Poll the future in place. The caller holds the running state.
    poll: unsafe fn(NonNull<Header>, &mut Context<'_>) -> Poll<()>,
    /// Drop the future in place. The caller has exclusive access to it.
    drop_future: unsafe fn(NonNull<Header>),
    /// Free the allocation, whose future is already gone.
    dealloc: unsafe fn(NonNull<Header>),
}

/// Type-erased front of every task allocation.
///
/// Header pointers passed to the vtable, [`Task::from_raw`], or the waker
/// functions must derive from the pointer `Task::new` leaked, which every
/// `Task` and task waker carries. A pointer made from a `&Header` covers only
/// the header, so reaching the future or freeing the cell through it is
/// undefined behavior, even at the same address.
#[repr(C)]
pub struct Header {
    /// Lifecycle and reference count, changed on any thread by wakers and
    /// references and by the poller.
    state: State,
    /// Operations on the concrete future behind this header.
    vtable: &'static Vtable,
    /// Worker that owns the task, reached by foreign wakes and spawns, without
    /// extending its lifetime.
    mailbox: Weak<Mailbox>,
    /// Arena slot on the owning worker, `u32::MAX` until assigned before the
    /// first poll. Only the owning worker reads or writes it, and it is
    /// atomic only so the header stays `Sync`.
    slot: AtomicU32,
}

/// A task allocation: the erased header followed by the concrete future.
///
/// `repr(C)` puts the header at offset zero, so the cell and header pointers
/// are one address. The whole cell is aligned like [`CachePadded`] (128 bytes
/// on x86_64 and aarch64, whose prefetchers fetch cache lines in pairs), so no
/// two tasks share a line. The header and the start of the future share the
/// first one.
#[repr(C)]
struct Cell<F> {
    /// Type-erased state shared by every reference.
    header: Header,
    /// The future, `None` once completed or cleared.
    future: UnsafeCell<Option<F>>,
    /// Aligns the cell without adding to its size.
    _align: [CachePadded<()>; 0],
}

impl<F: Future<Output = ()> + Send + 'static> Cell<F> {
    /// Operations on cells holding this future type. The table is a constant,
    /// so it is promoted to a static that every such cell shares.
    fn vtable() -> &'static Vtable {
        &Vtable {
            poll: Self::poll,
            drop_future: Self::drop_future,
            dealloc: Self::dealloc,
        }
    }

    /// Poll the future in place.
    ///
    /// # Safety
    ///
    /// `header` must point to a live `Cell<F>` with the allocation's
    /// provenance, and the caller must hold the running state, which gives it
    /// exclusive access to the future.
    unsafe fn poll(header: NonNull<Header>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: the header starts a `Cell<F>` per the contract, and the
        // running state gives this thread exclusive access to the future.
        let future = unsafe { &mut *header.cast::<Self>().as_ref().future.get() };
        let future = future.as_mut().expect("queued task retains its future");
        // SAFETY: the future lives inside the cell and is never moved out of
        // it, so pinning it in place is sound.
        unsafe { Pin::new_unchecked(future) }.poll(cx)
    }

    /// Drop the future in place.
    ///
    /// # Safety
    ///
    /// `header` must point to a live `Cell<F>` with the allocation's
    /// provenance, and the caller must have exclusive access to the future.
    unsafe fn drop_future(header: NonNull<Header>) {
        // SAFETY: per the contract. The old value drops in place, and the
        // slot holds `None` even if its destructor panics.
        unsafe { *header.cast::<Self>().as_ref().future.get() = None };
    }

    /// Free the cell.
    ///
    /// # Safety
    ///
    /// `header` must point to a `Cell<F>` allocated by [`Task::new`], with
    /// the allocation's provenance, that nothing references any more.
    unsafe fn dealloc(header: NonNull<Header>) {
        let cell = header.cast::<Self>();
        // Dropping the future here would run user code wherever the last
        // reference happened to go, possibly under a worker borrow. Checking
        // before taking ownership leaks the cell instead.
        // SAFETY: the last reference is gone, so nothing else touches the
        // future.
        let present = unsafe { (*cell.as_ref().future.get()).is_some() };
        assert!(!present, "task freed with its future still present");
        // SAFETY: `Task::new` leaked exactly this box, and the last reference
        // is gone.
        drop(unsafe { Box::from_raw(cell.as_ptr()) });
    }
}

/// An owning reference to a task, counted in its state.
///
/// Ready tokens and arena entries are `Task`s. Dropping the last reference
/// frees the cell, whose future must already be gone.
pub struct Task(NonNull<Header>);

// SAFETY: `Task::new` requires `F: Send`, so the future may be polled or
// dropped on any thread. The rest of the cell is atomic or immutable after
// construction, and only the thread that wins the running state or clears the
// task touches the future.
unsafe impl Send for Task {}
// SAFETY: see above. Methods on a shared reference touch atomics, except
// `clear`, which drops the future only after its state exchange excludes
// every poll. No `&F` is ever shared, so `F: Sync` is not needed.
unsafe impl Sync for Task {}

impl Deref for Task {
    type Target = Header;

    fn deref(&self) -> &Header {
        // SAFETY: an owned reference keeps the cell alive.
        unsafe { self.0.as_ref() }
    }
}

impl Clone for Task {
    #[inline]
    fn clone(&self) -> Self {
        self.state.retain();
        Self(self.0)
    }
}

impl Drop for Task {
    #[inline]
    fn drop(&mut self) {
        // The count sits in an atomic, so no reference into the rest of the
        // header is live across the decrement while another thread frees the
        // cell.
        if self.state.release() {
            fence(Ordering::Acquire);
            // SAFETY: the last reference is gone, so nothing else reaches the
            // cell, and the vtable frees the allocation `new` made.
            unsafe { (self.vtable.dealloc)(self.0) };
        }
    }
}

impl Task {
    /// Allocate a task owned by the worker behind `mailbox`, with its first
    /// poll queued. Returns its one reference, which is that poll's token.
    pub fn new<F>(future: F, mailbox: Weak<Mailbox>) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cell = Box::new(Cell {
            header: Header {
                state: State::queued(),
                vtable: Cell::<F>::vtable(),
                mailbox,
                slot: AtomicU32::new(u32::MAX),
            },
            future: UnsafeCell::new(Some(future)),
            _align: [],
        });
        Self(NonNull::from(Box::leak(cell)).cast())
    }

    /// Whether both references name one task.
    fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.0 == b.0
    }

    /// Adopt the reference a raw header pointer carries.
    ///
    /// # Safety
    ///
    /// `ptr` must carry a reference the caller gives up, with the
    /// allocation's provenance.
    const unsafe fn from_raw(ptr: NonNull<Header>) -> Self {
        Self(ptr)
    }

    /// A waker borrowing this reference for as long as `self` is borrowed.
    fn waker(&self) -> WakerRef<'_> {
        // SAFETY: the vtable expects a header pointer carrying a reference.
        // This one is borrowed from `self`, which outlives the wrapper, and
        // `ManuallyDrop` keeps the waker from releasing it.
        let waker =
            unsafe { Waker::from_raw(RawWaker::new(self.0.as_ptr().cast(), &WAKER_VTABLE)) };
        WakerRef {
            waker: ManuallyDrop::new(waker),
            _task: PhantomData,
        }
    }

    /// Wake with this reference, which a published token takes over and the
    /// state exchange releases otherwise.
    fn wake(self) {
        // The exchange decides what happens to this reference, so the
        // destructor must not release it as well.
        let this = ManuallyDrop::new(self);
        match this.state.notify_by_value() {
            Notify::Schedule => ManuallyDrop::into_inner(this).schedule(),
            Notify::DoNothing => {}
            Notify::Dealloc => {
                // SAFETY: the exchange released the last reference and
                // acquired every earlier release, so nothing else reaches the
                // cell, and the vtable frees the allocation `new` made.
                unsafe { (this.vtable.dealloc)(this.0) };
            }
        }
    }

    /// Wake without giving up this reference.
    fn wake_by_ref(&self) {
        if self.state.notify_by_ref() {
            // SAFETY: the exchange counted a reference for the published
            // token, which the new `Task` owns.
            unsafe { Self::from_raw(self.0) }.schedule();
        }
    }

    /// Drop the future in place, or mark a running task for its poller to
    /// drop. Does nothing to a completed task.
    ///
    /// The future's destructor may panic. Callers hold no worker borrow and
    /// choose the panic boundary.
    pub fn clear(&self) {
        // Terminal first, so a late wake cannot publish a token for this cell.
        if !self.state.clear() {
            return;
        }
        // SAFETY: the state left IDLE or QUEUED for COMPLETE, so no poll is
        // running and none can start.
        unsafe { (self.vtable.drop_future)(self.0) };
    }

    /// Deliver the ready token this reference represents to the owning
    /// worker, directly on its thread and through its mailbox otherwise.
    ///
    /// A closing worker, or a closed or dropped mailbox, releases the token.
    /// The task then stays queued until teardown clears it.
    fn schedule(self) {
        // On the owning thread, the token goes straight to the ready queue.
        // Polls and destructors run without the local borrow, so a wake from
        // inside one can take it here.
        if let Some(local) = Local::owner(&self.mailbox) {
            let mut local = local.borrow_mut();
            // A closing worker polls nothing more, so the token is dropped.
            // Releasing a reference runs no user code, so dropping it under
            // the borrow is fine.
            if !local.closing {
                local.tasks.push(self);
            }
            return;
        }
        // Any other thread hands the token to the mailbox, and the worker
        // queues it when it applies its messages. A closed mailbox returns
        // the token, which is dropped here, as is a token for a worker whose
        // mailbox is gone.
        if let Some(mailbox) = self.mailbox.upgrade() {
            let _ = mailbox.send(Message::Wake(Target::Task(self)));
        }
    }

    /// Poll the ready token this reference represents, containing panics.
    ///
    /// The caller holds no worker borrow, since the poll and the destructors
    /// it runs are user code.
    ///
    /// `finish` runs after a future that returned pending and before the
    /// poll is published as over. No wake can start another poll of the task
    /// until it returns. A completed task skips it. `finish` must not panic:
    /// the task would stay running, and teardown could never drop its future.
    pub fn poll(self, finish: impl FnOnce(&Header)) -> Outcome {
        // A token of a task teardown already cleared is released here.
        if !self.state.start_poll() {
            return Outcome::Stale;
        }

        // The poll and the destructors it may run stay behind one boundary,
        // and a panic completes the task like a ready future does. The waker
        // borrows this token's reference, so passing it counts nothing.
        let polled = Panics::contain(|| {
            let waker = self.waker();
            let mut cx = Context::from_waker(&waker);
            // SAFETY: start_poll granted this thread exclusive access to the
            // future until the state leaves RUNNING or NOTIFIED below.
            unsafe { (self.vtable.poll)(self.0, &mut cx) }
        });

        // A pending poll leaves the task idle or requeues this token, unless
        // teardown cleared the task meanwhile, which completes it below.
        if matches!(polled, Some(Poll::Pending)) {
            finish(&self);
            match self.state.finish_pending() {
                Finish::Idle => {
                    // The exchange released this token's reference.
                    mem::forget(self);
                    return Outcome::Idle;
                }
                Finish::Requeue => return Outcome::Requeue(self),
                Finish::Cancelled => {}
            }
        }

        // Publish the terminal state before destructors run. A destructor may
        // wake this task or panic, and either must observe a completed cell.
        self.state.complete();
        // SAFETY: exclusive access continues past `complete`, since
        // `start_poll` and `clear` both do nothing once the state is COMPLETE.
        Panics::contain(|| unsafe { (self.vtable.drop_future)(self.0) });
        Outcome::Complete(self)
    }
}

impl Header {
    /// Record the arena slot assigned by the owning worker.
    fn set_slot(&self, slot: usize) {
        self.slot.store(
            u32::try_from(slot).expect("arena slot overflow"),
            Ordering::Relaxed,
        );
    }
}

/// A waker that borrows a task's reference instead of counting its own, so
/// it lives no longer than the borrow of that task. Cloning it counts a
/// reference as usual.
struct WakerRef<'a> {
    /// Never dropped, since it holds no reference of its own.
    waker: ManuallyDrop<Waker>,
    /// Ties the waker to the borrowed task.
    _task: PhantomData<&'a Task>,
}

impl Deref for WakerRef<'_> {
    type Target = Waker;

    fn deref(&self) -> &Waker {
        &self.waker
    }
}

/// Waker operations on a header pointer that carries one reference.
static WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

/// Borrow the header behind a waker's data pointer.
///
/// # Safety
///
/// `ptr` must be a header pointer carrying a reference that outlives `'a`.
const unsafe fn header<'a>(ptr: *const ()) -> &'a Header {
    // SAFETY: per the contract, the reference keeps the cell alive.
    unsafe { &*ptr.cast::<Header>() }
}

/// Take over the reference behind a waker's data pointer.
///
/// # Safety
///
/// `ptr` must be a header pointer with the allocation's provenance, carrying
/// a reference the caller gives up.
const unsafe fn task(ptr: *const ()) -> Task {
    // SAFETY: per the contract.
    unsafe { Task::from_raw(NonNull::new_unchecked(ptr.cast_mut().cast())) }
}

/// Clone a waker, counting one more reference.
///
/// # Safety
///
/// `ptr` must be the data pointer of a waker built on [`WAKER_VTABLE`].
unsafe fn waker_clone(ptr: *const ()) -> RawWaker {
    // SAFETY: waker vtables receive the pointer their waker was built from.
    unsafe { header(ptr) }.state.retain();
    RawWaker::new(ptr, &WAKER_VTABLE)
}

/// Wake with the waker's reference, which a published token takes over.
///
/// # Safety
///
/// `ptr` must be the data pointer of a waker built on [`WAKER_VTABLE`].
unsafe fn waker_wake(ptr: *const ()) {
    // SAFETY: waker vtables receive the pointer their waker was built from,
    // and `wake` consumes the waker's reference.
    unsafe { task(ptr) }.wake();
}

/// Wake without releasing the waker's reference.
///
/// # Safety
///
/// `ptr` must be the data pointer of a waker built on [`WAKER_VTABLE`].
unsafe fn waker_wake_by_ref(ptr: *const ()) {
    // SAFETY: waker vtables receive the pointer their waker was built from.
    // The waker keeps its reference, which `ManuallyDrop` never releases.
    ManuallyDrop::new(unsafe { task(ptr) }).wake_by_ref();
}

/// Release the waker's reference.
///
/// # Safety
///
/// `ptr` must be the data pointer of a waker built on [`WAKER_VTABLE`].
unsafe fn waker_drop(ptr: *const ()) {
    // SAFETY: waker vtables receive the pointer their waker was built from,
    // and dropping the waker releases its reference.
    drop(unsafe { task(ptr) });
}

/// Root or task named by a wake that travels through a worker's mailbox.
pub enum Target {
    /// The root future pinned separately on the worker's stack.
    Root,
    /// A task, carrying its ready token.
    Task(Task),
}

/// Waker for the root future, which the worker pins on its stack.
pub struct RootWaker {
    /// Worker polling the root, without extending its lifetime.
    mailbox: Weak<Mailbox>,
}

impl RootWaker {
    /// Allocate a waker that notifies the root of the worker behind `mailbox`.
    pub fn new(mailbox: Weak<Mailbox>) -> Arc<Self> {
        Arc::new(Self { mailbox })
    }
}

impl Wake for RootWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(local) = Local::owner(&self.mailbox) {
            let mut local = local.borrow_mut();

            // Local wakes update readiness without a mailbox round trip.
            if !local.closing {
                local.root_ready = true;
            }
            return;
        }

        if let Some(mailbox) = self.mailbox.upgrade() {
            let _ = mailbox.send(Message::Wake(Target::Root));
        }
    }
}

/// One worker's registered tasks and ready tokens, touched only by that
/// worker.
#[derive(Default)]
pub struct Tasks {
    /// Every registered task by slot, holding one reference each so teardown
    /// can drop every future. Completion frees the slot.
    arena: Vec<Option<Task>>,
    /// Vacant arena slots, reused before the arena grows.
    free: Vec<usize>,
    /// Ready tokens in FIFO order.
    ready: VecDeque<Task>,
}

impl Tasks {
    /// Whether the worker behind `mailbox` currently accepts tasks.
    ///
    /// This does not reserve a place. Registration checks again after construction.
    pub fn is_open(mailbox: &Weak<Mailbox>) -> bool {
        if let Some(local) = Local::owner(mailbox) {
            // The owning thread can check closure without locking the mailbox.
            return !local.borrow().closing;
        }

        // Foreign callers use the mailbox's acceptance state.
        mailbox.upgrade().is_some_and(|mailbox| mailbox.is_open())
    }

    /// Register a new task on its owning worker, directly or through the
    /// worker's mailbox.
    ///
    /// Returns a rejected task, whose future the caller clears outside
    /// worker borrows.
    pub fn register(task: Task) -> Result<(), Task> {
        // The factory runs after is_open, so check acceptance again before
        // taking ownership of the constructed task.
        if let Some(local) = Local::owner(&task.mailbox) {
            let mut local = local.borrow_mut();
            if local.closing {
                return Err(task);
            }

            local.tasks.insert(task);
            return Ok(());
        }

        // Foreign callers transfer the task through the mailbox. If closure
        // wins the race, return the task to the caller.
        let Some(mailbox) = task.mailbox.upgrade() else {
            return Err(task);
        };
        match mailbox.send(Message::Spawn(task)) {
            Ok(()) => Ok(()),
            Err(Message::Spawn(task)) => Err(task),
            Err(_) => unreachable!("spawn publication returned another message kind"),
        }
    }

    /// Retain a new task in the arena and queue its first poll, whose token
    /// is the reference passed in.
    pub fn insert(&mut self, task: Task) {
        let slot = self.free.pop().unwrap_or_else(|| {
            self.arena.push(None);
            self.arena.len() - 1
        });
        // The task records its slot, so retiring it needs no search.
        task.set_slot(slot);
        self.arena[slot] = Some(task.clone());
        self.ready.push_back(task);
    }

    /// Queue a ready token.
    #[inline]
    pub fn push(&mut self, task: Task) {
        self.ready.push_back(task);
    }

    /// Take the oldest ready token.
    #[inline]
    pub fn pop(&mut self) -> Option<Task> {
        self.ready.pop_front()
    }

    /// Free the arena slot of a completed task. A cleared arena has already
    /// released it.
    ///
    /// The future is already gone, so releasing the references runs no user
    /// code.
    pub fn retire(&mut self, task: Task) {
        let slot = task.slot.load(Ordering::Relaxed) as usize;
        let Some(entry) = self.arena.get_mut(slot) else {
            return;
        };
        // Slots are freed only here, each by the completed task it holds, so
        // the recorded slot still holds this task.
        let retained = entry.take();
        assert!(
            retained.is_some_and(|retained| Task::ptr_eq(&retained, &task)),
            "completed task missing from its arena slot"
        );
        self.free.push(slot);
    }

    /// Whether at least one ready token is queued.
    pub fn is_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Release every ready token and detach every registered task. The caller
    /// clears each task's future outside worker borrows.
    pub fn clear(&mut self) -> impl Iterator<Item = Task> + use<> {
        // Each token is a second reference to a task the arena holds, so
        // releasing them runs no user code.
        self.ready.clear();
        self.free.clear();
        mem::take(&mut self.arena).into_iter().flatten()
    }
}

#[cfg(test)]
pub mod tests {
    //! Tests that start no runner, so they also run under Miri. Runtime-level
    //! task tests live in `iouring/tests.rs` and share the helpers here.

    use super::*;
    use commonware_utils::sync::Mutex;
    use std::{
        future::{pending, poll_fn},
        marker::PhantomPinned,
        ptr,
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    /// Record when a task's captured state is destroyed.
    struct DropCount(Arc<AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Future that keeps its own waker and wakes it when dropped. It finishes
    /// on its first poll when `complete` is set.
    struct WakesOnDrop {
        waker: Option<Waker>,
        complete: bool,
        _drops: DropCount,
    }

    impl Future for WakesOnDrop {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.waker = Some(cx.waker().clone());
            if self.complete {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for WakesOnDrop {
        fn drop(&mut self) {
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }

    /// Future that wakes itself `wakes` times per poll and finishes after `polls`.
    struct SelfWaker {
        wakes: usize,
        polls: usize,
        _drops: DropCount,
    }

    impl Future for SelfWaker {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            for _ in 0..self.wakes {
                cx.waker().wake_by_ref();
            }
            self.polls -= 1;
            if self.polls == 0 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    /// Future aligned beyond the cell's own alignment, above every padding
    /// unit crossbeam uses (at most 256 bytes), that must not move once pinned. It
    /// records its address on every poll and when dropped, since a failed
    /// assertion inside either would be contained by the poll.
    #[repr(align(512))]
    struct OverAligned {
        /// Polls left until ready.
        remaining: AtomicUsize,
        /// Addresses seen by each poll, then by the destructor.
        addresses: Arc<Mutex<Vec<usize>>>,
        _pinned: PhantomPinned,
    }

    impl Future for OverAligned {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            self.addresses.lock().push(ptr::from_ref(&*self).addr());
            if self.remaining.fetch_sub(1, Ordering::Relaxed) == 1 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for OverAligned {
        fn drop(&mut self) {
            self.addresses.lock().push(ptr::from_ref(self).addr());
        }
    }

    /// A live mailbox with no worker, so every wake takes the foreign path.
    fn mailbox() -> Arc<Mailbox> {
        Arc::new(Mailbox::new().unwrap())
    }

    /// Insert a task owned by `mailbox`, returning a second reference to it.
    fn insert(
        tasks: &mut Tasks,
        mailbox: &Arc<Mailbox>,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Task {
        let task = Task::new(future, Arc::downgrade(mailbox));
        tasks.insert(task.clone());
        task
    }

    /// References held to `task`, including the caller's.
    pub fn refs(task: &Task) -> usize {
        (task.state.0.load(Ordering::Acquire) & REFS) / REF_ONE
    }

    /// Tasks registered on a worker.
    pub const fn live(tasks: &Tasks) -> usize {
        tasks.arena.len() - tasks.free.len()
    }

    /// Take the ready tokens delivered to `mailbox`.
    fn scheduled(mailbox: &Mailbox) -> Vec<Task> {
        let mut messages = Vec::new();
        mailbox.take(&mut messages);
        messages
            .into_iter()
            .map(|message| match message {
                Message::Wake(Target::Task(task)) => task,
                _ => panic!("expected only ready tokens"),
            })
            .collect()
    }

    /// The whole cell is aligned like `CachePadded`, and the header, which
    /// fits one 64-byte line with room for the fields later PRs add, shares
    /// the first line with the future. Where the unit holds that line (128
    /// bytes on x86_64 and aarch64), a small future and its header take
    /// exactly one unit.
    #[test]
    fn test_cell_is_aligned_as_a_whole() {
        type Small = Cell<std::future::Pending<()>>;
        assert!(std::mem::size_of::<Header>() <= 64);
        let unit = std::mem::align_of::<CachePadded<()>>();
        assert_eq!(std::mem::align_of::<Small>(), unit);
        if unit >= 64 {
            assert_eq!(std::mem::size_of::<Small>(), unit);
        }
    }

    #[test]
    fn test_wakers_hold_references_until_the_cell_is_freed() {
        let mailbox = mailbox();
        let task = Task::new(pending::<()>(), Arc::downgrade(&mailbox));
        assert_eq!(refs(&task), 1);
        assert_eq!(Arc::weak_count(&mailbox), 1);

        // Polling borrows the token's reference for the waker it passes in.
        assert!(matches!(task.clone().poll(|_| {}), Outcome::Idle));
        assert_eq!(refs(&task), 1);

        // Cloned wakers count, and dropped ones release.
        let waker = Waker::clone(&task.waker());
        let other = waker.clone();
        assert_eq!(refs(&task), 3);
        drop(other);
        assert_eq!(refs(&task), 2);

        // Waking by value hands the waker's reference to the published token.
        waker.wake();
        assert_eq!(refs(&task), 2);
        let tokens = scheduled(&mailbox);
        assert_eq!(tokens.len(), 1);
        assert!(Task::ptr_eq(&tokens[0], &task));
        drop(tokens);
        assert_eq!(refs(&task), 1);

        // The last reference frees the cell, and with it the mailbox reference.
        task.clear();
        drop(task);
        assert_eq!(Arc::weak_count(&mailbox), 0);
    }

    #[test]
    fn test_foreign_wakes_coalesce_into_one_token() {
        let mailbox = mailbox();
        let mut tasks = Tasks::default();
        let task = insert(&mut tasks, &mailbox, pending());
        assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));

        // Wakes from a thread without a worker travel through the mailbox, and
        // duplicates publish one token. The coalesced wake by value releases
        // its reference, leaving the arena's, the caller's, and the token's.
        let waker = Waker::clone(&task.waker());
        thread::spawn(move || {
            waker.wake_by_ref();
            waker.wake_by_ref();
            waker.wake();
        })
        .join()
        .unwrap();
        assert_eq!(refs(&task), 3);
        let mut tokens = scheduled(&mailbox);
        assert_eq!(tokens.len(), 1);

        // The token polls the task again, which leaves it idle once more.
        tasks.push(tokens.pop().unwrap());
        assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));
        assert!(scheduled(&mailbox).is_empty());
        task.clear();
    }

    #[test]
    fn test_wakes_during_poll_coalesce_into_one_requeue() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let mut tasks = Tasks::default();
        let task = insert(
            &mut tasks,
            &mailbox,
            SelfWaker {
                wakes: 3,
                polls: 2,
                _drops: DropCount(drops.clone()),
            },
        );

        // Wakes during the poll leave exactly one successor token, returned
        // to the poller rather than published.
        let Outcome::Requeue(token) = tasks.pop().unwrap().poll(|_| {}) else {
            panic!("self-woken pending poll must requeue");
        };
        assert!(Task::ptr_eq(&token, &task));
        assert!(scheduled(&mailbox).is_empty());

        // The final poll wakes itself again, which the terminal state discards.
        let Outcome::Complete(token) = token.poll(|_| {}) else {
            panic!("final poll must complete");
        };
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        tasks.retire(token);
        assert!(scheduled(&mailbox).is_empty());
        assert_eq!(refs(&task), 1);
    }

    /// The finalizer sees the task before its poll is published as over: a
    /// wake arriving during it cannot start another poll, and is not lost.
    #[test]
    fn test_finalizer_runs_while_the_poll_still_owns_the_task() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let mut tasks = Tasks::default();
        let task = insert(
            &mut tasks,
            &mailbox,
            SelfWaker {
                wakes: 0,
                polls: 2,
                _drops: DropCount(drops.clone()),
            },
        );
        let waker = Waker::clone(&task.waker());
        let mut finalized = 0;
        let outcome = tasks.pop().unwrap().poll(|header| {
            finalized += 1;
            // Still running: no token can start a poll now.
            assert!(!header.state.start_poll());
            // A wake now is kept for the requeue that follows, not published.
            waker.wake_by_ref();
            assert!(scheduled(&mailbox).is_empty());
        });
        assert_eq!(finalized, 1);
        let Outcome::Requeue(token) = outcome else {
            panic!("the wake during the finalizer must requeue the task");
        };
        assert!(Task::ptr_eq(&token, &task));

        // The completing poll skips the finalizer.
        let outcome = token.poll(|_| finalized += 1);
        assert!(matches!(outcome, Outcome::Complete(_)));
        assert_eq!(finalized, 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_poll_panic_completes_the_task_and_frees_its_slot() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let mut tasks = Tasks::default();
        let guard = DropCount(drops.clone());
        let first = insert(&mut tasks, &mailbox, async move {
            let _guard = guard;
            panic!("poll panic");
        });
        let waker = Waker::clone(&first.waker());

        let Outcome::Complete(token) = tasks
            .pop()
            .unwrap()
            .poll(|_| panic!("a completed poll skips the finalizer"))
        else {
            panic!("panicking poll must complete the task");
        };
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        tasks.retire(token);

        // The next task takes the freed slot. The completed task's waker
        // neither publishes nor reaches that successor.
        let second = insert(&mut tasks, &mailbox, pending());
        assert_eq!(
            first.slot.load(Ordering::Relaxed),
            second.slot.load(Ordering::Relaxed)
        );
        assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));
        waker.wake_by_ref();
        assert!(scheduled(&mailbox).is_empty());
        drop(waker);
        assert_eq!(refs(&first), 1);
        second.clear();
    }

    /// A task registered from a thread without its worker travels through the
    /// mailbox, and a closed or dropped mailbox returns it to the caller with
    /// its future intact.
    #[test]
    fn test_foreign_registration_goes_through_the_mailbox() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let task = Task::new(pending(), Arc::downgrade(&mailbox));
        assert!(Tasks::register(task.clone()).is_ok());
        let mut messages = Vec::new();
        assert!(mailbox.take(&mut messages));
        let [Message::Spawn(spawned)] = messages.as_slice() else {
            panic!("expected one spawned task");
        };
        assert!(Task::ptr_eq(spawned, &task));
        task.clear();

        // A closed mailbox rejects the task without dropping its future.
        drop(mailbox.close());
        let guard = DropCount(drops.clone());
        let task = Task::new(
            async move {
                let _guard = guard;
                pending::<()>().await;
            },
            Arc::downgrade(&mailbox),
        );
        let Err(rejected) = Tasks::register(task.clone()) else {
            panic!("a closed mailbox must reject the task");
        };
        assert!(Task::ptr_eq(&rejected, &task));
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        rejected.clear();
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        // So does a worker whose mailbox is gone.
        let gone = Arc::downgrade(&mailbox);
        drop(mailbox);
        let Err(rejected) = Tasks::register(Task::new(pending(), gone)) else {
            panic!("a dropped mailbox must reject the task");
        };
        rejected.clear();
    }

    #[test]
    fn test_wake_to_a_closed_or_dropped_mailbox_releases_its_token() {
        let mut tasks = Tasks::default();
        let closed = mailbox();
        let dropped = mailbox();
        let first = insert(&mut tasks, &closed, pending());
        let second = insert(&mut tasks, &dropped, pending());
        for _ in 0..2 {
            assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));
        }

        // Each wake publishes a token no worker will take, and releases it,
        // leaving the arena's reference and the caller's.
        drop(closed.close());
        first.wake_by_ref();
        assert_eq!(refs(&first), 2);
        drop(dropped);
        second.wake_by_ref();
        assert_eq!(refs(&second), 2);

        // Both tasks stay queued without a token until teardown clears them.
        for task in tasks.clear() {
            task.clear();
        }
    }

    /// A future whose destructor wakes its own task finds it terminal,
    /// whether teardown clears it or its final poll completes it.
    #[test]
    fn test_destructor_waking_its_own_task_publishes_nothing() {
        for complete in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let mailbox = mailbox();
            let mut tasks = Tasks::default();
            let task = insert(
                &mut tasks,
                &mailbox,
                WakesOnDrop {
                    waker: None,
                    complete,
                    _drops: DropCount(drops.clone()),
                },
            );

            match tasks.pop().unwrap().poll(|_| {}) {
                Outcome::Complete(token) => tasks.retire(token),
                Outcome::Idle => task.clear(),
                _ => panic!("the poll must complete or leave the task idle"),
            }
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert!(scheduled(&mailbox).is_empty());
            assert_eq!(refs(&task), if complete { 1 } else { 2 });
        }
    }

    #[test]
    fn test_clear_detaches_tasks_in_each_state() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let mut tasks = Tasks::default();
        let handles = [(); 3].map(|_| {
            let guard = DropCount(drops.clone());
            insert(&mut tasks, &mailbox, async move {
                let _guard = guard;
                pending::<()>().await;
            })
        });

        // Leave one task idle, one queued with its token held outside the
        // worker, and one queued with its token still in the ready queue.
        assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));
        assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));
        handles[1].wake_by_ref();
        let mut tokens = scheduled(&mailbox);
        assert_eq!(tokens.len(), 1);

        // Clearing the worker's tasks releases tokens and detaches the arena
        // without dropping any future.
        let retired: Vec<_> = tasks.clear().collect();
        assert_eq!(retired.len(), 3);
        assert!(!tasks.is_ready());
        assert_eq!(tasks.clear().count(), 0);
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        for task in &retired {
            task.clear();
            task.clear();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);

        // Wakes after clearing publish nothing, and a leftover token is stale.
        for task in &handles {
            task.wake_by_ref();
        }
        assert!(scheduled(&mailbox).is_empty());
        assert!(matches!(tokens.pop().unwrap().poll(|_| {}), Outcome::Stale));

        // A cleared arena has already released every slot.
        tasks.retire(handles[0].clone());
        drop(retired);
        for task in &handles {
            assert_eq!(refs(&task), 1);
        }
    }

    /// Teardown clearing a task mid-poll leaves the future to the poller,
    /// which completes the task whether a wake arrived before or after the
    /// clear.
    #[test]
    fn test_clear_during_poll_is_finished_by_the_poller() {
        for wake_first in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let mailbox = mailbox();
            let mut tasks = Tasks::default();

            // The future clears its own task mid-poll, standing in for
            // teardown on another thread while this one is polling.
            let cell = Arc::new(Mutex::new(None::<Task>));
            let task = insert(&mut tasks, &mailbox, {
                let guard = DropCount(drops.clone());
                let cell = Arc::clone(&cell);
                poll_fn(move |cx| {
                    let _ = &guard;
                    if wake_first {
                        cx.waker().wake_by_ref();
                    }
                    cell.lock().as_ref().unwrap().clear();
                    if !wake_first {
                        cx.waker().wake_by_ref();
                    }
                    Poll::<()>::Pending
                })
            });
            *cell.lock() = Some(task.clone());

            // The poll returned pending, so the finalizer runs before the
            // poller sees the clear.
            let mut finalized = 0;
            let Outcome::Complete(token) = tasks.pop().unwrap().poll(|_| finalized += 1) else {
                panic!("a task cleared during its poll must complete");
            };
            assert_eq!(finalized, 1);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            tasks.retire(token);
            task.wake_by_ref();
            assert!(scheduled(&mailbox).is_empty());
            cell.lock().take();
        }
    }

    /// The last two references, released at once on different threads, free
    /// the cell exactly once, after its future was dropped exactly once.
    #[test]
    fn test_concurrent_final_releases_free_the_cell_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let baseline = Arc::weak_count(&mailbox);
        let mut tasks = Tasks::default();
        let guard = DropCount(drops.clone());
        let task = insert(&mut tasks, &mailbox, async move {
            let _guard = guard;
            pending::<()>().await;
        });
        let waker = Waker::clone(&task.waker());
        assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));

        // Clear the future and retire the arena entry, leaving the caller's
        // reference and the cloned waker's.
        task.clear();
        tasks.retire(task.clone());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(refs(&task), 2);

        let barrier = Arc::new(Barrier::new(2));
        let releaser = thread::spawn({
            let barrier = barrier.clone();
            move || {
                barrier.wait();
                drop(waker);
            }
        });
        barrier.wait();
        drop(task);
        releaser.join().unwrap();

        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(Arc::weak_count(&mailbox), baseline);
    }

    /// A waker left as the only reference to a completed task frees the cell
    /// when `wake` consumes it.
    #[test]
    fn test_wake_by_value_frees_a_completed_task() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let baseline = Arc::weak_count(&mailbox);
        let mut tasks = Tasks::default();
        let guard = DropCount(drops.clone());
        let task = insert(&mut tasks, &mailbox, async move {
            let _guard = guard;
        });
        let waker = Waker::clone(&task.waker());

        let Outcome::Complete(token) = tasks.pop().unwrap().poll(|_| {}) else {
            panic!("ready future must complete");
        };
        tasks.retire(token);
        drop(task);
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        // The waker holds the last reference, which its wake releases.
        waker.wake();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(Arc::weak_count(&mailbox), baseline);
    }

    /// A future aligned beyond the cell's own alignment, which must not move
    /// once pinned, is polled and dropped at one aligned address, whether it
    /// completes or teardown clears it.
    #[test]
    fn test_over_aligned_future_is_polled_and_dropped_in_place() {
        let align = std::mem::align_of::<OverAligned>();
        assert!(align > std::mem::align_of::<CachePadded<()>>());
        for complete in [true, false] {
            let mailbox = mailbox();
            let mut tasks = Tasks::default();
            let addresses = Arc::new(Mutex::new(Vec::new()));
            let task = insert(
                &mut tasks,
                &mailbox,
                OverAligned {
                    remaining: AtomicUsize::new(if complete { 3 } else { usize::MAX }),
                    addresses: addresses.clone(),
                    _pinned: PhantomPinned,
                },
            );

            // Two polls leave the task idle, and each wake queues it again.
            for _ in 0..2 {
                assert!(matches!(tasks.pop().unwrap().poll(|_| {}), Outcome::Idle));
                task.wake_by_ref();
                tasks.push(scheduled(&mailbox).pop().unwrap());
            }
            if complete {
                let Outcome::Complete(token) = tasks.pop().unwrap().poll(|_| {}) else {
                    panic!("the third poll must complete");
                };
                tasks.retire(token);
            } else {
                for retired in tasks.clear() {
                    retired.clear();
                }
            }

            // Every poll and the destructor saw the same aligned address.
            let addresses = addresses.lock();
            assert_eq!(addresses.len(), if complete { 4 } else { 3 });
            assert_eq!(addresses[0] % align, 0, "future is not aligned");
            assert!(
                addresses.iter().all(|address| *address == addresses[0]),
                "future moved: {addresses:?}"
            );
        }
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    //! Exhaustive weak-memory checks for the notification handoff and the
    //! reference count sharing its word.

    use super::{Finish, Notify, REF_ONE, REFS, State};
    use loom::{
        cell::UnsafeCell,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };

    /// References counted in `state`.
    fn refs(state: &State) -> usize {
        (state.0.load(Ordering::Acquire) & REFS) / REF_ONE
    }

    /// State of a registered task whose first poll is queued: the token's
    /// reference and the arena's.
    fn registered() -> State {
        let state = State::queued();
        state.retain();
        state
    }

    /// A wake racing the end of a pending poll transfers exactly one token,
    /// regardless of which side wins the handoff.
    #[test]
    fn test_pending_wake_handoff_publishes_once() {
        loom::model(|| {
            let state = Arc::new(registered());
            assert!(state.start_poll());

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || state.notify_by_ref()
            });
            let poll_publishes = matches!(state.finish_pending(), Finish::Requeue);
            let wake_publishes = wake.join().unwrap();

            assert_ne!(poll_publishes, wake_publishes);
            assert!(state.start_poll());
            state.complete();
        });
    }

    /// A wake that gives up its reference, racing the end of a pending poll,
    /// leaves exactly one token and the right count, whichever side wins.
    #[test]
    fn test_wake_by_value_racing_a_pending_poll_keeps_the_count() {
        loom::model(|| {
            // References: the polled token, the arena's, and the waker's.
            let state = Arc::new(registered());
            state.retain();
            assert!(state.start_poll());

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || matches!(state.notify_by_value(), Notify::Schedule)
            });
            let requeued = matches!(state.finish_pending(), Finish::Requeue);
            let published = wake.join().unwrap();

            // One token remains, holding one reference beside the arena's.
            assert_ne!(requeued, published);
            assert_eq!(refs(&state), 2);
        });
    }

    /// A wake racing a completing poll never publishes a token.
    #[test]
    fn test_ready_wake_handoff_never_publishes() {
        loom::model(|| {
            let state = Arc::new(State::queued());
            assert!(state.start_poll());

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || state.notify_by_ref()
            });
            state.complete();

            assert!(!wake.join().unwrap());
            assert!(!state.notify_by_ref());
            assert!(!state.start_poll());
        });
    }

    /// Two references released at once: exactly one release is the last.
    #[test]
    fn test_concurrent_releases_find_one_last() {
        loom::model(|| {
            let state = Arc::new(State::queued());
            state.retain();

            let other = thread::spawn({
                let state = Arc::clone(&state);
                move || state.release()
            });
            let mine = state.release();

            assert_ne!(mine, other.join().unwrap());
        });
    }

    /// Teardown racing a poll never touches the future while the poller does,
    /// and exactly one of them drops it: the poller if the clear saw the poll
    /// running, the clear otherwise.
    #[test]
    fn test_clear_racing_a_poll_drops_the_future_once() {
        loom::model(|| {
            let state = Arc::new(registered());
            let future = Arc::new(UnsafeCell::new(0_usize));
            let drops = Arc::new(AtomicUsize::new(0));

            let poller = thread::spawn({
                let state = Arc::clone(&state);
                let future = Arc::clone(&future);
                let drops = Arc::clone(&drops);
                move || {
                    if !state.start_poll() {
                        return;
                    }
                    // SAFETY: the running state gives the poller exclusive
                    // access to the future.
                    future.with_mut(|value| unsafe { *value += 1 });
                    match state.finish_pending() {
                        Finish::Idle => {}
                        Finish::Cancelled => {
                            state.complete();
                            // SAFETY: exclusive access continues past
                            // `complete`.
                            future.with_mut(|value| unsafe { *value = usize::MAX });
                            drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Finish::Requeue => unreachable!("no wake was issued"),
                    }
                }
            });
            if state.clear() {
                // SAFETY: `clear` returned true, so no poll runs or can start.
                future.with_mut(|value| unsafe { *value = usize::MAX });
                drops.fetch_add(1, Ordering::Relaxed);
            }
            poller.join().unwrap();
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        });
    }

    /// A wake racing teardown of an idle task leaves no token that can poll it.
    #[test]
    fn test_wake_racing_clear_of_an_idle_task_leaves_nothing_to_poll() {
        loom::model(|| {
            let state = Arc::new(registered());
            assert!(state.start_poll());
            assert!(matches!(state.finish_pending(), Finish::Idle));

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || state.notify_by_ref()
            });
            assert!(state.clear());
            let _ = wake.join().unwrap();

            assert!(!state.start_poll());
            assert!(!state.notify_by_ref());
        });
    }

    /// Every successful successor claim observes writes published before the
    /// wake, including when the wake coalesces through a same-value exchange,
    /// and a wake that has returned is never lost.
    #[test]
    fn test_wake_handoff_publishes_payload() {
        loom::model(|| {
            let state = Arc::new(registered());
            let payload = Arc::new(AtomicUsize::new(0));
            let done = Arc::new(AtomicBool::new(false));

            let producer = thread::spawn({
                let state = Arc::clone(&state);
                let payload = Arc::clone(&payload);
                let done = Arc::clone(&done);
                move || {
                    payload.store(1, Ordering::Relaxed);
                    state.notify_by_ref();
                    done.store(true, Ordering::Release);
                }
            });
            let consumer = thread::spawn({
                let state = Arc::clone(&state);
                let payload = Arc::clone(&payload);
                let done = Arc::clone(&done);
                move || {
                    assert!(state.start_poll());
                    if payload.load(Ordering::Acquire) == 1 {
                        state.complete();
                        return;
                    }
                    let _ = state.finish_pending();
                    loop {
                        // A failed claim after the producer finished means
                        // its wake published no token.
                        let finished = done.load(Ordering::Acquire);
                        if state.start_poll() {
                            break;
                        }
                        assert!(!finished, "wake lost");
                        thread::yield_now();
                    }
                    assert_eq!(payload.load(Ordering::Acquire), 1);
                    state.complete();
                }
            });

            producer.join().unwrap();
            consumer.join().unwrap();
        });
    }
}
