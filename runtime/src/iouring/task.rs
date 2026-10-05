//! Single-allocation tasks that double as their wakers.
//!
//! A spawned task is one [`Cell`]: a type-erased [`Header`], the concrete
//! future, and a trailer with the task's [`Links`] in the runner's task set.
//! The header holds the task's [`State`], a vtable for the erased future,
//! the mailbox of the worker that owns the task, and the identity of the set
//! that retains it. A [`Task`] and a task's [`Waker`] are each a thin pointer
//! to that header holding one reference, so cloning either counts a reference,
//! and a wake is an atomic transition on the state, plus a queue push when it
//! publishes a [`Runnable`].
//!
//! # Lifecycle
//!
//! A [`Runnable`] is the reference that entitles its holder to poll the task
//! once. It waits in the owning worker's ready queue, or travels there through
//! the worker's mailbox, and a task has at most one. Only a runnable polls or
//! schedules its task, so a cloned [`Task`] cannot manufacture queued work. A
//! wake publishes a runnable only when the task has none, so duplicate wakes
//! coalesce. A wake that arrives during a poll is recorded in the state, and
//! the poll hands its runnable back only if it returns pending. That runnable
//! joins the tail of the ready queue, so a self-waking task cannot skip other
//! ready work. Completion is terminal, so a late wake of a finished task is a
//! no-op.
//!
//! ```text
//! Wakers, from any thread (`notify_by_ref`, `notify_by_value`):
//!   Idle              -> Queued       publishes a runnable
//!   Running           -> Notified     a pending poll requeues its runnable
//!   Queued, Notified  -> unchanged    coalesced, still a releasing exchange
//!   Complete          -> unchanged    ignored
//!
//! The poller, holding the runnable:
//!   Queued            -> Running      `start_poll`
//!   Running           -> Idle         `finish_pending`, no wake arrived
//!   Notified          -> Queued       `finish_pending`, the runnable is reused
//!   Running, Notified -> Complete     `complete`, then the future drops
//!
//! Teardown, through `clear`:
//!   Idle, Queued      -> Complete     the caller drops the future
//!   Running, Notified -> + CANCELLED  even a pending poll ends in `complete`
//! ```
//!
//! # Ownership
//!
//! Every runnable, cloned waker, and task set entry holds one reference,
//! counted in the state word above the lifecycle bits. Transitions that create
//! or consume a reference change the count in the same exchange: a wake by
//! reference that publishes counts the runnable's, a wake by value hands its
//! reference to the runnable it publishes or releases it, and a poll that ends
//! idle releases its runnable's. The waker passed to a poll borrows its
//! runnable's.
//!
//! The runner's [`Tasks`] set retains every registered task so teardown can
//! drop its future, and completion removes it on whichever thread finishes the
//! task. A future is dropped in place when its task completes or is cleared,
//! and freeing a cell whose future is still present panics, so releasing a
//! reference runs no user code. A stale waker keeps the cell's allocation, not
//! its future, alive.
//!
//! Wakes on the owning worker queue the runnable directly. Wakes from other
//! threads, including a foreign spawn's first runnable, travel through its
//! mailbox.

use super::{
    cell::UnsafeCell,
    mailbox::{Mailbox, Message},
    runtime::{Local, Panics},
    tasks::{Links, Tasks},
};
use crossbeam_utils::CachePadded;
use std::{
    collections::VecDeque,
    future::Future,
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    num::NonZeroU64,
    ops::Deref,
    pin::Pin,
    ptr::NonNull,
    sync::{Arc, Weak},
    task::{Context, Poll, RawWaker, RawWakerVTable, Wake, Waker},
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::atomic::{AtomicUsize, Ordering, fence};
    } else {
        use std::sync::atomic::{AtomicUsize, Ordering, fence};
    }
}

/// Pending without a runnable. The next wake publishes one.
const IDLE: usize = 0;
/// No poll is running, and the task's runnable waits to poll it. Discarding
/// that runnable leaves the task queued until `clear`.
const QUEUED: usize = 1;
/// The runnable's holder is polling the future.
const RUNNING: usize = 2;
/// Polling, and a wake arrived during the poll, so a pending poll requeues its
/// runnable.
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

/// Next step for a poller whose poll returned pending.
///
/// `finish_pending` has already made the state and reference changes, so each
/// variant is only what remains for the poller.
enum AfterPending {
    /// Nothing. No wake arrived and the task went idle. The exchange released
    /// the polled runnable's reference, so the poller forgets the runnable.
    Done,
    /// Queue the polled runnable again. A wake arrived during the poll and
    /// published nothing, so the runnable stays valid for the next poll,
    /// keeping its reference.
    Requeue,
    /// Complete the task and drop its future. Teardown cleared the task during
    /// the poll and left the future to the poller.
    Complete,
}

/// Next step for a waker that gave up its reference.
///
/// `notify_by_value` has already handed the reference to a new runnable or
/// released it.
enum AfterWake {
    /// Schedule the new runnable. The task was idle, and the waker's reference
    /// is now the runnable's.
    Schedule,
    /// Nothing. The task was queued, running, or complete. The exchange
    /// released the waker's reference, and others remain.
    Done,
    /// Free the cell. The exchange released the waker's reference, and it was
    /// the last.
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
/// A runnable owns the right to poll while the lifecycle is `QUEUED`. Polling
/// moves to `RUNNING`, a concurrent wake moves to `NOTIFIED` without a second
/// runnable, and the poller requeues its runnable only after observing pending.
/// `COMPLETE` is terminal.
///
/// Transitions exchange with acquire-release ordering, so writes made before a
/// wake are visible to the poll it causes, and a poll's writes are visible to
/// the next poll and to teardown.
struct State(AtomicUsize);

impl State {
    /// State of a new task whose first poll is queued, holding two references:
    /// its first runnable's and the one its task set takes over.
    // Loom's atomics have no const constructor.
    #[allow(clippy::missing_const_for_fn)]
    fn new() -> Self {
        Self(AtomicUsize::new(QUEUED | (2 * REF_ONE)))
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
    /// Returns whether the caller must schedule a runnable, whose reference the
    /// exchange counted.
    #[inline]
    fn notify_by_ref(&self) -> bool {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, publish) = match state & LIFECYCLE {
                // No runnable exists, so this wake publishes one. The waker
                // keeps its own reference, so the runnable's is counted here.
                IDLE => {
                    // Guarded as in `retain`.
                    if state > isize::MAX as usize {
                        std::process::abort();
                    }
                    (Self::with_lifecycle(state, QUEUED) + REF_ONE, true)
                }
                // A runnable already waits to poll the task, unless it was
                // discarded for teardown to clear the task. Coalesced wakes
                // still exchange, so writes made before them are published to
                // the next acquiring transition.
                QUEUED => (state, false),
                // A poll is running. The wake is recorded so that poll requeues
                // its runnable if it returns pending, and wakes during one poll
                // coalesce into that requeue.
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
    /// published runnable takes the reference over, and otherwise the exchange
    /// releases it.
    ///
    /// The transitions match [`notify_by_ref`](Self::notify_by_ref), except for
    /// whose reference a published runnable holds. Folding the release of an
    /// unused reference into the exchange saves a separate decrement on every
    /// coalesced wake.
    #[inline]
    fn notify_by_value(&self) -> AfterWake {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, publish) = match state & LIFECYCLE {
                // No runnable exists, so the waker's reference becomes one, and
                // the count is unchanged.
                IDLE => (Self::with_lifecycle(state, QUEUED), true),
                // A runnable already waits, or nothing will poll again, so the
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
                Ok(_) if publish => return AfterWake::Schedule,
                // Only a completed task can lose its last reference here, since
                // a runnable, a poll, or the reference obliged to clear the
                // task holds one otherwise. The acquiring exchange orders every
                // earlier release before the free.
                Ok(_) if next & REFS == 0 => return AfterWake::Dealloc,
                Ok(_) => return AfterWake::Done,
                Err(actual) => state = actual,
            }
        }
    }

    /// Claim a poll with the runnable, whose reference the poll then holds.
    /// Fails for a stale runnable, whose task was cleared while it waited.
    #[inline]
    fn start_poll(&self) -> bool {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            // Only a queued task has a runnable to claim. A runnable that finds
            // the task complete is stale.
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
    /// runnable's reference in the same exchange.
    #[inline]
    fn finish_pending(&self) -> AfterPending {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            // Teardown cleared the task mid-poll and left the future to this
            // poller. The lifecycle stays running until `complete`, so wakes
            // meanwhile publish nothing.
            if state & CANCELLED != 0 {
                return AfterPending::Complete;
            }

            let (next, result) = match state & LIFECYCLE {
                // No wake arrived. The next wake publishes a new runnable, so
                // this one is released in the same exchange.
                RUNNING => {
                    // The task set holds a reference to every task that can go
                    // idle, so the runnable's is never the last.
                    assert!(
                        state & REFS > REF_ONE,
                        "idle task would release its last reference"
                    );
                    (
                        Self::with_lifecycle(state, IDLE) - REF_ONE,
                        AfterPending::Done,
                    )
                }
                // A wake arrived and published nothing, so the polled runnable
                // becomes the next one, keeping its reference.
                NOTIFIED => (Self::with_lifecycle(state, QUEUED), AfterPending::Requeue),
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
                // runnable still queued is found stale when taken.
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

/// Next step for a worker that polled a runnable.
///
/// [`Runnable::poll`] has already dropped a finished future. Ignoring a
/// [`Requeue`](Self::Requeue) leaves the task queued with nothing to poll it,
/// and ignoring a [`Retire`](Self::Retire) leaves the task linked in its set,
/// each until teardown.
#[must_use]
pub enum AfterPoll {
    /// Nothing. The poll returned pending with no wake during it, so the next
    /// wake publishes a new runnable, or the runnable was stale because its
    /// task was already cleared. Either way the runnable's reference is
    /// released.
    Done,
    /// Queue the carried runnable again. A wake arrived during the pending
    /// poll, so the task needs another poll.
    Requeue(Runnable),
    /// Remove the carried task, which holds the polled runnable's reference,
    /// from its [`Tasks`] set. The future returned ready, panicked, or was
    /// cleared during the poll, and has been dropped.
    Retire(Task),
}

/// Operations that need the concrete future type behind a header, one table
/// per future type.
///
/// Each takes a header pointer that carries the whole allocation's provenance,
/// as described on [`Header`].
struct Vtable {
    /// Poll the future in place. The caller holds the running state.
    poll: unsafe fn(NonNull<Header>, &mut Context<'_>) -> Poll<()>,
    /// Drop the future in place. The caller has exclusive access to it.
    drop_future: unsafe fn(NonNull<Header>),
    /// Free the allocation, whose future is already gone.
    dealloc: unsafe fn(NonNull<Header>),
    /// Byte offset of the cell's [`Links`] from its header.
    trailer: usize,
}

/// Type-erased front of every task allocation.
///
/// Header pointers passed to the vtable, [`Task::from_raw`], [`Header::links`],
/// or the waker functions must derive from the pointer `Task::new` leaked,
/// which every `Task` and task waker carries. A pointer made from a `&Header`
/// covers only the header, so reaching the rest of the cell or freeing it
/// through that pointer is undefined behavior, even at the same address.
#[repr(C)]
pub struct Header {
    /// Lifecycle and reference count, changed on any thread by wakers and
    /// references and by the poller.
    state: State,
    /// Operations on the concrete future behind this header.
    vtable: &'static Vtable,
    /// Worker that owns the task, reached by foreign wakes, without extending
    /// its lifetime.
    mailbox: Weak<Mailbox>,
    /// Identity of the [`Tasks`] set that retains the task.
    owner: NonZeroU64,
}

impl Header {
    /// Identity of the [`Tasks`] set that retains the task.
    pub const fn owner(&self) -> NonZeroU64 {
        self.owner
    }

    /// The [`Links`] of the task behind `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live task with the allocation's provenance.
    pub const unsafe fn links(ptr: NonNull<Self>) -> NonNull<Links> {
        // SAFETY: per the contract. The vtable records where this cell type
        // keeps its links, within the same allocation.
        unsafe {
            let offset = ptr.as_ref().vtable.trailer;
            ptr.cast::<u8>().add(offset).cast()
        }
    }
}

/// A task allocation: the erased header, the concrete future, and a trailer.
///
/// `repr(C)` puts the header at offset zero, so the cell and header pointers
/// are one address. The whole cell is aligned with [`CachePadded`], so no two
/// tasks share a line. Depending on the future's layout, its start can share
/// the first line with the header.
#[repr(C)]
struct Cell<F> {
    /// Type-erased state shared by every reference.
    header: Header,
    /// The future, `None` once completed or cleared.
    future: UnsafeCell<Option<F>>,
    /// Links in the task set, after the future as in tokio's trailer,
    /// since only insertion, removal, and teardown touch them.
    links: Links,
    /// Sets the cell's alignment with a zero-sized field.
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
            trailer: mem::offset_of!(Self, links),
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
        // SAFETY: the header starts a `Cell<F>` per the contract.
        let cell = unsafe { header.cast::<Self>().as_ref() };
        cell.future.with_mut(|future| {
            // SAFETY: the running state gives this thread exclusive access to
            // the future.
            let future = unsafe { &mut *future };
            let future = future.as_mut().expect("queued task retains its future");

            // SAFETY: the future lives inside the cell and is never moved out
            // of it, so pinning it in place is sound.
            unsafe { Pin::new_unchecked(future) }.poll(cx)
        })
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
        unsafe {
            header
                .cast::<Self>()
                .as_ref()
                .future
                .with_mut(|future| *future = None)
        };
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
        let present = unsafe { cell.as_ref().future.with(|future| (*future).is_some()) };
        assert!(!present, "task freed with its future still present");

        // SAFETY: `Task::new` leaked exactly this box, and the last reference
        // is gone.
        drop(unsafe { Box::from_raw(cell.as_ptr()) });
    }
}

/// An owning reference to a task, counted in its state.
///
/// Task set entries are `Task`s, and a [`Runnable`] wraps one. Dropping the
/// last reference frees the cell, whose future must already be gone.
pub struct Task(NonNull<Header>);

// SAFETY: `Task::new` requires `F: Send`, and the header (including its
// `Weak<Mailbox>`) is `Send + Sync`. Only the thread that wins the running
// state, clears a nonrunning task, or frees the cell accesses the future, and
// only the holder of the task's shard lock in the task set accesses its links.
unsafe impl Send for Task {}
// SAFETY: the header is `Sync`, and `F: Send` permits `clear` to drop the
// future on another thread. Its state transition grants exclusive access,
// and no `&F` is shared, so `F: Sync` is not needed. The links are guarded as
// described for `Send`.
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
    /// Allocate a task for `tasks` to retain, owned by the worker behind
    /// `mailbox`, with its first poll queued. Returns the reference for the
    /// set to take over, and the task's first runnable.
    pub fn new<F>(future: F, tasks: &Tasks, mailbox: Weak<Mailbox>) -> (Self, Runnable)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cell = Box::new(Cell {
            header: Header {
                state: State::new(),
                vtable: Cell::<F>::vtable(),
                mailbox,
                owner: tasks.id(),
            },
            future: UnsafeCell::new(Some(future)),
            links: Links::default(),
            _align: [],
        });

        // The state counts both references.
        let ptr = NonNull::from(Box::leak(cell)).cast();
        (Self(ptr), Runnable(Self(ptr)))
    }

    /// The header pointer, with the allocation's provenance, holding no
    /// reference of its own.
    pub const fn as_ptr(&self) -> NonNull<Header> {
        self.0
    }

    /// Give up this reference as a header pointer with the allocation's
    /// provenance.
    pub fn into_raw(self) -> NonNull<Header> {
        ManuallyDrop::new(self).0
    }

    /// Adopt the reference a raw header pointer carries.
    ///
    /// # Safety
    ///
    /// `ptr` must carry a reference the caller gives up, with the allocation's
    /// provenance.
    pub const unsafe fn from_raw(ptr: NonNull<Header>) -> Self {
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

    /// Wake with this reference, which a published runnable takes over and the
    /// state exchange releases otherwise.
    fn wake(self) {
        // The exchange decides what happens to this reference, so the
        // destructor must not release it as well.
        let this = ManuallyDrop::new(self);

        match this.state.notify_by_value() {
            AfterWake::Schedule => Runnable(ManuallyDrop::into_inner(this)).schedule(),
            AfterWake::Done => {}
            AfterWake::Dealloc => {
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
            // runnable, which the adopted task takes over, and `self.0`
            // carries the allocation's provenance.
            Runnable(unsafe { Self::from_raw(self.0) }).schedule();
        }
    }

    /// Drop the future in place, or mark a running task for its poller to
    /// drop. Does nothing to a completed task.
    ///
    /// The future's destructor may panic. Callers hold no worker borrow and
    /// choose the panic boundary.
    pub fn clear(&self) {
        // Terminal first, so a late wake cannot publish a runnable.
        if !self.state.clear() {
            return;
        }

        // SAFETY: `self` keeps the cell alive and carries the pointer `new`
        // leaked. The state left IDLE or QUEUED for COMPLETE, so no poll is
        // running and none can start.
        unsafe { (self.vtable.drop_future)(self.0) };
    }
}

/// The reference that entitles its holder to poll its task once.
///
/// A runnable comes only from allocation or from a wake that finds the task
/// idle, and a pending poll during which a wake arrived hands its own runnable
/// back. It leaves through [`schedule`](Self::schedule), [`poll`](Self::poll),
/// or [`discard`](Self::discard).
///
/// Dropping a runnable releases its reference and leaves its task queued with
/// no runnable to poll it, so a later wake publishes nothing. A runnable may
/// therefore be discarded only when its task is complete, or when another
/// reference is obliged to clear the task: the closed task set's, which
/// teardown drains, or the [`Task`] a refused registration returns to its
/// caller.
#[repr(transparent)]
#[must_use = "a dropped runnable wedges its task, so schedule, poll, or discard it"]
pub struct Runnable(Task);

impl Runnable {
    /// Deliver the runnable to the owning worker, directly on its thread and
    /// through its mailbox otherwise.
    ///
    /// A closing worker, or a closed or dropped mailbox, discards the runnable,
    /// and teardown clears the task if it has not already.
    pub fn schedule(self) {
        // On the owning thread, the runnable goes straight to the ready queue.
        // Polls and destructors run without the local borrow, so a wake from
        // inside one can take it here.
        if let Some(local) = Local::owner(&self.0.mailbox) {
            let mut local = local.borrow_mut();

            // A closing worker polls nothing more, and its closed task set
            // retains the task for the drain. Releasing a reference runs no
            // user code, so discarding the runnable under the borrow is fine.
            if local.closing {
                self.discard();
            } else {
                local.ready.push(self);
            }

            return;
        }

        // Any other thread hands the runnable to the mailbox, and the worker
        // queues it when it applies its messages. A closed mailbox returns the
        // runnable, and a dropped one takes none. Either way the ordinary
        // worker, which owns every task, has closed its task set, so the drain
        // clears the task or already has.
        let Some(mailbox) = self.0.mailbox.upgrade() else {
            self.discard();
            return;
        };
        if let Err(Message::Wake(Target::Task(runnable))) =
            mailbox.send(Message::Wake(Target::Task(self)))
        {
            runnable.discard();
        }
    }

    /// Poll the task, containing panics.
    ///
    /// The caller holds no worker borrow, since the poll and the destructors it
    /// runs are user code.
    pub fn poll(self) -> AfterPoll {
        // A runnable whose task was already cleared is stale.
        if !self.0.state.start_poll() {
            self.discard();
            return AfterPoll::Done;
        }

        // The poll and the destructors it may run stay behind one boundary,
        // and a panic completes the task like a ready future does. The waker
        // borrows this runnable's reference, so passing it counts nothing.
        let task = &self.0;
        let polled = Panics::contain(|| {
            let waker = task.waker();
            let mut cx = Context::from_waker(&waker);

            // SAFETY: the runnable's reference keeps the cell alive, and its
            // pointer is the one `new` leaked. `start_poll` granted this thread
            // exclusive access to the future until the state leaves RUNNING or
            // NOTIFIED below.
            unsafe { (task.vtable.poll)(task.0, &mut cx) }
        });

        // A pending poll leaves the task idle or requeues this runnable, unless
        // teardown cleared the task meanwhile, which completes it below.
        if matches!(polled, Some(Poll::Pending)) {
            match task.state.finish_pending() {
                AfterPending::Done => {
                    // The exchange released this runnable's reference.
                    mem::forget(self);
                    return AfterPoll::Done;
                }
                AfterPending::Requeue => return AfterPoll::Requeue(self),
                AfterPending::Complete => {}
            }
        }

        // Publish the terminal state before destructors run. A destructor may
        // wake this task or panic, and either must observe a completed cell.
        task.state.complete();

        // SAFETY: the cell is alive as for the poll, and exclusive access
        // continues past `complete`, since `start_poll` and `clear` both do
        // nothing once the state is COMPLETE.
        Panics::contain(|| unsafe { (task.vtable.drop_future)(task.0) });
        AfterPoll::Retire(self.0)
    }

    /// Release the runnable where the contract on [`Runnable`] permits it.
    pub fn discard(self) {
        drop(self);
    }
}

/// A waker that borrows a task's reference instead of counting its own, so it
/// lives no longer than the borrow of that task. Cloning it counts a reference
/// as usual.
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
/// `ptr` must be a header pointer with the allocation's provenance, carrying a
/// reference the caller gives up. A caller that keeps the reference must never
/// drop the result, and must use it only while that reference lives.
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

/// Wake with the waker's reference, which a published runnable takes over.
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
    /// A task, carrying its runnable.
    Task(Runnable),
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

/// One worker's ready queue of runnables, touched only by that worker.
#[derive(Default)]
pub struct Ready {
    /// Runnables in FIFO order.
    runnables: VecDeque<Runnable>,
}

impl Ready {
    /// Queue a runnable.
    #[inline]
    pub fn push(&mut self, runnable: Runnable) {
        self.runnables.push_back(runnable);
    }

    /// Take the oldest runnable.
    #[inline]
    #[must_use]
    pub fn pop(&mut self) -> Option<Runnable> {
        self.runnables.pop_front()
    }

    /// Whether no runnable is queued.
    pub fn is_empty(&self) -> bool {
        self.runnables.is_empty()
    }

    /// Discard every runnable at teardown.
    ///
    /// The closed task set retains each runnable's task, so discarding them
    /// loses nothing and runs no user code.
    pub fn discard(&mut self) {
        for runnable in self.runnables.drain(..) {
            runnable.discard();
        }
    }
}

#[cfg(test)]
pub mod tests {
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

    /// Future whose destructor records its invocation and panics.
    struct PanicsOnDrop {
        complete: bool,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PanicsOnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.complete {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for PanicsOnDrop {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            panic!("future drop panic");
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

    /// Future aligned beyond the cell's own alignment, above every padding unit
    /// crossbeam uses (at most 256 bytes), that must not move once pinned. It
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

    /// Retain a task owned by `mailbox` in `set` and queue its first runnable
    /// in `ready`, returning the caller's own reference.
    fn insert(
        set: &Tasks,
        ready: &mut Ready,
        mailbox: &Arc<Mailbox>,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Task {
        let (task, runnable) = Task::new(future, set, Arc::downgrade(mailbox));
        assert!(set.insert(task.clone()).is_ok());
        ready.push(runnable);
        task
    }

    /// Remove a completed task from `set`, which must still retain it.
    fn retire(set: &Tasks, task: Task) {
        assert!(set.remove(&task).is_some(), "completed task not retained");
    }

    /// References held to `task`, including the caller's.
    pub fn refs(task: &Task) -> usize {
        (task.state.0.load(Ordering::Acquire) & REFS) / REF_ONE
    }

    /// The task `runnable` entitles its holder to poll.
    pub const fn task_of(runnable: &Runnable) -> &Task {
        &runnable.0
    }

    /// Take the runnables delivered to `mailbox`.
    fn scheduled(mailbox: &Mailbox) -> Vec<Runnable> {
        let mut messages = Vec::new();
        mailbox.take(&mut messages);
        messages
            .into_iter()
            .map(|message| match message {
                Message::Wake(Target::Task(runnable)) => runnable,
                _ => panic!("expected only runnables"),
            })
            .collect()
    }

    /// The whole cell is aligned with `CachePadded`, and the header, which fits
    /// one 64-byte line, shares the first line with the future. Where the unit
    /// holds that line (128 bytes on x86_64 and aarch64), a small future, its
    /// header, and the trailer take exactly one unit.
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

    /// The vtable's trailer offset reaches the cell's own links, for futures
    /// smaller than, larger than, and aligned beyond the header.
    #[test]
    fn test_links_follow_the_future() {
        fn check<F: Future<Output = ()> + Send + 'static>(future: F) {
            let set = Tasks::new(1);
            let (task, runnable) = Task::new(future, &set, Weak::new());
            let cell = task.as_ptr().cast::<Cell<F>>();
            // SAFETY: the task's reference keeps the cell alive, and `new`
            // leaked a `Cell<F>` at this pointer.
            let expected = unsafe { ptr::addr_of!((*cell.as_ptr()).links) };
            // SAFETY: the task's reference keeps the cell alive.
            let links = unsafe { Header::links(task.as_ptr()) };
            assert_eq!(links.as_ptr().cast_const(), expected);
            task.clear();
            runnable.discard();
        }

        check(pending::<()>());

        // The array is used after the suspension point, so the future keeps it.
        let large = async {
            let large = [0_u8; 300];
            pending::<()>().await;
            std::hint::black_box(&large);
        };
        assert!(std::mem::size_of_val(&large) >= 300);
        check(large);
        check(OverAligned {
            remaining: AtomicUsize::new(usize::MAX),
            addresses: Arc::new(Mutex::new(Vec::new())),
            _pinned: PhantomPinned,
        });
    }

    /// The shared header, including its mailbox handle, can cross threads.
    #[test]
    fn test_header_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<Header>();
    }

    /// Every waker and runnable counts a reference, and the last one frees the
    /// cell.
    #[test]
    fn test_wakers_hold_references_until_the_cell_is_freed() {
        let mailbox = mailbox();

        // A new task holds the caller's reference, its first runnable's, and
        // one mailbox reference.
        let (task, runnable) = Task::new(pending::<()>(), &Tasks::new(1), Arc::downgrade(&mailbox));
        assert_eq!(refs(&task), 2);
        assert_eq!(Arc::weak_count(&mailbox), 1);

        // Polling borrows the runnable's reference for the waker it passes in,
        // and going idle releases it.
        assert!(matches!(runnable.poll(), AfterPoll::Done));
        assert_eq!(refs(&task), 1);

        // Cloned wakers count, and dropped ones release.
        let waker = Waker::clone(&task.waker());
        let other = waker.clone();
        assert_eq!(refs(&task), 3);
        drop(other);
        assert_eq!(refs(&task), 2);

        // Waking by value hands the waker's reference to the published
        // runnable.
        waker.wake();
        assert_eq!(refs(&task), 2);
        let mut runnables = scheduled(&mailbox);
        assert_eq!(runnables.len(), 1);
        let runnable = runnables.pop().unwrap();
        assert_eq!(task_of(&runnable).as_ptr(), task.as_ptr());
        runnable.discard();
        assert_eq!(refs(&task), 1);

        // The last reference frees the cell, and with it the mailbox reference.
        task.clear();
        drop(task);
        assert_eq!(Arc::weak_count(&mailbox), 0);
    }

    /// Duplicate wakes from a foreign thread deliver one runnable through the
    /// mailbox.
    #[test]
    fn test_foreign_wakes_coalesce_into_one_runnable() {
        let mailbox = mailbox();
        let set = Tasks::new(1);
        let mut ready = Ready::default();
        let task = insert(&set, &mut ready, &mailbox, pending());
        assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));

        // Wakes from a thread without a worker travel through the mailbox, and
        // duplicates publish one runnable. The coalesced wake by value releases
        // its reference, leaving the set's, the caller's, and the runnable's.
        let waker = Waker::clone(&task.waker());
        thread::spawn(move || {
            waker.wake_by_ref();
            waker.wake_by_ref();
            waker.wake();
        })
        .join()
        .unwrap();
        assert_eq!(refs(&task), 3);
        let mut runnables = scheduled(&mailbox);
        assert_eq!(runnables.len(), 1);

        // The runnable polls the task again, which leaves it idle once more.
        ready.push(runnables.pop().unwrap());
        assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));
        assert!(scheduled(&mailbox).is_empty());
        task.clear();
        drop(set.teardown());
    }

    /// A running poll keeps exclusive access before and after a wake.
    #[test]
    fn test_running_poll_cannot_be_claimed_again() {
        let state = State::new();
        assert!(state.start_poll());

        // A running poll cannot be claimed again.
        assert!(!state.start_poll());

        // A wake during the poll records a requeue without publishing a
        // runnable.
        assert!(!state.notify_by_ref());
        assert!(!state.start_poll());
    }

    /// Wakes during a pending poll requeue the polled runnable once, and wakes
    /// during the final poll are ignored.
    #[test]
    fn test_wakes_during_poll_coalesce_into_one_requeue() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let set = Tasks::new(1);
        let mut ready = Ready::default();
        let task = insert(
            &set,
            &mut ready,
            &mailbox,
            SelfWaker {
                wakes: 3,
                polls: 2,
                _drops: DropCount(drops.clone()),
            },
        );

        // Wakes during the poll leave the task queued, and the poll hands its
        // runnable back rather than publishing one.
        let AfterPoll::Requeue(runnable) = ready.pop().unwrap().poll() else {
            panic!("self-woken pending poll must requeue");
        };
        assert_eq!(task_of(&runnable).as_ptr(), task.as_ptr());
        assert!(scheduled(&mailbox).is_empty());

        // The final poll wakes itself again, which the terminal state ignores.
        let AfterPoll::Retire(retired) = runnable.poll() else {
            panic!("final poll must complete");
        };
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        retire(&set, retired);
        assert!(scheduled(&mailbox).is_empty());
        assert_eq!(refs(&task), 1);
    }

    /// A panicking poll completes its task, which leaves the set, and its
    /// waker reaches neither the set nor a later task.
    #[test]
    fn test_poll_panic_completes_the_task_and_leaves_the_set() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let set = Tasks::new(1);
        let mut ready = Ready::default();
        let guard = DropCount(drops.clone());
        let first = insert(&set, &mut ready, &mailbox, async move {
            let _guard = guard;
            panic!("poll panic");
        });
        let waker = Waker::clone(&first.waker());

        // The panicking poll completes the task and drops its future.
        let AfterPoll::Retire(retired) = ready.pop().unwrap().poll() else {
            panic!("panicking poll must complete the task");
        };
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        retire(&set, retired);
        assert_eq!(set.live(), 0);

        // The completed task's waker neither publishes nor reaches the next
        // task.
        let second = insert(&set, &mut ready, &mailbox, pending());
        assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));
        waker.wake_by_ref();
        assert!(scheduled(&mailbox).is_empty());
        drop(waker);
        assert_eq!(refs(&first), 1);
        assert_eq!(set.live(), 1);
        second.clear();
        drop(set.teardown());
    }

    /// A task registered from a thread without its worker joins the set at once
    /// and sends its first runnable through the mailbox. A closed or dropped
    /// mailbox discards the runnable and leaves the task to teardown, and a
    /// closed set returns the new task to the caller with its future intact and
    /// its runnable discarded.
    #[test]
    fn test_foreign_registration_retains_the_task_and_mails_its_runnable() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let set = Tasks::new(1);

        // The set retains the task, and its first runnable arrives as a wake.
        assert!(set.register(pending(), Arc::downgrade(&mailbox)).is_ok());
        assert_eq!(set.live(), 1);
        let mut runnables = scheduled(&mailbox);
        assert_eq!(runnables.len(), 1);
        let runnable = runnables.pop().unwrap();
        assert_eq!(refs(task_of(&runnable)), 2);
        runnable.discard();

        // A closed or dropped mailbox discards the runnable, and the set keeps
        // the task until teardown clears it.
        drop(mailbox.close());
        assert!(set.register(pending(), Arc::downgrade(&mailbox)).is_ok());
        let gone = Arc::downgrade(&mailbox);
        drop(mailbox);
        assert!(set.register(pending(), gone).is_ok());
        assert_eq!(set.live(), 3);

        // Closing hands out each task with the set's reference as its only
        // one, and a closed set rejects a new task without dropping its future.
        let retained = set.teardown();
        assert_eq!(retained.len(), 3);
        assert!(retained.iter().all(|task| refs(task) == 1));
        let guard = DropCount(drops.clone());
        let registered = set.register(
            async move {
                let _guard = guard;
                pending::<()>().await;
            },
            Weak::new(),
        );
        let Err(rejected) = registered else {
            panic!("a closed set must reject the task");
        };
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(refs(&rejected), 1);
        rejected.clear();
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        for task in retained {
            task.clear();
        }
    }

    /// A wake whose mailbox is closed or gone discards its runnable instead of
    /// leaking it.
    #[test]
    fn test_wake_to_a_closed_or_dropped_mailbox_discards_its_runnable() {
        let set = Tasks::new(1);
        let mut ready = Ready::default();
        let closed = mailbox();
        let dropped = mailbox();
        let first = insert(&set, &mut ready, &closed, pending());
        let second = insert(&set, &mut ready, &dropped, pending());
        for _ in 0..2 {
            assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));
        }

        // Each wake publishes a runnable no worker will take, and discards it,
        // leaving the set's reference and the caller's.
        drop(closed.close());
        first.wake_by_ref();
        assert_eq!(refs(&first), 2);
        drop(dropped);
        second.wake_by_ref();
        assert_eq!(refs(&second), 2);

        // Both tasks stay queued without a runnable until teardown clears them.
        for task in set.teardown() {
            task.clear();
        }
    }

    /// A future whose destructor wakes its own task finds it terminal, whether
    /// teardown clears it or its final poll completes it.
    #[test]
    fn test_destructor_waking_its_own_task_publishes_nothing() {
        for complete in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let mailbox = mailbox();
            let set = Tasks::new(1);
            let mut ready = Ready::default();
            let task = insert(
                &set,
                &mut ready,
                &mailbox,
                WakesOnDrop {
                    waker: None,
                    complete,
                    _drops: DropCount(drops.clone()),
                },
            );

            match ready.pop().unwrap().poll() {
                AfterPoll::Retire(retired) => retire(&set, retired),
                AfterPoll::Done => task.clear(),
                _ => panic!("the poll must complete or leave the task idle"),
            }
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert!(scheduled(&mailbox).is_empty());
            assert_eq!(refs(&task), if complete { 1 } else { 2 });
            drop(set.teardown());
        }
    }

    /// Teardown detaches idle and queued tasks, drops each future once, and
    /// leaves nothing to poll.
    #[test]
    fn test_clear_detaches_tasks_in_each_state() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let set = Tasks::new(1);
        let mut ready = Ready::default();
        let handles = [(); 3].map(|_| {
            let guard = DropCount(drops.clone());
            insert(&set, &mut ready, &mailbox, async move {
                let _guard = guard;
                pending::<()>().await;
            })
        });

        // Leave one task idle, one queued with its runnable held outside the
        // worker, and one queued with its runnable still in the ready queue.
        assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));
        assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));
        handles[1].wake_by_ref();
        let mut runnables = scheduled(&mailbox);
        assert_eq!(runnables.len(), 1);

        // The ready queue's runnable is discarded, and closing and draining
        // the set hands out every task. Neither drops a future.
        ready.discard();
        assert!(ready.is_empty());
        let retired = set.teardown();
        assert_eq!(retired.len(), 3);
        assert!(set.drain().next().is_none());
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        // Clearing each detached task drops its future once, even when repeated.
        for task in &retired {
            task.clear();
            task.clear();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);

        // Wakes after clearing publish nothing, and polling a leftover runnable
        // only releases it, leaving the handle's and the one handed out.
        for task in &handles {
            task.wake_by_ref();
        }
        assert!(scheduled(&mailbox).is_empty());
        assert!(matches!(runnables.pop().unwrap().poll(), AfterPoll::Done));
        assert_eq!(refs(&handles[1]), 2);

        // A closed set has already handed out every task.
        assert!(set.remove(&handles[0]).is_none());
        drop(retired);
        for task in &handles {
            assert_eq!(refs(task), 1);
        }
    }

    /// Teardown clearing a task mid-poll leaves the future to the poller, which
    /// completes the task whether a wake arrived before or after the clear.
    #[test]
    fn test_clear_during_poll_is_finished_by_the_poller() {
        for wake_first in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let mailbox = mailbox();
            let set = Tasks::new(1);
            let mut ready = Ready::default();

            // The future clears its own task mid-poll, standing in for
            // teardown on another thread while this one is polling.
            let cell = Arc::new(Mutex::new(None::<Task>));
            let task = insert(&set, &mut ready, &mailbox, {
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

            // The poller completes the task and drops the future, and a later
            // wake publishes nothing.
            let AfterPoll::Retire(retired) = ready.pop().unwrap().poll() else {
                panic!("a task cleared during its poll must complete");
            };
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            retire(&set, retired);
            task.wake_by_ref();
            assert!(scheduled(&mailbox).is_empty());
            cell.lock().take();
        }
    }

    /// The last two references, released at once on different threads, free the
    /// cell exactly once, after its future was dropped exactly once.
    #[test]
    fn test_concurrent_final_releases_free_the_cell_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mailbox = mailbox();
        let baseline = Arc::weak_count(&mailbox);
        let set = Tasks::new(1);
        let mut ready = Ready::default();
        let guard = DropCount(drops.clone());
        let task = insert(&set, &mut ready, &mailbox, async move {
            let _guard = guard;
            pending::<()>().await;
        });
        let waker = Waker::clone(&task.waker());
        assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));

        // Clear the future and remove the set's entry, leaving the caller's
        // reference and the cloned waker's.
        task.clear();
        retire(&set, task.clone());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(refs(&task), 2);

        // Release both references at once on different threads.
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
        let set = Tasks::new(1);
        let mut ready = Ready::default();
        let guard = DropCount(drops.clone());
        let task = insert(&set, &mut ready, &mailbox, async move {
            let _guard = guard;
        });
        let waker = Waker::clone(&task.waker());

        let AfterPoll::Retire(retired) = ready.pop().unwrap().poll() else {
            panic!("ready future must complete");
        };
        retire(&set, retired);
        drop(task);
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        // The waker holds the last reference, which its wake releases.
        waker.wake();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(Arc::weak_count(&mailbox), baseline);
    }

    /// Completion and teardown free the cell after containing a destructor panic.
    #[test]
    fn test_panicking_destructor_releases_the_cell() {
        for complete in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let mailbox = mailbox();
            let baseline = Arc::weak_count(&mailbox);
            let set = Tasks::new(1);
            let mut ready = Ready::default();
            let task = insert(
                &set,
                &mut ready,
                &mailbox,
                PanicsOnDrop {
                    complete,
                    drops: drops.clone(),
                },
            );
            let waker = Waker::clone(&task.waker());
            let outcome = ready.pop().unwrap().poll();

            if complete {
                // The ready future's destructor panics inside the poll.
                let AfterPoll::Retire(retired) = outcome else {
                    panic!("ready future must complete despite its destructor panic");
                };
                retire(&set, retired);
            } else {
                // Teardown clears the idle task and contains its destructor panic.
                assert!(matches!(outcome, AfterPoll::Done));
                for retired in set.teardown() {
                    assert!(Panics::contain(|| retired.clear()).is_none());
                }
            }

            // The future was dropped once, leaving the caller's and the
            // waker's references.
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(refs(&task), 2);
            drop(task);

            // The last waker frees a cell whose future has already been dropped.
            waker.wake();
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(Arc::weak_count(&mailbox), baseline);
        }
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
            let set = Tasks::new(1);
            let mut ready = Ready::default();
            let addresses = Arc::new(Mutex::new(Vec::new()));
            let task = insert(
                &set,
                &mut ready,
                &mailbox,
                OverAligned {
                    remaining: AtomicUsize::new(if complete { 3 } else { usize::MAX }),
                    addresses: addresses.clone(),
                    _pinned: PhantomPinned,
                },
            );

            // Two polls leave the task idle, and each wake queues it again.
            for _ in 0..2 {
                assert!(matches!(ready.pop().unwrap().poll(), AfterPoll::Done));
                task.wake_by_ref();
                ready.push(scheduled(&mailbox).pop().unwrap());
            }
            if complete {
                // The third poll completes the future, which drops in place.
                let AfterPoll::Retire(retired) = ready.pop().unwrap().poll() else {
                    panic!("the third poll must complete");
                };
                retire(&set, retired);
            } else {
                // Teardown drops the idle future in place.
                for retired in set.teardown() {
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

/// Loom models of the real task path, through cells, runnables, the waker
/// vtable, the mailbox, and the task set, then of the state word alone.
#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{
        AfterPending, AfterPoll, AfterWake, Mailbox, Message, Panics, REF_ONE, REFS, Runnable,
        State, Target, Task, Tasks,
    };
    use loom::{
        cell::UnsafeCell,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };
    use std::{
        future::{Future, poll_fn},
        task::{Poll, Waker},
    };

    /// References counted in `state`.
    fn refs(state: &State) -> usize {
        (state.0.load(Ordering::Acquire) & REFS) / REF_ONE
    }

    /// A live mailbox with no worker. Task headers hold a standard `Weak` to
    /// it.
    fn mailbox() -> std::sync::Arc<Mailbox> {
        std::sync::Arc::new(Mailbox::new().unwrap())
    }

    /// Counts the drops of a future's captured state.
    struct DropCount(Arc<AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A future that completes once `signal` is set, counting its drop.
    fn signaled(
        signal: Arc<AtomicBool>,
        drops: &Arc<AtomicUsize>,
    ) -> impl Future<Output = ()> + Send + 'static {
        let guard = DropCount(drops.clone());
        poll_fn(move |_| {
            let _ = &guard;
            if signal.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
    }

    /// A future that never completes, counting its drop.
    fn pending(drops: &Arc<AtomicUsize>) -> impl Future<Output = ()> + Send + 'static {
        signaled(Arc::new(AtomicBool::new(false)), drops)
    }

    /// Poll `runnable` as a worker does, polling again while wakes arrive
    /// during its polls, and remove the task from `set` once it completes.
    /// Returns whether it completed.
    fn run(set: &Tasks, runnable: Runnable) -> bool {
        let mut next = Some(runnable);
        while let Some(runnable) = next.take() {
            match runnable.poll() {
                AfterPoll::Done => {}
                AfterPoll::Requeue(runnable) => next = Some(runnable),
                AfterPoll::Retire(task) => {
                    drop(set.remove(&task));
                    return true;
                }
            }
        }
        false
    }

    /// The runnables among `messages`, which carry nothing else.
    fn runnables(messages: Vec<Message>) -> impl Iterator<Item = Runnable> {
        messages.into_iter().map(|message| match message {
            Message::Wake(Target::Task(runnable)) => runnable,
            _ => panic!("expected only runnables"),
        })
    }

    /// Tear down as a closing worker does: close the set, then the mailbox,
    /// discarding its queued runnables, then drain the set and clear each
    /// task.
    fn teardown(set: &Tasks, mailbox: &Mailbox) {
        set.close();
        for runnable in runnables(mailbox.close()) {
            runnable.discard();
        }
        for task in set.drain() {
            Panics::contain(|| task.clear());
        }
    }

    /// A foreign wake racing the poll path, by value or by reference, is never
    /// lost: the task completes in its first poll, in the poll its requeued
    /// runnable runs, or in the poll of the runnable the wake delivers through
    /// the mailbox. No reference leaks.
    #[test]
    fn test_foreign_wake_racing_the_poll_path_is_never_lost() {
        for by_value in [false, true] {
            loom::model(move || {
                let mailbox = mailbox();
                let set = Tasks::new(1);
                let signal = Arc::new(AtomicBool::new(false));
                let drops = Arc::new(AtomicUsize::new(0));
                let (task, runnable) = Task::new(
                    signaled(signal.clone(), &drops),
                    &set,
                    std::sync::Arc::downgrade(&mailbox),
                );
                assert!(set.insert(task.clone()).is_ok());
                let waker = Waker::clone(&task.waker());

                // Another thread signals the future and wakes it while this
                // one polls.
                let waking = thread::spawn(move || {
                    signal.store(true, Ordering::Release);
                    if by_value {
                        waker.wake();
                    } else {
                        waker.wake_by_ref();
                    }
                });
                let mut completed = run(&set, runnable);
                waking.join().unwrap();

                // A wake that found the task idle delivered a runnable.
                let mut delivered = Vec::new();
                mailbox.take(&mut delivered);
                for runnable in runnables(delivered) {
                    assert!(!completed, "a completed task received a runnable");
                    completed = run(&set, runnable);
                }
                assert!(completed, "wake lost");
                assert_eq!(drops.load(Ordering::Relaxed), 1);

                // Only this reference remains, and it frees the cell.
                assert_eq!(refs(&task.state), 1);
                drop(task);
                assert_eq!(std::sync::Arc::weak_count(&mailbox), 0);
            });
        }
    }

    /// Teardown racing a foreign wake drops the future once, whether the
    /// wake's runnable reaches the open mailbox or the closed one, or the wake
    /// finds the task already cleared. Whichever reference goes last frees
    /// the cell, the consuming waker's included.
    #[test]
    fn test_teardown_racing_a_foreign_wake_disposes_of_the_task_once() {
        loom::model(|| {
            let mailbox = mailbox();
            let set = Tasks::new(1);
            let drops = Arc::new(AtomicUsize::new(0));
            let (task, runnable) =
                Task::new(pending(&drops), &set, std::sync::Arc::downgrade(&mailbox));

            // The set takes the only `Task`, so the waker's reference can be
            // the last.
            let waker = Waker::clone(&task.waker());
            assert!(set.insert(task).is_ok());

            // The first poll leaves the task idle, so the wake publishes a
            // runnable unless teardown has already cleared the task.
            assert!(!run(&set, runnable));
            let waking = thread::spawn(move || waker.wake());
            teardown(&set, &mailbox);
            waking.join().unwrap();

            // Every reference is gone, so the cell freed its mailbox handle.
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(std::sync::Arc::weak_count(&mailbox), 0);
        });
    }

    /// A registration racing teardown disposes of its task once: the drain
    /// clears a task the set retained, wherever its first runnable is, and the
    /// caller clears a task the closed set refused. No reference leaks.
    #[test]
    fn test_registration_racing_teardown_disposes_of_the_task_once() {
        loom::model(|| {
            let mailbox = mailbox();
            let set = Arc::new(Tasks::new(1));
            let drops = Arc::new(AtomicUsize::new(0));
            let registering = thread::spawn({
                let set = set.clone();
                let mailbox = std::sync::Arc::downgrade(&mailbox);
                let future = pending(&drops);
                move || {
                    if let Err(task) = set.register(future, mailbox) {
                        task.clear();
                    }
                }
            });
            teardown(&set, &mailbox);
            registering.join().unwrap();

            // Every reference is gone, so the cell freed its mailbox handle.
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(std::sync::Arc::weak_count(&mailbox), 0);
        });
    }

    /// Teardown on another thread, racing the poll path of a task that wakes
    /// itself once, never touches the future during a poll and drops it once:
    /// the drain's clear when no poll runs, the poller when the clear finds
    /// its poll running, with or without a wake recorded. Only the set and the
    /// poller's runnable hold references, and whichever goes last frees the
    /// cell.
    #[test]
    fn test_teardown_racing_the_poll_path_drops_the_future_once() {
        loom::model(|| {
            let mailbox = mailbox();
            let set = Arc::new(Tasks::new(1));
            let drops = Arc::new(AtomicUsize::new(0));
            let guard = DropCount(drops.clone());
            let mut woken = false;
            let future = poll_fn(move |cx| {
                let _ = &guard;
                if !woken {
                    woken = true;
                    cx.waker().wake_by_ref();
                }
                Poll::<()>::Pending
            });
            let (task, runnable) = Task::new(future, &set, std::sync::Arc::downgrade(&mailbox));
            assert!(set.insert(task).is_ok());

            let tearing_down = thread::spawn({
                let set = set.clone();
                let mailbox = mailbox.clone();
                move || teardown(&set, &mailbox)
            });
            run(&set, runnable);
            tearing_down.join().unwrap();

            // Every reference is gone, so the cell freed its mailbox handle.
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(std::sync::Arc::weak_count(&mailbox), 0);
        });
    }

    /// A wake racing the end of a pending poll transfers exactly one runnable,
    /// regardless of which side wins the handoff.
    #[test]
    fn test_pending_wake_handoff_publishes_once() {
        loom::model(|| {
            let state = Arc::new(State::new());
            assert!(state.start_poll());

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || state.notify_by_ref()
            });
            let poll_publishes = matches!(state.finish_pending(), AfterPending::Requeue);
            let wake_publishes = wake.join().unwrap();

            assert_ne!(poll_publishes, wake_publishes);
            assert!(state.start_poll());
            state.complete();
        });
    }

    /// A wake that gives up its reference, racing the end of a pending poll,
    /// leaves exactly one runnable and the right count, whichever side wins.
    #[test]
    fn test_wake_by_value_racing_a_pending_poll_keeps_the_count() {
        loom::model(|| {
            // References: the polled runnable's, the set's, and the waker's.
            let state = Arc::new(State::new());
            state.retain();
            assert!(state.start_poll());

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || matches!(state.notify_by_value(), AfterWake::Schedule)
            });
            let requeued = matches!(state.finish_pending(), AfterPending::Requeue);
            let published = wake.join().unwrap();

            // One runnable remains, holding one reference beside the task
            // set's.
            assert_ne!(requeued, published);
            assert_eq!(refs(&state), 2);
        });
    }

    /// A wake racing a completing poll never publishes a runnable.
    #[test]
    fn test_ready_wake_handoff_never_publishes() {
        loom::model(|| {
            let state = Arc::new(State::new());
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
            let state = Arc::new(State::new());

            let other = thread::spawn({
                let state = Arc::clone(&state);
                move || state.release()
            });
            let mine = state.release();

            assert_ne!(mine, other.join().unwrap());
        });
    }

    /// A last consuming wake acquires writes published by an earlier release.
    #[test]
    fn test_completed_wake_racing_release_finds_one_last() {
        loom::model(|| {
            let state = Arc::new(State::new());
            assert!(state.start_poll());
            state.complete();
            let payload = Arc::new(AtomicUsize::new(0));

            let releaser = thread::spawn({
                let state = Arc::clone(&state);
                let payload = Arc::clone(&payload);
                move || {
                    payload.store(1, Ordering::Relaxed);
                    state.release()
                }
            });

            let wake_was_last = match state.notify_by_value() {
                AfterWake::Dealloc => {
                    // Check before joining so only the wake can acquire the write.
                    assert_eq!(payload.load(Ordering::Relaxed), 1);
                    true
                }
                AfterWake::Done => false,
                AfterWake::Schedule => panic!("completed task cannot be scheduled"),
            };
            let release_was_last = releaser.join().unwrap();

            assert_ne!(wake_was_last, release_was_last);
            assert_eq!(refs(&state), 0);
        });
    }

    /// Teardown racing a poll never touches the future while the poller does,
    /// and exactly one of them drops it: the poller if the clear saw the poll
    /// running, the clear otherwise.
    #[test]
    fn test_clear_racing_a_poll_drops_the_future_once() {
        loom::model(|| {
            let state = Arc::new(State::new());
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
                        AfterPending::Done => {}
                        AfterPending::Complete => {
                            state.complete();

                            // SAFETY: exclusive access continues past
                            // `complete`.
                            future.with_mut(|value| unsafe { *value = usize::MAX });
                            drops.fetch_add(1, Ordering::Relaxed);
                        }
                        AfterPending::Requeue => unreachable!("no wake was issued"),
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

    /// A wake racing teardown of an idle task leaves no runnable that can poll
    /// it.
    #[test]
    fn test_wake_racing_clear_of_an_idle_task_leaves_nothing_to_poll() {
        loom::model(|| {
            let state = Arc::new(State::new());
            assert!(state.start_poll());
            assert!(matches!(state.finish_pending(), AfterPending::Done));

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
            let state = Arc::new(State::new());
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
                        // its wake published no runnable.
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
