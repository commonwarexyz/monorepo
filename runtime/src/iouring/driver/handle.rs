//! Thread-affine op submission for the io_uring runtime.
//!
//! The [Handle] is the shared half of the driver: the waiter slab, the
//! staged/cancel queues, and the capacity wait list reached by op futures
//! and by the event loop that services them (see [super::Driver]). The
//! runtime traits force [crate::Blob], [crate::Sink], and [crate::Stream] to
//! be `Send + Sync` and op futures to be `Send`, so they reach this state
//! through an [Affine] cell that pins every access to the loop thread instead
//! of through locks: submissions and completions are single-threaded by
//! construction, and the compiler-visible `Sync` is backed by a runtime
//! thread assert.
//!
//! Op futures ([Op]) stage requests by inserting into the slab and pushing
//! onto the staged queue during `poll`. The loop builds and submits SQEs in
//! its own turn, parks terminal results in the slot, and wakes the stored
//! task waker. Dropping an op future orphans its slot: cancelable kinds are
//! async-cancelled eagerly, while storage writes and syncs detach and keep
//! running for durability parity with the tokio backend. Dropping an admitted
//! op future or a [Ticket] (including one held inside a front-end object such
//! as a listener) on a foreign thread cannot touch the table directly (drop
//! must not panic, so the affinity check cannot reject it); it is routed
//! through the [OrphanMailbox] and wound down by the loop on its next turn.
//! Ring-bound resources may therefore be dropped from any thread, even
//! though they must only be used on their owning worker.

use super::{
    Tick,
    request::{
        AcceptRequest, ConnectRequest, Output, RawSocketAddr, ReadAtRequest, RecvRequest, Request,
        SendRequest, SyncRequest, WriteAtRequest,
    },
    waiter::{DropOutcome, WaiterId, Waiters},
    waker::Waker as RingWaker,
};
use crate::{Error, IoBufMut, IoBufs};
use commonware_utils::sync::Mutex;
use std::{
    cell::RefCell,
    collections::VecDeque,
    fs::File,
    future::Future,
    net::SocketAddr,
    os::fd::OwnedFd,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    thread::{self, ThreadId},
    time::Instant,
};

/// Cell whose contents are only accessible from the thread that created it.
///
/// The affinity assert makes the cell shareable (`Sync`) without any lock:
/// cross-thread access fails loudly instead of racing.
pub(crate) struct Affine<T> {
    owner: ThreadId,
    cell: T,
}

// SAFETY: `cell` is only ever accessed through `with`/`try_with`, which
// require the calling thread to be `owner`, so no concurrent access to the
// contents can occur. `T: Send` keeps the final drop (which may happen on
// whichever thread releases the last reference) sound.
unsafe impl<T: Send> Sync for Affine<T> {}

impl<T> Affine<T> {
    /// Wrap `cell`, pinning access to the calling thread.
    pub(crate) fn new(cell: T) -> Self {
        Self::pinned(thread::current().id(), cell)
    }

    /// Wrap `cell`, pinning access to `owner`.
    ///
    /// Used when the cell is built away from its owning thread (e.g. a task
    /// registered from another thread but polled only on its worker). Handing
    /// the contents to `owner` is an ordinary `Send` transfer, which the auto
    /// `Send` bound on `Affine<T>` already requires.
    pub(crate) const fn pinned(owner: ThreadId, cell: T) -> Self {
        Self { owner, cell }
    }

    /// Access the contents from the owning thread.
    ///
    /// Panics when called from any other thread.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        assert!(
            thread::current().id() == self.owner,
            "io_uring runtime operations must run on the runtime thread"
        );
        f(&self.cell)
    }

    /// Access the contents if the calling thread is the owner.
    ///
    /// Returns `None` off-thread. Used on drop paths, which must not panic.
    fn try_with<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        (thread::current().id() == self.owner).then(|| f(&self.cell))
    }
}

/// The in-flight op table shared between futures and the event loop.
pub(crate) struct Ops {
    /// Slot table tracking every admitted logical request. Slots own all
    /// operation resources (buffers, FDs) for the request lifetime.
    pub(super) waiters: Waiters,
    /// Waiter ids whose next SQE the loop must build, in FIFO order. Fresh
    /// admissions and requeued partial operations share this queue.
    pub(super) staged: VecDeque<WaiterId>,
    /// Waiter ids needing an async-cancel SQE.
    pub(super) pending_cancels: VecDeque<WaiterId>,
    /// Wheel ticks released by dropped tickets, awaiting removal by the loop
    /// (the timeout wheel is loop-owned, so drop paths cannot touch it).
    pub(super) released_deadlines: Vec<Tick>,
    /// Tasks waiting for a free waiter slot, woken all at once whenever a
    /// slot frees (a woken future re-registers if it loses the race).
    pub(super) capacity: CapacityWaiters,
    /// Set at teardown: admission fails with the kind-specific error.
    pub(super) closed: bool,
}

/// The capacity wait list: tasks parked until a waiter slot frees.
///
/// Registrations live in a slot arena (with a free list, so cancellation
/// under a saturated ring reuses slots instead of growing the arena) and are
/// epoch-tagged: [Self::drain] wakes every waiter and bumps the epoch,
/// invalidating all outstanding registrations at once. Each admission holds
/// at most one slot — re-polls refresh the stored waker in place — and
/// cancellation clears the slot immediately, so a long-saturated ring
/// retains no wakers for admissions that no longer exist.
pub(super) struct CapacityWaiters {
    /// Slot arena; `None` entries are cancelled registrations awaiting reuse.
    slots: Vec<Option<Waker>>,
    /// Indices of `None` entries in `slots`.
    free: Vec<usize>,
    /// Bumped by every drain: a [CapacitySlot] from an older epoch is no
    /// longer registered (its waker was already woken and discarded).
    epoch: u64,
}

/// One admission attempt's registration in [CapacityWaiters].
struct CapacitySlot {
    epoch: u64,
    index: usize,
}

impl CapacityWaiters {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            epoch: 0,
        }
    }

    /// Register an admission attempt, or refresh its waker in place when it
    /// already holds a live slot.
    fn register(&mut self, registration: &mut Option<CapacitySlot>, waker: &Waker) {
        if let Some(slot) = registration
            && slot.epoch == self.epoch
        {
            self.slots[slot.index]
                .as_mut()
                .expect("registered capacity slot missing its waker")
                .clone_from(waker);
            return;
        }
        // First registration, or the previous one was invalidated by a drain.
        let index = match self.free.pop() {
            Some(index) => {
                self.slots[index] = Some(waker.clone());
                index
            }
            None => {
                self.slots.push(Some(waker.clone()));
                self.slots.len() - 1
            }
        };
        *registration = Some(CapacitySlot {
            epoch: self.epoch,
            index,
        });
    }

    /// Cancel a registration whose admission attempt no longer exists,
    /// releasing its waker and recycling the slot.
    fn cancel(&mut self, registration: CapacitySlot) {
        if registration.epoch != self.epoch {
            return;
        }
        let waker = self.slots[registration.index].take();
        assert!(waker.is_some(), "capacity slot cancelled twice");
        self.free.push(registration.index);
    }

    /// Release every waiter for the caller to wake, invalidating all
    /// outstanding registrations (woken futures re-register if they lose the
    /// admission race).
    ///
    /// This is the only wake-all path: every slot-free and close site funnels
    /// through it, so the epoch advances in exactly one place.
    pub(super) fn drain_into(&mut self, wakers: &mut Vec<Waker>) {
        self.epoch = self
            .epoch
            .checked_add(1)
            .expect("capacity epoch overflowed");
        self.free.clear();
        wakers.extend(self.slots.drain(..).flatten());
    }

    /// [Self::drain_into] into a fresh vector.
    fn drain(&mut self) -> Vec<Waker> {
        let mut wakers = Vec::new();
        self.drain_into(&mut wakers);
        wakers
    }

    /// Number of live registrations.
    #[cfg(test)]
    pub(super) fn registered(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Size of the slot arena, including recyclable entries.
    #[cfg(test)]
    pub(super) const fn arena_len(&self) -> usize {
        self.slots.len()
    }
}

/// RAII registration of one admission attempt on the capacity wait list.
///
/// The slot is cleared on admission or closed-driver resolution (inside the
/// admission poll) and cancelled when the attempt is dropped while parked. A
/// foreign-thread drop cannot clear its slot (drop must not panic); the entry
/// is discarded by the next drain, consistent with the documented policy that
/// op futures must not move to other threads.
struct Registration<'a> {
    handle: &'a Handle,
    slot: Option<CapacitySlot>,
}

impl<'a> Registration<'a> {
    const fn new(handle: &'a Handle) -> Self {
        Self { handle, slot: None }
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        let _ = self.handle.try_with(|ops| ops.capacity.cancel(slot));
    }
}

/// Thread-affine handle to the driver's op state, cloned by the network and
/// storage front-ends and held by the event loop itself.
///
/// All access goes through the affinity-checked [Affine] cell.
#[derive(Clone)]
pub(crate) struct Handle {
    ops: Arc<Affine<RefCell<Ops>>>,
    /// Cross-thread wind-down mailbox for foreign-thread drops.
    pub(super) orphans: Arc<OrphanMailbox>,
}

/// Waiter ids whose owning future or ticket was dropped on a foreign thread,
/// where the thread-affine op table is unreachable.
///
/// Drop is the one op interaction that can legally arrive off-thread (drop
/// must not panic, so the affinity check cannot reject it). Ids pushed here
/// are wound down by the loop on its next turn exactly as an on-thread drop
/// would have been, so foreign drops release their slots instead of leaking
/// them until shutdown.
pub(super) struct OrphanMailbox {
    /// Fast-path gate so the loop's per-turn drain skips the lock when the
    /// mailbox is empty (the common case).
    pending: AtomicBool,
    ids: Mutex<Vec<WaiterId>>,
    /// Wakes the loop so a parked runtime winds the orphan down promptly.
    waker: RingWaker,
}

impl OrphanMailbox {
    fn push(&self, id: WaiterId) {
        self.ids.lock().push(id);
        self.pending.store(true, Ordering::Release);
        self.waker.wake();
    }

    /// Take all pending foreign-drop ids.
    ///
    /// A push racing the gate check lands on the next turn: its `wake` latch
    /// guarantees the loop runs again before parking indefinitely.
    pub(super) fn take(&self) -> Vec<WaiterId> {
        if !self.pending.load(Ordering::Acquire) {
            return Vec::new();
        }
        self.pending.store(false, Ordering::Relaxed);
        std::mem::take(&mut *self.ids.lock())
    }
}

impl Handle {
    /// Create the op state for a driver whose slab tracks at most `capacity`
    /// requests, waking the loop through `waker` for foreign-thread drops.
    ///
    /// The calling thread becomes the owning (runtime) thread.
    pub(crate) fn new(capacity: usize, waker: RingWaker) -> Self {
        Self {
            ops: Arc::new(Affine::new(RefCell::new(Ops {
                waiters: Waiters::new(capacity),
                staged: VecDeque::with_capacity(capacity),
                pending_cancels: VecDeque::with_capacity(capacity),
                released_deadlines: Vec::new(),
                capacity: CapacityWaiters::new(),
                closed: false,
            }))),
            orphans: Arc::new(OrphanMailbox {
                pending: AtomicBool::new(false),
                ids: Mutex::new(Vec::new()),
                waker,
            }),
        }
    }

    /// Access the shared op state from the runtime thread.
    ///
    /// The borrow is a leaf section: callers must not invoke wakers or user
    /// code inside `f`.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Ops) -> R) -> R {
        self.ops.with(|cell| f(&mut cell.borrow_mut()))
    }

    /// Access the shared op state if called on the runtime thread.
    fn try_with<R>(&self, f: impl FnOnce(&mut Ops) -> R) -> Option<R> {
        self.ops.try_with(|cell| f(&mut cell.borrow_mut()))
    }

    /// Close the op state: subsequent admissions fail with their
    /// kind-specific error. Returns the capacity waiters so the caller can wake them
    /// outside the borrow.
    pub(crate) fn close(&self) -> Vec<Waker> {
        self.with(|ops| {
            ops.closed = true;
            ops.capacity.drain()
        })
    }

    /// Submit a logical send request and wait for its completion.
    pub(crate) async fn send(
        &self,
        fd: Arc<OwnedFd>,
        bufs: IoBufs,
        deadline: Instant,
    ) -> Result<(), Error> {
        let request = Request::Send(SendRequest {
            fd,
            write: bufs.into(),
            deadline: Some(deadline),
        });
        match Op::new(self, request).await {
            Output::Send(result) => result.map_err(|e| *e),
            _ => unreachable!("send op produced foreign output"),
        }
    }

    /// Submit a logical recv request and wait for its completion.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn recv(
        &self,
        fd: Arc<OwnedFd>,
        buf: IoBufMut,
        offset: usize,
        len: usize,
        exact: bool,
        deadline: Instant,
    ) -> Result<(IoBufMut, usize), (IoBufMut, Error)> {
        assert!(
            offset <= len && len <= buf.capacity(),
            "recv invariant violated: need offset <= len <= capacity"
        );
        let request = Request::Recv(RecvRequest {
            fd,
            buf,
            offset,
            len,
            exact,
            deadline: Some(deadline),
        });
        match Op::new(self, request).await {
            Output::Recv(result) => result.map_err(|e| *e),
            _ => unreachable!("recv op produced foreign output"),
        }
    }

    /// Begin a logical accept request, returning the completion ticket
    /// without waiting.
    ///
    /// Admission applies the same backpressure as every other request. The
    /// returned ticket resolves once a connection is accepted, the deadline
    /// expires, or the accept fails. Callers should treat [Error::Timeout] as
    /// a cue to issue a fresh accept: the deadline exists so an abandoned
    /// accept cannot occupy a waiter slot forever.
    pub(crate) async fn start_accept(&self, fd: Arc<OwnedFd>, deadline: Instant) -> AcceptTicket {
        let request = Request::Accept(AcceptRequest {
            fd,
            addr: RawSocketAddr::zeroed(),
            deadline: Some(deadline),
        });
        AcceptTicket(Ticket::admit(self, request).await)
    }

    /// Submit a logical connect request and wait for its completion.
    pub(crate) async fn connect(
        &self,
        fd: Arc<OwnedFd>,
        addr: SocketAddr,
        deadline: Instant,
    ) -> Result<(), Error> {
        let request = Request::Connect(ConnectRequest {
            fd,
            addr: RawSocketAddr::boxed_from_socket_addr(&addr),
            deadline: Some(deadline),
        });
        match Op::new(self, request).await {
            Output::Connect(result) => result.map_err(|e| *e),
            _ => unreachable!("connect op produced foreign output"),
        }
    }

    /// Submit a logical positioned read request and wait for its completion.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn read_at(
        &self,
        file: Arc<File>,
        offset: u64,
        len: usize,
        buf: IoBufMut,
    ) -> Result<IoBufMut, (IoBufMut, Error)> {
        assert!(len <= buf.capacity(), "read_at len exceeds buffer capacity");
        let request = Request::ReadAt(ReadAtRequest {
            file,
            offset,
            len,
            read: 0,
            buf,
        });
        match Op::new(self, request).await {
            Output::ReadAt(result) => result.map_err(|e| *e),
            _ => unreachable!("read_at op produced foreign output"),
        }
    }

    /// Submit a logical positioned write request and wait for its completion.
    pub(crate) async fn write_at(
        &self,
        file: Arc<File>,
        offset: u64,
        bufs: IoBufs,
    ) -> Result<(), Error> {
        self.write_at_inner(file, offset, bufs, false).await
    }

    /// Submit a logical positioned write with per-write sync and wait for its
    /// completion.
    ///
    /// The kernel executes `RWF_SYNC` writes on its io-wq pool, which
    /// serializes work per inode: concurrent synced writes to one file run
    /// one at a time. Callers needing concurrent durable writes to a single
    /// blob should prefer [Self::write_at] followed by [Self::sync].
    pub(crate) async fn write_at_sync(
        &self,
        file: Arc<File>,
        offset: u64,
        bufs: IoBufs,
    ) -> Result<(), Error> {
        self.write_at_inner(file, offset, bufs, true).await
    }

    async fn write_at_inner(
        &self,
        file: Arc<File>,
        offset: u64,
        bufs: IoBufs,
        sync: bool,
    ) -> Result<(), Error> {
        let request = Request::WriteAt(WriteAtRequest {
            file,
            offset,
            written: 0,
            write: bufs.into(),
            sync,
        });
        match Op::new(self, request).await {
            Output::WriteAt(result) => result.map_err(|e| *e),
            _ => unreachable!("write_at op produced foreign output"),
        }
    }

    /// Submit a logical fsync request and wait for its completion.
    pub(crate) async fn sync(&self, file: Arc<File>) -> Result<(), Error> {
        self.start_sync(file).await.await
    }

    /// Begin a logical fsync request, returning the completion ticket without
    /// waiting.
    ///
    /// Admission applies the same backpressure as every other request. The
    /// returned ticket resolves once the fsync completes.
    pub(crate) async fn start_sync(&self, file: Arc<File>) -> SyncTicket {
        let request = Request::Sync(SyncRequest { file });
        SyncTicket(Ticket::admit(self, request).await)
    }
}

/// Poll one admission attempt for `request`.
///
/// On a closed driver the request resolves immediately to its kind-specific
/// failure (returned as `Err`). On a full slab the task parks on the capacity
/// wait list through `registration` (one slot per attempt, refreshed on
/// re-polls and released here once the attempt resolves). Otherwise the
/// request is admitted: the slab owns it (along with the task waker) and its
/// id is pushed onto the staged queue for the loop.
fn poll_admission(
    handle: &Handle,
    request: &mut Option<Request>,
    registration: &mut Registration<'_>,
    cx: &mut Context<'_>,
) -> Poll<Result<WaiterId, Output>> {
    let outcome = handle.with(|ops| {
        if ops.closed {
            if let Some(slot) = registration.slot.take() {
                ops.capacity.cancel(slot);
            }
            return Admission::Closed;
        }
        if ops.waiters.is_full() {
            ops.capacity.register(&mut registration.slot, cx.waker());
            return Admission::Full;
        }
        if let Some(slot) = registration.slot.take() {
            ops.capacity.cancel(slot);
        }
        let request = request.take().expect("request consumed before admission");
        let id = ops.waiters.insert(request, cx.waker().clone());
        ops.staged.push_back(id);
        Admission::Admitted(id)
    });
    match outcome {
        Admission::Admitted(id) => Poll::Ready(Ok(id)),
        Admission::Full => Poll::Pending,
        Admission::Closed => {
            let request = request.take().expect("request lost on closed driver");
            Poll::Ready(Err(request.fail()))
        }
    }
}

/// Poll for the parked result of an admitted request.
///
/// Taking a result frees a slot, so capacity waiters are released (outside
/// the state borrow). A pending poll refreshes the stored task waker.
fn poll_completion(handle: &Handle, id: WaiterId, cx: &mut Context<'_>) -> Poll<Output> {
    let (output, wakers) = handle.with(|ops| {
        let output = ops.waiters.poll_take(id, cx.waker());
        let wakers = if output.is_some() {
            ops.capacity.drain()
        } else {
            Vec::new()
        };
        (output, wakers)
    });
    for waker in wakers {
        waker.wake();
    }
    output.map_or(Poll::Pending, Poll::Ready)
}

/// Apply the orphan wind-down for `id` on the op table.
///
/// Returns true when a slot was freed (the caller releases capacity waiters
/// through its own wake path).
pub(super) fn wind_down_orphan(ops: &mut Ops, id: WaiterId) -> bool {
    match ops.waiters.mark_orphaned(id) {
        // A parked result was dropped, freeing a slot.
        DropOutcome::Freed => true,
        DropOutcome::Cancel {
            needs_sqe,
            target_tick,
        } => {
            if needs_sqe {
                ops.pending_cancels.push_back(id);
            }
            // Release deadline accounting for the transition out of active
            // timeout tracking.
            ops.released_deadlines.extend(target_tick);
            false
        }
        DropOutcome::Detached => false,
    }
}

/// Wind down an admitted request whose future or ticket is being dropped.
///
/// Drop must not panic, so a foreign-thread drop cannot touch the
/// thread-affine table directly: it hands the id to the loop through the
/// orphan mailbox instead, and the loop applies the same wind-down on its
/// next turn.
fn orphan(handle: &Handle, id: WaiterId) {
    let Some(wakers) = handle.try_with(|ops| {
        if wind_down_orphan(ops, id) {
            ops.capacity.drain()
        } else {
            Vec::new()
        }
    }) else {
        handle.orphans.push(id);
        return;
    };
    for waker in wakers {
        waker.wake();
    }
}

/// Outcome of one admission attempt.
enum Admission {
    Admitted(WaiterId),
    Full,
    Closed,
}

/// Progress state of an op future.
///
/// The queued request rides inside the future until admission (boxing it
/// would put an allocation on the op hot path), so the variant sizes
/// legitimately diverge. The option is always `Some` while queued: it exists
/// so admission can move the request out in place instead of round-tripping
/// the whole state through a stack temporary on every poll.
#[allow(clippy::large_enum_variant)]
enum OpState {
    /// Not yet admitted: the future still owns the request and its buffers.
    Queued(Option<Request>),
    /// Admitted: the slot owns the request, the future holds the reservation.
    Waiting(WaiterId),
    /// The output was delivered.
    Done,
}

/// Future driving one logical request through admission and completion.
///
/// Borrows the driver from its front-end, so the hot path carries no
/// refcount traffic. Dropping the future before completion orphans the slot;
/// see the module docs for the wind-down rules.
#[must_use]
struct Op<'a> {
    handle: &'a Handle,
    state: OpState,
    /// Capacity wait-list registration while queued on a full slab; released
    /// on admission or by drop (via its RAII guard).
    registration: Registration<'a>,
}

impl<'a> Op<'a> {
    const fn new(handle: &'a Handle, request: Request) -> Self {
        Self {
            handle,
            state: OpState::Queued(Some(request)),
            registration: Registration::new(handle),
        }
    }
}

impl Future for Op<'_> {
    type Output = Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Output> {
        let this = self.get_mut();
        match &mut this.state {
            OpState::Queued(request) => {
                match poll_admission(this.handle, request, &mut this.registration, cx) {
                    // Completion cannot be ready before the loop's next turn,
                    // so an admitted op always returns pending here.
                    Poll::Ready(Ok(id)) => {
                        this.state = OpState::Waiting(id);
                        Poll::Pending
                    }
                    Poll::Ready(Err(output)) => {
                        this.state = OpState::Done;
                        Poll::Ready(output)
                    }
                    // A full slab leaves the request in place: no bytes move.
                    Poll::Pending => Poll::Pending,
                }
            }
            OpState::Waiting(id) => {
                let output = std::task::ready!(poll_completion(this.handle, *id, cx));
                this.state = OpState::Done;
                Poll::Ready(output)
            }
            OpState::Done => panic!("io_uring op polled after completion"),
        }
    }
}

impl Drop for Op<'_> {
    fn drop(&mut self) {
        // Queued: the request (and its buffers) drops with the future, nothing
        // reached the loop or the kernel. Done: nothing to release.
        if let OpState::Waiting(id) = self.state {
            orphan(self.handle, id);
        }
    }
}

/// State of a detached ticket.
///
/// Unlike [OpState] this never holds a [Request]: tickets are only built
/// after admission, which keeps them `Sync` (requests own iovec scratch
/// pointers) so the front-ends that retain them stay `Sync`.
enum TicketState {
    /// Admitted: the slot owns the request, the ticket holds the reservation.
    Waiting(WaiterId),
    /// Admission failed on a closed driver: the failure output is parked
    /// locally for the next poll.
    Failed(Option<Output>),
    /// The output was delivered.
    Done,
}

/// Detached completion handle for an admitted request.
///
/// Owns a driver clone so it can outlive its front-end call. Dropping the
/// ticket orphans the slot.
struct Ticket {
    handle: Handle,
    state: TicketState,
}

impl Ticket {
    /// Admit `request`, parking on slab capacity, and return the reservation.
    async fn admit(handle: &Handle, request: Request) -> Self {
        let mut request = Some(request);
        // The guard lives outside the poll closure so cancelling this future
        // while parked releases its capacity slot.
        let mut registration = Registration::new(handle);
        let state = std::future::poll_fn(|cx| {
            poll_admission(handle, &mut request, &mut registration, cx).map(|admitted| {
                match admitted {
                    Ok(id) => TicketState::Waiting(id),
                    Err(output) => TicketState::Failed(Some(output)),
                }
            })
        })
        .await;
        Self {
            handle: handle.clone(),
            state,
        }
    }
}

impl Future for Ticket {
    type Output = Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Output> {
        let this = self.get_mut();
        match &mut this.state {
            TicketState::Waiting(id) => {
                let output = std::task::ready!(poll_completion(&this.handle, *id, cx));
                this.state = TicketState::Done;
                Poll::Ready(output)
            }
            TicketState::Failed(output) => {
                let output = output.take().expect("failed ticket already delivered");
                this.state = TicketState::Done;
                Poll::Ready(output)
            }
            TicketState::Done => panic!("io_uring ticket polled after completion"),
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let TicketState::Waiting(id) = self.state {
            orphan(&self.handle, id);
        }
    }
}

/// Detached completion handle for an admitted accept.
///
/// Retained by the listener so a cancelled accept future resumes the same
/// admitted accept instead of losing a connection. Dropping the ticket
/// orphans the slot (closing an accepted connection nobody will take).
#[must_use]
pub(crate) struct AcceptTicket(Ticket);

impl Future for AcceptTicket {
    type Output = Result<(OwnedFd, SocketAddr), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match std::task::ready!(Pin::new(&mut self.0).poll(cx)) {
            Output::Accept(result) => Poll::Ready(result.map_err(|e| *e)),
            _ => unreachable!("accept op produced foreign output"),
        }
    }
}

/// Detached completion handle for an admitted fsync.
#[must_use]
pub(crate) struct SyncTicket(Ticket);

impl Future for SyncTicket {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match std::task::ready!(Pin::new(&mut self.0).poll(cx)) {
            Output::Sync(result) => Poll::Ready(result.map_err(|e| *e)),
            _ => unreachable!("sync op produced foreign output"),
        }
    }
}
