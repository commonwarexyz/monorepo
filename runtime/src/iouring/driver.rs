//! Thread-affine op submission for the io_uring runtime.
//!
//! The [Driver] holds the state shared between op futures and the event loop:
//! the waiter slab, the staged/cancel queues, and the capacity wait list. The
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
//! op future on a foreign thread cannot be rejected (drop must not panic), so
//! it leaks the slot until shutdown; this is reachable only by deliberately
//! moving an already-polled future to a raw thread.

use super::{
    Tick,
    request::{
        AcceptRequest, ConnectRequest, Output, RawSocketAddr, ReadAtRequest, RecvRequest, Request,
        SendRequest, SyncRequest, WriteAtRequest,
    },
    waiter::{DropOutcome, WaiterId, Waiters},
};
use crate::{Error, IoBufMut, IoBufs};
use std::{
    cell::RefCell,
    collections::VecDeque,
    fs::File,
    future::Future,
    net::SocketAddr,
    os::fd::OwnedFd,
    pin::Pin,
    sync::Arc,
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
        Self {
            owner: thread::current().id(),
            cell,
        }
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

/// Op state shared between futures and the event loop.
pub(crate) struct Shared {
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
    pub(super) capacity: Vec<Waker>,
    /// Set at teardown: admission fails with the kind-specific error.
    pub(super) closed: bool,
}

/// Thread-affine handle to the loop's op state.
///
/// Held by the network and storage front-ends (via `Arc`) and by the event
/// loop itself. All access goes through the affinity-checked [Affine] cell.
pub(crate) struct Driver {
    shared: Affine<RefCell<Shared>>,
}

impl Driver {
    /// Create a driver whose slab tracks at most `capacity` requests.
    ///
    /// The calling thread becomes the owning (runtime) thread.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            shared: Affine::new(RefCell::new(Shared {
                waiters: Waiters::new(capacity),
                staged: VecDeque::with_capacity(capacity),
                pending_cancels: VecDeque::with_capacity(capacity),
                released_deadlines: Vec::new(),
                capacity: Vec::new(),
                closed: false,
            })),
        }
    }

    /// Access the shared op state from the runtime thread.
    ///
    /// The borrow is a leaf section: callers must not invoke wakers or user
    /// code inside `f`.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Shared) -> R) -> R {
        self.shared.with(|cell| f(&mut cell.borrow_mut()))
    }

    /// Access the shared op state if called on the runtime thread.
    fn try_with<R>(&self, f: impl FnOnce(&mut Shared) -> R) -> Option<R> {
        self.shared.try_with(|cell| f(&mut cell.borrow_mut()))
    }

    /// Close the driver: subsequent admissions fail with their kind-specific
    /// error. Returns the capacity waiters so the caller can wake them
    /// outside the borrow.
    pub(crate) fn close(&self) -> Vec<Waker> {
        self.with(|shared| {
            shared.closed = true;
            std::mem::take(&mut shared.capacity)
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
    pub(crate) async fn start_accept(
        self: &Arc<Self>,
        fd: Arc<OwnedFd>,
        deadline: Instant,
    ) -> AcceptTicket {
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
    pub(crate) async fn sync(self: &Arc<Self>, file: Arc<File>) -> Result<(), Error> {
        self.start_sync(file).await.await
    }

    /// Begin a logical fsync request, returning the completion ticket without
    /// waiting.
    ///
    /// Admission applies the same backpressure as every other request. The
    /// returned ticket resolves once the fsync completes.
    pub(crate) async fn start_sync(self: &Arc<Self>, file: Arc<File>) -> SyncTicket {
        let request = Request::Sync(SyncRequest { file });
        SyncTicket(Ticket::admit(self, request).await)
    }
}

/// Poll one admission attempt for `request`.
///
/// On a closed driver the request resolves immediately to its kind-specific
/// failure (returned as `Err`). On a full slab the task parks on the capacity
/// wait list. Otherwise the request is admitted: the slab owns it (along with
/// the task waker) and its id is pushed onto the staged queue for the loop.
fn poll_admission(
    driver: &Driver,
    request: &mut Option<Request>,
    cx: &mut Context<'_>,
) -> Poll<Result<WaiterId, Output>> {
    let outcome = driver.with(|shared| {
        if shared.closed {
            return Admission::Closed;
        }
        if shared.waiters.is_full() {
            shared.capacity.push(cx.waker().clone());
            return Admission::Full;
        }
        let request = request.take().expect("request consumed before admission");
        let id = shared.waiters.insert(request, cx.waker().clone());
        shared.staged.push_back(id);
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
fn poll_completion(driver: &Driver, id: WaiterId, cx: &mut Context<'_>) -> Poll<Output> {
    let (output, wakers) = driver.with(|shared| {
        let output = shared.waiters.poll_take(id, cx.waker());
        let wakers = if output.is_some() {
            std::mem::take(&mut shared.capacity)
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

/// Wind down an admitted request whose future or ticket is being dropped.
///
/// Drop must not panic, so a foreign-thread drop cannot be rejected: the slot
/// simply leaks until shutdown (drain force-cancels it). This is reachable
/// only by moving an already-polled op future to a raw thread, which nothing
/// in the workspace does.
fn orphan(driver: &Driver, id: WaiterId) {
    let wakers = driver.try_with(|shared| {
        match shared.waiters.mark_orphaned(id) {
            // A parked result was dropped, freeing a slot.
            DropOutcome::Freed => std::mem::take(&mut shared.capacity),
            DropOutcome::Cancel {
                needs_sqe,
                target_tick,
            } => {
                if needs_sqe {
                    shared.pending_cancels.push_back(id);
                }
                // Release deadline accounting for the transition out of
                // active timeout tracking.
                shared.released_deadlines.extend(target_tick);
                Vec::new()
            }
            DropOutcome::Detached => Vec::new(),
        }
    });
    for waker in wakers.into_iter().flatten() {
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
    driver: &'a Driver,
    state: OpState,
}

impl<'a> Op<'a> {
    const fn new(driver: &'a Driver, request: Request) -> Self {
        Self {
            driver,
            state: OpState::Queued(Some(request)),
        }
    }
}

impl Future for Op<'_> {
    type Output = Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Output> {
        let this = self.get_mut();
        match &mut this.state {
            OpState::Queued(request) => {
                match poll_admission(this.driver, request, cx) {
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
                let output = std::task::ready!(poll_completion(this.driver, *id, cx));
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
            orphan(self.driver, id);
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
    driver: Arc<Driver>,
    state: TicketState,
}

impl Ticket {
    /// Admit `request`, parking on slab capacity, and return the reservation.
    async fn admit(driver: &Arc<Driver>, request: Request) -> Self {
        let mut request = Some(request);
        let state = std::future::poll_fn(|cx| {
            poll_admission(driver, &mut request, cx).map(|admitted| match admitted {
                Ok(id) => TicketState::Waiting(id),
                Err(output) => TicketState::Failed(Some(output)),
            })
        })
        .await;
        Self {
            driver: Arc::clone(driver),
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
                let output = std::task::ready!(poll_completion(&this.driver, *id, cx));
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
            orphan(&self.driver, id);
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
