//! Linux native AIO on a few long-lived read lanes.
//!
//! A lane is a thread that owns one AIO context and one aligned staging slab for the life of the
//! process. It keeps up to [NR_EVENTS] `O_DIRECT` reads in flight, issuing more as completions
//! land, and takes reads in turn from every batch queued on it, so a small batch never waits for
//! a large one to finish. [`read_many`] splits a batch across lanes with one channel send each,
//! so the caller pays no blocking-pool task per batch and the device sees the reads at once.

use super::*;
use crate::{BLOB_PAGE_SIZE, BufMut as _, IoBufMut, buffer::paged, utils::page_pool};
use commonware_utils::NZUsize;
use futures::stream::{self, BoxStream};
use std::{
    collections::VecDeque, num::NonZeroUsize, os::unix::fs::OpenOptionsExt as _,
    sync::atomic::AtomicUsize,
};

/// The `nr_events` each lane's AIO context is created with (`io_setup`), and so the most reads
/// one lane keeps in flight.
///
/// One context's worth is one device queue's worth of reads: NVMe queues hold 256 to 1024
/// commands, and a queue depth of 256 saturates the devices this runtime targets.
const NR_EVENTS: usize = 256;

/// Requests (iocbs) issued per `io_submit` call before the completions that have landed are
/// reaped.
///
/// The kernel spends about 2 us issuing each direct read, so issuing a whole context's worth
/// in one call takes longer than one read takes to complete. Reaping between calls lets the
/// earliest completions reach the stream while the rest are still being issued, at the cost
/// of one non-blocking `io_getevents` per call. Much smaller calls pay more in per-call
/// overhead than they return.
const IOCBS_PER_SUBMIT: usize = 32;

/// The fewest lanes started. A lane issues about 200k reads per second, so fewer would leave a
/// fast device idle.
const MIN_LANES: usize = 2;

/// The most lanes started. Each is a thread, [NR_EVENTS] of the host-wide `fs.aio-max-nr`
/// budget, and a [NR_EVENTS]-block staging slab (1 MiB).
const MAX_LANES: usize = 8;

/// Cores per lane. Issuing a direct read costs its lane a few microseconds of CPU, so lanes
/// scale with the cores available to serve them, leaving the rest to the tasks consuming the
/// reads.
const CORES_PER_LANE: usize = 2;

/// The fewest reads of one batch a lane is handed, so a small batch is not spread across lanes
/// for less than one submission each.
const MIN_SHARE: usize = IOCBS_PER_SUBMIT;

/// A pending read: its index among the [`read_many`] call's ranges and the physical file range.
struct Read {
    index: usize,
    offset: u64,
    len: usize,
}

/// One completed read.
type Completion = Result<(usize, IoBufsMut), Error>;

/// Delivers a batch's completions to its stream, a reap's worth at a time.
type Completions = tokio::sync::mpsc::UnboundedSender<Vec<Completion>>;

/// The blob's `O_DIRECT` descriptor on its inode, opened by the first submission that needs
/// it and shared by every later one. `None` when the filesystem rejects direct I/O, which
/// the blob remembers, or when the open fails for a reason that may not recur, such as a
/// descriptor limit, which leaves the cell empty for the next submission to try again.
pub(super) fn direct(file: &Shared) -> Option<&File> {
    file.direct
        .get_or_try_init(|| {
            let path = format!("/proc/self/fd/{}", file.as_raw_fd());
            let mut options = std::fs::OpenOptions::new();
            options.read(true).custom_flags(libc::O_DIRECT);
            match options.open(path) {
                Ok(direct) => Ok(Some(direct)),
                Err(err) if err.raw_os_error() == Some(libc::EINVAL) => Ok(None),
                Err(err) => Err(err),
            }
        })
        .ok()?
        .as_ref()
}

/// Kernel ABI (`struct iocb`, little-endian layout).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Iocb {
    aio_data: u64,
    aio_key: u32,
    aio_rw_flags: u32,
    aio_lio_opcode: u16,
    aio_reqprio: i16,
    aio_fildes: u32,
    aio_buf: u64,
    aio_nbytes: u64,
    aio_offset: i64,
    aio_reserved2: u64,
    aio_flags: u32,
    aio_resfd: u32,
}

/// Kernel ABI (`struct io_event`).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct IoEvent {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

/// The `aio_lio_opcode` of a positioned read.
const IOCB_CMD_PREAD: u16 = 0;

/// An AIO context, owned by one lane. `io_getevents` returns any completion in a context, so
/// only its lane may submit to it.
///
/// Every context charges [NR_EVENTS] against the host-wide `fs.aio-max-nr` budget (65,536 by
/// default) until it is destroyed. A lane that cannot create one serves its reads one blocking
/// task per read.
struct Context(libc::c_ulong);

impl Context {
    /// Create a context for [NR_EVENTS] concurrent requests. `None` when the kernel cannot
    /// create one, for example when its outstanding-request limit (`fs.aio-max-nr`) is exhausted.
    fn new() -> Option<Self> {
        let mut ctx: libc::c_ulong = 0;
        // SAFETY: `io_setup` writes the new context handle to the valid out pointer.
        let r = unsafe { libc::syscall(libc::SYS_io_setup, NR_EVENTS as libc::c_ulong, &mut ctx) };
        (r == 0).then(|| Self(ctx))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: this handle belongs exclusively to this owner. Successful destruction
        // waits for every pending request before the destination buffers can be released.
        let result = unsafe { libc::syscall(libc::SYS_io_destroy, self.0) };
        if result != 0 {
            // Without a completion barrier, releasing the buffers would be unsafe.
            std::process::abort();
        }
    }
}

/// Serve `read` with a positioned read, as [`crate::Blob::read_at`] does for
/// [`ReadOptions::DONT_CACHE`].
fn read_positioned(file: &Shared, read: &Read) -> Completion {
    let mut buf = IoBufMut::with_capacity(read.len);
    // SAFETY: read_exact_at fills all `len` bytes before the buffer is yielded.
    unsafe { buf.set_len(read.len) };
    Blob::read_exact_at(Cache::Disabled, file, buf.as_mut(), read.offset)?;
    Ok((read.index, buf.into()))
}

/// Serve `reads` without native AIO: one blocking task per read, as [`crate::Blob::read_at`]
/// does.
fn read_positioned_each(
    runtime: &tokio::runtime::Handle,
    file: &Arc<Shared>,
    reads: Vec<Read>,
    tx: &Completions,
) {
    for read in reads {
        let (file, tx) = (file.clone(), tx.clone());
        runtime.spawn_blocking(move || {
            let _ = tx.send(vec![read_positioned(&file, &read)]);
        });
    }
}

/// One lane's share of a [`read_many`] call.
struct Job {
    file: Arc<Shared>,
    reads: Vec<Read>,
    tx: Completions,
    /// Whether each read is a physical page the lane validates (see [ReadOptions::CHECK_PAGES]).
    check_pages: bool,
    /// Serves the reads one blocking task per read when the lane cannot read them directly.
    runtime: tokio::runtime::Handle,
}

/// A job a lane is serving.
struct Active {
    file: Arc<Shared>,
    fd: u32,
    /// Reads not yet issued.
    reads: std::vec::IntoIter<Read>,
    tx: Completions,
    check_pages: bool,
    in_flight: usize,
    /// Whether the job is in the lane's ready queue.
    queued: bool,
    /// Completions reaped since the last delivery.
    done: Vec<Completion>,
}

/// A read in flight in one slot of a lane's window.
struct Slot {
    job: usize,
    read: Read,
    /// Bytes between the start of the aligned superset and the requested range.
    skip: usize,
    destination: Destination,
}

/// Where a read in flight lands.
enum Destination {
    /// The slot's block of the slab, for an unaligned superset of one block.
    Slab,
    /// A buffer of exactly the requested range, which is aligned, yielded without a copy.
    Exact(IoBufMut),
    /// A buffer for an unaligned superset larger than one block.
    Superset(IoBufMut),
}

/// The state of one lane: a context, a window of [NR_EVENTS] slots backed by one block of an
/// aligned slab each, and the jobs those slots serve.
struct Lane {
    // Declared first so it drops first: destroying the context waits for every read in
    // flight, which may still be writing into the slab or an owned buffer.
    ctx: Context,
    /// One block per slot, the destination of reads that fit in a block.
    slab: IoBufMut,
    block: usize,
    /// The read in flight in each slot, if any.
    slots: Vec<Option<Slot>>,
    /// Slots with no read in flight.
    free: Vec<usize>,
    /// The jobs being served, by id. A retired job leaves its id free for the next.
    jobs: Vec<Option<Active>>,
    /// Jobs with reads not yet issued, in the order the lane takes from them.
    ready: VecDeque<usize>,
    /// Jobs with completions to deliver.
    touched: Vec<usize>,
    in_flight: usize,
    /// Recycled blob-page buffers for aligned one-page reads, refilled from the [page_pool].
    pages: Vec<IoBufMut>,
    /// Reads prepared for the next `io_submit`.
    iocbs: Vec<Iocb>,
    events: Vec<IoEvent>,
}

impl Lane {
    /// `None` when the kernel cannot create a context or the slab cannot be allocated.
    fn new() -> Option<Self> {
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        let ctx = Context::new()?;
        let slab = IoBufMut::try_with_alignment(NR_EVENTS * block, NZUsize!(block))?;
        Some(Self {
            ctx,
            slab,
            block,
            slots: (0..NR_EVENTS).map(|_| None).collect(),
            free: (0..NR_EVENTS).rev().collect(),
            jobs: Vec::new(),
            ready: VecDeque::new(),
            touched: Vec::new(),
            in_flight: 0,
            pages: Vec::new(),
            iocbs: Vec::with_capacity(IOCBS_PER_SUBMIT),
            events: vec![IoEvent::default(); NR_EVENTS],
        })
    }

    /// Whether the lane has nothing in flight and nothing left to issue.
    fn is_idle(&self) -> bool {
        self.in_flight == 0 && self.ready.is_empty()
    }

    /// Queue `job` ahead of the jobs already being served, so a small job is issued within one
    /// turn of arriving. Each job then gets turns in order.
    fn admit(&mut self, job: Job) {
        let Job {
            file,
            reads,
            tx,
            check_pages,
            runtime,
        } = job;

        // Without a direct descriptor (the filesystem rejects direct I/O, or a transient open
        // failure), the reads are served one blocking task per read, as read_at would.
        let Some(direct) = direct(&file) else {
            return read_positioned_each(&runtime, &file, reads, &tx);
        };
        let fd = u32::try_from(direct.as_raw_fd()).expect("an open descriptor is non-negative");
        let active = Active {
            file,
            fd,
            reads: reads.into_iter(),
            tx,
            check_pages,
            in_flight: 0,
            queued: true,
            done: Vec::new(),
        };
        let id = match self.jobs.iter().position(Option::is_none) {
            Some(id) => {
                self.jobs[id] = Some(active);
                id
            }
            None => {
                self.jobs.push(Some(active));
                self.jobs.len() - 1
            }
        };
        self.ready.push_front(id);
    }

    /// Issue reads into free slots, then deliver what has landed, waiting for at least one
    /// completion when no more reads can be issued. An error means the context can no longer
    /// be reaped.
    fn advance(&mut self) -> Result<(), Error> {
        self.fill();
        self.submit();
        let wait = self.in_flight > 0 && (self.free.is_empty() || self.ready.is_empty());
        let result = self.reap(wait);
        self.deliver();
        result
    }

    /// Prepare up to [IOCBS_PER_SUBMIT] reads, taking as many as fit from the job at the front
    /// of the queue before moving it to the back.
    fn fill(&mut self) {
        let slab_ptr = self.slab.chunk_mut().as_mut_ptr();
        while self.iocbs.len() < IOCBS_PER_SUBMIT && !self.free.is_empty() {
            let Some(&id) = self.ready.front() else {
                break;
            };
            let job = self.jobs[id].as_mut().expect("a ready job is active");

            // A dropped stream wants none of the reads it has not been issued.
            if job.tx.is_closed() {
                job.reads = Vec::new().into_iter();
            }
            let take = (IOCBS_PER_SUBMIT - self.iocbs.len()).min(self.free.len());
            for _ in 0..take {
                let Some(read) = job.reads.next() else {
                    break;
                };

                // Every read covers the superset of its range aligned to a blob page, which is
                // the largest logical block size of supported devices and so satisfies direct
                // I/O's alignment of offsets, lengths, and buffers. An aligned range lands in a
                // buffer of its own, which becomes the result. An unaligned superset of one
                // block lands in a slot of the slab, and a larger one in a buffer of its own.
                let aligned_offset = read.offset - read.offset % u64::from(BLOB_PAGE_SIZE);
                let skip = usize::try_from(read.offset - aligned_offset)
                    .expect("an offset within a block fits in usize");
                let Some(aligned_len) = skip
                    .checked_add(read.len)
                    .and_then(|len| len.checked_next_multiple_of(self.block))
                else {
                    job.fail(Error::OffsetOverflow);
                    break;
                };
                let aligned = skip == 0 && aligned_len == read.len;
                let slot = self.free.pop().expect("a free slot was checked");
                let (destination, buf) = if !aligned && aligned_len <= self.block {
                    // SAFETY: `slot < NR_EVENTS`, so the slot's block lies in the slab.
                    (Destination::Slab, unsafe {
                        slab_ptr.add(slot * self.block)
                    })
                } else {
                    let recycled = if aligned_len == self.block {
                        if self.pages.is_empty() {
                            page_pool::take(&mut self.pages, NR_EVENTS);
                        }
                        self.pages.pop()
                    } else {
                        None
                    };
                    let Some(mut owned) = recycled.or_else(|| {
                        IoBufMut::try_with_alignment(aligned_len, NZUsize!(self.block))
                    }) else {
                        self.free.push(slot);
                        job.fail(Error::OffsetOverflow);
                        break;
                    };
                    let buf = owned.chunk_mut().as_mut_ptr();
                    if aligned {
                        (Destination::Exact(owned), buf)
                    } else {
                        (Destination::Superset(owned), buf)
                    }
                };
                self.iocbs.push(Iocb {
                    aio_data: Widen::widen(slot),
                    aio_lio_opcode: IOCB_CMD_PREAD,
                    aio_fildes: job.fd,
                    // The kernel writes through this integer address, so it exposes the
                    // destination's provenance.
                    aio_buf: Widen::widen(buf.expose_provenance()),
                    aio_nbytes: Widen::widen(aligned_len),
                    // An offset past the largest signed file offset wraps negative. The kernel
                    // rejects it at submission and the read is served positioned.
                    aio_offset: aligned_offset as i64,
                    ..Iocb::default()
                });
                self.slots[slot] = Some(Slot {
                    job: id,
                    read,
                    skip,
                    destination,
                });
                job.in_flight += 1;
                self.in_flight += 1;
            }

            // A job with reads left goes to the back of the queue. One with none leaves it, and
            // is retired once its last read is delivered.
            self.ready.pop_front();
            if !job.reads.as_slice().is_empty() {
                self.ready.push_back(id);
            } else {
                job.queued = false;
                self.touched.push(id);
            }
        }
    }

    /// Submit the prepared reads. A failed submission accepted none of the requests passed to
    /// it. The first of them may be one the kernel rejects (for example, a superset ending
    /// beyond the largest signed file offset), so it is served here and the rest are
    /// submitted again.
    fn submit(&mut self) {
        let mut ptrs: [*mut Iocb; IOCBS_PER_SUBMIT] = [std::ptr::null_mut(); IOCBS_PER_SUBMIT];
        for (ptr, iocb) in ptrs.iter_mut().zip(self.iocbs.iter_mut()) {
            *ptr = iocb;
        }
        let n = self.iocbs.len();
        let mut next = 0;
        while next < n {
            // SAFETY: `ptrs[next..n]` are valid iocbs whose destinations are slab slots or owned
            // buffers this lane keeps until their reads are reaped. The context has room for
            // them because every one holds a slot of the [NR_EVENTS] in the window.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_io_submit,
                    self.ctx.0,
                    (n - next) as libc::c_long,
                    ptrs.as_ptr().add(next),
                )
            };
            if r <= 0 {
                let slot = self.iocbs[next].aio_data;
                self.complete(&IoEvent {
                    data: slot,
                    res: -1,
                    ..IoEvent::default()
                });
                next += 1;
                continue;
            }
            next += r as usize;
        }
        self.iocbs.clear();
    }

    /// Reap the completions that have landed, waiting for at least one when `wait` is set.
    fn reap(&mut self, wait: bool) -> Result<(), Error> {
        if self.in_flight == 0 {
            return Ok(());
        }
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let timeout: *const libc::timespec = if wait { std::ptr::null() } else { &zero };
        let got = loop {
            // SAFETY: `events` has room for [NR_EVENTS] events and `timeout` is null or a valid
            // timespec.
            let got = unsafe {
                libc::syscall(
                    libc::SYS_io_getevents,
                    self.ctx.0,
                    wait as libc::c_long,
                    NR_EVENTS as libc::c_long,
                    self.events.as_mut_ptr(),
                    timeout,
                )
            };
            if got >= 0 {
                break got as usize;
            }

            // A signal interrupts the wait before it reaps anything, and the kernel never
            // restarts it.
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err.into());
            }
        };
        for i in 0..got {
            let event = self.events[i];
            self.complete(&event);
        }
        Ok(())
    }

    /// Free the slot `event` names and record its read's result with its job. A read the
    /// kernel rejected, failed, or completed short is served by [`read_positioned`] instead.
    fn complete(&mut self, event: &IoEvent) {
        let slot = event.data as usize;
        let Slot {
            job: id,
            read,
            skip,
            destination,
        } = self.slots[slot]
            .take()
            .expect("a completed slot is in flight");
        self.free.push(slot);
        self.in_flight -= 1;
        let job = self.jobs[id]
            .as_mut()
            .expect("a job with reads in flight is active");
        job.in_flight -= 1;
        self.touched.push(id);

        // A superset ending past the file completes short but still covers its range. A read
        // that failed or stopped before the end of its range (for example, it was interrupted
        // or capped at the most one read returns) is served by a positioned read, which fails
        // only where read_at would.
        let item = if event.res < 0 || (event.res as usize) < skip + read.len {
            read_positioned(&job.file, &read)
        } else {
            let copy_out = |src: *mut u8| {
                // SAFETY: this completed request initialized the requested range of `src`,
                // which no other request in flight writes.
                let bytes = unsafe { std::slice::from_raw_parts(src.add(skip), read.len) };
                let mut buf = IoBufMut::with_capacity(read.len);
                buf.put_slice(bytes);
                buf
            };
            let buf = match destination {
                Destination::Exact(mut buf) => {
                    // SAFETY: the completed request initialized all `read.len` bytes.
                    unsafe { buf.set_len(read.len) };
                    if job.check_pages
                        && let Some(len) = paged::full_page_len(buf.as_ref())
                    {
                        buf.truncate(len);
                    }
                    buf
                }
                Destination::Superset(mut owned) => copy_out(owned.chunk_mut().as_mut_ptr()),
                Destination::Slab => {
                    // SAFETY: `slot < NR_EVENTS`, so the slot's block lies in the slab.
                    let src = unsafe { self.slab.chunk_mut().as_mut_ptr().add(slot * self.block) };
                    copy_out(src)
                }
            };
            #[cfg(test)]
            job.file.test.direct_reads.fetch_add(1, Ordering::Relaxed);
            Ok((read.index, buf.into()))
        };
        match item {
            Ok(item) => job.done.push(Ok(item)),
            Err(err) => job.fail(err),
        }
    }

    /// Send every touched job its completions, and retire the jobs that have left the ready
    /// queue and have nothing in flight.
    fn deliver(&mut self) {
        for id in self.touched.drain(..) {
            let Some(job) = self.jobs[id].as_mut() else {
                continue;
            };
            if !job.done.is_empty() {
                let _ = job.tx.send(std::mem::take(&mut job.done));
            }
            if job.in_flight == 0 && !job.queued {
                self.jobs[id] = None;
            }
        }
    }

    /// Fail every job the lane is serving with `err`, the first verbatim and the rest as
    /// [Error::ReadFailed].
    fn fail_all(&mut self, err: Error) {
        let mut err = Some(err);
        for job in self.jobs.iter_mut().flatten() {
            let _ = job
                .tx
                .send(vec![Err(err.take().unwrap_or(Error::ReadFailed))]);
        }
    }
}

impl Active {
    /// Report `err` to the job's stream, which ends it, and issue none of its remaining reads.
    fn fail(&mut self, err: Error) {
        self.done.push(Err(err));
        self.reads = Vec::new().into_iter();
    }
}

/// Run a lane on the calling thread until every sender of its inbox is gone.
fn serve(inbox: std::sync::mpsc::Receiver<Job>) {
    let mut lane = Lane::new();
    loop {
        // Block for work only when nothing is in flight or waiting to be issued.
        if lane.as_ref().is_none_or(Lane::is_idle) {
            let Ok(job) = inbox.recv() else {
                return;
            };
            admit(&mut lane, job);
        }
        while let Ok(job) = inbox.try_recv() {
            admit(&mut lane, job);
        }
        let Some(active) = lane.as_mut() else {
            continue;
        };
        if active.is_idle() {
            continue;
        }

        // A context that can no longer be reaped fails every job it serves. Replacing the lane
        // destroys the context, which waits for every read still in flight.
        if let Err(err) = active.advance() {
            active.fail_all(err);
            lane = Lane::new();
        }
    }
}

/// Queue `job` on `lane`, or serve it one blocking task per read when the lane has no context.
fn admit(lane: &mut Option<Lane>, job: Job) {
    match lane {
        Some(lane) => lane.admit(job),
        None => read_positioned_each(&job.runtime, &job.file, job.reads, &job.tx),
    }
}

/// The process's read lanes, started by the first batched read.
struct Lanes {
    inboxes: Vec<std::sync::mpsc::Sender<Job>>,
    /// The lane the next batch starts on, so concurrent batches spread across lanes.
    next: AtomicUsize,
}

impl Lanes {
    /// Start one lane per [CORES_PER_LANE] available cores, from [MIN_LANES] to [MAX_LANES]. A
    /// lane whose thread cannot be spawned is left out.
    fn start() -> Self {
        let cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let inboxes = (0..(cores / CORES_PER_LANE).clamp(MIN_LANES, MAX_LANES))
            .filter_map(|i| {
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::Builder::new()
                    .name(format!("storage-read-{i}"))
                    .spawn(move || serve(rx))
                    .ok()
                    .map(|_| tx)
            })
            .collect();
        Self {
            inboxes,
            next: AtomicUsize::new(0),
        }
    }

    /// Split `reads` into one share per lane, each at least [MIN_SHARE] reads, and queue each
    /// share on its lane.
    fn dispatch(
        &self,
        runtime: &tokio::runtime::Handle,
        file: &Arc<Shared>,
        reads: Vec<Read>,
        check_pages: bool,
        tx: &Completions,
    ) {
        let shares = reads.len().div_ceil(MIN_SHARE).clamp(1, self.inboxes.len());
        let share = reads.len().div_ceil(shares);
        let first = self.next.fetch_add(shares, Ordering::Relaxed);
        let mut reads = reads.into_iter();
        for k in 0..shares {
            let chunk: Vec<_> = reads.by_ref().take(share).collect();
            if chunk.is_empty() {
                break;
            }
            let job = Job {
                file: file.clone(),
                reads: chunk,
                tx: tx.clone(),
                check_pages,
                runtime: runtime.clone(),
            };

            // A lane whose thread panicked no longer receives, and its share is served one
            // blocking task per read.
            if let Err(std::sync::mpsc::SendError(job)) =
                self.inboxes[first.wrapping_add(k) % self.inboxes.len()].send(job)
            {
                read_positioned_each(runtime, &job.file, job.reads, &job.tx);
            }
        }
    }
}

/// The process's read lanes.
static LANES: OnceLock<Lanes> = OnceLock::new();

/// Read `ranges` of a blob's data with direct I/O, yielding each range's `(index, bytes)` as
/// it completes. Offsets are relative to `data_offset`. Without an error every range is
/// yielded exactly once, and an error ends the stream.
///
/// The reads are split across the read lanes, so the device sees them all at once and no
/// thread blocks per read. They use direct I/O on every Linux kernel, so they do not read
/// data the OS page cache holds. Their concurrency assumes filesystem-native direct I/O (such
/// as ext4 or XFS): a filesystem that serves direct I/O through a buffered fallback stays
/// correct but completes each lane's reads one at a time. A blob whose filesystem rejects
/// direct I/O is read one blocking task per read.
///
/// With [ReadOptions::CHECK_PAGES], each lane validates the pages it reads directly.
pub(super) fn read_many(
    file: &Arc<Shared>,
    data_offset: u64,
    ranges: &[(u64, usize)],
    options: ReadOptions,
) -> BoxStream<'static, Completion> {
    // Translate each range to its physical file range, keeping its index so the stream can
    // name it. An offset beyond the file's address space fails the call before anything is read.
    let mut reads = Vec::with_capacity(ranges.len());
    for (index, &(offset, len)) in ranges.iter().enumerate() {
        let Some(offset) = offset.checked_add(data_offset) else {
            return stream::iter(vec![Err(Error::OffsetOverflow)]).boxed();
        };
        reads.push(Read { index, offset, len });
    }

    // Every share sends to the channel the stream drains, so completions arrive in whatever
    // order they land.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let runtime = tokio::runtime::Handle::current();
    let lanes = LANES.get_or_init(Lanes::start);
    if lanes.inboxes.is_empty() || matches!(file.direct.get(), Some(None)) {
        read_positioned_each(&runtime, file, reads, &tx);
    } else {
        let check_pages = options.contains(ReadOptions::CHECK_PAGES);
        lanes.dispatch(&runtime, file, reads, check_pages, &tx);
    }

    // The stream ends once every range is yielded or at the first error. A share that ends
    // without reporting its reads (its lane panicked, or the runtime shut down before a
    // blocking task ran) closes the channel early, which is an error.
    stream::unfold(
        (rx, VecDeque::new(), ranges.len()),
        |(mut rx, mut ready, remaining)| async move {
            if remaining == 0 {
                return None;
            }
            while ready.is_empty() {
                match rx.recv().await {
                    Some(batch) => ready.extend(batch),
                    None => return Some((Err(Error::ReadFailed), (rx, ready, 0))),
                }
            }
            let item = ready.pop_front().expect("a batch was received");
            let remaining = if item.is_ok() { remaining - 1 } else { 0 };
            Some((item, (rx, ready, remaining)))
        },
    )
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, Storage as _,
        storage::{
            Layout,
            tokio::{Config, Storage},
        },
    };
    use commonware_cryptography::Crc32;
    use futures::TryStreamExt as _;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    /// Open a blob holding `data` in a fresh directory that supports direct I/O.
    async fn direct_blob(label: &str, data: Vec<u8>) -> (Storage, Blob, PathBuf) {
        let directory =
            std::env::temp_dir().join(format!("storage_tokio_aio_{label}_{}", std::process::id()));
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL));
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, data, WriteOptions::SYNC).await.unwrap();
        assert!(
            direct(&blob.shared).is_some(),
            "temporary directory must support O_DIRECT"
        );
        (storage, blob, directory)
    }

    async fn remove(storage: Storage, blob: Blob, directory: PathBuf) {
        drop(blob);
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A job reading `ranges` of `blob`, and the receiver of its completions.
    fn job(
        blob: &Blob,
        ranges: &[(u64, usize)],
    ) -> (Job, tokio::sync::mpsc::UnboundedReceiver<Vec<Completion>>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let reads = ranges
            .iter()
            .enumerate()
            .map(|(index, &(offset, len))| Read {
                index,
                offset: offset + blob.data_offset,
                len,
            })
            .collect();
        let job = Job {
            file: blob.shared.clone(),
            reads,
            tx,
            check_pages: false,
            runtime: tokio::runtime::Handle::current(),
        };
        (job, rx)
    }

    /// Drain every completion `rx` has received.
    fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<Completion>>) -> Vec<Completion> {
        let mut all = Vec::new();
        while let Ok(batch) = rx.try_recv() {
            all.extend(batch);
        }
        all
    }

    #[tokio::test]
    async fn test_rejected_read_fails_only_its_job() {
        const LEN: usize = 64 << 10;
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        let (storage, blob, directory) = direct_blob("rejected", vec![0xAB; LEN]).await;
        let mut lane = Lane::new().unwrap();

        // The kernel rejects the second read (its offset exceeds the largest signed file
        // offset), whose positioned read then fails, so the job ends with an error while its
        // first read may still be in flight.
        let (failing, mut failing_rx) = job(&blob, &[(0, LEN), (1 << 63, block)]);
        lane.admit(failing);
        while !lane.is_idle() {
            lane.advance().unwrap();
        }
        assert!(drain(&mut failing_rx).iter().any(Result::is_err));

        // The lane serves the next job in full.
        let (next, mut next_rx) = job(&blob, &[(0, LEN), (100, 10)]);
        lane.admit(next);
        while !lane.is_idle() {
            lane.advance().unwrap();
        }
        let mut served: Vec<_> = drain(&mut next_rx)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        served.sort_by_key(|(index, _)| *index);
        assert!(served.iter().map(|(index, _)| *index).eq(0..2));
        for ((_, len), (_, bufs)) in [(0, LEN), (100, 10)].into_iter().zip(served) {
            assert_eq!(bufs.coalesce().as_ref(), vec![0xAB; len]);
        }
        drop(lane);
        remove(storage, blob, directory).await;
    }

    #[tokio::test]
    async fn test_small_job_does_not_wait_for_large_one() {
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        let (storage, blob, directory) = direct_blob("interleave", vec![0xCD; 64 * block]).await;
        let mut lane = Lane::new().unwrap();

        // The large job is queued first and holds more reads than four full windows.
        let large_ranges: Vec<(u64, usize)> = (0..4 * NR_EVENTS + 1)
            .map(|i| (Widen::widen((i % 64) * block), block))
            .collect();
        let (large, mut large_rx) = job(&blob, &large_ranges);
        let (small, mut small_rx) = job(&blob, &[(0, block)]);
        lane.admit(large);
        lane.admit(small);

        // The small job arrived last, so its read is issued in the lane's first submission and
        // delivered while most of the large job's reads have not even been issued.
        let mut large_done = 0;
        let small = loop {
            lane.advance().unwrap();
            large_done += drain(&mut large_rx).len();
            let small = drain(&mut small_rx);
            if !small.is_empty() {
                break small;
            }
        };
        assert_eq!(small.len(), 1);
        assert!(large_done < large_ranges.len() / 2, "{large_done}");
        while !lane.is_idle() {
            lane.advance().unwrap();
        }
        large_done += drain(&mut large_rx).len();
        assert_eq!(large_done, large_ranges.len());
        drop(lane);
        remove(storage, blob, directory).await;
    }

    #[tokio::test]
    async fn test_lane_survives_signals() {
        extern "C" fn ignore(_: libc::c_int) {}

        // A handled signal interrupts a blocked io_getevents, which the kernel never restarts.
        // SAFETY: a zeroed sigaction is valid, `ignore` has the handler ABI, and both
        // pointers are valid.
        let previous = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = ignore as extern "C" fn(libc::c_int) as usize;
            let mut previous: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGUSR1, &action, &mut previous), 0);
            previous
        };

        // One large read keeps io_getevents waiting long enough to be interrupted.
        const LEN: usize = 64 << 20;
        let (storage, blob, directory) = direct_blob("signals", vec![0xAB; LEN]).await;
        let (job, mut rx) = job(&blob, &[(0, LEN)]);
        let done = Arc::new(AtomicBool::new(false));
        let (thread_tx, thread_rx) = std::sync::mpsc::channel();
        let lane = {
            let done = done.clone();
            std::thread::spawn(move || {
                // SAFETY: pthread_self has no preconditions.
                thread_tx.send(unsafe { libc::pthread_self() }).unwrap();
                let mut lane = Lane::new().unwrap();
                lane.admit(job);
                let mut result = Ok(());
                while result.is_ok() && !lane.is_idle() {
                    result = lane.advance();
                }
                done.store(true, Ordering::Release);
                result.is_ok()
            })
        };
        let thread = thread_rx.recv().unwrap();
        while !done.load(Ordering::Acquire) {
            // SAFETY: the lane thread has not been joined, so its thread id is still valid.
            unsafe { libc::pthread_kill(thread, libc::SIGUSR1) };
            std::thread::sleep(Duration::from_micros(10));
        }
        let served = lane.join().unwrap();

        // SAFETY: restores the action saved above.
        unsafe { libc::sigaction(libc::SIGUSR1, &previous, std::ptr::null_mut()) };
        assert!(served);
        let mut completions = drain(&mut rx);
        assert_eq!(completions.len(), 1);
        let Ok((0, bufs)) = completions.pop().unwrap() else {
            panic!("expected the read");
        };
        assert_eq!(bufs.coalesce().as_ref(), vec![0xAB; LEN].as_slice());
        remove(storage, blob, directory).await;
    }

    /// An open that fails for a reason that may not recur leaves the blob free to try again,
    /// while a filesystem's rejection is final for the blob.
    #[tokio::test]
    async fn test_direct_open_retries_after_descriptor_limit() {
        let directory = std::env::temp_dir().join(format!(
            "storage_tokio_aio_retry_open_{}",
            std::process::id()
        ));
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL));
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, vec![0; Widen::widen(BLOB_PAGE_SIZE)], WriteOptions::SYNC)
            .await
            .unwrap();

        // Forbid further descriptors for the duration of one open attempt, which must leave
        // the blob free to try again.
        // SAFETY: getrlimit and setrlimit take valid pointers to an rlimit.
        let denied = unsafe {
            let mut previous: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut previous), 0);
            let none = libc::rlimit {
                rlim_cur: 0,
                rlim_max: previous.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &none), 0);
            let denied = direct(&blob.shared);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &previous), 0);
            denied.is_none()
        };
        assert!(denied);
        assert!(blob.shared.direct.get().is_none());

        // The next submission opens it, unless the filesystem rejects direct I/O outright,
        // which is recorded instead.
        let opened = direct(&blob.shared).is_some();
        assert_eq!(opened, matches!(blob.shared.direct.get(), Some(Some(_))));
        remove(storage, blob, directory).await;
    }

    /// More ranges than one lane keeps in flight are split across lanes and windows and still
    /// yield every range exactly once, each served by its direct read.
    #[tokio::test]
    async fn test_read_many_serves_more_ranges_than_one_window() {
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        let data: Vec<u8> = (0..8 * block).map(|i| (i % 251) as u8).collect();
        let (storage, blob, directory) = direct_blob("many_windows", data.clone()).await;

        let ranges: Vec<(u64, usize)> = (0..2 * NR_EVENTS + 1)
            .map(|i| (Widen::widen((i % 16) * 2048), 2048))
            .collect();
        let before = blob.shared.test.direct_reads.load(Ordering::Relaxed);
        let mut served: Vec<(usize, IoBufsMut)> = read_many(
            &blob.shared,
            blob.data_offset,
            &ranges,
            ReadOptions::DONT_CACHE,
        )
        .try_collect()
        .await
        .unwrap();
        assert_eq!(
            blob.shared.test.direct_reads.load(Ordering::Relaxed) - before,
            ranges.len()
        );
        served.sort_by_key(|(index, _)| *index);
        assert!(served.iter().map(|(index, _)| *index).eq(0..ranges.len()));
        for (index, bufs) in served {
            let (offset, len) = ranges[index];
            let offset = usize::try_from(offset).unwrap();
            assert_eq!(bufs.coalesce().as_ref(), &data[offset..offset + len]);
        }
        remove(storage, blob, directory).await;
    }

    /// Pages read with [ReadOptions::CHECK_PAGES] arrive as only their logical bytes when valid
    /// and full, and in full otherwise.
    #[tokio::test]
    async fn test_check_pages_trims_valid_full_pages() {
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        let logical = block - paged::CHECKSUM_SIZE as usize;
        let page = |data: &[u8]| {
            let mut page = data.to_vec();
            page.resize(logical, 0);
            page.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            page.extend_from_slice(&Crc32::checksum(data).to_be_bytes());
            page.extend_from_slice(&[0; 6]);
            page
        };
        let full = page(&vec![1; logical]);
        let partial = page(&[2; 100]);
        let mut corrupt = page(&vec![3; logical]);
        corrupt[0] ^= 0xFF;
        let data = [full.clone(), partial.clone(), corrupt.clone()].concat();
        let (storage, blob, directory) = direct_blob("check_pages", data).await;

        let ranges: Vec<(u64, usize)> = (0..3).map(|i| (Widen::widen(i * block), block)).collect();
        let options = ReadOptions::DONT_CACHE | ReadOptions::CHECK_PAGES;
        let mut served: Vec<(usize, IoBufsMut)> =
            read_many(&blob.shared, blob.data_offset, &ranges, options)
                .try_collect()
                .await
                .unwrap();
        served.sort_by_key(|(index, _)| *index);
        let served: Vec<_> = served
            .into_iter()
            .map(|(_, bufs)| bufs.coalesce())
            .collect();
        assert_eq!(served[0].as_ref(), &full[..logical]);
        assert_eq!(served[1].as_ref(), partial.as_slice());
        assert_eq!(served[2].as_ref(), corrupt.as_slice());
        remove(storage, blob, directory).await;
    }

    #[tokio::test]
    async fn test_reads_without_context_are_served_individually() {
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        let data: Vec<u8> = (0..3 * block).map(|i| (i % 251) as u8).collect();
        let (storage, blob, directory) = direct_blob("without_context", data.clone()).await;

        // Each read is served on its own blocking task, and one past the end fails alone.
        let ranges = [
            (10u64, 5000usize),
            (u64::from(BLOB_PAGE_SIZE) - 1, 2),
            (data.len() as u64, 1),
        ];
        let (job, mut rx) = job(&blob, &ranges);
        read_positioned_each(&job.runtime, &job.file, job.reads, &job.tx);
        drop(job.tx);
        let mut served = Vec::new();
        let mut failed = 0;
        while let Some(batch) = rx.recv().await {
            for item in batch {
                match item {
                    Ok(item) => served.push(item),
                    Err(_) => failed += 1,
                }
            }
        }
        assert_eq!(failed, 1);
        served.sort_by_key(|(index, _)| *index);
        assert_eq!(served.len(), 2);
        for ((offset, len), (index, bufs)) in ranges.iter().zip(served) {
            let offset = *offset as usize;
            assert_eq!(
                bufs.coalesce().as_ref(),
                &data[offset..offset + len],
                "{index}"
            );
        }
        remove(storage, blob, directory).await;
    }
}
