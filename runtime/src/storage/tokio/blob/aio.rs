//! Linux native AIO: one thread submits up to [NR_EVENTS] `O_DIRECT` reads through one AIO
//! context and reaps completions as they arrive. Unlike a thread per read, the device sees
//! them all at once and the submitting thread pays only a few microseconds per read.

use super::*;
use crate::{BLOB_PAGE_SIZE, BufMut as _, IoBufMut};
use commonware_utils::NZUsize;
use std::os::unix::fs::OpenOptionsExt as _;

/// The `nr_events` each AIO context is created with (`io_setup`): the requests it processes
/// concurrently, and so the reads one blocking task submits through one context in
/// [`crate::Blob::read_many`].
///
/// One context's worth is one device queue's worth of reads: NVMe queues hold 256 to 1024
/// commands, and a queue depth of 256 saturates the devices this runtime targets. A larger
/// `read_many` splits into that many reads per task, so issue cost spreads across tasks while
/// each task keeps a full queue in flight.
pub(super) const NR_EVENTS: usize = 256;

/// Requests (iocbs) issued per `io_submit` call before the completions that have landed are
/// reaped.
///
/// The kernel spends about 2 us issuing each direct read, so issuing a whole context's worth
/// in one call takes longer than one read takes to complete. Reaping between calls lets the
/// earliest completions reach the stream while the rest are still being issued, at the cost
/// of one non-blocking `io_getevents` per call. Much smaller calls pay more in per-call
/// overhead than they return.
const IOCBS_PER_SUBMIT: usize = 32;

/// A pending read: its index among the `read_many` call's ranges and the physical file range.
pub(super) struct Read {
    pub(super) index: usize,
    pub(super) offset: u64,
    pub(super) len: usize,
}

/// One completed read, sent to the stream as soon as the kernel reports it.
pub(super) type Completion = Result<(usize, IoBufsMut), Error>;

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

/// A long-lived AIO context. Each submission in flight holds one of its own: `io_getevents`
/// returns any completion in a context, so sharing one would hand a submission the reads of
/// others.
///
/// Destroying a context waits for RCU grace periods (~30 ms), so one is destroyed only when
/// a submission fails with reads in flight, because the slab must outlive them. Every
/// pooled context charges [NR_EVENTS] against the host-wide `fs.aio-max-nr` budget (65,536
/// by default, so 256 contexts) until the process exits and the kernel reclaims them. A
/// submission that cannot obtain a context is served one blocking task per read, and other
/// users of Linux AIO on the same host see that budget as taken.
struct Context(libc::c_ulong);

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

/// The process-wide free list of idle contexts. A submission takes one before `io_submit`
/// and returns it after reaping every completion, so the list grows to the peak number of
/// concurrent submissions. The lock guards one pop or push per submission and is never held
/// across a syscall.
static CONTEXTS: Mutex<Vec<Context>> = Mutex::new(Vec::new());

/// Take a pooled context or create one for [NR_EVENTS] concurrent requests. `None` when the kernel
/// cannot create one, for example when its outstanding-request limit (`fs.aio-max-nr`) is
/// exhausted.
fn take_context() -> Option<Context> {
    if let Some(ctx) = CONTEXTS.lock().pop() {
        return Some(ctx);
    }
    let mut ctx: libc::c_ulong = 0;
    // SAFETY: `io_setup` writes the new context handle to the valid out pointer.
    let r = unsafe { libc::syscall(libc::SYS_io_setup, NR_EVENTS as libc::c_ulong, &mut ctx) };
    (r == 0).then(|| Context(ctx))
}

/// Serve `read` with a positioned read, as [`crate::Blob::read_at`] does for
/// [`ReadOptions::DONT_CACHE`].
fn read_positioned(file: &Shared, pool: &BufferPool, read: &Read) -> Completion {
    // SAFETY: read_exact_at fills all `len` bytes before the buffer is yielded.
    let mut buf = unsafe { pool.alloc_len(read.len) };
    Blob::read_exact_at(Cache::Disabled, file, buf.as_mut(), read.offset)?;
    Ok((read.index, buf.into()))
}

/// Submit every read in `reads` through `ctx`, delivering each one as it completes. A read
/// the kernel rejects, fails, or completes short is served by [`read_positioned`] instead.
/// Returns `ctx` once every submitted read has completed. On error, dropping it waits for the
/// reads still in flight.
fn submit(
    file: &Shared,
    direct: &File,
    pool: &BufferPool,
    ctx: Context,
    reads: Vec<Read>,
    tx: &tokio::sync::mpsc::UnboundedSender<Completion>,
) -> Result<Context, Error> {
    let fd = u32::try_from(direct.as_raw_fd()).expect("an open descriptor is non-negative");
    let n = reads.len();

    // Every read covers the superset of its range aligned to a blob page, which is the largest
    // logical block size of supported devices and so satisfies direct I/O's alignment of
    // offsets, lengths, and buffers. The supersets lie back to back in one aligned slab, and
    // the requested bytes are copied into pool buffers on completion.
    let block: usize = Widen::widen(BLOB_PAGE_SIZE);
    let mut spans = Vec::with_capacity(n);
    let mut slab_len = 0usize;
    for read in &reads {
        let aligned_offset = read.offset - read.offset % u64::from(BLOB_PAGE_SIZE);
        let skip = usize::try_from(read.offset - aligned_offset)
            .expect("an offset within a block fits in usize");
        let aligned_len = skip
            .checked_add(read.len)
            .and_then(|len| len.checked_next_multiple_of(block))
            .ok_or(Error::OffsetOverflow)?;
        spans.push((aligned_offset, skip, slab_len, aligned_len));
        slab_len = slab_len
            .checked_add(aligned_len)
            .ok_or(Error::OffsetOverflow)?;
    }

    // Like an overflowing span, a slab no allocation layout can hold fails the submission.
    // The allocation adds a header and alignment padding, each shorter than a block, so a
    // slab within two blocks of the largest layout cannot be allocated either.
    if slab_len > isize::MAX.cast_unsigned() - 2 * block {
        return Err(Error::OffsetOverflow);
    }
    let mut slab = IoBufMut::with_alignment(slab_len, NZUsize!(block));
    let slab_ptr = slab.chunk_mut().as_mut_ptr();

    // This local drops before the slab. Context destruction waits for pending kernel
    // writes, including when submission or completion processing unwinds.
    let active = ctx;
    let mut iocbs: Vec<Iocb> = spans
        .iter()
        .enumerate()
        .map(|(i, &(aligned_offset, _, start, aligned_len))| Iocb {
            aio_data: Widen::widen(i),
            aio_lio_opcode: IOCB_CMD_PREAD,
            aio_fildes: fd,
            // SAFETY: `start + aligned_len <= slab_len`. The kernel writes through this
            // integer address, so it exposes the slab's provenance.
            aio_buf: Widen::widen(unsafe { slab_ptr.add(start) }.expose_provenance()),
            aio_nbytes: Widen::widen(aligned_len),
            // An offset past the largest signed file offset wraps negative. The kernel
            // rejects it at submission and the read is served positioned.
            aio_offset: aligned_offset as i64,
            ..Iocb::default()
        })
        .collect();

    // Each completion is delivered as it is reaped: a request the kernel completed in full
    // is copied out of the slab, anything else is re-served by a positioned read.
    let ptrs: Vec<*mut Iocb> = iocbs.iter_mut().map(|iocb| iocb as *mut Iocb).collect();
    let deliver = |event: &IoEvent| -> Result<(), Error> {
        let i = event.data as usize;
        let read = &reads[i];

        // A superset ending past the file completes short but still covers its range. A
        // read that failed or stopped before the end of its range (for example, it was
        // interrupted or capped at the most one read returns) is served by a positioned
        // read, which fails only where read_at would.
        let (_, skip, start, _) = spans[i];
        let item = if event.res < 0 || (event.res as usize) < skip + read.len {
            read_positioned(file, pool, read)?
        } else {
            // SAFETY: this completed request initialized the requested range, which
            // is disjoint from every other request's destination in the slab.
            let bytes = unsafe { std::slice::from_raw_parts(slab_ptr.add(start + skip), read.len) };
            let mut buf = pool.alloc(read.len);
            buf.put_slice(bytes);
            #[cfg(test)]
            file.test.direct_reads.fetch_add(1, Ordering::Relaxed);
            (read.index, buf.into())
        };
        let _ = tx.send(Ok(item));
        Ok(())
    };

    // A failed submission accepted none of the requests passed to it. The first of them may
    // be one the kernel rejects (for example, a superset ending beyond the largest signed
    // file offset), so it is served here and the rest are submitted again.
    let mut events = vec![IoEvent::default(); n];
    let mut next = 0;
    let mut accepted = 0;
    let mut completed = 0;
    while next < n {
        let count = (n - next).min(IOCBS_PER_SUBMIT);
        // SAFETY: `ptrs[next..next + count]` are valid iocbs whose buffers lie in the slab,
        // which outlives every accepted request. The context accepts at least `n` requests
        // because `n <= NR_EVENTS`.
        let r = unsafe {
            libc::syscall(
                libc::SYS_io_submit,
                active.0,
                count as libc::c_long,
                ptrs.as_ptr().add(next),
            )
        };
        if r < 0 {
            let _ = tx.send(Ok(read_positioned(file, pool, &reads[next])?));
            next += 1;
            continue;
        }
        next += r as usize;
        accepted += r as usize;
        if next < n {
            let got = reap(&active, &mut events[..accepted - completed], false)?;
            events[..got].iter().try_for_each(&deliver)?;
            completed += got;
        }
    }
    while completed < accepted {
        let got = reap(&active, &mut events[..accepted - completed], true)?;
        events[..got].iter().try_for_each(&deliver)?;
        completed += got;
    }
    Ok(active)
}

/// Reap up to `events.len()` completions from `ctx` into `events`, waiting for at least one
/// when `wait` is set and returning whatever has landed otherwise.
fn reap(ctx: &Context, events: &mut [IoEvent], wait: bool) -> Result<usize, Error> {
    if events.is_empty() {
        return Ok(0);
    }
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let timeout: *const libc::timespec = if wait { std::ptr::null() } else { &zero };
    loop {
        // SAFETY: `events` has room for `events.len()` events and `timeout` is null or a
        // valid timespec.
        let got = unsafe {
            libc::syscall(
                libc::SYS_io_getevents,
                ctx.0,
                wait as libc::c_long,
                events.len() as libc::c_long,
                events.as_mut_ptr(),
                timeout,
            )
        };
        if got >= 0 {
            return Ok(got as usize);
        }

        // A signal interrupts the wait before it reaps anything, and the kernel never
        // restarts it.
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err.into());
        }
    }
}

/// Serve `reads` without native AIO: one blocking task per read, as
/// [`crate::Blob::read_at`] does.
pub(super) fn read_positioned_each(
    file: &Arc<Shared>,
    pool: &BufferPool,
    reads: Vec<Read>,
    tx: &tokio::sync::mpsc::UnboundedSender<Completion>,
) {
    for read in reads {
        let (file, pool, tx) = (file.clone(), pool.clone(), tx.clone());
        task::spawn_blocking(move || {
            let _ = tx.send(read_positioned(&file, &pool, &read));
        });
    }
}

/// Run one submission on the calling (blocking) thread.
pub(super) fn run(
    file: &Arc<Shared>,
    pool: &BufferPool,
    reads: Vec<Read>,
    tx: &tokio::sync::mpsc::UnboundedSender<Completion>,
) {
    // Without a direct descriptor (the filesystem rejects direct I/O, or a transient open
    // failure) or a context (for example, the kernel's request limit is exhausted), the
    // submission is served one blocking task per read, as read_at would.
    let Some(direct) = direct(file) else {
        return read_positioned_each(file, pool, reads, tx);
    };
    let Some(ctx) = take_context() else {
        return read_positioned_each(file, pool, reads, tx);
    };
    match submit(file, direct, pool, ctx, reads, tx) {
        Ok(ctx) => CONTEXTS.lock().push(ctx),
        Err(err) => {
            let _ = tx.send(Err(err));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, BufferPoolConfig, Storage as _,
        storage::{
            Layout,
            tokio::{Config, Storage},
        },
        telemetry::metrics::Registry,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    fn pool() -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default())
    }

    /// Open a blob holding `data` in a fresh directory that supports direct I/O.
    async fn direct_blob(label: &str, data: Vec<u8>) -> (Storage, Blob, PathBuf) {
        let directory =
            std::env::temp_dir().join(format!("storage_tokio_aio_{label}_{}", std::process::id()));
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL), pool());
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

    #[tokio::test]
    async fn test_failed_submission_keeps_slab_until_reads_complete() {
        const LEN: usize = 64 << 10;
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        let (storage, blob, directory) = direct_blob("failed_submission", vec![0xAB; LEN]).await;
        let pool = pool();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        // The kernel accepts the first read and rejects the second (its offset exceeds the
        // largest signed file offset), whose positioned read then fails, so the submission
        // returns an error while the first read may still be in flight. A slab released
        // before that read completes receives the file's bytes after its memory is reused.
        for _ in 0..20 {
            let reads = vec![
                Read {
                    index: 0,
                    offset: 0,
                    len: LEN,
                },
                Read {
                    index: 1,
                    offset: 1 << 63,
                    len: block,
                },
            ];
            let ctx = take_context().unwrap();
            let direct = direct(&blob.shared).unwrap();
            assert!(submit(&blob.shared, direct, &pool, ctx, reads, &tx).is_err());

            let canary = IoBufMut::zeroed_with_alignment(LEN + block, NZUsize!(block));
            std::thread::sleep(Duration::from_millis(10));
            assert!(!canary.as_ref().contains(&0xAB));
        }
        remove(storage, blob, directory).await;
    }

    #[tokio::test]
    async fn test_submission_survives_signals() {
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
        let reads = vec![Read {
            index: 0,
            offset: blob.data_offset,
            len: LEN,
        }];
        let shared = blob.shared.clone();
        let done = Arc::new(AtomicBool::new(false));
        let (thread_tx, thread_rx) = std::sync::mpsc::channel();
        let submitter = {
            let done = done.clone();
            std::thread::spawn(move || {
                // SAFETY: pthread_self has no preconditions.
                thread_tx.send(unsafe { libc::pthread_self() }).unwrap();
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                let ctx = take_context().unwrap();
                let direct = direct(&shared).unwrap();
                let result = submit(&shared, direct, &pool(), ctx, reads, &tx);
                done.store(true, Ordering::Release);
                (result.is_ok(), rx.try_recv().ok(), rx.try_recv().is_err())
            })
        };
        let thread = thread_rx.recv().unwrap();
        while !done.load(Ordering::Acquire) {
            // SAFETY: the submitter has not been joined, so its thread id is still valid.
            unsafe { libc::pthread_kill(thread, libc::SIGUSR1) };
            std::thread::sleep(Duration::from_micros(10));
        }
        let (submitted, first, drained) = submitter.join().unwrap();

        // SAFETY: restores the action saved above.
        unsafe { libc::sigaction(libc::SIGUSR1, &previous, std::ptr::null_mut()) };
        assert!(submitted);
        assert!(drained);
        let Some(Ok((0, bufs))) = first else {
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
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL), pool());
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
        let reads = ranges
            .iter()
            .enumerate()
            .map(|(index, &(offset, len))| Read {
                index,
                offset: offset + blob.data_offset,
                len,
            })
            .collect();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        read_positioned_each(&blob.shared, &pool(), reads, &tx);
        drop(tx);
        let mut served = Vec::new();
        let mut failed = 0;
        while let Some(item) = rx.recv().await {
            match item {
                Ok(item) => served.push(item),
                Err(_) => failed += 1,
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
