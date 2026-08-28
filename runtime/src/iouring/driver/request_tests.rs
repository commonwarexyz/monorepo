use super::*;
use crate::iouring::{RingConfig, driver::testing::TestLoop};
use std::{
    env,
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::net::UnixStream,
    },
    panic::{AssertUnwindSafe, catch_unwind},
    process::Command,
    time::Duration,
};

fn make_socket_fd() -> Arc<OwnedFd> {
    let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
    Arc::new(left.into())
}

fn make_file_fd() -> Arc<File> {
    let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
    // SAFETY: `left` is a valid owned fd and is transferred into `File`.
    let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
    Arc::new(file)
}

fn make_read_request(cache: Cache) -> ReadAtRequest {
    ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache,
    }
}

fn make_write_request(cache: Cache, state: WriteAtState) -> WriteAtRequest {
    WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state,
        cache,
    }
}

fn unwrap_send(output: RequestOutput) -> Result<(), Error> {
    match output {
        RequestOutput::Send(result) => result.map_err(|e| *e),
        _ => panic!("expected send output"),
    }
}

fn unwrap_recv(output: RequestOutput) -> Result<(IoBufMut, usize), (IoBufMut, Error)> {
    match output {
        RequestOutput::Recv(result) => result.map_err(|e| *e),
        _ => panic!("expected recv output"),
    }
}

fn unwrap_accept(output: RequestOutput) -> Result<(OwnedFd, SocketAddr), Error> {
    match output {
        RequestOutput::Accept(result) => result.map_err(|e| *e),
        _ => panic!("expected accept output"),
    }
}

fn unwrap_connect(output: RequestOutput) -> Result<(), Error> {
    match output {
        RequestOutput::Connect(result) => result.map_err(|e| *e),
        _ => panic!("expected connect output"),
    }
}

fn unwrap_read_at(output: RequestOutput) -> Result<IoBufMut, (IoBufMut, Error)> {
    match output {
        RequestOutput::ReadAt(result) => result.map_err(|e| *e),
        _ => panic!("expected read-at output"),
    }
}

fn unwrap_write_at(output: RequestOutput) -> Result<(), Error> {
    match output {
        RequestOutput::WriteAt(result) => result.map_err(|e| *e),
        _ => panic!("expected write-at output"),
    }
}

fn unwrap_sync(output: RequestOutput) -> Result<(), Error> {
    match output {
        RequestOutput::Sync(result) => result.map_err(|e| *e),
        _ => panic!("expected sync output"),
    }
}

#[test]
fn test_cqe_result_from_raw_retryable_codes() {
    for code in [-libc::EAGAIN, -libc::EWOULDBLOCK, -libc::EINTR] {
        assert!(matches!(
            CqeResult::from_raw(code, WaiterState::Active { target_tick: None }),
            CqeResult::Retry
        ));
    }

    for code in [0, -libc::EINVAL, -libc::ETIMEDOUT] {
        assert!(!matches!(
            CqeResult::from_raw(code, WaiterState::Active { target_tick: None }),
            CqeResult::Retry
        ));
    }
}

#[test]
fn test_single_buffer_sqe_len_boundaries() {
    let max = i32::MAX as usize;
    assert_eq!(single_buffer_sqe_len(0), 0);
    assert_eq!(single_buffer_sqe_len(max), i32::MAX as u32);
    assert_eq!(single_buffer_sqe_len(max + 1), i32::MAX as u32);
    assert_eq!(single_buffer_sqe_len(usize::MAX), i32::MAX as u32);
}

#[test]
fn test_unsolicited_ecanceled_remains_an_error() {
    assert!(matches!(
        CqeResult::from_raw(
            -libc::ECANCELED,
            WaiterState::Active { target_tick: None }
        ),
        CqeResult::Error(code) if code == -libc::ECANCELED
    ));
}

#[test]
fn test_active_send_paths() {
    // Verify send state handling across retry, timeout, success, and hard-failure CQEs.

    // Retryable CQEs should simply requeue while the request is still active.
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
            .is_none()
    );

    // Partial progress followed by a retry after timeout should resolve to timeout.
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 2)
            .is_none()
    );
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            -libc::EAGAIN,
        )
        .expect("terminal CQE");
    assert!(matches!(unwrap_send(output), Err(Error::Timeout)));

    // Partial progress after timeout must also resolve to timeout rather than requeueing.
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 2)
            .is_none()
    );
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            1,
        )
        .expect("terminal CQE");
    assert!(matches!(unwrap_send(output), Err(Error::Timeout)));

    // A canceled send that comes back as ECANCELED should also resolve to timeout.
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            -libc::ECANCELED,
        )
        .expect("terminal CQE");
    assert!(matches!(unwrap_send(output), Err(Error::Timeout)));

    // Vectored writes should advance across multiple CQEs and complete once all bytes are sent.
    let mut vectored = IoBufs::default();
    vectored.append(IoBuf::from(b"abc"));
    vectored.append(IoBuf::from(b"de"));
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: vectored.into(),
        deadline: None,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 3)
            .is_none()
    );
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 2)
        .expect("terminal CQE");
    unwrap_send(output).expect("send should complete successfully");

    // Zero-byte and hard-error CQEs should both surface as send failures.
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 0)
        .expect("terminal CQE");
    assert!(matches!(unwrap_send(output), Err(Error::SendFailed)));

    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
        .expect("terminal CQE");
    assert!(matches!(unwrap_send(output), Err(Error::SendFailed)));

    // A fully successful CQE still wins even if timeout was already requested.
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            5,
        )
        .expect("terminal CQE");
    unwrap_send(output).expect("send should complete successfully");
}

#[test]
fn test_active_recv_paths() {
    // Verify recv state handling across buffered progress, timeout, success, and hard failure.

    // Retryable CQEs should requeue while the recv is still active.
    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
            .is_none()
    );

    // Non-exact recv should complete as soon as any positive byte count arrives.
    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: false,
        deadline: None,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 3)
        .expect("terminal CQE");
    let (_buf, read) = unwrap_recv(output).expect("recv should complete successfully");
    assert_eq!(read, 3);

    // Exact recv should requeue after partial progress, but timeout wins if the follow-up CQE
    // arrives after cancellation was requested.
    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 3)
            .is_none()
    );
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            1,
        )
        .expect("terminal CQE");
    assert!(matches!(unwrap_recv(output), Err((_, Error::Timeout))));

    // Retryable and ECANCELED completions after timeout should both resolve to timeout.
    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            -libc::EINTR,
        )
        .expect("terminal CQE");
    assert!(matches!(unwrap_recv(output), Err((_, Error::Timeout))));

    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            -libc::ECANCELED,
        )
        .expect("terminal CQE");
    assert!(matches!(unwrap_recv(output), Err((_, Error::Timeout))));

    // A fully successful CQE still wins after timeout was requested.
    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    let output = request
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            5,
        )
        .expect("terminal CQE");
    let (_buf, read) = unwrap_recv(output).expect("recv should complete successfully");
    assert_eq!(read, 5);

    // A kernel completion larger than the requested remaining length must
    // trip the local invariant before it can corrupt buffer state.
    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    let overflow = catch_unwind(AssertUnwindSafe(|| {
        let _ = request.on_cqe(WaiterState::Active { target_tick: None }, 6);
    }));
    assert!(overflow.is_err());

    // Zero-byte and hard-error CQEs should both surface as recv failures.
    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 0)
        .expect("terminal CQE");
    assert!(matches!(unwrap_recv(output), Err((_, Error::RecvFailed))));

    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
        .expect("terminal CQE");
    assert!(matches!(unwrap_recv(output), Err((_, Error::RecvFailed))));
}

#[test]
fn test_active_read_at_paths() {
    // Verify read-at state handling across retry, EOF, and hard failure.

    // Retryable CQEs should requeue the positioned read.
    let mut request = Request::ReadAt(ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache: Cache::Enabled,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
            .is_none()
    );

    // Partial reads should requeue until the full logical length is satisfied.
    let mut request = Request::ReadAt(ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache: Cache::Enabled,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 2)
            .is_none()
    );
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 3)
        .expect("terminal CQE");
    unwrap_read_at(output).expect("read should complete successfully");

    // EOF and hard-error CQEs should map to the storage read error surface.
    let mut request = Request::ReadAt(ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache: Cache::Enabled,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 0)
        .expect("terminal CQE");
    assert!(matches!(
        unwrap_read_at(output),
        Err((_, Error::BlobInsufficientLength))
    ));

    let mut request = Request::ReadAt(ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache: Cache::Enabled,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
        .expect("terminal CQE");
    match unwrap_read_at(output) {
        Err((_, Error::Io(err))) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
        other => panic!("expected EIO read failure, got {other:?}"),
    }
}

#[test]
fn test_uncached_read_fallback_preserves_progress_and_is_shared_with_writes() {
    let supported = Arc::new(AtomicBool::new(true));
    let mut read = make_read_request(Cache::Disabled(supported.clone()));

    assert_eq!(read.rw_flags(), libc::RWF_DONTCACHE);
    assert!(
        read.on_cqe(WaiterState::Active { target_tick: None }, 2)
            .is_none()
    );
    assert_eq!(read.read, 2);
    assert_eq!(read.rw_flags(), libc::RWF_DONTCACHE);

    assert!(
        read.on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
            .is_none()
    );
    assert_eq!(read.read, 2);
    assert!(!supported.load(Ordering::Relaxed));
    assert_eq!(read.rw_flags(), 0);

    let mut sibling_write = make_write_request(Cache::Disabled(supported), WriteAtState::Writing);
    assert_eq!(sibling_write.rw_flags(), 0);

    let supported = Arc::new(AtomicBool::new(true));
    let mut write = make_write_request(Cache::Disabled(supported.clone()), WriteAtState::Writing);
    assert_eq!(write.rw_flags(), libc::RWF_DONTCACHE);
    assert!(
        write
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
            .is_none()
    );
    let mut sibling_read = make_read_request(Cache::Disabled(supported));
    assert_eq!(sibling_read.rw_flags(), 0);

    let supported = Arc::new(AtomicBool::new(true));
    let mut failing_read = make_read_request(Cache::Disabled(supported.clone()));
    assert_eq!(failing_read.rw_flags(), libc::RWF_DONTCACHE);
    match failing_read
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
        .expect("hard read error should be terminal")
    {
        Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
        other => panic!("expected EIO read failure, got {other:?}"),
    }
    assert!(supported.load(Ordering::Relaxed));
}

#[test]
fn test_cached_positional_io_reports_unsupported_as_terminal_error() {
    let mut read = make_read_request(Cache::Enabled);
    let read_result = read
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
        .expect("cached read EOPNOTSUPP should be terminal");
    match read_result {
        Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP)),
        other => panic!("expected EOPNOTSUPP read failure, got {other:?}"),
    }
    assert_eq!(read.read, 0);

    let mut write = make_write_request(Cache::Enabled, WriteAtState::Writing);
    let write_result = write
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
        .expect("cached write EOPNOTSUPP should be terminal");
    match write_result {
        Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP)),
        other => panic!("expected EOPNOTSUPP write failure, got {other:?}"),
    }
    assert_eq!(write.written, 0);
    assert_eq!(write.write.remaining_len(), 5);
    assert!(matches!(write.state, WriteAtState::Writing));
}

#[test]
fn test_queued_cache_fallbacks_retry() {
    let supported = Arc::new(AtomicBool::new(true));
    let mut first = make_read_request(Cache::Disabled(supported.clone()));
    let mut second = make_read_request(Cache::Disabled(supported.clone()));

    assert_eq!(first.rw_flags(), libc::RWF_DONTCACHE);
    assert_eq!(second.rw_flags(), libc::RWF_DONTCACHE);
    assert!(
        first
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
            .is_none()
    );
    assert!(
        second
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
            .is_none()
    );
    assert!(!supported.load(Ordering::Relaxed));
    assert_eq!(first.rw_flags(), 0);
    assert_eq!(second.rw_flags(), 0);
}

#[test]
fn test_active_write_at_paths() {
    // Verify write-at state handling across retry, partial progress, and failure.

    // Retryable CQEs should requeue the positioned write.
    let mut write = WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    };
    assert_eq!(write.rw_flags(), 0);
    let mut request = Request::WriteAt(write);
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
            .is_none()
    );

    // Single-buffer writes should track partial progress until complete.
    let mut request = Request::WriteAt(WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 2)
            .is_none()
    );
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 3)
        .expect("terminal CQE");
    unwrap_write_at(output).expect("write should complete successfully");

    // Vectored writes should advance across buffer boundaries and then complete.
    let mut vectored = IoBufs::default();
    vectored.append(IoBuf::from(b"abc"));
    vectored.append(IoBuf::from(b"de"));
    let mut request = Request::WriteAt(WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: vectored.into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 4)
            .is_none()
    );
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 1)
        .expect("terminal CQE");
    unwrap_write_at(output).expect("vectored write should complete successfully");

    // Zero-byte and hard-error CQEs should surface as write failures.
    let mut request = Request::WriteAt(WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 0)
        .expect("terminal CQE");
    assert!(matches!(unwrap_write_at(output), Err(Error::WriteFailed)));

    let mut request = Request::WriteAt(WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
        .expect("terminal CQE");
    match unwrap_write_at(output) {
        Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
        other => panic!("expected EIO write failure, got {other:?}"),
    }

    // A durable write reports write errors before entering its sync phase.
    let mut write = WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::WritingBeforeSync,
        cache: Cache::Enabled,
    };
    assert_eq!(write.rw_flags(), 0);
    let mut request = Request::WriteAt(write);
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINVAL)
        .expect("terminal CQE");
    match unwrap_write_at(output) {
        Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EINVAL)),
        other => panic!("expected EINVAL write failure, got {other:?}"),
    }
}

#[test]
fn test_single_submission_sync_write_finishes_with_datasync() {
    let mut request = WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::WritingBeforeSync,
        cache: Cache::Enabled,
    };

    let write = request.build_sqe();
    assert_eq!(write.get_opcode(), u32::from(opcode::Write::CODE));
    assert_eq!(request.rw_flags(), 0);
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 5)
            .is_none()
    );
    assert!(matches!(request.state, WriteAtState::Syncing));

    let sync = request.build_sqe();
    assert_eq!(sync.get_opcode(), u32::from(opcode::Fsync::CODE));
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR)
            .is_none()
    );
    assert!(matches!(request.state, WriteAtState::Syncing));
    assert!(matches!(
        request.on_cqe(WaiterState::Active { target_tick: None }, 0),
        Some(Ok(()))
    ));
}

#[test]
fn test_uncached_durable_write_retries_without_hint_when_unsupported() {
    let supported = Arc::new(AtomicBool::new(true));
    let mut request = make_write_request(
        Cache::Disabled(supported.clone()),
        WriteAtState::WritingBeforeSync,
    );

    assert_eq!(request.rw_flags(), libc::RWF_DONTCACHE);
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
            .is_none()
    );
    assert!(!supported.load(Ordering::Relaxed));
    request.cache = Cache::Disabled(supported);
    assert_eq!(request.rw_flags(), 0);
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 5)
            .is_none()
    );
    assert!(matches!(request.state, WriteAtState::Syncing));
    assert!(matches!(
        request.on_cqe(WaiterState::Active { target_tick: None }, 0),
        Some(Ok(()))
    ));
}

#[test]
fn test_sync_write_reports_trailing_datasync_error() {
    let mut request = make_write_request(Cache::Enabled, WriteAtState::WritingBeforeSync);

    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 5)
            .is_none()
    );
    assert!(matches!(request.state, WriteAtState::Syncing));
    let result = request
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
        .expect("data-sync failure should be terminal");
    match result {
        Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
        other => panic!("expected EIO data-sync failure, got {other:?}"),
    }
}

#[test]
fn test_multi_submission_sync_write_finishes_with_datasync() {
    let mut bufs = IoBufs::default();
    for _ in 0..=IOVEC_BATCH_SIZE {
        bufs.append(IoBuf::from(b"x"));
    }
    let mut request = WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: bufs.into(),
        state: WriteAtState::WritingBeforeSync,
        cache: Cache::Enabled,
    };

    let first = request.build_sqe();
    assert_eq!(first.get_opcode(), u32::from(opcode::Writev::CODE));
    assert!(
        request
            .on_cqe(
                WaiterState::Active { target_tick: None },
                IOVEC_BATCH_SIZE as i32
            )
            .is_none()
    );
    assert!(matches!(request.state, WriteAtState::WritingBeforeSync));

    let second = request.build_sqe();
    assert_eq!(second.get_opcode(), u32::from(opcode::Writev::CODE));
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 1)
            .is_none()
    );
    assert!(matches!(request.state, WriteAtState::Syncing));

    let sync = request.build_sqe();
    assert_eq!(sync.get_opcode(), u32::from(opcode::Fsync::CODE));
    assert!(matches!(
        request.on_cqe(WaiterState::Active { target_tick: None }, 0),
        Some(Ok(()))
    ));
}

#[test]
fn test_active_sync_paths() {
    // Verify sync state handling across retry, error conversion, and success.

    // Retryable CQEs should requeue the data-sync request.
    let mut request = Request::Sync(SyncRequest {
        file: make_file_fd(),
    });
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR)
            .is_none()
    );

    // Hard errors should round-trip as std::io::Error values.
    let mut request = Request::Sync(SyncRequest {
        file: make_file_fd(),
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
        .expect("terminal CQE");
    let err = unwrap_sync(output).expect_err("expected hard error");
    match err {
        Error::Io(err) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
        other => panic!("expected io error, got {other:?}"),
    }

    // Both zero and positive CQE results should count as sync success.
    let mut request = Request::Sync(SyncRequest {
        file: make_file_fd(),
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 0)
        .expect("terminal CQE");
    unwrap_sync(output).expect("sync should succeed on zero");

    let mut request = Request::Sync(SyncRequest {
        file: make_file_fd(),
    });
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 1)
        .expect("terminal CQE");
    unwrap_sync(output).expect("sync should succeed on positive");
}

#[test]
fn test_fail_uses_fallback_results() {
    // Network sends and recvs should preserve their wrapper-specific fallback errors.
    let request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    assert!(matches!(
        unwrap_send(request.fail()),
        Err(Error::SendFailed)
    ));

    let request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    assert!(matches!(
        unwrap_recv(request.fail()),
        Err((_, Error::RecvFailed))
    ));

    // Accepts and connects both collapse to the connection fallback.
    let request = Request::Accept(AcceptRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::zeroed(),
        deadline: None,
    });
    assert!(matches!(
        unwrap_accept(request.fail()),
        Err(Error::ConnectionFailed)
    ));

    let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let request = Request::Connect(ConnectRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::boxed_from_socket_addr(&target),
        deadline: None,
    });
    assert!(matches!(
        unwrap_connect(request.fail()),
        Err(Error::ConnectionFailed)
    ));

    // Storage reads and writes should surface the corresponding storage wrapper errors.
    let request = Request::ReadAt(ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache: Cache::Enabled,
    });
    assert!(matches!(
        unwrap_read_at(request.fail()),
        Err((_, Error::ReadFailed))
    ));

    let request = Request::WriteAt(WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    });
    assert!(matches!(
        unwrap_write_at(request.fail()),
        Err(Error::WriteFailed)
    ));

    // A sync that never ran must fail rather than report durability.
    let request = Request::Sync(SyncRequest {
        file: make_file_fd(),
    });
    assert!(matches!(unwrap_sync(request.fail()), Err(Error::Closed)));
}

#[test]
fn test_finish_timeout_delivers_timeout_results() {
    // Network operations should map directly to the shared logical timeout.
    let mut request = Request::Send(SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    });
    assert!(matches!(
        unwrap_send(request.interrupt(Error::Timeout)),
        Err(Error::Timeout)
    ));

    let mut request = Request::Recv(RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    });
    assert!(matches!(
        unwrap_recv(request.interrupt(Error::Timeout)),
        Err((_, Error::Timeout))
    ));

    // Accepts and connects also surface the shared logical timeout.
    let mut request = Request::Accept(AcceptRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::zeroed(),
        deadline: None,
    });
    assert!(matches!(
        unwrap_accept(request.interrupt(Error::Timeout)),
        Err(Error::Timeout)
    ));

    let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let mut request = Request::Connect(ConnectRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::boxed_from_socket_addr(&target),
        deadline: None,
    });
    assert!(matches!(
        unwrap_connect(request.interrupt(Error::Timeout)),
        Err(Error::Timeout)
    ));
}

#[test]
fn test_shutdown_cancellation_resolves_retry_and_partial_races() {
    // Network retries become Closed during shutdown, while storage retries
    // continue until their kernel references retire.
    let shutdown = WaiterState::CancelRequested {
        reason: CancelReason::Shutdown,
    };

    // Retry races across all four network kinds.
    let mut send = SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    };
    assert!(matches!(
        send.on_cqe(shutdown, -libc::EAGAIN),
        Some(Err(Error::Closed))
    ));

    let mut recv = RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    };
    assert!(matches!(
        recv.on_cqe(shutdown, -libc::EAGAIN),
        Some(Err(Error::Closed))
    ));

    let mut accept = AcceptRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::zeroed(),
        deadline: None,
    };
    assert!(matches!(
        accept.on_cqe(shutdown, -libc::EAGAIN),
        Some(Err(Error::Closed))
    ));

    let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let mut connect = ConnectRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::boxed_from_socket_addr(&target),
        deadline: None,
    };
    assert!(matches!(
        connect.on_cqe(shutdown, -libc::EAGAIN),
        Some(Err(Error::Closed))
    ));

    // Partial-progress races: a send with bytes still unsent and an
    // exact recv with bytes still missing.
    let mut send = SendRequest {
        fd: make_socket_fd(),
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        deadline: None,
    };
    assert!(matches!(send.on_cqe(shutdown, 2), Some(Err(Error::Closed))));

    let mut recv = RecvRequest {
        fd: make_socket_fd(),
        buf: IoBufMut::with_capacity(5),
        offset: 0,
        len: 5,
        exact: true,
        deadline: None,
    };
    assert!(matches!(recv.on_cqe(shutdown, 2), Some(Err(Error::Closed))));

    // Storage kinds under the same shutdown state carry two distinct
    // expectations. First, ECANCELED (classified as a cancellation only
    // because the waiter already requested one) resolves to Closed. The
    // owned buffer stays inside the request for the waiter layer to
    // return with the parked output.
    let mut read_at = ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache: Cache::Enabled,
    };
    assert!(matches!(
        read_at.on_cqe(shutdown, -libc::ECANCELED),
        Some(Err(Error::Closed))
    ));
    assert_eq!(read_at.buf.capacity(), 5, "read buffer must stay owned");

    let mut write_at = WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    };
    assert!(matches!(
        write_at.on_cqe(shutdown, -libc::ECANCELED),
        Some(Err(Error::Closed))
    ));

    let mut sync = SyncRequest {
        file: make_file_fd(),
    };
    assert!(matches!(
        sync.on_cqe(shutdown, -libc::ECANCELED),
        Some(Err(Error::Closed))
    ));

    // Second, a retry errno under the same shutdown state yields None:
    // unlike the four network kinds above, the storage on_cqe arms map
    // CqeResult::Retry to None unconditionally (CqeResult::from_raw
    // classifies retry errnos before cancellation state), and the
    // pending cancellation is resolved later by the staging layer when
    // the requeued request is restaged.
    let mut read_at = ReadAtRequest {
        file: make_file_fd(),
        offset: 0,
        len: 5,
        read: 0,
        buf: IoBufMut::with_capacity(5),
        cache: Cache::Enabled,
    };
    assert!(read_at.on_cqe(shutdown, -libc::EAGAIN).is_none());

    let mut write_at = WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: IoBufs::from(IoBuf::from(b"hello")).into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    };
    assert!(write_at.on_cqe(shutdown, -libc::EAGAIN).is_none());

    let mut sync = SyncRequest {
        file: make_file_fd(),
    };
    assert!(sync.on_cqe(shutdown, -libc::EAGAIN).is_none());
}

fn make_accept() -> AcceptRequest {
    AcceptRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::zeroed(),
        deadline: None,
    }
}

#[test]
fn test_active_accept_paths() {
    // Transient results retry with another SQE.
    let mut accept = make_accept();
    assert!(
        accept
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
            .is_none()
    );

    // Hard errors are terminal connection failures.
    assert!(matches!(
        accept.on_cqe(
            WaiterState::Active { target_tick: None },
            -libc::ECONNABORTED
        ),
        Some(Err(Error::ConnectionFailed))
    ));

    // Cancellation after a timeout maps to a logical timeout.
    let mut accept = make_accept();
    assert!(matches!(
        accept.on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            -libc::ECANCELED
        ),
        Some(Err(Error::Timeout))
    ));

    // A success CQE takes ownership of the descriptor and decodes the
    // peer address, even when cancellation raced the completion.
    let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let (left, _right) = UnixStream::pair().unwrap();
    let raw_fd = left.into_raw_fd();
    let mut accept = make_accept();
    accept.addr = RawSocketAddr::boxed_from_socket_addr(&peer);
    let (owned, addr) = accept
        .on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            raw_fd,
        )
        .expect("missing accept result")
        .expect("racing accept success should win over cancellation");
    assert_eq!(addr, peer);
    assert_eq!(owned.as_raw_fd(), raw_fd);

    // An undecodable peer address still takes (and releases) ownership of
    // the accepted descriptor.
    let (left, _right) = UnixStream::pair().unwrap();
    let raw_fd = left.into_raw_fd();
    let mut accept = make_accept();
    assert!(matches!(
        accept.on_cqe(WaiterState::Active { target_tick: None }, raw_fd),
        Some(Err(Error::ConnectionFailed))
    ));
}

/// Ground truth for what a vectored `build_sqe` must describe to the
/// kernel: `chunks_vectored` is the same call `build_sqe` uses to fill
/// the scratch and compute the SQE's iovec count, so its output pins the
/// submitted pointers, lengths, and `iovcnt` without cracking the opaque
/// squeue entry.
fn expected_iovecs(bufs: &IoBufs, cap: usize) -> Vec<(*const u8, usize)> {
    use crate::Buf as _;
    let mut slices = vec![std::io::IoSlice::new(&[]); cap];
    let filled = bufs.chunks_vectored(&mut slices);
    slices[..filled]
        .iter()
        .map(|slice| (slice.as_ptr(), slice.len()))
        .collect()
}

/// Assert the scratch prefix matches the ground-truth chunk pointers and
/// lengths (pointer identity, not mere non-nullness: a stale entry can
/// hold a plausible non-null pointer into freed memory).
fn check_vectored_scratch(write: &WriteBuffers, expected_lens: &[usize]) {
    let WriteBuffers::Vectored(v) = write else {
        panic!("expected vectored write buffers");
    };
    let expected = expected_iovecs(&v.bufs, v.iovecs.len());
    assert_eq!(expected.len(), expected_lens.len());
    for (i, (ptr, len)) in expected.iter().enumerate() {
        assert_eq!(*len, expected_lens[i], "iovec {i} length");
        assert_eq!(
            v.iovecs[i].iov_base.cast::<u8>().cast_const(),
            *ptr,
            "iovec {i} must point at the current chunk"
        );
        assert_eq!(v.iovecs[i].iov_len, *len, "iovec {i} scratch length");
    }
}

#[test]
fn test_vectored_build_sqe_refreshes_iovecs_across_restaging() {
    // Verify the reusable iovec scratch is refreshed from the co-owned
    // buffers on every staging: after partial progress drops a fully
    // consumed chunk (freeing its backing memory), the rebuilt SQE must
    // describe only the remaining bytes and never reuse a stale entry.
    let mut vectored = IoBufs::default();
    vectored.append(IoBuf::from(b"abc"));
    vectored.append(IoBuf::from(b"defg"));
    vectored.append(IoBuf::from(b"hi"));
    let mut request = SendRequest {
        fd: make_socket_fd(),
        write: vectored.into(),
        deadline: None,
    };

    // First staging describes all three chunks.
    let _ = request.build_sqe();
    check_vectored_scratch(&request.write, &[3, 4, 2]);

    // Consume the first chunk plus one byte of the second: the freed
    // chunk's iovec entry is now stale until the next staging.
    assert!(
        request
            .on_cqe(WaiterState::Active { target_tick: None }, 4)
            .is_none()
    );

    // Restaging refreshes the scratch from the advanced buffers.
    let _ = request.build_sqe();
    check_vectored_scratch(&request.write, &[3, 2]);

    // Finish the request: the remaining five bytes complete it.
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 5)
        .expect("terminal CQE");
    output.expect("vectored send should complete");
}

#[test]
fn test_vectored_send_builds_sendmsg() {
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<SendRequest>();

    let mut vectored = IoBufs::default();
    vectored.append(IoBuf::from(b"hello"));
    vectored.append(IoBuf::from(b" world"));
    let mut request = SendRequest {
        fd: make_socket_fd(),
        write: vectored.into(),
        deadline: None,
    };

    let sqe = request.build_sqe();
    assert_eq!(sqe.get_opcode(), u32::from(opcode::SendMsg::CODE));
    let WriteBuffers::Vectored(v) = &request.write else {
        panic!("expected vectored write buffers");
    };
    assert_eq!(v.message.msg_iov, v.iovecs.as_ptr().cast_mut());
    assert_eq!(v.message.msg_iovlen, 2);
}

#[test]
fn test_send_to_closed_socket_does_not_raise_sigpipe() {
    const CHILD_ENV: &str = "COMMONWARE_TEST_IOURING_SEND_SIGPIPE_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        // SAFETY: this child process runs only this test on one test thread,
        // before creating the loop or any operation that can raise SIGPIPE.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }

        let mut harness = TestLoop::new(RingConfig::default());
        let handle = harness.clone_handle();
        // The single-buffer and vectored paths each use an independent
        // closed socket, so one failed request cannot affect the other.
        let (sender, receiver) = UnixStream::pair().expect("failed to create socket pair");
        drop(receiver);
        let result = harness.block_on(handle.send(
            Arc::new(sender.into()),
            IoBuf::from(b"hello").into(),
            Instant::now() + Duration::from_secs(5),
        ));
        assert!(matches!(result, Err(Error::SendFailed)));

        let (sender, receiver) = UnixStream::pair().expect("failed to create socket pair");
        drop(receiver);
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"hello"));
        vectored.append(IoBuf::from(b" world"));
        let result = harness.block_on(handle.send(
            Arc::new(sender.into()),
            vectored,
            Instant::now() + Duration::from_secs(5),
        ));
        assert!(matches!(result, Err(Error::SendFailed)));
        return;
    }

    let status = Command::new(env::current_exe().expect("missing current test executable"))
        .arg("test_send_to_closed_socket_does_not_raise_sigpipe")
        .arg("--test-threads=1")
        .env(CHILD_ENV, "1")
        .status()
        .expect("failed to run SIGPIPE child test");
    assert!(status.success(), "SIGPIPE child failed with {status}");
}

#[test]
fn test_vectored_build_sqe_caps_iovec_batch() {
    // More chunks than IOVEC_BATCH_SIZE must clamp the SQE to the scratch
    // capacity, and later stagings pick up the tail as earlier chunks drain.
    let mut vectored = IoBufs::default();
    for _ in 0..(IOVEC_BATCH_SIZE + 4) {
        vectored.append(IoBuf::from(b"x"));
    }
    let mut request = WriteAtRequest {
        file: make_file_fd(),
        offset: 0,
        written: 0,
        write: vectored.into(),
        state: WriteAtState::Writing,
        cache: Cache::Enabled,
    };

    let _ = request.build_sqe();
    {
        let WriteBuffers::Vectored(v) = &request.write else {
            panic!("expected vectored write buffers");
        };
        // The scratch (and so the submitted iovcnt) is clamped to the
        // batch size even though more chunks are queued.
        assert_eq!(v.iovecs.len(), IOVEC_BATCH_SIZE);
    }
    check_vectored_scratch(&request.write, &[1; IOVEC_BATCH_SIZE]);

    // Drain one full batch, and the remaining four chunks stage next.
    assert!(
        request
            .on_cqe(
                WaiterState::Active { target_tick: None },
                IOVEC_BATCH_SIZE as i32
            )
            .is_none()
    );
    let _ = request.build_sqe();
    check_vectored_scratch(&request.write, &[1, 1, 1, 1]);
    let output = request
        .on_cqe(WaiterState::Active { target_tick: None }, 4)
        .expect("terminal CQE");
    output.expect("vectored write should complete");
}

#[test]
fn test_accept_build_sqe_resets_addr_len() {
    // The kernel treats the address length as an in/out parameter, so a
    // reissued accept must restore it to the scratch capacity.
    let mut accept = make_accept();
    *accept.addr.len_mut() = 0;
    let _ = accept.build_sqe();
    assert_eq!(
        accept.addr.len() as usize,
        size_of::<libc::sockaddr_storage>()
    );
}

#[test]
fn test_active_connect_paths() {
    let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let make_connect = || ConnectRequest {
        fd: make_socket_fd(),
        addr: RawSocketAddr::boxed_from_socket_addr(&target),
        deadline: None,
    };

    // A zero result is a successful connect.
    let mut connect = make_connect();
    assert!(matches!(
        connect.on_cqe(WaiterState::Active { target_tick: None }, 0),
        Some(Ok(()))
    ));

    // Transient results retry with another SQE, and a reissued connect
    // may observe the previous attempt still in progress or already
    // established.
    let mut connect = make_connect();
    assert!(
        connect
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR)
            .is_none()
    );
    assert!(
        connect
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EALREADY)
            .is_none()
    );
    assert!(matches!(
        connect.on_cqe(WaiterState::Active { target_tick: None }, -libc::EISCONN),
        Some(Ok(()))
    ));

    // Refused connections are terminal failures.
    let mut connect = make_connect();
    assert!(matches!(
        connect.on_cqe(
            WaiterState::Active { target_tick: None },
            -libc::ECONNREFUSED
        ),
        Some(Err(Error::ConnectionFailed))
    ));

    // Cancellation after a timeout maps to a logical timeout.
    let mut connect = make_connect();
    assert!(matches!(
        connect.on_cqe(
            WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            },
            -libc::ECANCELED
        ),
        Some(Err(Error::Timeout))
    ));
}
