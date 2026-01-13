//! This module provides an io_uring-based implementation of the [crate::Network] trait,
//! offering fast, high-throughput network operations on Linux systems.
//!
//! ## Architecture
//!
//! Network operations are sent via a [futures::channel::mpsc] channel to a dedicated io_uring event
//! loop running in a separate thread. Operation results are returned via a [futures::channel::oneshot]
//! channel. This implementation uses two separate io_uring instances: one for send operations and
//! one for receive operations.
//!
//! ## Memory Safety
//!
//! We pass to the kernel, via io_uring, a pointer to the buffer being read from/written into.
//! Therefore, we ensure that the memory location is valid for the duration of the operation.
//! That is, it doesn't move or go out of scope until the operation completes.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring-network` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.

use crate::iouring::{self, should_retry, IoVecBuf, OpBuf};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_utils::StableBuf;
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt as _,
};
use io_uring::types::Fd;
use prometheus_client::{metrics::counter::Counter, registry::Registry};
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// Default read buffer size (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;

/// Thresholds for send strategy selection.
const TINY: usize = 1024; // 1 KB - below this, copy overhead is negligible
const SMALL: usize = 8 * 1024; // 8 KB - threshold for small vs large payloads
const IOV_SMALL: usize = 4; // Max iovecs for small payloads before consolidating
const COALESCE_MAX: usize = 64 * 1024; // 64 KB - max size to consolidate
const TINY_CHUNK_AVG: usize = 64; // Avg chunk size threshold for pathological fragmentation
const EXTREME_FRAG_MULTIPLIER: usize = 4; // Consolidate if n > iov_msg_max * this, regardless of avg

/// Returns the maximum number of iovecs before we consider consolidation.
/// Derived from iov_max() to be adaptive to kernel limits, capped at a reasonable value.
///
/// The divisor (64) is conservative to avoid excessive iovec setup overhead for
/// typical workloads. For high-throughput deployments where iovec overhead is
/// acceptable, this could be adjusted. The formula uses 1/64th of iov_max,
/// clamped to [16, 64], meaning:
/// - On typical Linux (iov_max=1024): iov_msg_max = 16
/// - On systems with higher limits: scales up to 64
fn iov_msg_max() -> usize {
    (crate::iouring::iov_max() / 64).clamp(16, 64)
}

/// Strategy for sending data over io_uring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendStrategy {
    /// Nothing to send.
    Noop,
    /// Small single-chunk: use Send opcode (simpler than SendMsg).
    Send,
    /// Consolidate chunks to single buffer + Send opcode (for fragmented payloads).
    Consolidate,
    /// Vectored send using SendMsg (for multi-chunk or large single-chunk payloads).
    SendMsg,
}

/// Metrics for tracking send strategy selection.
/// Useful for tuning heuristics in `choose_strategy`.
#[derive(Debug)]
struct StrategyMetrics {
    noop: Counter,
    send: Counter,
    consolidate: Counter,
    send_msg: Counter,
}

impl StrategyMetrics {
    fn new(registry: &mut Registry) -> Self {
        let registry = registry.sub_registry_with_prefix("send_strategy");
        let metrics = Self {
            noop: Counter::default(),
            send: Counter::default(),
            consolidate: Counter::default(),
            send_msg: Counter::default(),
        };
        registry.register("noop", "Empty sends (no-op)", metrics.noop.clone());
        registry.register(
            "send",
            "Small single-chunk sends using Send opcode",
            metrics.send.clone(),
        );
        registry.register(
            "consolidate",
            "Fragmented sends consolidated to single buffer",
            metrics.consolidate.clone(),
        );
        registry.register(
            "send_msg",
            "Multi-chunk or large sends using SendMsg opcode",
            metrics.send_msg.clone(),
        );
        metrics
    }

    fn inc(&self, strategy: SendStrategy) {
        match strategy {
            SendStrategy::Noop => self.noop.inc(),
            SendStrategy::Send => self.send.inc(),
            SendStrategy::Consolidate => self.consolidate.inc(),
            SendStrategy::SendMsg => self.send_msg.inc(),
        };
    }
}

/// Choose the optimal send strategy based on payload size and fragmentation.
///
/// Decision tree:
/// 1. Empty payload -> Noop
/// 2. Single small chunk (<8KB) -> Send (simpler opcode, minimal copy overhead)
/// 3. Single large chunk (>=8KB) -> SendMsg (avoid copy for large buffers)
/// 4. Tiny multi-chunk payload (<1KB) -> Consolidate (copy overhead is negligible)
/// 5. Small multi-chunk payload (<8KB) with few chunks (<=4) -> SendMsg
/// 6. Small multi-chunk payload with many chunks -> Consolidate
/// 7. Large payload with few chunks (<=iov_msg_max) -> SendMsg
/// 8. Extreme fragmentation (n > 4*iov_msg_max, <=64KB) -> Consolidate
/// 9. Pathologically fragmented (avg chunk < 64B, <=64KB) -> Consolidate
/// 10. Large payload with moderate+ fragmentation -> SendMsg (avoid huge copy)
fn choose_strategy(total: usize, n: usize) -> SendStrategy {
    if n == 0 || total == 0 {
        return SendStrategy::Noop;
    }

    // Single chunk handling
    if n == 1 {
        // Small single chunk: Send opcode is simpler/faster than SendMsg
        if total < SMALL {
            return SendStrategy::Send;
        }
        // Large single chunk: use SendMsg to avoid potential copy in Send path
        return SendStrategy::SendMsg;
    }

    // Multi-chunk: tiny payloads - copy overhead is negligible
    if total < TINY {
        return SendStrategy::Consolidate;
    }

    // Multi-chunk: small/medium payloads
    if total < SMALL {
        if n <= IOV_SMALL {
            return SendStrategy::SendMsg;
        }
        return SendStrategy::Consolidate;
    }

    // Multi-chunk: large payloads with few chunks - use vectored send
    let max_iovecs = iov_msg_max();
    if n <= max_iovecs {
        return SendStrategy::SendMsg;
    }

    // Only consider consolidation if total size is reasonable
    if total <= COALESCE_MAX {
        // Extreme fragmentation: consolidate regardless of average chunk size
        // This catches skewed distributions (e.g., one big chunk + many tiny ones)
        // where average is misleadingly high but iovec overhead is still significant
        let extreme_threshold = max_iovecs.saturating_mul(EXTREME_FRAG_MULTIPLIER);
        if n > extreme_threshold {
            return SendStrategy::Consolidate;
        }

        // Pathological fragmentation: many tiny chunks
        let avg_chunk_size = total / n;
        if avg_chunk_size < TINY_CHUNK_AVG {
            return SendStrategy::Consolidate;
        }
    }

    // Large payload with moderate-sized chunks or huge payload: use SendMsg
    // Even with many chunks, the iovec overhead is worth avoiding a large copy
    SendStrategy::SendMsg
}

/// Result of analyzing a buffer for sending.
enum ExtractedBuf {
    /// Single chunk, can use Send or SendMsg.
    Single(Bytes),
    /// Multiple chunks for SendMsg.
    Multi(Vec<Bytes>),
    /// Already consolidated into a single buffer (for Consolidate strategy).
    Consolidated(Bytes),
}

/// Analyzes and extracts buffer contents based on the chosen strategy.
/// This avoids double-copy by consolidating directly when needed.
fn extract_for_strategy(mut buf: impl Buf, strategy: SendStrategy) -> ExtractedBuf {
    let total = buf.remaining();

    // Fast path: single contiguous chunk
    let first_chunk_len = buf.chunk().len();
    if first_chunk_len == total {
        return ExtractedBuf::Single(buf.copy_to_bytes(first_chunk_len));
    }

    // For Consolidate strategy, copy directly to a single buffer (avoid double-copy)
    if strategy == SendStrategy::Consolidate {
        let mut consolidated = BytesMut::with_capacity(total);
        while buf.has_remaining() {
            consolidated.extend_from_slice(buf.chunk());
            let len = buf.chunk().len();
            buf.advance(len);
        }
        return ExtractedBuf::Consolidated(consolidated.freeze());
    }

    // Multi-chunk extraction for SendMsg
    let mut chunks = Vec::new();
    while buf.has_remaining() {
        let chunk_len = buf.chunk().len();
        chunks.push(buf.copy_to_bytes(chunk_len));
    }
    ExtractedBuf::Multi(chunks)
}

/// Estimates chunk count for strategy selection.
///
/// The Buf trait doesn't allow iterating chunks without consuming the buffer,
/// so we use a conservative heuristic based on the first chunk size.
///
/// Key insight: we only need to know if chunk count exceeds certain thresholds
/// (1, IOV_SMALL, iov_msg_max, extreme_threshold). The heuristic is designed to:
/// - Return exact count for single-chunk buffers (common case)
/// - Be conservative (overestimate) when first chunk is tiny, which safely
///   triggers consolidation for potentially fragmented buffers
/// - Use proportional estimate when first chunk is substantial
fn estimate_chunk_count(buf: &impl Buf) -> usize {
    let remaining = buf.remaining();
    if remaining == 0 {
        return 0;
    }

    // Fast path: single contiguous chunk (most common case)
    let first_chunk = buf.chunk().len();
    if first_chunk == remaining {
        return 1;
    }

    // Multi-chunk buffer: estimate based on first chunk proportion
    //
    // If first chunk is very small (< 1/8 of total), assume highly fragmented.
    // This is conservative - we'd rather consolidate a few extra cases than
    // use SendMsg with excessive iovecs.
    //
    // The threshold 8 is chosen because:
    // - For truly fragmented buffers (many small chunks), first chunk is tiny
    // - For 2-3 chunk buffers, first chunk is usually > 1/8 of total
    // - Consolidating a 2-chunk buffer unnecessarily is cheap
    let fragmentation_threshold = remaining / 8;
    if first_chunk < fragmentation_threshold {
        // First chunk is tiny - likely highly fragmented
        // Return a large estimate to trigger consolidation checks
        let extreme = iov_msg_max().saturating_mul(EXTREME_FRAG_MULTIPLIER);
        return extreme + 1;
    }

    // First chunk is substantial - estimate proportionally
    // Add 1 to ensure we round up (at least 2 chunks since we're in multi-chunk path)
    let estimate = (remaining / first_chunk) + 1;

    // Cap at a reasonable maximum to avoid overflow concerns
    estimate.min(remaining)
}

#[derive(Clone, Debug)]
pub struct Config {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    pub tcp_nodelay: Option<bool>,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
    /// Size of the read buffer for batching network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per call,
    /// but uses more memory per connection. Defaults to 64 KB.
    pub read_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_nodelay: None,
            iouring_config: iouring::Config::default(),
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
        }
    }
}

#[derive(Clone, Debug)]
/// [crate::Network] implementation that uses io_uring to do async I/O.
pub struct Network {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    tcp_nodelay: Option<bool>,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: mpsc::Sender<iouring::Op>,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: mpsc::Sender<iouring::Op>,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Strategy selection metrics.
    strategy_metrics: Arc<StrategyMetrics>,
}

impl Network {
    /// Returns a new [Network] instance.
    /// This function creates two io_uring instances, one for sending and one for receiving.
    /// This function spawns two threads to run the io_uring event loops.
    /// The threads run until the work submission channel is closed or an error occurs.
    /// The caller should take special care to ensure the io_uring `size` given in `cfg` is
    /// large enough, given the number of connections that will be maintained.
    /// Each ongoing send/recv to/from each connection will consume a slot in the io_uring.
    /// The io_uring `size` should be a multiple of the number of expected connections.
    pub(crate) fn start(mut cfg: Config, registry: &mut Registry) -> Result<Self, crate::Error> {
        // Create an io_uring instance to handle send operations.
        let (send_submitter, rx) = mpsc::channel(cfg.iouring_config.size as usize);

        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        cfg.iouring_config.single_issuer = true;

        std::thread::spawn({
            let cfg = cfg.clone();
            let registry = registry.sub_registry_with_prefix("iouring_sender");
            let metrics = Arc::new(iouring::Metrics::new(registry));
            move || block_on(iouring::run(cfg.iouring_config, metrics, rx))
        });

        // Create an io_uring instance to handle receive operations.
        let (recv_submitter, rx) = mpsc::channel(cfg.iouring_config.size as usize);
        let registry = registry.sub_registry_with_prefix("iouring_receiver");
        let metrics = Arc::new(iouring::Metrics::new(registry));
        std::thread::spawn(|| block_on(iouring::run(cfg.iouring_config, metrics, rx)));

        // Create strategy metrics.
        let strategy_registry = registry.sub_registry_with_prefix("network");
        let strategy_metrics = Arc::new(StrategyMetrics::new(strategy_registry));

        Ok(Self {
            tcp_nodelay: cfg.tcp_nodelay,
            send_submitter,
            recv_submitter,
            read_buffer_size: cfg.read_buffer_size,
            strategy_metrics,
        })
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        let listener = TcpListener::bind(socket)
            .await
            .map_err(|_| crate::Error::BindFailed)?;
        Ok(Listener {
            tcp_nodelay: self.tcp_nodelay,
            inner: listener,
            send_submitter: self.send_submitter.clone(),
            recv_submitter: self.recv_submitter.clone(),
            read_buffer_size: self.read_buffer_size,
            strategy_metrics: self.strategy_metrics.clone(),
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| crate::Error::ConnectionFailed)?
            .into_std()
            .map_err(|_| crate::Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let fd = Arc::new(OwnedFd::from(stream));
        Ok((
            Sink::new(
                fd.clone(),
                self.send_submitter.clone(),
                self.strategy_metrics.clone(),
            ),
            Stream::new(fd, self.recv_submitter.clone(), self.read_buffer_size),
        ))
    }
}

/// Implementation of [crate::Listener] for an io-uring [Network].
pub struct Listener {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    tcp_nodelay: Option<bool>,
    inner: TcpListener,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: mpsc::Sender<iouring::Op>,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: mpsc::Sender<iouring::Op>,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Strategy selection metrics.
    strategy_metrics: Arc<StrategyMetrics>,
}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        let (stream, remote_addr) = self
            .inner
            .accept()
            .await
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let stream = stream
            .into_std()
            .map_err(|_| crate::Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let fd = Arc::new(OwnedFd::from(stream));

        Ok((
            remote_addr,
            Sink::new(
                fd.clone(),
                self.send_submitter.clone(),
                self.strategy_metrics.clone(),
            ),
            Stream::new(fd, self.recv_submitter.clone(), self.read_buffer_size),
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.inner.local_addr()
    }
}

/// Implementation of [crate::Sink] for an io-uring [Network].
pub struct Sink {
    fd: Arc<OwnedFd>,
    /// Used to submit send operations to the io_uring event loop.
    submitter: mpsc::Sender<iouring::Op>,
    /// Strategy selection metrics.
    strategy_metrics: Arc<StrategyMetrics>,
}

impl Sink {
    const fn new(
        fd: Arc<OwnedFd>,
        submitter: mpsc::Sender<iouring::Op>,
        strategy_metrics: Arc<StrategyMetrics>,
    ) -> Self {
        Self {
            fd,
            submitter,
            strategy_metrics,
        }
    }

    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }

    /// Send a single buffer using the Send opcode.
    /// This is the simplest and fastest path for small contiguous payloads.
    async fn send_single(&mut self, buf: Bytes) -> Result<(), crate::Error> {
        let mut msg: StableBuf = BytesMut::from(buf).into();
        let mut bytes_sent = 0;
        let msg_len = msg.len();

        while bytes_sent < msg_len {
            // SAFETY: `msg` is a `StableBuf` guaranteeing the memory won't move.
            // `bytes_sent` is always < `msg_len` due to the loop condition.
            let remaining = unsafe {
                std::slice::from_raw_parts(
                    msg.as_mut_ptr().add(bytes_sent) as *const u8,
                    msg_len - bytes_sent,
                )
            };

            let op = io_uring::opcode::Send::new(
                self.as_raw_fd(),
                remaining.as_ptr(),
                remaining.len() as u32,
            )
            .build();

            let (tx, rx) = oneshot::channel();
            self.submitter
                .send(crate::iouring::Op {
                    work: op,
                    sender: tx,
                    buffers: Some(OpBuf::Single(msg)),
                })
                .await
                .map_err(|_| crate::Error::SendFailed)?;

            let (result, got_buffers) = rx.await.map_err(|_| crate::Error::SendFailed)?;
            msg = got_buffers.unwrap().into_single().unwrap();

            if should_retry(result) {
                continue;
            }

            if result <= 0 {
                return Err(crate::Error::SendFailed);
            }

            bytes_sent += result as usize;
        }
        Ok(())
    }

    /// Vectored send using SendMsg opcode.
    /// Used for multi-chunk payloads or large single-chunk payloads.
    async fn send_msg(&mut self, chunks: Vec<Bytes>) -> Result<(), crate::Error> {
        let mut iov_buf = IoVecBuf::new(chunks);

        loop {
            if iov_buf.is_complete() {
                return Ok(());
            }

            let op = io_uring::opcode::SendMsg::new(self.as_raw_fd(), iov_buf.msghdr_ptr()).build();

            let (tx, rx) = oneshot::channel();
            self.submitter
                .send(crate::iouring::Op {
                    work: op,
                    sender: tx,
                    buffers: Some(OpBuf::Vectored(iov_buf)),
                })
                .await
                .map_err(|_| crate::Error::SendFailed)?;

            let (result, got_buffers) = rx.await.map_err(|_| crate::Error::SendFailed)?;
            iov_buf = got_buffers.unwrap().into_vectored().unwrap();

            if should_retry(result) {
                continue;
            }

            if result <= 0 {
                return Err(crate::Error::SendFailed);
            }

            // Advance past sent bytes
            iov_buf.advance(result as usize);
        }
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: impl Buf + Send) -> Result<(), crate::Error> {
        let total = msg.remaining();
        let n = estimate_chunk_count(&msg);

        // Choose strategy before extracting to enable optimized extraction
        let strategy = choose_strategy(total, n);
        self.strategy_metrics.inc(strategy);

        if strategy == SendStrategy::Noop {
            return Ok(());
        }

        // Extract buffer contents based on the chosen strategy
        let extracted = extract_for_strategy(msg, strategy);

        match (strategy, extracted) {
            (SendStrategy::Noop, _) => Ok(()),
            (SendStrategy::Send, ExtractedBuf::Single(buf)) => self.send_single(buf).await,
            (SendStrategy::Send, ExtractedBuf::Consolidated(buf)) => self.send_single(buf).await,
            (SendStrategy::Consolidate, ExtractedBuf::Single(buf)) => self.send_single(buf).await,
            (SendStrategy::Consolidate, ExtractedBuf::Consolidated(buf)) => {
                self.send_single(buf).await
            }
            (SendStrategy::SendMsg, ExtractedBuf::Single(buf)) => self.send_msg(vec![buf]).await,
            (SendStrategy::SendMsg, ExtractedBuf::Multi(chunks)) => self.send_msg(chunks).await,
            // Fallback cases (shouldn't happen with correct strategy selection)
            (SendStrategy::Send, ExtractedBuf::Multi(chunks)) => {
                // Shouldn't happen: Send strategy only for n=1
                self.send_msg(chunks).await
            }
            (SendStrategy::Consolidate, ExtractedBuf::Multi(_)) => {
                // Shouldn't happen: Consolidate extracts directly to Consolidated
                unreachable!("Consolidate strategy should produce Consolidated variant")
            }
            (SendStrategy::SendMsg, ExtractedBuf::Consolidated(buf)) => {
                // Can happen if strategy changed, just send as single chunk
                self.send_msg(vec![buf]).await
            }
        }
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
///
/// Uses an internal buffer to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    fd: Arc<OwnedFd>,
    /// Used to submit recv operations to the io_uring event loop.
    submitter: mpsc::Sender<iouring::Op>,
    /// Internal read buffer.
    buffer: Vec<u8>,
    /// Current read position in the buffer.
    buffer_pos: usize,
    /// Number of valid bytes in the buffer.
    buffer_len: usize,
}

impl Stream {
    fn new(fd: Arc<OwnedFd>, submitter: mpsc::Sender<iouring::Op>, buffer_capacity: usize) -> Self {
        Self {
            fd,
            submitter,
            buffer: vec![0u8; buffer_capacity],
            buffer_pos: 0,
            buffer_len: 0,
        }
    }

    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }

    /// Submits a recv operation to io_uring.
    ///
    /// # Arguments
    /// * `buffer` - Buffer for ownership tracking (kept alive during io_uring op)
    /// * `offset` - Offset into buffer to write received data
    /// * `len` - Maximum bytes to receive
    ///
    /// # Returns
    /// The buffer and either bytes received or an error.
    async fn submit_recv(
        &mut self,
        mut buffer: StableBuf,
        offset: usize,
        len: usize,
    ) -> (StableBuf, Result<usize, crate::Error>) {
        loop {
            // SAFETY: offset + len <= buffer.len() as guaranteed by callers.
            let ptr = unsafe { buffer.as_mut_ptr().add(offset) };
            let op = io_uring::opcode::Recv::new(self.as_raw_fd(), ptr, len as u32).build();

            let (tx, rx) = oneshot::channel();
            if self
                .submitter
                .send(crate::iouring::Op {
                    work: op,
                    sender: tx,
                    buffers: Some(OpBuf::Single(buffer)),
                })
                .await
                .is_err()
            {
                // Channel closed - io_uring thread died, buffer is lost
                return (StableBuf::default(), Err(crate::Error::RecvFailed));
            }

            let Ok((result, got_buffers)) = rx.await else {
                // Channel closed - io_uring thread died, buffer is lost
                return (StableBuf::default(), Err(crate::Error::RecvFailed));
            };
            buffer = got_buffers.unwrap().into_single().unwrap();

            if should_retry(result) {
                continue;
            }

            if result <= 0 {
                let err = if result == -libc::ETIMEDOUT {
                    crate::Error::Timeout
                } else {
                    crate::Error::RecvFailed
                };
                return (buffer, Err(err));
            }

            return (buffer, Ok(result as usize));
        }
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self) -> Result<usize, crate::Error> {
        self.buffer_pos = 0;
        self.buffer_len = 0;

        let buffer: StableBuf = std::mem::take(&mut self.buffer).into();
        let len = buffer.len();

        // If the buffer is lost due to a channel error, we don't restore it.
        // Channel errors mean the io_uring thread died, so the stream is unusable anyway.
        let (buffer, result) = self.submit_recv(buffer, 0, len).await;
        self.buffer = buffer.into();
        self.buffer_len = result?;
        Ok(self.buffer_len)
    }
}

impl crate::Stream for Stream {
    async fn recv(&mut self, mut buf: impl BufMut + Send) -> Result<(), crate::Error> {
        let mut owned_buf: StableBuf = BytesMut::zeroed(buf.remaining_mut()).into();
        let mut bytes_received = 0;
        let buf_len = owned_buf.len();

        while bytes_received < buf_len {
            // First drain any buffered data
            let buffered = self.buffer_len - self.buffer_pos;
            if buffered > 0 {
                let to_copy = std::cmp::min(buffered, buf_len - bytes_received);
                owned_buf.as_mut()[bytes_received..bytes_received + to_copy]
                    .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
                self.buffer_pos += to_copy;
                bytes_received += to_copy;
                continue;
            }

            let remaining = buf_len - bytes_received;

            // Skip internal buffer if disabled, or if the read is large enough
            // to fill the buffer and immediately drain it
            let buffer_len = self.buffer.len();
            if buffer_len == 0 || remaining >= buffer_len {
                let (returned_buf, result) =
                    self.submit_recv(owned_buf, bytes_received, remaining).await;
                owned_buf = returned_buf;
                bytes_received += result?;
            } else {
                // Fill internal buffer, then loop will copy
                self.fill_buffer().await?;
            }
        }

        buf.put_slice(owned_buf.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        iouring,
        network::{
            iouring::{Config, Network},
            tests,
        },
    };
    use commonware_macros::test_group;
    use prometheus_client::registry::Registry;
    use std::time::Duration;

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            Network::start(
                Config {
                    iouring_config: iouring::Config {
                        force_poll: Duration::from_millis(100),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &mut Registry::default(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(|| {
            Network::start(
                Config {
                    iouring_config: iouring::Config {
                        size: 256,
                        force_poll: Duration::from_millis(100),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &mut Registry::default(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[tokio::test]
    async fn test_small_send_read_quickly() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};

        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Read a small message (much smaller than the 64KB buffer)
            let mut buf = [0u8; 10];
            stream.recv(&mut buf[..]).await.unwrap();
            buf
        });

        // Connect and send a small message
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        let msg = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        sink.send(msg.as_ref()).await.unwrap();

        // Wait for the reader to complete
        let received = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(received.as_slice(), &msg[..]);
    }

    #[tokio::test]
    async fn test_read_timeout_with_partial_data() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};
        use std::time::Instant;

        // Use a short timeout to make the test fast
        let op_timeout = Duration::from_millis(100);
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    op_timeout: Some(op_timeout),
                    force_poll: Duration::from_millis(10),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Try to read 100 bytes, but only 5 will be sent
            let start = Instant::now();
            let mut buf = [0u8; 100];
            let result = stream.recv(&mut buf[..]).await;
            let elapsed = start.elapsed();

            (result, elapsed)
        });

        // Connect and send only partial data
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();

        // Wait for the reader to complete
        let (result, elapsed) = reader.await.unwrap();
        assert!(matches!(result, Err(crate::Error::Timeout)));

        // Verify the timeout occurred around the expected time
        assert!(elapsed >= op_timeout);
        // Allow some margin for timing variance
        assert!(elapsed < op_timeout * 3);
    }

    #[tokio::test]
    async fn test_unbuffered_mode() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};

        // Set read_buffer_size to 0 to disable buffering
        let network = Network::start(
            Config {
                read_buffer_size: 0,
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Read messages without buffering
            let mut buf1 = [0u8; 5];
            let mut buf2 = [0u8; 5];
            stream.recv(&mut buf1[..]).await.unwrap();
            stream.recv(&mut buf2[..]).await.unwrap();
            (buf1, buf2)
        });

        // Connect and send two messages
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
        sink.send([6u8, 7, 8, 9, 10].as_slice()).await.unwrap();

        // Wait for the reader to complete
        let (buf1, buf2) = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(buf1.as_slice(), &[1u8, 2, 3, 4, 5]);
        assert_eq!(buf2.as_slice(), &[6u8, 7, 8, 9, 10]);
    }

    mod strategy_tests {
        use super::super::{
            choose_strategy, iov_msg_max, SendStrategy, COALESCE_MAX, EXTREME_FRAG_MULTIPLIER,
            IOV_SMALL, SMALL, TINY,
        };

        #[test]
        fn test_noop_cases() {
            // Empty buffer
            assert_eq!(choose_strategy(0, 0), SendStrategy::Noop);
            assert_eq!(choose_strategy(0, 1), SendStrategy::Noop);
            assert_eq!(choose_strategy(100, 0), SendStrategy::Noop);
        }

        #[test]
        fn test_single_chunk_strategy() {
            // Small single chunk uses Send (simpler opcode)
            assert_eq!(choose_strategy(1, 1), SendStrategy::Send);
            assert_eq!(choose_strategy(TINY, 1), SendStrategy::Send);
            assert_eq!(choose_strategy(SMALL - 1, 1), SendStrategy::Send);

            // Large single chunk uses SendMsg (avoid copy)
            assert_eq!(choose_strategy(SMALL, 1), SendStrategy::SendMsg);
            assert_eq!(choose_strategy(COALESCE_MAX, 1), SendStrategy::SendMsg);
            assert_eq!(choose_strategy(COALESCE_MAX + 1, 1), SendStrategy::SendMsg);
        }

        #[test]
        fn test_tiny_payloads() {
            // Tiny payloads (<1KB) should always consolidate
            assert_eq!(choose_strategy(TINY - 1, 2), SendStrategy::Consolidate);
            assert_eq!(choose_strategy(TINY - 1, 10), SendStrategy::Consolidate);
            assert_eq!(choose_strategy(TINY - 1, 100), SendStrategy::Consolidate);
        }

        #[test]
        fn test_small_payloads() {
            // Small payloads (1KB to 8KB)
            // With few chunks (<=4): SendMsg
            assert_eq!(choose_strategy(TINY, IOV_SMALL), SendStrategy::SendMsg);
            assert_eq!(choose_strategy(SMALL - 1, IOV_SMALL), SendStrategy::SendMsg);
            // With many chunks (>4): Consolidate
            assert_eq!(
                choose_strategy(TINY, IOV_SMALL + 1),
                SendStrategy::Consolidate
            );
            assert_eq!(
                choose_strategy(SMALL - 1, IOV_SMALL + 1),
                SendStrategy::Consolidate
            );
        }

        #[test]
        fn test_large_payloads_few_chunks() {
            // Large payloads with few chunks use SendMsg
            let max_iovecs = iov_msg_max();
            assert_eq!(choose_strategy(SMALL, max_iovecs), SendStrategy::SendMsg);
            assert_eq!(
                choose_strategy(COALESCE_MAX, max_iovecs),
                SendStrategy::SendMsg
            );
            assert_eq!(
                choose_strategy(COALESCE_MAX + 1, max_iovecs),
                SendStrategy::SendMsg
            );
        }

        #[test]
        fn test_pathological_fragmentation_tiny_chunks() {
            // Pathological fragmentation with tiny average chunk size
            // avg_chunk_size < TINY_CHUNK_AVG (64B) AND total <= COALESCE_MAX -> Consolidate
            // 1024 chunks of 32B each = 32KB total, avg = 32B
            let tiny_chunk_payload = 32 * 1024; // 32KB
            let many_tiny_chunks = 1024; // avg = 32B < 64B
            assert_eq!(
                choose_strategy(tiny_chunk_payload, many_tiny_chunks),
                SendStrategy::Consolidate
            );
        }

        #[test]
        fn test_pathological_fragmentation_moderate_chunks() {
            // Many chunks but average size >= TINY_CHUNK_AVG -> SendMsg
            // (as long as chunk count isn't extreme)
            // e.g., 100 chunks of 4KB each = 400KB total, avg = 4KB
            // But 400KB > COALESCE_MAX, so SendMsg regardless
            let moderate_payload = 400 * 1024;
            let moderate_chunks = 100; // avg = 4KB > 64B
            assert_eq!(
                choose_strategy(moderate_payload, moderate_chunks),
                SendStrategy::SendMsg
            );

            // For smaller payload within COALESCE_MAX, moderate chunks use SendMsg
            // 30 chunks of 500B each = 15KB, avg = 500B > 64B, n < extreme threshold
            let max_iovecs = iov_msg_max();
            let moderate_n = max_iovecs + 10; // Above iov_msg_max but below extreme
            assert_eq!(choose_strategy(15_000, moderate_n), SendStrategy::SendMsg);
        }

        #[test]
        fn test_extreme_fragmentation_consolidates() {
            // Extreme fragmentation (n > 4 * iov_msg_max) consolidates regardless of avg
            // This catches skewed distributions like one big chunk + many tiny ones
            let max_iovecs = iov_msg_max();
            let extreme_threshold = max_iovecs * EXTREME_FRAG_MULTIPLIER;

            // Just above extreme threshold with reasonable avg -> Consolidate
            // e.g., 65 chunks of 500B = 32.5KB, avg = 500B > 64B
            // But 65 > 16*4 = 64 (extreme threshold), so consolidate
            let extreme_n = extreme_threshold + 1;
            let total = extreme_n * 500; // Keep under COALESCE_MAX
            if total <= COALESCE_MAX {
                assert_eq!(
                    choose_strategy(total, extreme_n),
                    SendStrategy::Consolidate,
                    "extreme fragmentation should consolidate even with high avg"
                );
            }

            // Just at extreme threshold -> still uses avg check
            // 64 chunks of 500B = 32KB, avg = 500B > 64B -> SendMsg
            let at_threshold = extreme_threshold;
            assert_eq!(
                choose_strategy(at_threshold * 500, at_threshold),
                SendStrategy::SendMsg
            );
        }

        #[test]
        fn test_huge_payload_always_sendmsg() {
            // Huge payloads (>64KB) should use SendMsg even with pathological fragmentation
            // to avoid massive copy
            let huge_payload = COALESCE_MAX + 1;
            let many_chunks = 2000; // avg = ~32B, pathological
            assert_eq!(
                choose_strategy(huge_payload, many_chunks),
                SendStrategy::SendMsg
            );
        }

        #[test]
        fn test_boundary_conditions() {
            // Test exact boundary values
            assert_eq!(choose_strategy(TINY - 1, 2), SendStrategy::Consolidate); // Just under TINY
            assert_eq!(choose_strategy(TINY, 2), SendStrategy::SendMsg); // Exactly TINY, 2 chunks
            assert_eq!(choose_strategy(SMALL - 1, 2), SendStrategy::SendMsg); // Just under SMALL
            assert_eq!(choose_strategy(SMALL, 2), SendStrategy::SendMsg); // Exactly SMALL (large)

            // IOV_SMALL boundary (now 4)
            assert_eq!(choose_strategy(TINY, 4), SendStrategy::SendMsg); // At IOV_SMALL
            assert_eq!(choose_strategy(TINY, 5), SendStrategy::Consolidate); // Above IOV_SMALL
        }

        #[test]
        fn test_avg_chunk_size_threshold() {
            // Test the TINY_CHUNK_AVG (64B) threshold
            //
            // Note: For total >= SMALL (8KB) and n <= extreme_threshold (64),
            // the minimum avg is 8192/64 = 128B, which is >= 64B. So the avg
            // check can only trigger via the extreme fragmentation path.
            //
            // The avg check is primarily useful when:
            // - n > extreme_threshold (so extreme check doesn't fire)
            // - total <= COALESCE_MAX
            // - avg < 64B

            let max_iovecs = iov_msg_max();
            let extreme_threshold = max_iovecs * EXTREME_FRAG_MULTIPLIER;

            // Case 1: n > extreme_threshold with low avg -> Consolidate
            // 1000 chunks of 32B = 32KB, avg = 32B < 64B
            let many_tiny_n = extreme_threshold + 100;
            let many_tiny_total = many_tiny_n * 32; // 32KB if extreme_threshold=64
            if many_tiny_total <= COALESCE_MAX {
                assert_eq!(
                    choose_strategy(many_tiny_total, many_tiny_n),
                    SendStrategy::Consolidate
                );
            }

            // Case 2: n between iov_msg_max and extreme_threshold with high avg -> SendMsg
            // 30 chunks of 400B = 12KB, avg = 400B >= 64B
            let moderate_n = max_iovecs + 10;
            assert!(moderate_n <= extreme_threshold);
            let moderate_total = moderate_n * 400;
            assert!(moderate_total >= SMALL);
            assert_eq!(
                choose_strategy(moderate_total, moderate_n),
                SendStrategy::SendMsg
            );

            // Case 3: Above COALESCE_MAX, always use SendMsg even with tiny avg
            // 65537 bytes / 2000 chunks = 32.7B avg, but too big to consolidate
            assert_eq!(
                choose_strategy(COALESCE_MAX + 1, 2000),
                SendStrategy::SendMsg
            );
        }

        #[test]
        fn test_iov_msg_max_derived_from_iov_max() {
            // Verify iov_msg_max is derived from iov_max and within expected bounds
            let max = iov_msg_max();
            assert!(max >= 16, "iov_msg_max should be at least 16");
            assert!(max <= 64, "iov_msg_max should be at most 64");
        }
    }

    #[tokio::test]
    async fn test_multi_chunk_sendmsg() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};
        use bytes::Bytes;

        // This test forces SendMsg by using a payload size >= TINY with few chunks
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create two chunks that together are >= TINY (1KB) to trigger SendMsg
        let chunk1 = Bytes::from(vec![0xAA; 600]);
        let chunk2 = Bytes::from(vec![0xBB; 600]);
        let total_len = chunk1.len() + chunk2.len();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; total_len];
            stream.recv(&mut buf[..]).await.unwrap();
            buf
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();

        // Use bytes::Buf::chain to create a multi-chunk buffer
        use bytes::Buf;
        let chained = chunk1.chain(chunk2);
        sink.send(chained).await.unwrap();

        let received = reader.await.unwrap();

        // Verify byte ordering is preserved
        assert_eq!(&received[..600], &[0xAA; 600]);
        assert_eq!(&received[600..], &[0xBB; 600]);
    }

    #[tokio::test]
    async fn test_large_payload_triggers_partial_sends() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};
        use bytes::Bytes;

        // This test sends a large payload that may trigger partial sends
        // depending on socket buffer size. The goal is to exercise the
        // advance() logic in IoVecBuf.
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create multiple chunks totaling ~256KB to potentially trigger partial sends
        let chunk_size = 32 * 1024; // 32KB per chunk
        let num_chunks = 8;
        let chunks: Vec<Bytes> = (0..num_chunks)
            .map(|i| Bytes::from(vec![i as u8; chunk_size]))
            .collect();
        let total_len = chunk_size * num_chunks;

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; total_len];
            stream.recv(&mut buf[..]).await.unwrap();
            buf
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();

        // Chain all chunks together
        use bytes::Buf;
        let mut chained: Box<dyn Buf + Send> = Box::new(chunks[0].clone());
        for chunk in chunks.iter().skip(1) {
            chained = Box::new(chained.chain(chunk.clone()));
        }
        sink.send(chained).await.unwrap();

        let received = reader.await.unwrap();

        // Verify each chunk's data is correct
        for i in 0..num_chunks {
            let start = i * chunk_size;
            let end = start + chunk_size;
            assert!(
                received[start..end].iter().all(|&b| b == i as u8),
                "chunk {} corrupted",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_pathological_fragmentation_consolidates() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};
        use bytes::Bytes;

        // Test that pathologically fragmented payloads (many tiny chunks)
        // are handled correctly via the Consolidate path.
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create 100 tiny chunks of 32 bytes each = 3200 bytes total
        // avg_chunk_size = 32 < TINY_CHUNK_AVG (64), so this should consolidate
        let num_chunks = 100;
        let chunk_size = 32;
        let chunks: Vec<Bytes> = (0..num_chunks)
            .map(|i| Bytes::from(vec![i as u8; chunk_size]))
            .collect();
        let total_len = chunk_size * num_chunks;

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; total_len];
            stream.recv(&mut buf[..]).await.unwrap();
            buf
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();

        // Chain all chunks together
        use bytes::Buf;
        let mut chained: Box<dyn Buf + Send> = Box::new(chunks[0].clone());
        for chunk in chunks.iter().skip(1) {
            chained = Box::new(chained.chain(chunk.clone()));
        }
        sink.send(chained).await.unwrap();

        let received = reader.await.unwrap();

        // Verify each chunk's data is correct
        for i in 0..num_chunks {
            let start = i * chunk_size;
            let end = start + chunk_size;
            assert!(
                received[start..end].iter().all(|&b| b == i as u8),
                "chunk {} corrupted",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_single_chunk_zero_copy_path() {
        use crate::{Listener as _, Network as _, Sink as _, Stream as _};
        use bytes::Bytes;

        // Test that single-chunk sends go through the SendMsg path
        // (zero-copy) rather than consolidation.
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Single large chunk (64KB) - should use SendMsg for zero-copy
        let data = Bytes::from(vec![0xAB; 64 * 1024]);
        let total_len = data.len();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; total_len];
            stream.recv(&mut buf[..]).await.unwrap();
            buf
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(data).await.unwrap();

        let received = reader.await.unwrap();
        assert!(received.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn test_iov_max_batching_end_to_end() {
        use crate::{iouring::iov_max, Listener as _, Network as _, Sink as _, Stream as _};
        use bytes::Bytes;

        // This test sends more chunks than IOV_MAX to validate the batching
        // logic in IoVecBuf::advance and rebuild_iovecs through real network I/O.
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create more chunks than IOV_MAX to force batching
        let iov_max_val = iov_max();
        let num_chunks = iov_max_val + 100; // e.g., 1124 chunks on typical Linux
        let chunk_size = 100; // 100 bytes per chunk
        let chunks: Vec<Bytes> = (0..num_chunks)
            .map(|i| Bytes::from(vec![(i % 256) as u8; chunk_size]))
            .collect();
        let total_len = chunk_size * num_chunks;

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; total_len];
            stream.recv(&mut buf[..]).await.unwrap();
            buf
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();

        // Chain all chunks together to create a multi-chunk buffer
        use bytes::Buf;
        let mut chained: Box<dyn Buf + Send> = Box::new(chunks[0].clone());
        for chunk in chunks.iter().skip(1) {
            chained = Box::new(chained.chain(chunk.clone()));
        }
        sink.send(chained).await.unwrap();

        let received = reader.await.unwrap();

        // Verify each chunk's data is correct
        for i in 0..num_chunks {
            let start = i * chunk_size;
            let end = start + chunk_size;
            let expected = (i % 256) as u8;
            assert!(
                received[start..end].iter().all(|&b| b == expected),
                "chunk {} corrupted: expected {}, got first byte {}",
                i,
                expected,
                received[start]
            );
        }
    }
}
