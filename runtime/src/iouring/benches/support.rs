//! Shared primitives for scheduler benchmarks.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

/// Runtime implementation exercised by a benchmark row.
#[derive(Clone, Copy)]
pub enum Backend {
    /// Commonware's single-threaded io_uring runtime.
    IoUring,
    /// Tokio's direct current-thread runtime.
    Tokio,
}

impl Backend {
    /// Backends emitted for every workload shape.
    pub const ALL: [Self; 2] = [Self::IoUring, Self::Tokio];

    /// Return the stable benchmark parameter value for this backend.
    pub const fn name(self) -> &'static str {
        match self {
            Self::IoUring => "iouring",
            Self::Tokio => "tokio",
        }
    }
}

/// Construct the Tokio baseline used by every comparative row.
pub fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .event_interval(64)
        .global_queue_interval(31)
        .build()
        .expect("failed to build Tokio benchmark runtime")
}

/// Future that wakes itself a fixed number of times before completing.
pub struct SelfWake {
    /// Number of pending polls that still issue a self-wake.
    remaining: usize,
}

impl SelfWake {
    /// Create a future that performs exactly `wakes` self-wakes.
    pub const fn new(wakes: usize) -> Self {
        Self { remaining: wakes }
    }
}

impl Future for SelfWake {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.remaining == 0 {
            return Poll::Ready(());
        }
        self.remaining -= 1;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Persistent self-waking load that stops when its shared flag is set.
pub struct ReadyLoad {
    /// Shared completion flag controlled by the benchmark root.
    stop: Arc<AtomicBool>,
}

impl ReadyLoad {
    /// Create a ready-load future controlled by `stop`.
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self { stop }
    }
}

impl Future for ReadyLoad {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.stop.load(Ordering::Relaxed) {
            return Poll::Ready(());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
