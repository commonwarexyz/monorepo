//! Fixed-total foreign wake handoffs at narrow and moderate task widths.
//!
//! This measures bounded-channel handoff to a foreign helper thread and the
//! executor's scheduler reinjection path. It is not a proven parked-wake
//! latency measurement because the helper may wake a task before the executor
//! enters the kernel.

use super::support::{Backend, tokio_runner};
use commonware_runtime::{Runner, Spawner, Supervisor as _, iouring};
use criterion::{Criterion, Throughput};
use futures::future::join_all;
use std::{
    future::Future,
    pin::Pin,
    sync::mpsc::{SyncSender, sync_channel},
    task::{Context, Poll, Waker},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TOTAL_HANDOFFS: usize = 65_536;
const WIDTHS: [usize; 2] = [1, 64];

/// Future that delegates every wake to a foreign helper thread.
struct ForeignWake {
    /// Number of pending polls that still issue a foreign wake.
    remaining: usize,
    /// Bounded channel to the helper thread.
    sender: SyncSender<Waker>,
}

impl ForeignWake {
    /// Create a future that performs exactly `handoffs` foreign wake handoffs.
    const fn new(handoffs: usize, sender: SyncSender<Waker>) -> Self {
        Self {
            remaining: handoffs,
            sender,
        }
    }
}

impl Future for ForeignWake {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.remaining == 0 {
            return Poll::Ready(());
        }
        self.remaining -= 1;
        self.sender
            .send(cx.waker().clone())
            .expect("foreign wake helper stopped");
        Poll::Pending
    }
}

/// Register fixed-total foreign wake rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(TOTAL_HANDOFFS as u64));

    for width in WIDTHS {
        let handoffs_per_task = TOTAL_HANDOFFS / width;
        for backend in Backend::ALL {
            let name = format!(
                "runtime={} width={width} total_handoffs={TOTAL_HANDOFFS}",
                backend.name()
            );
            match backend {
                Backend::IoUring => group.bench_function(&name, |b| {
                    b.iter_custom(|iters| {
                        measure(iters, width, handoffs_per_task, iouring::Runner::default)
                    });
                }),
                Backend::Tokio => group.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure(iters, width, handoffs_per_task, tokio_runner));
                }),
            };
        }
    }

    group.finish();
}

/// Start the helper and wait until its receive loop can run.
fn start_helper(capacity: usize) -> (SyncSender<Waker>, JoinHandle<u64>) {
    let (sender, receiver) = sync_channel::<Waker>(capacity);
    let (ready_sender, ready_receiver) = sync_channel(0);
    let helper = thread::spawn(move || {
        ready_sender
            .send(())
            .expect("foreign wake benchmark stopped during setup");
        let mut handoffs = 0u64;
        for waker in receiver {
            handoffs += 1;
            waker.wake();
        }
        handoffs
    });
    ready_receiver
        .recv()
        .expect("foreign wake helper stopped during setup");
    (sender, helper)
}

/// Join the helper outside the measured interval and verify its work count.
fn finish_helper(helper: JoinHandle<u64>, iters: u64) {
    let handoffs = helper.join().expect("foreign wake helper panicked");
    assert_eq!(handoffs, iters * TOTAL_HANDOFFS as u64);
}

/// Measure foreign wake handoffs inside one runtime root.
fn measure<R, F>(iters: u64, width: usize, handoffs_per_task: usize, runner: F) -> Duration
where
    R: Runner,
    R::Context: Spawner,
    F: FnOnce() -> R,
{
    let (sender, helper) = start_helper(width);
    let elapsed = runner().start(move |context| async move {
        let start = Instant::now();
        for _ in 0..iters {
            let mut handles = Vec::with_capacity(width);
            for _ in 0..width {
                handles.push(context.child("foreign_wake").spawn({
                    let sender = sender.clone();
                    move |_| ForeignWake::new(handoffs_per_task, sender)
                }));
            }
            for result in join_all(handles).await {
                result.expect("foreign wake task failed");
            }
        }
        start.elapsed()
    });
    finish_helper(helper, iters);
    elapsed
}
