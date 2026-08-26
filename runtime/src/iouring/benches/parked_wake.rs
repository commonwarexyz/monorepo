//! Low-load root wake latency after a practical park-settle interval.
//!
//! Each iteration polls one future in the runtime root. Its first poll sends
//! the root waker to a foreign helper and returns pending, leaving no other
//! benchmark work ready. The helper waits [`PARK_SETTLE`] before publishing a
//! timestamp and calling `Waker::wake`. The measured interval runs from that
//! timestamp publication through the root's next poll of the future.
//!
//! The settle interval is excluded from the reported duration. It is a
//! practical assumption that the idle runtime has passed any spin phase and
//! parked, not direct proof of kernel scheduler state.

use super::support::{Backend, tokio_runner};
use commonware_runtime::{Runner, iouring};
use criterion::{Criterion, SamplingMode};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        mpsc::{SyncSender, sync_channel},
    },
    task::{Context, Poll, Waker},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const PARK_SETTLE: Duration = Duration::from_millis(5);
const SAMPLE_SIZE: usize = 30;
const WARM_UP_TIME: Duration = Duration::from_secs(2);
const MEASUREMENT_TIME: Duration = Duration::from_secs(5);

/// One sequential request for the helper to wake the runtime root.
struct WakeRequest {
    sequence: u64,
    started: Arc<OnceLock<Instant>>,
    waker: Waker,
}

/// Future resumed exactly once by the foreign helper.
struct ParkedWake {
    sequence: u64,
    sender: SyncSender<WakeRequest>,
    started: Arc<OnceLock<Instant>>,
    requested: bool,
}

impl ParkedWake {
    /// Create the next sequential parked-wake operation.
    fn new(sequence: u64, sender: SyncSender<WakeRequest>) -> Self {
        Self {
            sequence,
            sender,
            started: Arc::new(OnceLock::new()),
            requested: false,
        }
    }
}

impl Future for ParkedWake {
    type Output = Duration;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(started) = self.started.get() {
            return Poll::Ready(started.elapsed());
        }

        if !self.requested {
            self.requested = true;
            self.sender
                .send(WakeRequest {
                    sequence: self.sequence,
                    started: Arc::clone(&self.started),
                    waker: cx.waker().clone(),
                })
                .expect("parked-wake helper stopped");
        }

        Poll::Pending
    }
}

/// Register matched parked-root wake latency rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());

    // The mandatory untimed settle delay dominates wall time. Flat, small
    // sample batches avoid increasingly long linear batches while every
    // Criterion-requested iteration is still executed and validated.
    group
        .sample_size(SAMPLE_SIZE)
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(WARM_UP_TIME)
        .measurement_time(MEASUREMENT_TIME);

    for backend in Backend::ALL {
        let name = format!(
            "runtime={} park_settle_us={}",
            backend.name(),
            PARK_SETTLE.as_micros()
        );
        match backend {
            Backend::IoUring => group.bench_function(&name, |b| {
                b.iter_custom(|iters| measure(iters, iouring::Runner::default));
            }),
            Backend::Tokio => group.bench_function(&name, |b| {
                b.iter_custom(|iters| measure(iters, tokio_runner));
            }),
        };
    }

    group.finish();
}

/// Start the helper and wait until its receive loop can accept a request.
fn start_helper() -> (SyncSender<WakeRequest>, JoinHandle<u64>) {
    let (sender, receiver) = sync_channel::<WakeRequest>(0);
    let (ready_sender, ready_receiver) = sync_channel(0);
    let helper = thread::spawn(move || {
        ready_sender
            .send(())
            .expect("parked-wake benchmark stopped during setup");

        let mut actions = 0u64;
        for request in receiver {
            assert_eq!(request.sequence, actions, "parked-wake request reordered");
            thread::sleep(PARK_SETTLE);
            request
                .started
                .set(Instant::now())
                .expect("parked-wake request handled more than once");
            request.waker.wake();
            actions += 1;
        }
        actions
    });
    ready_receiver
        .recv()
        .expect("parked-wake helper stopped during setup");
    (sender, helper)
}

/// Join the helper outside the measured intervals and verify every action.
fn finish_helper(helper: JoinHandle<u64>, expected: u64) {
    let actions = helper.join().expect("parked-wake helper panicked");
    assert_eq!(actions, expected, "parked-wake helper action mismatch");
}

/// Sum helper-wake-to-root-poll latency inside one runtime root.
fn measure<R, F>(iters: u64, runner: F) -> Duration
where
    R: Runner,
    F: FnOnce() -> R,
{
    let (sender, helper) = start_helper();
    let (elapsed, completed) = runner().start(move |_| async move {
        let mut elapsed = Duration::ZERO;
        let mut completed = 0u64;
        for sequence in 0..iters {
            elapsed = elapsed
                .checked_add(ParkedWake::new(sequence, sender.clone()).await)
                .expect("parked-wake duration overflow");
            completed += 1;
        }
        drop(sender);
        (elapsed, completed)
    });

    assert_eq!(completed, iters, "parked-wake root completion mismatch");
    finish_helper(helper, iters);
    elapsed
}
