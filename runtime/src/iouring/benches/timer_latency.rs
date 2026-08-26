//! Spawned timer consumer latency under a persistent self-waking task load.

use super::support::{Backend, ReadyLoad, tokio_runner};
use commonware_runtime::{Clock, Runner, Spawner, Supervisor as _, iouring};
use criterion::Criterion;
use futures::future::join_all;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const DELAY: Duration = Duration::from_millis(1);
const LOAD_WIDTH: usize = 1024;

/// Register loaded timer-consumer latency rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    for backend in Backend::ALL {
        let name = format!(
            "{}/runtime={} load_width={LOAD_WIDTH} delay_us={}",
            module_path!(),
            backend.name(),
            DELAY.as_micros()
        );
        match backend {
            Backend::IoUring => c.bench_function(&name, |b| {
                b.iter_custom(|iters| measure(iters, iouring::Runner::default));
            }),
            Backend::Tokio => c.bench_function(&name, |b| {
                b.iter_custom(|iters| measure(iters, tokio_runner));
            }),
        };
    }
}

/// Sum timer-consumer latencies under persistent ready load.
fn measure<R, F>(iters: u64, runner: F) -> Duration
where
    R: Runner,
    R::Context: Clock + Spawner,
    F: FnOnce() -> R,
{
    runner().start(move |context| async move {
        let stop = Arc::new(AtomicBool::new(false));
        let mut load = Vec::with_capacity(LOAD_WIDTH);
        for _ in 0..LOAD_WIDTH {
            load.push(context.child("load").spawn({
                let stop = Arc::clone(&stop);
                move |_| ReadyLoad::new(stop)
            }));
        }

        let mut elapsed = Duration::ZERO;
        for _ in 0..iters {
            let timer = context.child("timer").spawn(|context| async move {
                // Start inside the consumer so queueing before its first poll is setup.
                let start = Instant::now();
                context.sleep(DELAY).await;
                start.elapsed()
            });
            elapsed += timer.await.expect("timer task failed");
        }

        stop.store(true, Ordering::Relaxed);
        for result in join_all(load).await {
            result.expect("load task failed");
        }
        elapsed
    })
}
