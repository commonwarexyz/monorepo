//! Spawned timer consumer latency under a persistent self-waking task load.

use super::support::{Backend, ReadyLoad, tokio_runtime};
use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _, iouring};
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
                b.iter_custom(measure_iouring);
            }),
            Backend::Tokio => c.bench_function(&name, |b| {
                b.iter_custom(measure_tokio);
            }),
        };
    }
}

/// Sum io_uring timer-consumer latencies under persistent ready load.
fn measure_iouring(iters: u64) -> Duration {
    iouring::Runner::default().start(move |context| async move {
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
            elapsed += timer.await.expect("io_uring timer task failed");
        }

        stop.store(true, Ordering::Relaxed);
        for result in join_all(load).await {
            result.expect("io_uring load task failed");
        }
        elapsed
    })
}

/// Sum Tokio timer-consumer latencies under persistent ready load.
fn measure_tokio(iters: u64) -> Duration {
    let runtime = tokio_runtime();
    runtime.block_on(async move {
        let stop = Arc::new(AtomicBool::new(false));
        let mut load = Vec::with_capacity(LOAD_WIDTH);
        for _ in 0..LOAD_WIDTH {
            load.push(tokio::spawn(ReadyLoad::new(Arc::clone(&stop))));
        }

        let mut elapsed = Duration::ZERO;
        for _ in 0..iters {
            let timer = tokio::spawn(async {
                // Start inside the consumer so queueing before its first poll is setup.
                let start = Instant::now();
                tokio::time::sleep(DELAY).await;
                start.elapsed()
            });
            elapsed += timer.await.expect("Tokio timer task failed");
        }

        stop.store(true, Ordering::Relaxed);
        for result in join_all(load).await {
            result.expect("Tokio load task failed");
        }
        elapsed
    })
}
