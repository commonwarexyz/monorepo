//! Fixed-total self-wake throughput at narrow and wide task counts.

use super::support::{Backend, SelfWake, tokio_runtime};
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, iouring};
use criterion::Criterion;
use futures::future::join_all;
use std::time::{Duration, Instant};

const TOTAL_WAKES: usize = 65_536;
const WIDTHS: [usize; 3] = [1, 64, 1024];

/// Register fixed-total self-wake rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    for width in WIDTHS {
        let wakes_per_task = TOTAL_WAKES / width;
        for backend in Backend::ALL {
            let name = format!(
                "{}/runtime={} width={width} total_wakes={TOTAL_WAKES}",
                module_path!(),
                backend.name()
            );
            match backend {
                Backend::IoUring => c.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_iouring(iters, width, wakes_per_task));
                }),
                Backend::Tokio => c.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_tokio(iters, width, wakes_per_task));
                }),
            };
        }
    }
}

/// Measure io_uring self-wake work inside one runtime root.
fn measure_iouring(iters: u64, width: usize, wakes_per_task: usize) -> Duration {
    iouring::Runner::default().start(move |context| async move {
        let start = Instant::now();
        for _ in 0..iters {
            let mut handles = Vec::with_capacity(width);
            for _ in 0..width {
                handles.push(
                    context
                        .child("self_wake")
                        .spawn(move |_| SelfWake::new(wakes_per_task)),
                );
            }
            for result in join_all(handles).await {
                result.expect("io_uring self-wake task failed");
            }
        }
        start.elapsed()
    })
}

/// Measure Tokio self-wake work inside one `block_on` root.
fn measure_tokio(iters: u64, width: usize, wakes_per_task: usize) -> Duration {
    let runtime = tokio_runtime();
    runtime.block_on(async move {
        let start = Instant::now();
        for _ in 0..iters {
            let mut handles = Vec::with_capacity(width);
            for _ in 0..width {
                handles.push(tokio::spawn(SelfWake::new(wakes_per_task)));
            }
            for result in join_all(handles).await {
                result.expect("Tokio self-wake task failed");
            }
        }
        start.elapsed()
    })
}
