//! Ready task spawn and join throughput at representative batch widths.

use super::support::{Backend, tokio_runtime};
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, iouring};
use criterion::Criterion;
use futures::future::join_all;
use std::time::{Duration, Instant};

const WIDTHS: [usize; 3] = [1, 64, 1024];

/// Register ready spawn-and-join rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    for width in WIDTHS {
        for backend in Backend::ALL {
            let name = format!(
                "{}/runtime={} width={width}",
                module_path!(),
                backend.name()
            );
            match backend {
                Backend::IoUring => c.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_iouring(iters, width));
                }),
                Backend::Tokio => c.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_tokio(iters, width));
                }),
            };
        }
    }
}

/// Measure io_uring batches inside one runtime root.
fn measure_iouring(iters: u64, width: usize) -> Duration {
    iouring::Runner::default().start(move |context| async move {
        let start = Instant::now();
        for _ in 0..iters {
            let mut handles = Vec::with_capacity(width);
            for _ in 0..width {
                handles.push(context.child("ready").spawn(|_| async {}));
            }
            for result in join_all(handles).await {
                result.expect("io_uring ready task failed");
            }
        }
        start.elapsed()
    })
}

/// Measure Tokio batches inside one `block_on` root.
fn measure_tokio(iters: u64, width: usize) -> Duration {
    let runtime = tokio_runtime();
    runtime.block_on(async move {
        let start = Instant::now();
        for _ in 0..iters {
            let mut handles = Vec::with_capacity(width);
            for _ in 0..width {
                handles.push(tokio::spawn(async {}));
            }
            for result in join_all(handles).await {
                result.expect("Tokio ready task failed");
            }
        }
        start.elapsed()
    })
}
