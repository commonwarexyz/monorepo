//! Ready task spawn and join throughput at representative batch widths.

use super::support::{Backend, tokio_runner};
use commonware_runtime::{Runner, Spawner, Supervisor as _, iouring};
use criterion::Criterion;
use futures::future::join_all;
use std::time::{Duration, Instant};

const WIDTHS: [usize; 7] = [1, 29, 30, 31, 32, 64, 1024];

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
                    b.iter_custom(|iters| measure(iters, width, iouring::Runner::default));
                }),
                Backend::Tokio => c.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure(iters, width, tokio_runner));
                }),
            };
        }
    }
}

/// Measure batches inside one runtime root.
fn measure<R, F>(iters: u64, width: usize, runner: F) -> Duration
where
    R: Runner,
    R::Context: Spawner,
    F: FnOnce() -> R,
{
    runner().start(move |context| async move {
        let start = Instant::now();
        for _ in 0..iters {
            let mut handles = Vec::with_capacity(width);
            for _ in 0..width {
                handles.push(context.child("ready").spawn(|_| async {}));
            }
            for result in join_all(handles).await {
                result.expect("ready task failed");
            }
        }
        start.elapsed()
    })
}
