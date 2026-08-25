use commonware_parallel::{heartbeat, Rayon, Strategy};
use criterion::{criterion_group, Criterion};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::{hint::black_box, num::NonZeroUsize, time::Duration};

/// Total compute threads for every parallel strategy. The heartbeat pool spawns one fewer
/// worker because the calling thread participates in execution.
const THREADS: usize = 8;

/// A cheap per-element operation (about a nanosecond).
fn cheap(acc: u64, x: &u64) -> u64 {
    acc.wrapping_add(x.rotate_left(7) ^ x)
}

/// An expensive per-element operation (about a microsecond of dependent arithmetic).
fn expensive(acc: u64, x: &u64) -> u64 {
    let mut v = x.wrapping_add(1);
    for _ in 0..1000 {
        v = black_box(
            v.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407),
        );
    }
    acc.wrapping_add(v)
}

#[allow(clippy::too_many_arguments)]
fn bench_workload(
    c: &mut Criterion,
    work: &str,
    sizes: &[usize],
    grain: usize,
    op: fn(u64, &u64) -> u64,
    adaptive: &Rayon,
    raw: &rayon::ThreadPool,
    hb: &heartbeat::Pool,
) {
    for &n in sizes {
        let data: Vec<u64> = (0..n as u64).collect();

        c.bench_function(
            &format!("{}/strategy=sequential work={work} n={n}", module_path!()),
            |b| {
                b.iter(|| black_box(data.iter().fold(0u64, op)));
            },
        );

        c.bench_function(
            &format!("{}/strategy=adaptive work={work} n={n}", module_path!()),
            |b| {
                b.iter(|| black_box(adaptive.fold(&data, || 0u64, op, |a, b| a.wrapping_add(b))));
            },
        );

        c.bench_function(
            &format!("{}/strategy=rayon work={work} n={n}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(raw.install(|| {
                        data.par_iter()
                            .fold(|| 0u64, op)
                            .reduce(|| 0u64, |a, b| a.wrapping_add(b))
                    }))
                });
            },
        );

        c.bench_function(
            &format!("{}/strategy=heartbeat work={work} n={n}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(hb.run(|scope| {
                        heartbeat::fold(
                            scope,
                            &data,
                            grain,
                            &|| 0u64,
                            &|acc, x| op(acc, x),
                            &|a, b| a.wrapping_add(b),
                        )
                    }))
                });
            },
        );
    }
}

fn bench_fold(c: &mut Criterion) {
    let adaptive = Rayon::new(NonZeroUsize::new(THREADS).unwrap()).unwrap();
    let raw = rayon::ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .build()
        .unwrap();
    let hb = heartbeat::Pool::new(THREADS - 1);

    bench_workload(
        c,
        "cheap",
        &[16, 256, 4096, 65536, 1048576],
        1024,
        cheap,
        &adaptive,
        &raw,
        &hb,
    );
    bench_workload(
        c,
        "expensive",
        &[2, 16, 64, 128, 512, 1024, 8192],
        1,
        expensive,
        &adaptive,
        &raw,
        &hb,
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_fold,
}
