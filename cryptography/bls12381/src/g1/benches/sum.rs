use super::utils::{points, to_blst};
use commonware_cryptography_bls12381::g1::G1;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

fn bench_sum(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [8, 32, 128, 512] {
        let points = points(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("impl=lanes n={n}"), |b| {
            b.iter(|| black_box(G1::sum(&points)));
        });
        let blst_points: Vec<_> = points.iter().map(to_blst).collect();
        group.bench_function(format!("impl=blst n={n}"), |b| {
            b.iter(|| {
                let mut acc = blst::blst_p1::default();
                for point in &blst_points {
                    // SAFETY: valid pointers to point structures.
                    unsafe { blst::blst_p1_add_or_double(&mut acc, &acc, point) };
                }
                black_box(acc)
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sum
}
