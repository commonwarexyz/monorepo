use commonware_utils::rational::BigRationalExt;
use criterion::{criterion_group, Criterion};
use num_rational::BigRational;

fn benchmark_log2_ceil(c: &mut Criterion) {
    let cases = [
        BigRational::from_frac_u64(1, 2),
        BigRational::from_frac_u64(1, 4),
        BigRational::from_frac_u64(3, 4),
        BigRational::from_frac_u64(3, 8),
        BigRational::from_frac_u64(7, 8),
        BigRational::from_frac_u64(15, 16),
        BigRational::from_frac_u64(511, 512),
        BigRational::from_frac_u64(1023, 1024),
    ];

    for value in cases.iter() {
        for precision in [4, 8, 12] {
            c.bench_function(
                &format!(
                    "{}/value={}:{} precision={}",
                    module_path!(),
                    value.numer(),
                    value.denom(),
                    precision
                ),
                |b| {
                    b.iter(|| value.log2_ceil(precision));
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_log2_ceil,
}
