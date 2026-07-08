use commonware_math::{fields::goldilocks::F, ntt::Matrix};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;

/// Benchmark the forward dense NTT (`PolynomialVector::evaluate`) at sizes that
/// mirror ZODA encoding (`2^15` encoded rows; `cols` grows with the block size,
/// reaching ~192 for an 8 MiB block).
fn bench_evaluate(c: &mut Criterion) {
    let lg_rows = 15u32;
    let rows = 1usize << lg_rows;
    for &cols in &[1usize, 4, 16, 64, 192] {
        let data: Vec<F> = F::stream_from_u64s((0..).map(|i| i as u64 | 1))
            .take(rows * cols)
            .collect();
        let matrix = Matrix::init(rows, cols, data.into_iter());
        let poly = matrix
            .as_polynomials(rows)
            .expect("min_coefficients == rows");

        let label = format!("{}::evaluate/lg_rows={lg_rows} cols={cols}", module_path!());
        c.bench_function(&label, |b| {
            b.iter_batched(
                || poly.clone(),
                |p| black_box(p.evaluate()),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_evaluate,
}
criterion_main!(benches);
