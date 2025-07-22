use criterion::{criterion_group, criterion_main, Criterion};

mod lthash_operations;

use lthash_operations::*;

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_lthash_add, bench_lthash_subtract, bench_lthash_combine, bench_lthash_finalize, bench_lthash_operations_comparison
}
criterion_main!(benches);
