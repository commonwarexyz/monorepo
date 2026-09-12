use super::advancement::{self, Operation};
use criterion::{Criterion, criterion_group};

fn bench_prepare_apply(c: &mut Criterion) {
    advancement::benches(c, module_path!(), Operation::Prepare);
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_prepare_apply,}
