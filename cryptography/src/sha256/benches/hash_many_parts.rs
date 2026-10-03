use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};

fn bench_hash_many_parts(c: &mut Criterion) {
    crate::hash_workloads::bench_hash_many_parts::<Sha256>(c, module_path!());
}

criterion_group!(benches, bench_hash_many_parts);
