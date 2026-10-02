use commonware_cryptography::blake3::Blake3;
use criterion::{Criterion, criterion_group};

fn bench_hash_many_parts(c: &mut Criterion) {
    crate::hash_workloads::bench_hash_many_parts::<Blake3>(c, module_path!());
}

criterion_group!(benches, bench_hash_many_parts);
