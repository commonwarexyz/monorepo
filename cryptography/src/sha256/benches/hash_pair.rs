use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};

fn bench_hash_pair(c: &mut Criterion) {
    crate::hash_workloads::bench_hash_pair::<Sha256>(c, module_path!());
}

fn bench_dependent_hash_pair(c: &mut Criterion) {
    crate::hash_workloads::bench_dependent_hash_pair::<Sha256>(c, module_path!());
}

criterion_group!(benches, bench_hash_pair, bench_dependent_hash_pair);
