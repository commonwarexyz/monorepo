use crate::{bench_decode_generic, bench_encode_generic};
use commonware_coding::ReedSolomon;
use commonware_cryptography::Sha256;
use criterion::{criterion_group, Criterion};

fn bench_encode(c: &mut Criterion) {
    bench_encode_generic::<ReedSolomon<Sha256>>("reed_solomon::encode", c);
}

fn bench_decode(c: &mut Criterion) {
    bench_decode_generic::<ReedSolomon<Sha256>>("reed_solomon::decode", c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode
}
