use commonware_coding::ReedSolomon;
use commonware_cryptography::Sha256;
use criterion::{criterion_group, Criterion};

use crate::{benchmark_decode_generic, benchmark_encode_generic};

fn benchmark_encode(c: &mut Criterion) {
    benchmark_encode_generic::<ReedSolomon<Sha256>>("reed_solomon_encode", c);
}

fn benchmark_decode(c: &mut Criterion) {
    benchmark_decode_generic::<ReedSolomon<Sha256>>("reed_solomon_decode", c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_encode, benchmark_decode
}
