use crate::{bench_decode_generic, bench_encode_generic};
use commonware_coding::Zoda;
use commonware_cryptography::Sha256;
use criterion::{criterion_group, Criterion};

fn bench_encode(c: &mut Criterion) {
    bench_encode_generic::<Zoda<Sha256>>("zoda::encode", c);
}

fn bench_decode(c: &mut Criterion) {
    bench_decode_generic::<Zoda<Sha256>>("zoda::decode", c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode
}
