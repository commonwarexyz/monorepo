use crate::{bench_decode_generic, bench_encode_generic};
use commonware_coding::ReedSolomon;
#[cfg(feature = "isa-l")]
use commonware_coding::ReedSolomonGf8;
use commonware_cryptography::Sha256;
use criterion::{criterion_group, Criterion};

fn bench_encode(c: &mut Criterion) {
    bench_encode_generic::<ReedSolomon<Sha256>>("reed_solomon::encode", c);
}

#[cfg(feature = "isa-l")]
fn bench_encode_gf8(c: &mut Criterion) {
    bench_encode_generic::<ReedSolomonGf8<Sha256>>("reed_solomon_gf8::encode", c);
}

fn bench_decode(c: &mut Criterion) {
    bench_decode_generic::<ReedSolomon<Sha256>>("reed_solomon::decode", c);
}

#[cfg(feature = "isa-l")]
fn bench_decode_gf8(c: &mut Criterion) {
    bench_decode_generic::<ReedSolomonGf8<Sha256>>("reed_solomon_gf8::decode", c);
}

#[cfg(feature = "isa-l")]
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode, bench_encode_gf8, bench_decode_gf8
}

#[cfg(not(feature = "isa-l"))]
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode
}
