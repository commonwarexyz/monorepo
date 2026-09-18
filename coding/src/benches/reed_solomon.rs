use crate::{
    bench_decode_generic, bench_encode_generic, shard_selection::ShardSelection::Interleaved,
};
use commonware_coding::ReedSolomon;
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};

fn bench_encode(c: &mut Criterion) {
    bench_encode_generic::<ReedSolomon<Sha256>>("reed_solomon::encode", c);
}

fn bench_decode(c: &mut Criterion) {
    // Payload bytes, total shards, worker count, and shard selection.
    let cases = [(1 << 20, 500, 4, Interleaved)];
    bench_decode_generic::<ReedSolomon<Sha256>>("reed_solomon::decode", c, &cases);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode
}
