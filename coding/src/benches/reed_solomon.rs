use crate::{
    bench_decode_generic, bench_encode_generic,
    shard_selection::ShardSelection::{Best, Interleaved, Worst},
};
use commonware_codec::{EncodeSize, Write};
use commonware_coding::{Config, ReedSolomon, Scheme};
use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::{NZU16, NZUsize};
use criterion::{Criterion, SamplingMode, Throughput, criterion_group};
use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use std::{hint::black_box, time::Duration};

type RS = ReedSolomon<Sha256>;

fn bench_encode(c: &mut Criterion) {
    bench_encode_generic::<ReedSolomon<Sha256>>("reed_solomon::encode", c);
}

fn bench_encode_value_with_strategy(c: &mut Criterion, strategy: &impl Strategy, workers: usize) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut group = c.benchmark_group(format!("{}::encode_value", module_path!()));
    group
        .sample_size(30)
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));

    for size in [1 << 20, 4 << 20, 16 << 20] {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        group.throughput(Throughput::Bytes(size as u64));

        for shards in [10u16, 100] {
            let minimum = shards / 3;
            let config = Config {
                minimum_shards: NZU16!(minimum),
                extra_shards: NZU16!(shards - minimum),
            };
            let value = (data.as_slice(), config);
            let buffered = || {
                let value = black_box(&value);
                let mut bytes = Vec::with_capacity(value.encode_size());
                value.write(&mut bytes);
                RS::encode(black_box(&config), bytes.as_slice(), strategy).unwrap()
            };
            let direct =
                || RS::encode_value(black_box(&config), black_box(&value), strategy).unwrap();
            assert_eq!(buffered(), direct());

            let parameters = format!("size={size} shards={shards} workers={workers}");
            group.bench_function(format!("{parameters} mode=buffered"), |b| b.iter(buffered));
            group.bench_function(format!("{parameters} mode=direct"), |b| b.iter(direct));
        }
    }
    group.finish();
}

fn bench_encode_value(c: &mut Criterion) {
    bench_encode_value_with_strategy(c, &Sequential, 1);
    let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
    bench_encode_value_with_strategy(c, &strategy, 4);
}

fn bench_decode(c: &mut Criterion) {
    // Payload bytes, total shards, worker count, and shard selection.
    let cases = [
        (1 << 12, 20, 1, Interleaved),
        (1 << 20, 20, 1, Interleaved),
        (1 << 20, 20, 4, Interleaved),
        (1 << 23, 20, 1, Interleaved),
        (1 << 23, 20, 4, Interleaved),
        (1 << 20, 100, 4, Interleaved),
        (1 << 20, 250, 4, Interleaved),
        (1 << 20, 500, 4, Interleaved),
        (1 << 20, 20, 4, Best),
        (1 << 20, 20, 4, Worst),
    ];
    bench_decode_generic::<ReedSolomon<Sha256>>("reed_solomon::decode", c, &cases);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode, bench_encode_value
}
