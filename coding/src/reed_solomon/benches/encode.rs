use commonware_coding::reed_solomon::encode;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn benchmark_encode(c: &mut Criterion) {
    let mut sampler = StdRng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        let total_pieces = 7;
        let min_pieces = 4;
        c.bench_function(
            &format!("{}/data_len={}", module_path!(), data_length),
            |b| {
                b.iter_batched(
                    || {
                        let mut data = vec![0u8; data_length];
                        sampler.fill_bytes(&mut data);
                        data
                    },
                    |data| {
                        encode(&data, total_pieces, min_pieces).unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group!(benches, benchmark_encode);
