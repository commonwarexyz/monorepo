use commonware_coding::reed_solomon::{decode, encode};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, RngCore, SeedableRng};

fn benchmark_decode(c: &mut Criterion) {
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
                        let (root, proofs) = encode(&data, total_pieces, min_pieces).unwrap();

                        // Compute shard_size
                        let extended_len = 8 + data_length;
                        let mut shard_size = extended_len.div_ceil(min_pieces);
                        if shard_size % 2 != 0 {
                            shard_size += 1;
                        }

                        // Select min_pieces random proofs
                        let mut pieces = Vec::with_capacity(min_pieces);
                        let mut indices: Vec<usize> = (0..total_pieces).collect();
                        indices.shuffle(&mut sampler);
                        for &i in indices.iter().take(min_pieces) {
                            pieces.push((i, proofs[i].clone()));
                        }

                        (root, pieces, shard_size)
                    },
                    |(root, pieces, shard_size)| {
                        decode(&root, &pieces, total_pieces, min_pieces, shard_size).unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_decode
}
