use commonware_coding::reed_solomon::{decode, encode};
use commonware_cryptography::Sha256;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, RngCore, SeedableRng};

fn benchmark_decode(c: &mut Criterion) {
    let mut sampler = StdRng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        let total_pieces = 7u32;
        let min_pieces = 4u32;
        c.bench_function(
            &format!("{}/data_len={}", module_path!(), data_length),
            |b| {
                b.iter_batched(
                    || {
                        let mut data = vec![0u8; data_length];
                        sampler.fill_bytes(&mut data);
                        let (root, proofs) =
                            encode::<Sha256>(total_pieces, min_pieces, data).unwrap();

                        // Select min_pieces random proofs
                        let mut pieces = Vec::with_capacity(min_pieces as usize);
                        let mut indices: Vec<u32> = (0..total_pieces).collect();
                        indices.shuffle(&mut sampler);
                        for &i in indices.iter().take(min_pieces as usize) {
                            pieces.push(proofs[i as usize].clone());
                        }

                        (root, pieces)
                    },
                    |(root, pieces)| {
                        decode::<Sha256>(total_pieces, min_pieces, &root, pieces).unwrap();
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
