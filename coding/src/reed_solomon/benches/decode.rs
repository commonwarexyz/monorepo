use commonware_coding::reed_solomon::{decode, encode};
use commonware_cryptography::Sha256;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, RngCore, SeedableRng};

fn benchmark_decode(c: &mut Criterion) {
    let mut sampler = StdRng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10, 25, 50, 100, 250] {
            let min = chunks / 3;
            c.bench_function(
                &format!(
                    "{}/msg_len={} chunks={}",
                    module_path!(),
                    data_length,
                    chunks
                ),
                |b| {
                    b.iter_batched(
                        || {
                            // Generate random data
                            let mut data = vec![0u8; data_length];
                            sampler.fill_bytes(&mut data);

                            // Encode data
                            let (root, proofs) = encode::<Sha256>(chunks, min, data).unwrap();

                            // Select min random chunks
                            let mut shuffled = Vec::with_capacity(min as usize);
                            let mut indices: Vec<u16> = (0..chunks).collect();
                            indices.shuffle(&mut sampler);
                            for &i in indices.iter().take(min as usize) {
                                shuffled.push(proofs[i as usize].clone());
                            }

                            (root, shuffled)
                        },
                        |(root, shuffled)| {
                            decode::<Sha256>(chunks, min, &root, shuffled).unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_decode
}
