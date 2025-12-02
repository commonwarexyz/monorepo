use commonware_cryptography::{sha256, Digest as _, Hasher, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_multi(c: &mut Criterion) {
    for n in [256, 1_024, 4_096, 16_384, 65_536] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            builder.add(&element);
            elements.push(element);
        }
        let tree = builder.build();
        let root = tree.root();

        // Benchmark multi-proof generation for random non-contiguous positions
        c.bench_function(
            &format!("{}/generate/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        // Select random non-contiguous positions
                        let mut positions: Vec<u32> = (0..n as u32).collect();
                        positions.shuffle(&mut sampler);
                        positions.truncate(SAMPLE_SIZE);
                        positions.sort();
                        positions
                    },
                    |positions| tree.multi_proof(&positions).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        // Benchmark multi-proof verification for random non-contiguous positions
        c.bench_function(
            &format!("{}/verify/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        // Select random non-contiguous positions
                        let mut positions: Vec<u32> = (0..n as u32).collect();
                        positions.shuffle(&mut sampler);
                        positions.truncate(SAMPLE_SIZE);
                        positions.sort();
                        let proof = tree.multi_proof(&positions).unwrap();
                        let proof_elements: Vec<_> = positions
                            .iter()
                            .map(|&p| (elements[p as usize], p))
                            .collect();
                        (proof, proof_elements)
                    },
                    |(proof, proof_elements)| {
                        let mut hasher = Sha256::new();
                        assert!(proof
                            .verify_multi(&mut hasher, &proof_elements, &root)
                            .is_ok());
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        // Benchmark with strided access pattern (similar to ZODA shards)
        let stride = n / SAMPLE_SIZE;
        if stride > 0 {
            let strided_positions: Vec<u32> =
                (0..SAMPLE_SIZE as u32).map(|i| i * stride as u32).collect();
            let strided_proof = tree.multi_proof(&strided_positions).unwrap();
            let strided_elements: Vec<_> = strided_positions
                .iter()
                .map(|&p| (elements[p as usize], p))
                .collect();

            c.bench_function(
                &format!("{}/strided/n={} items={}", module_path!(), n, SAMPLE_SIZE),
                |b| {
                    b.iter(|| {
                        let mut hasher = Sha256::new();
                        assert!(strided_proof
                            .verify_multi(&mut hasher, &strided_elements, &root)
                            .is_ok());
                    })
                },
            );
        }
    }
}

fn bench_multi_proof_sizes(c: &mut Criterion) {
    // Benchmark how proof size scales with number of elements proved
    let n = 4096;
    let mut builder = Builder::<Sha256>::new(n);
    let mut elements = Vec::with_capacity(n);
    let mut sampler = StdRng::seed_from_u64(42);
    for _ in 0..n {
        let element = sha256::Digest::random(&mut sampler);
        builder.add(&element);
        elements.push(element);
    }
    let tree = builder.build();

    for num_elements in [1, 10, 50, 100, 500, 1000, 2000] {
        if num_elements > n {
            continue;
        }

        c.bench_function(
            &format!("{}/scaling/n={} items={}", module_path!(), n, num_elements),
            |b| {
                b.iter_batched(
                    || {
                        let mut positions: Vec<u32> = (0..n as u32).collect();
                        positions.shuffle(&mut sampler);
                        positions.truncate(num_elements);
                        positions.sort();
                        positions
                    },
                    |positions| tree.multi_proof(&positions).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_multi, bench_multi_proof_sizes
}
