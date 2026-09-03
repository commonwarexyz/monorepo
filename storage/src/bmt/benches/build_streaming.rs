use commonware_cryptography::{Sha256, sha256};
use commonware_math::algebra::Random as _;
use commonware_parallel::{Rayon, Sequential};
use commonware_storage::bmt::{Builder, StreamingBuilder};
use commonware_utils::test_rng;
use core::num::NonZeroUsize;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const WORKERS: usize = 8;

fn bench_build_streaming(c: &mut Criterion) {
    let strategy = Rayon::new(NonZeroUsize::new(WORKERS).unwrap())
        .expect("benchmark worker pool must initialize");
    for n in [100_000usize, 1_000_003] {
        let mut sampler = test_rng();
        let elements = (0..n)
            .map(|_| sha256::Digest::random(&mut sampler))
            .collect::<Vec<_>>();

        let mut dense = Builder::<Sha256>::new(n);
        for element in &elements {
            dense.add(element);
        }
        let expected = dense.build(&Sequential).root();

        for subtree_size in [1_024usize, 16_384] {
            let mut check = StreamingBuilder::<Sha256>::new(n as u32, subtree_size).unwrap();
            check.extend(&elements, &strategy).unwrap();
            assert_eq!(check.finish(&strategy).unwrap(), expected);

            c.bench_function(
                &format!(
                    "{}/n={n} subtree_size={subtree_size} workers={WORKERS}",
                    module_path!(),
                ),
                |b| {
                    b.iter(|| {
                        let mut builder =
                            StreamingBuilder::<Sha256>::new(n as u32, subtree_size).unwrap();
                        builder
                            .extend(black_box(&elements), black_box(&strategy))
                            .unwrap();
                        black_box(builder.finish(black_box(&strategy)).unwrap())
                    })
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_build_streaming,
}
