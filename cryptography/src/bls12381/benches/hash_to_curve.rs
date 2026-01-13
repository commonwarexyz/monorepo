use commonware_cryptography::bls12381::primitives::{
    ops::hash_with_namespace,
    variant::{MinSig, Variant},
};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn bench_hash_to_curve(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [10, 50, 100, 200] {
        // Generate random messages
        let mut msgs: Vec<[u8; 32]> = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }

        for concurrency in [1, 8] {
            let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
            c.bench_function(
                &format!("{}/n={} conc={}", module_path!(), n, concurrency),
                |b| {
                    b.iter_batched(
                        || msgs.clone(),
                        |msgs| {
                            let hms: Vec<_> = if concurrency > 1 {
                                strategy.map_collect_vec(&msgs, |msg| {
                                    hash_with_namespace::<MinSig>(MinSig::MESSAGE, namespace, msg)
                                })
                            } else {
                                Sequential.map_collect_vec(&msgs, |msg| {
                                    hash_with_namespace::<MinSig>(MinSig::MESSAGE, namespace, msg)
                                })
                            };
                            black_box(hms)
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
    targets = bench_hash_to_curve
}
