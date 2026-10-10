use commonware_cryptography::{Hasher, Sha512};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, test_rng};
use criterion::{Criterion, criterion_group};
use rand::Rng;

/// Workers in the pool behind the parallel rows.
const CONCURRENCY: usize = 8;

fn bench_hash_many(c: &mut Criterion) {
    let mut sampler = test_rng();
    let strategy = Rayon::new(NZUsize!(CONCURRENCY)).unwrap();
    for len in [96, 1024, 16_384, 65_536, 262_144] {
        let mut messages: [Vec<u8>; 128] = core::array::from_fn(|_| vec![0; len]);
        for message in &mut messages {
            sampler.fill_bytes(message);
        }
        let messages = messages.each_ref().map(Vec::as_slice);
        for count in [1, 2, 7, 8, 9, 16, 32, 128] {
            let messages = &messages[..count];
            c.bench_function(
                &format!("{}::individual/count={count} len={len}", module_path!()),
                |b| {
                    b.iter(|| {
                        messages
                            .iter()
                            .map(|&message| Sha512::hash(&[message]))
                            .collect::<Vec<_>>()
                    })
                },
            );
            c.bench_function(
                &format!("{}::batch/count={count} len={len} conc=1", module_path!()),
                |b| b.iter(|| Sha512::hash_many(messages, &Sequential)),
            );
            c.bench_function(
                &format!(
                    "{}::batch/count={count} len={len} conc={CONCURRENCY}",
                    module_path!()
                ),
                |b| b.iter(|| Sha512::hash_many(messages, &strategy)),
            );
        }
    }
}

criterion_group!(benches, bench_hash_many);
