use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng;

fn bench_hash_many(c: &mut Criterion) {
    let mut sampler = test_rng();
    for len in [64, 256, 4096, 16_384, 65_536, 262_144] {
        let mut messages: [Vec<u8>; 32] = core::array::from_fn(|_| vec![0; len]);
        for message in &mut messages {
            sampler.fill_bytes(message);
        }
        let messages = messages.each_ref().map(Vec::as_slice);
        for count in [1, 2, 6, 7, 15, 16, 17, 32] {
            let messages = &messages[..count];
            c.bench_function(
                &format!("{}::individual/count={count} len={len}", module_path!()),
                |b| {
                    b.iter(|| {
                        messages
                            .iter()
                            .map(|&message| Sha256::hash(&[message]))
                            .collect::<Vec<_>>()
                    })
                },
            );
            c.bench_function(
                &format!("{}::batch/count={count} len={len}", module_path!()),
                |b| b.iter(|| Sha256::hash_many(messages, &Sequential)),
            );
        }
    }
}

criterion_group!(benches, bench_hash_many);
