//! Hash independent messages one at a time, with [Hasher::hash_many] on the calling thread, and
//! with [Hasher::hash_many_with] across a pool.

use commonware_cryptography::Hasher;
use commonware_parallel::Rayon;
use commonware_utils::{NZUsize, test_rng};
use criterion::Criterion;
use rand::Rng;

/// Workers in the pool behind the parallel rows.
const CONCURRENCY: usize = 8;

/// Bench `H` on `count` random messages of `len` bytes for every `len` in `lens` and `count`
/// in `counts`, naming each benchmark under `module`.
pub fn bench<H: Hasher>(c: &mut Criterion, module: &str, lens: &[usize], counts: &[usize]) {
    let mut sampler = test_rng();
    let strategy = Rayon::new(NZUsize!(CONCURRENCY)).unwrap();
    let most = counts.iter().copied().max().unwrap_or(0);
    for &len in lens {
        let messages: Vec<Vec<u8>> = (0..most)
            .map(|_| {
                let mut message = vec![0; len];
                sampler.fill_bytes(&mut message);
                message
            })
            .collect();
        let messages: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        for &count in counts {
            let messages = &messages[..count];
            c.bench_function(
                &format!("{module}::individual/count={count} len={len}"),
                |b| {
                    b.iter(|| {
                        messages
                            .iter()
                            .map(|&message| H::hash(&[message]))
                            .collect::<Vec<_>>()
                    })
                },
            );
            c.bench_function(
                &format!("{module}::batch/count={count} len={len} conc=1"),
                |b| b.iter(|| H::hash_many(messages)),
            );
            c.bench_function(
                &format!("{module}::batch/count={count} len={len} conc={CONCURRENCY}"),
                |b| b.iter(|| H::hash_many_with(messages, &strategy)),
            );
        }
    }
}
