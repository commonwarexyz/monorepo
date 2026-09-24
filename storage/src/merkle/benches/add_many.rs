//! Benchmarks for bulk appends with `add_many`, followed by `merkleize`, on a committed tree.

use bytes::Bytes;
use commonware_cryptography::{Sha256, sha256};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_storage::merkle::{
    self, Bagging::ForwardFold, Family, batch::MerkleizedBatch, mem::Mem,
};
use commonware_utils::{NZUsize, test_rng};
use criterion::{Criterion, criterion_group};
use rand::Rng as _;
use std::hint::black_box;

type StandardHasher<H> = merkle::hasher::Standard<H>;

/// Leaves already in the tree (deliberately not a power of two).
const COMMITTED: u64 = 100_003;

/// Batch sizes for small items, including sizes on either side of the smallest split.
const OPS: [usize; 5] = [100, 128, 1_000, 8_192, 65_536];

/// Size of each small item.
const SMALL: usize = 64;

/// Items in each skewed batch.
const SKEWED_OPS: usize = 512;

/// Size of each large item in a skewed batch.
const LARGE: usize = 1024 * 1024;

/// Workers in the parallel strategy.
const WORKERS: usize = 8;

fn committed<F: Family>(hasher: &StandardHasher<Sha256>) -> Mem<F, sha256::Digest> {
    let mut mem = Mem::new();
    let batch = {
        let mut batch = mem.new_batch();
        for i in 0..COMMITTED {
            batch = batch.add(hasher, &i.to_be_bytes());
        }
        batch.merkleize(&mem, hasher)
    };
    mem.apply_batch(&batch).unwrap();
    mem
}

fn bench_case<F: Family, S: Strategy>(
    c: &mut Criterion,
    name: &str,
    mem: &Mem<F, sha256::Digest>,
    strategy: &S,
    items: &[Bytes],
) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    c.bench_function(&format!("{}/{name}", module_path!()), |b| {
        b.iter(|| {
            let batch = MerkleizedBatch::from_mem_with_strategy(mem, strategy.clone())
                .new_batch()
                .add_many(&hasher, items)
                .merkleize(mem, &hasher);
            black_box(batch)
        });
    });
}

/// Bench `items` on `mem` with one worker and with `WORKERS` workers.
fn bench_workers<F: Family>(
    c: &mut Criterion,
    params: &str,
    mem: &Mem<F, sha256::Digest>,
    rayon: &Rayon,
    items: &[Bytes],
) {
    bench_case(c, &format!("{params} workers=1"), mem, &Sequential, items);
    bench_case(c, &format!("{params} workers={WORKERS}"), mem, rayon, items);
}

fn bench_uniform(c: &mut Criterion) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    let mmr = committed::<commonware_storage::mmr::Family>(&hasher);
    let mmb = committed::<commonware_storage::mmb::Family>(&hasher);
    let rayon = Rayon::new(NZUsize!(WORKERS)).unwrap();
    let mut rng = test_rng();
    for ops in OPS {
        let items: Vec<Bytes> = (0..ops)
            .map(|_| {
                let mut item = vec![0; SMALL];
                rng.fill_bytes(&mut item);
                Bytes::from(item)
            })
            .collect();
        bench_workers(c, &format!("family=mmr ops={ops}"), &mmr, &rayon, &items);
        bench_workers(c, &format!("family=mmb ops={ops}"), &mmb, &rayon, &items);
    }
}

fn bench_skewed(c: &mut Criterion) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    let mmr = committed::<commonware_storage::mmr::Family>(&hasher);
    let rayon = Rayon::new(NZUsize!(WORKERS)).unwrap();
    let small = Bytes::from(vec![7; SMALL]);
    let large = Bytes::from(vec![7; LARGE]);
    let dominant = Bytes::from(vec![7; 16 * LARGE]);
    for payload in ["clustered", "spread", "few", "dominant"] {
        let items: Vec<Bytes> = (0..SKEWED_OPS)
            .map(|i| match payload {
                "clustered" if i < 64 => large.clone(),
                "spread" if i.is_multiple_of(8) => large.clone(),
                "few" if i < 16 => large.clone(),
                "dominant" if i == 0 => dominant.clone(),
                _ => small.clone(),
            })
            .collect();
        let params = format!("family=mmr ops={SKEWED_OPS} payload={payload}");
        bench_workers(c, &params, &mmr, &rayon, &items);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_uniform
}

criterion_group! {
    name = skewed;
    config = Criterion::default().sample_size(10);
    targets = bench_skewed
}
