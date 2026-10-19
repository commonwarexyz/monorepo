//! Benchmarks for bulk appends with `add_many`, followed by `merkleize`, on a committed tree.

use bytes::Bytes;
use commonware_cryptography::{Sha256, sha256};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_storage::merkle::{
    self, Bagging::ForwardFold, Family, batch::MerkleizedBatch, mem::Mem,
};
use commonware_utils::{NZUsize, test_rng};
use criterion::{Criterion, criterion_group};
use rand::Rng;

type StandardHasher<H> = merkle::hasher::Standard<H>;

/// Leaves already in the tree (deliberately not a power of two).
const COMMITTED: u64 = 100_003;

/// Batch sizes for small items.
const ITEMS: [usize; 5] = [100, 128, 1_000, 8_192, 65_536];

/// Size of each small item.
const SMALL: usize = 64;

/// Items in each skewed batch.
const SKEWED_ITEMS: usize = 512;

/// Large items at the front of a clustered batch.
const CLUSTERED: usize = 64;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// Whether the item at an index of a skewed batch is large.
type IsLarge = fn(usize) -> bool;

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
            MerkleizedBatch::from_mem_with_strategy(mem, strategy.clone())
                .new_batch()
                .add_many(&hasher, items)
                .merkleize(mem, &hasher)
        });
    });
}

/// Bench `items` on `mem` with one worker and with `WORKERS` workers.
fn bench_workers<F: Family>(
    c: &mut Criterion,
    params: &str,
    family: &str,
    mem: &Mem<F, sha256::Digest>,
    rayon: &Rayon,
    items: &[Bytes],
) {
    let name = |workers| format!("{params} workers={workers} family={family}");
    bench_case(c, &name(1), mem, &Sequential, items);
    bench_case(c, &name(WORKERS), mem, rayon, items);
}

/// A random item of `len` bytes in its own allocation.
fn item(rng: &mut impl Rng, len: usize) -> Bytes {
    let mut item = vec![0; len];
    rng.fill_bytes(&mut item);
    Bytes::from(item)
}

fn bench_uniform(c: &mut Criterion) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    let mmr = committed::<commonware_storage::mmr::Family>(&hasher);
    let mmb = committed::<commonware_storage::mmb::Family>(&hasher);
    let rayon = Rayon::new(NZUsize!(WORKERS)).unwrap();
    let mut rng = test_rng();
    for n in ITEMS {
        let items: Vec<Bytes> = (0..n).map(|_| item(&mut rng, SMALL)).collect();
        let params = format!("items={n}");
        bench_workers(c, &params, "mmr", &mmr, &rayon, &items);
        bench_workers(c, &params, "mmb", &mmb, &rayon, &items);
    }
}

fn bench_skewed(c: &mut Criterion) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    let mmr = committed::<commonware_storage::mmr::Family>(&hasher);
    let rayon = Rayon::new(NZUsize!(WORKERS)).unwrap();
    let mut rng = test_rng();
    let cases: [(&str, usize, IsLarge); 4] = [
        ("clustered", MIB, |i| i < CLUSTERED),
        ("clustered", 8 * KIB, |i| i < CLUSTERED),
        ("spread", MIB, |i| i.is_multiple_of(8)),
        ("dominant", 16 * MIB, |i| i == 0),
    ];
    for (payload, large, is_large) in cases {
        let items: Vec<Bytes> = (0..SKEWED_ITEMS)
            .map(|i| item(&mut rng, if is_large(i) { large } else { SMALL }))
            .collect();
        let params = format!("items={SKEWED_ITEMS} payload={payload} large={large}");
        bench_workers(c, &params, "mmr", &mmr, &rayon, &items);
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
