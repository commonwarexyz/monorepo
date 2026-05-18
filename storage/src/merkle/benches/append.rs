use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::merkle::{self, mem::Mem, Bagging::ForwardFold, Family};
use criterion::{criterion_group, BatchSize, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, SeedableRng};

type StandardHasher<H> = merkle::hasher::Standard<H>;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

fn make_elements(n: usize) -> Vec<sha256::Digest> {
    let mut elements = Vec::with_capacity(n);
    let mut sampler = StdRng::seed_from_u64(0);
    for _ in 0..n {
        elements.push(sha256::Digest::random(&mut sampler));
    }
    elements
}

fn bench_append_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        c.bench_function(&format!("{}/n={n} family={family}", module_path!()), |b| {
            b.iter_batched(
                || make_elements(n),
                |elements| {
                    block_on(async {
                        let h = StandardHasher::<Sha256>::new(ForwardFold);
                        let mut mem = Mem::<F, _>::new();
                        let batch = {
                            let mut batch = mem.new_batch();
                            for digest in &elements {
                                batch = batch.add(&h, digest);
                            }
                            batch.merkleize(&mem, &h)
                        };
                        mem.apply_batch(&batch).unwrap();
                        mem
                    })
                },
                BatchSize::LargeInput,
            );
        });
    }
}

fn bench_append(c: &mut Criterion) {
    bench_append_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_append_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_append
}
