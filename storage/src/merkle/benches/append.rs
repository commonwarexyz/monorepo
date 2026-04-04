use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::merkle::{self, mem::Mem, Family};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, SeedableRng};

type StandardHasher<H> = merkle::hasher::Standard<H>;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

fn bench_append_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            elements.push(element);
        }

        c.bench_function(&format!("{}/n={n} family={family}", module_path!()), |b| {
            b.iter(|| {
                block_on(async {
                    let h = StandardHasher::<Sha256>::new();
                    let mut mem = Mem::<F, _>::new(&h);
                    let batch = {
                        let mut batch = mem.new_batch();
                        for digest in &elements {
                            batch = batch.add(&h, digest);
                        }
                        batch.merkleize(&h, &mem)
                    };
                    mem.apply_batch(&batch).unwrap();
                    mem
                })
            });
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
