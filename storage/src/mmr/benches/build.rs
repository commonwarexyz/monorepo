use commonware_cryptography::{Digest, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};

fn bench_build(c: &mut Criterion) {
    let element = Digest::from_static(&[100u8; 32]);
    c.bench_function(module_path!(), |b| {
        let mut mmr = Mmr::<Sha256>::new();
        // bootstrap w/ 5M elements
        for _ in 0..5_000_000 {
            mmr.add(&element);
        }
        // time adding 1M more
        b.iter(|| {
            for _ in 0..1_000_000 {
                mmr.add(&element);
            }
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_build
}
