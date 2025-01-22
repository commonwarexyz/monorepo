use commonware_cryptography::{Digest, Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};

fn bench_prove_single_element(c: &mut Criterion) {
    let mut mmr = Mmr::<Sha256>::new();
    let mut leaf_sample = Vec::new();
    let element = Digest::from_static(&[100u8; 32]);
    const NUM_ELEMENTS: usize = 5_000_000;
    const SAMPLE_SIZE: usize = 100;
    let mut elements = Vec::with_capacity(NUM_ELEMENTS);
    for i in 0..NUM_ELEMENTS {
        let pos = mmr.add(&element);
        elements.push(element.clone());
        if i % SAMPLE_SIZE == 0 {
            leaf_sample.push(pos);
        }
    }
    let root_hash = mmr.root_hash();

    c.bench_function(module_path!(), |b| {
        let mut hasher = Sha256::new();
        b.iter(|| {
            for pos in &leaf_sample {
                let proof = mmr.proof(*pos);
                assert!(proof.verify_element_inclusion(&element, *pos, &root_hash, &mut hasher));
            }
        })
    });
}
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_single_element
}
