use commonware_cryptography::{Digest, Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};

fn bench_prove_element_range(c: &mut Criterion) {
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
            let mut iter = leaf_sample.iter();
            let mut pos1 = iter.next().unwrap();
            let mut count: usize = 0;
            for pos2 in iter {
                let proof = mmr.range_proof(*pos1, *pos2);
                assert!(proof.verify_range_inclusion(
                    &elements[count..count + SAMPLE_SIZE + 1],
                    *pos1,
                    *pos2,
                    &root_hash,
                    &mut hasher
                ));
                pos1 = pos2;
                count += SAMPLE_SIZE;
            }
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_element_range
}
