use commonware_codec::{Copying, DecodeExt, Encode};
use commonware_cryptography::banderwagon::G as ReferenceGroup;
use commonware_cryptography_bls::banderwagon::{G, Scalar};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn points() -> (G, G, ReferenceGroup, ReferenceGroup) {
    let generator = G::generator();
    let left = G::from_bytes(&generator.mul(&Scalar::from_u64(17)).to_bytes()).unwrap();
    let right = G::from_bytes(&generator.mul(&Scalar::from_u64(29)).to_bytes()).unwrap();
    let reference_left = ReferenceGroup::decode(Copying(&left.to_bytes())).unwrap();
    let reference_right = ReferenceGroup::decode(Copying(&right.to_bytes())).unwrap();

    assert_eq!(
        left.add(&right).to_bytes().as_slice(),
        (reference_left.clone() + &reference_right)
            .encode()
            .as_ref(),
    );
    (left, right, reference_left, reference_right)
}

fn bench(c: &mut Criterion) {
    let (left, right, reference_left, reference_right) = points();
    c.bench_function(&format!("{}/impl=native", module_path!()), |b| {
        b.iter(|| black_box(black_box(&left).add(black_box(&right))));
    });
    c.bench_function(&format!("{}/impl=existing", module_path!()), |b| {
        b.iter(|| black_box(black_box(&reference_left).clone() + black_box(&reference_right)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
