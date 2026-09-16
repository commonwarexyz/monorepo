use super::utils::{
    blst_g1_decode, blst_g1_encode, blst_g2_decode, blst_g2_encode, group_fixtures,
};
use commonware_cryptography_bls::bls12381::group::{G1, G2};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn reference_g1(point: &blst::blst_p1) -> blst::blst_p1 {
    let mut result = blst::blst_p1::default();
    // SAFETY: point and result are initialized G1 values.
    unsafe { blst::blst_p1_double(&mut result, point) };
    result
}

fn reference_g2(point: &blst::blst_p2) -> blst::blst_p2 {
    let mut result = blst::blst_p2::default();
    // SAFETY: point and result are initialized G2 values.
    unsafe { blst::blst_p2_double(&mut result, point) };
    result
}

fn bench(c: &mut Criterion) {
    let fixtures = group_fixtures();
    let native_g1 = G1::from_bytes(&fixtures.g1_left).expect("valid G1 fixture");
    let native_g2 = G2::from_bytes(&fixtures.g2_left).expect("valid G2 fixture");
    let blst_g1 = blst_g1_decode(&fixtures.g1_left);
    let blst_g2 = blst_g2_decode(&fixtures.g2_left);
    assert_eq!(
        native_g1.double().to_bytes(),
        blst_g1_encode(&reference_g1(&blst_g1))
    );
    assert_eq!(
        native_g2.double().to_bytes(),
        blst_g2_encode(&reference_g2(&blst_g2))
    );

    c.bench_function(&format!("{}/group=g1 impl=native", module_path!()), |b| {
        b.iter(|| black_box(black_box(&native_g1).double()));
    });
    c.bench_function(&format!("{}/group=g1 impl=blst", module_path!()), |b| {
        b.iter(|| black_box(reference_g1(black_box(&blst_g1))));
    });
    c.bench_function(&format!("{}/group=g2 impl=native", module_path!()), |b| {
        b.iter(|| black_box(black_box(&native_g2).double()));
    });
    c.bench_function(&format!("{}/group=g2 impl=blst", module_path!()), |b| {
        b.iter(|| black_box(reference_g2(black_box(&blst_g2))));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
