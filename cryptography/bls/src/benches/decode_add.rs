use super::utils::{
    blst_g1_decode, blst_g1_encode, blst_g2_decode, blst_g2_encode, group_fixtures,
};
use commonware_cryptography_bls::bls12381::group::{G1, G2};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn native_g1(left: &[u8; 48], right: &[u8; 48]) -> [u8; 48] {
    G1::from_bytes(left)
        .expect("valid G1 fixture")
        .add(&G1::from_bytes(right).expect("valid G1 fixture"))
        .to_bytes()
}

fn native_g2(left: &[u8; 96], right: &[u8; 96]) -> [u8; 96] {
    G2::from_bytes(left)
        .expect("valid G2 fixture")
        .add(&G2::from_bytes(right).expect("valid G2 fixture"))
        .to_bytes()
}

fn reference_g1(left: &[u8; 48], right: &[u8; 48]) -> [u8; 48] {
    let left = blst_g1_decode(left);
    let right = blst_g1_decode(right);
    let mut result = blst::blst_p1::default();
    // SAFETY: the inputs and result are initialized G1 points.
    unsafe { blst::blst_p1_add_or_double(&mut result, &left, &right) };
    blst_g1_encode(&result)
}

fn reference_g2(left: &[u8; 96], right: &[u8; 96]) -> [u8; 96] {
    let left = blst_g2_decode(left);
    let right = blst_g2_decode(right);
    let mut result = blst::blst_p2::default();
    // SAFETY: the inputs and result are initialized G2 points.
    unsafe { blst::blst_p2_add_or_double(&mut result, &left, &right) };
    blst_g2_encode(&result)
}

fn bench(c: &mut Criterion) {
    let fixtures = group_fixtures();
    assert_eq!(
        native_g1(&fixtures.g1_left, &fixtures.g1_right),
        reference_g1(&fixtures.g1_left, &fixtures.g1_right)
    );
    assert_eq!(
        native_g2(&fixtures.g2_left, &fixtures.g2_right),
        reference_g2(&fixtures.g2_left, &fixtures.g2_right)
    );

    c.bench_function(&format!("{}/group=g1 impl=native", module_path!()), |b| {
        b.iter(|| {
            black_box(native_g1(
                black_box(&fixtures.g1_left),
                black_box(&fixtures.g1_right),
            ))
        });
    });
    c.bench_function(&format!("{}/group=g1 impl=blst", module_path!()), |b| {
        b.iter(|| {
            black_box(reference_g1(
                black_box(&fixtures.g1_left),
                black_box(&fixtures.g1_right),
            ))
        });
    });
    c.bench_function(&format!("{}/group=g2 impl=native", module_path!()), |b| {
        b.iter(|| {
            black_box(native_g2(
                black_box(&fixtures.g2_left),
                black_box(&fixtures.g2_right),
            ))
        });
    });
    c.bench_function(&format!("{}/group=g2 impl=blst", module_path!()), |b| {
        b.iter(|| {
            black_box(reference_g2(
                black_box(&fixtures.g2_left),
                black_box(&fixtures.g2_right),
            ))
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
