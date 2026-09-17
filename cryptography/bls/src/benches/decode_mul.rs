use super::utils::{
    blst_g1_decode, blst_g1_encode, blst_g2_decode, blst_g2_encode, group_fixtures,
};
use commonware_cryptography_bls::bls12381::{
    group::{G1, G2},
    scalar::Scalar,
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn native_g1(point: &[u8; 48], scalar: &Scalar) -> [u8; 48] {
    G1::from_bytes(point)
        .expect("valid G1 fixture")
        .mul(scalar)
        .to_bytes()
}

fn native_g2(point: &[u8; 96], scalar: &Scalar) -> [u8; 96] {
    G2::from_bytes(point)
        .expect("valid G2 fixture")
        .mul(scalar)
        .to_bytes()
}

fn reference_g1(point: &[u8; 48], scalar: &[u8; 32]) -> [u8; 48] {
    let point = blst_g1_decode(point);
    let mut result = blst::blst_p1::default();
    // SAFETY: point is initialized and scalar has 256 readable bits.
    unsafe { blst::blst_p1_mult(&mut result, &point, scalar.as_ptr(), 256) };
    blst_g1_encode(&result)
}

fn reference_g2(point: &[u8; 96], scalar: &[u8; 32]) -> [u8; 96] {
    let point = blst_g2_decode(point);
    let mut result = blst::blst_p2::default();
    // SAFETY: point is initialized and scalar has 256 readable bits.
    unsafe { blst::blst_p2_mult(&mut result, &point, scalar.as_ptr(), 256) };
    blst_g2_encode(&result)
}

fn bench(c: &mut Criterion) {
    let fixtures = group_fixtures();
    assert_eq!(
        native_g1(&fixtures.g1_left, &fixtures.scalar),
        reference_g1(&fixtures.g1_left, &fixtures.blst_scalar)
    );
    assert_eq!(
        native_g2(&fixtures.g2_left, &fixtures.scalar),
        reference_g2(&fixtures.g2_left, &fixtures.blst_scalar)
    );

    c.bench_function(&format!("{}/group=g1 impl=native", module_path!()), |b| {
        b.iter(|| {
            black_box(native_g1(
                black_box(&fixtures.g1_left),
                black_box(&fixtures.scalar),
            ))
        });
    });
    c.bench_function(&format!("{}/group=g1 impl=blst", module_path!()), |b| {
        b.iter(|| {
            black_box(reference_g1(
                black_box(&fixtures.g1_left),
                black_box(&fixtures.blst_scalar),
            ))
        });
    });
    c.bench_function(&format!("{}/group=g2 impl=native", module_path!()), |b| {
        b.iter(|| {
            black_box(native_g2(
                black_box(&fixtures.g2_left),
                black_box(&fixtures.scalar),
            ))
        });
    });
    c.bench_function(&format!("{}/group=g2 impl=blst", module_path!()), |b| {
        b.iter(|| {
            black_box(reference_g2(
                black_box(&fixtures.g2_left),
                black_box(&fixtures.blst_scalar),
            ))
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
