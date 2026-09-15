use commonware_codec::{Copying, DecodeExt, Encode};
use commonware_cryptography::banderwagon::{F as ReferenceScalar, G as ReferenceGroup};
use commonware_cryptography_bls::{
    banderwagon::{G, Scalar},
    bls12381::{
        group::{G1, G2},
        scalar::Scalar as BlsScalar,
    },
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

macro_rules! bench_group {
    ($c:ident, $group:ident, $label:literal, $raw:ty, $affine:ty,
     $uncompress:path, $from_affine:path, $mult:path, $compress:path, $size:literal) => {{
        let scalar = BlsScalar::from_wide_bytes(&[42; 64]);
        let mut scalar_bytes = scalar.to_bytes();
        scalar_bytes.reverse();
        let point = $group::generator().double();
        let encoded = point.to_bytes();
        let point = $group::from_bytes(&encoded).unwrap();
        let mut affine = <$affine>::default();
        let mut reference = <$raw>::default();
        // SAFETY: The encoding has the required size, and both outputs are valid writable points.
        unsafe {
            assert_eq!(
                $uncompress(&mut affine, encoded.as_ptr()),
                blst::BLST_ERROR::BLST_SUCCESS
            );
            $from_affine(&mut reference, &affine);
        }
        let multiply = |point: &$raw, bytes: &[u8; 32]| {
            let mut result = <$raw>::default();
            // SAFETY: The point is initialized and the scalar has 256 readable bits.
            unsafe { $mult(&mut result, point, bytes.as_ptr(), 256) };
            result
        };
        let expected = multiply(&reference, &scalar_bytes);
        let mut expected_bytes = [0; $size];
        // SAFETY: The initialized result and output buffer have the group's required sizes.
        unsafe { $compress(expected_bytes.as_mut_ptr(), &expected) };
        assert_eq!(point.mul(&scalar).to_bytes(), expected_bytes);
        $c.bench_function(
            &format!("{}/group={} impl=native", module_path!(), $label),
            |b| b.iter(|| black_box(black_box(&point).mul(black_box(&scalar)))),
        );
        $c.bench_function(
            &format!("{}/group={} impl=blst", module_path!(), $label),
            |b| b.iter(|| black_box(multiply(black_box(&reference), black_box(&scalar_bytes)))),
        );
    }};
}

fn bench(c: &mut Criterion) {
    bench_group!(
        c,
        G1,
        "g1",
        blst::blst_p1,
        blst::blst_p1_affine,
        blst::blst_p1_uncompress,
        blst::blst_p1_from_affine,
        blst::blst_p1_mult,
        blst::blst_p1_compress,
        48
    );
    bench_group!(
        c,
        G2,
        "g2",
        blst::blst_p2,
        blst::blst_p2_affine,
        blst::blst_p2_uncompress,
        blst::blst_p2_from_affine,
        blst::blst_p2_mult,
        blst::blst_p2_compress,
        96
    );

    let scalar = Scalar::from_wide_bytes(&[42; 64]);
    let point = G::generator().double();
    let reference_scalar = ReferenceScalar::decode(Copying(&scalar.to_bytes())).unwrap();
    let reference_point = ReferenceGroup::decode(Copying(&point.to_bytes())).unwrap();
    assert_eq!(
        point.mul(&scalar).to_bytes().as_slice(),
        (reference_point.clone() * &reference_scalar)
            .encode()
            .as_ref(),
    );

    c.bench_function(
        &format!("{}/group=banderwagon impl=native", module_path!()),
        |b| {
            b.iter(|| black_box(black_box(&point).mul(black_box(&scalar))));
        },
    );
    c.bench_function(
        &format!("{}/group=banderwagon impl=existing", module_path!()),
        |b| {
            b.iter(|| {
                black_box(black_box(&reference_point).clone() * black_box(&reference_scalar))
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
