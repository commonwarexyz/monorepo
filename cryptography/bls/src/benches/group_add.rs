use commonware_cryptography_bls::bls12381::{
    group::{G1, G2},
    scalar::Scalar,
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

macro_rules! bench_group {
    ($c:ident, $group:ident, $label:literal, $raw:ty, $affine:ty,
     $uncompress:path, $from_affine:path, $double:path, $add:path, $cneg:path,
     $compress:path, $size:literal) => {{
        let to_raw = |point: &$group| {
            let encoded = point.to_bytes();
            let mut affine = <$affine>::default();
            let mut raw = <$raw>::default();
            // SAFETY: The canonical encoding has the group's required size, and both outputs
            // are valid writable points.
            unsafe {
                assert_eq!(
                    $uncompress(&mut affine, encoded.as_ptr()),
                    blst::BLST_ERROR::BLST_SUCCESS
                );
                $from_affine(&mut raw, &affine);
            }
            raw
        };
        let raw_double = |point: &$raw| {
            let mut result = <$raw>::default();
            // SAFETY: Both arguments point to initialized values of the expected group type.
            unsafe { $double(&mut result, point) };
            result
        };
        let raw_add = |left: &$raw, right: &$raw| {
            let mut result = <$raw>::default();
            // SAFETY: All arguments point to initialized values of the expected group type.
            unsafe { $add(&mut result, left, right) };
            result
        };
        let raw_bytes = |point: &$raw| {
            let mut encoded = [0u8; $size];
            // SAFETY: The point is initialized and the output has the group's required size.
            unsafe { $compress(encoded.as_mut_ptr(), point) };
            encoded
        };

        // Doubling matched affine points gives both implementations nontrivial projective inputs.
        let left_base = $group::generator().mul(&Scalar::from_u64(17));
        let right_base = $group::generator().mul(&Scalar::from_u64(29));
        let left = left_base.double();
        let right = right_base.double();
        let raw_left = raw_double(&to_raw(&left_base));
        let raw_right = raw_double(&to_raw(&right_base));
        assert_eq!(left.to_bytes(), raw_bytes(&raw_left));
        assert_eq!(right.to_bytes(), raw_bytes(&raw_right));

        let mut raw_inverse = raw_left;
        // SAFETY: raw_inverse is an initialized projective point.
        unsafe { $cneg(&mut raw_inverse, true) };
        let cases = [
            ("normal", left, right, raw_left, raw_right),
            ("equal", left, left, raw_left, raw_left),
            ("inverse", left, left.neg(), raw_left, raw_inverse),
            (
                "identity",
                left,
                $group::identity(),
                raw_left,
                <$raw>::default(),
            ),
        ];

        for (case, native_left, native_right, blst_left, blst_right) in cases {
            let expected = raw_add(&blst_left, &blst_right);
            assert_eq!(
                native_left.add(&native_right).to_bytes(),
                raw_bytes(&expected)
            );
            $c.bench_function(
                &format!(
                    "{}/group={} case={case} impl=native",
                    module_path!(),
                    $label
                ),
                |b| {
                    b.iter(|| black_box(black_box(&native_left).add(black_box(&native_right))));
                },
            );
            $c.bench_function(
                &format!("{}/group={} case={case} impl=blst", module_path!(), $label),
                |b| {
                    b.iter(|| black_box(raw_add(black_box(&blst_left), black_box(&blst_right))));
                },
            );
        }
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
        blst::blst_p1_double,
        blst::blst_p1_add_or_double,
        blst::blst_p1_cneg,
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
        blst::blst_p2_double,
        blst::blst_p2_add_or_double,
        blst::blst_p2_cneg,
        blst::blst_p2_compress,
        96
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
