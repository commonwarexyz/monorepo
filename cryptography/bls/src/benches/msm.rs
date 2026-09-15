use blst::{blst_fr, blst_scalar};
use commonware_cryptography_bls::bls12381::{
    group::{G1, G2},
    scalar::Scalar,
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn coefficient(index: usize, bits: usize) -> Scalar {
    let mut state = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    match bits {
        128 => {
            bytes[..16].fill(0);
            bytes[16] |= 0x80;
        }
        255 => bytes[0] = 0x40 | (bytes[0] & 0x0f),
        _ => unreachable!(),
    }
    Scalar::from_bytes(&bytes).unwrap()
}

macro_rules! bench_group {
    ($c:ident, $group:ident, $label:literal, $raw:ty, $affine:ty, $generator:path,
     $mult:path, $to_affine:path, $scratch_size:path, $pippenger:path,
     $compress:path, $size:literal) => {{
        let raw_multiply = |scalar: &Scalar| {
            let mut bytes = scalar.to_bytes();
            bytes.reverse();
            let mut result = <$raw>::default();
            // SAFETY: The generator is valid, result is writable, and bytes provides 256 bits.
            unsafe { $mult(&mut result, $generator(), bytes.as_ptr(), 256) };
            result
        };
        let raw_bytes = |point: &$raw| {
            let mut encoded = [0u8; $size];
            // SAFETY: The point is initialized and the output has the group's required size.
            unsafe { $compress(encoded.as_mut_ptr(), point) };
            encoded
        };

        for count in [1, 2, 8, 16, 31, 32, 64, 128, 256] {
            let point_scalars: Vec<_> = (0..count)
                .map(|i| Scalar::from_u64((i as u64 + 3).wrapping_mul(0x1_0000_01b3)))
                .collect();
            let points: Vec<_> = point_scalars
                .iter()
                .map(|scalar| $group::generator().mul(scalar))
                .collect();
            let raw_points: Vec<$raw> = point_scalars
                .iter()
                .map(|scalar| raw_multiply(scalar))
                .collect();

            for bits in [128, 255] {
                let scalars: Vec<_> = (0..count).map(|i| coefficient(i, bits)).collect();
                let blst_scalars: Vec<blst_fr> = scalars
                    .iter()
                    .map(|scalar| {
                        let bytes = scalar.to_bytes();
                        let mut encoded = blst_scalar::default();
                        let mut field = blst_fr::default();
                        // SAFETY: bytes is a canonical 32-byte scalar, and both outputs are
                        // valid writable scalar representations.
                        unsafe {
                            blst::blst_scalar_from_bendian(&mut encoded, bytes.as_ptr());
                            blst::blst_fr_from_scalar(&mut field, &encoded);
                        }
                        field
                    })
                    .collect();

                // Each call includes blst's required projective/field-scalar preparation and
                // allocations, matching the preparation included by the native public API.
                let blst_msm = |raw_points: &[$raw], field_scalars: &[blst_fr]| {
                    let point_ptrs = [raw_points.as_ptr(), std::ptr::null()];
                    let mut affine = vec![<$affine>::default(); raw_points.len()];
                    // SAFETY: The pointer array uses blst's null-sentinel convention for one
                    // contiguous input, and affine has one writable slot per point.
                    unsafe {
                        $to_affine(affine.as_mut_ptr(), point_ptrs.as_ptr(), raw_points.len())
                    };

                    let scalar_stride = bits.div_ceil(8);
                    let mut scalar_bytes = Vec::with_capacity(field_scalars.len() * scalar_stride);
                    for scalar in field_scalars {
                        let mut value = blst_scalar::default();
                        // SAFETY: scalar is initialized and value is a valid writable scalar.
                        unsafe { blst::blst_scalar_from_fr(&mut value, scalar) };
                        scalar_bytes.extend_from_slice(&value.b[..scalar_stride]);
                    }
                    let affine_ptrs = [affine.as_ptr(), std::ptr::null()];
                    let scalar_ptrs = [scalar_bytes.as_ptr(), std::ptr::null()];
                    // SAFETY: The sizing function accepts every point count used here.
                    let scratch_bytes = unsafe { $scratch_size(raw_points.len()) };
                    let mut scratch =
                        vec![0u64; scratch_bytes.div_ceil(std::mem::size_of::<u64>())];
                    let mut result = <$raw>::default();
                    // SAFETY: The null-sentinel pointer arrays address contiguous point and
                    // scalar storage that outlives the call, scratch has the size requested by
                    // blst, and result is writable.
                    unsafe {
                        $pippenger(
                            &mut result,
                            affine_ptrs.as_ptr(),
                            raw_points.len(),
                            scalar_ptrs.as_ptr(),
                            bits,
                            scratch.as_mut_ptr(),
                        )
                    };
                    result
                };

                let expected = blst_msm(&raw_points, &blst_scalars);
                assert_eq!(
                    $group::msm_vartime(&points, &scalars).unwrap().to_bytes(),
                    raw_bytes(&expected)
                );
                $c.bench_function(
                    &format!(
                        "{}/group={} points={count} bits={bits} impl=native",
                        module_path!(),
                        $label
                    ),
                    |b| {
                        b.iter(|| {
                            black_box(
                                $group::msm_vartime(black_box(&points), black_box(&scalars))
                                    .unwrap(),
                            )
                        });
                    },
                );
                $c.bench_function(
                    &format!(
                        "{}/group={} points={count} bits={bits} impl=blst",
                        module_path!(),
                        $label
                    ),
                    |b| {
                        b.iter(|| {
                            black_box(blst_msm(black_box(&raw_points), black_box(&blst_scalars)))
                        });
                    },
                );
            }
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
        blst::blst_p1_generator,
        blst::blst_p1_mult,
        blst::blst_p1s_to_affine,
        blst::blst_p1s_mult_pippenger_scratch_sizeof,
        blst::blst_p1s_mult_pippenger,
        blst::blst_p1_compress,
        48
    );
    bench_group!(
        c,
        G2,
        "g2",
        blst::blst_p2,
        blst::blst_p2_affine,
        blst::blst_p2_generator,
        blst::blst_p2_mult,
        blst::blst_p2s_to_affine,
        blst::blst_p2s_mult_pippenger_scratch_sizeof,
        blst::blst_p2s_mult_pippenger,
        blst::blst_p2_compress,
        96
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
