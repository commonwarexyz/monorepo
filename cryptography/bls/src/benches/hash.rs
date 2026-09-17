use super::utils::{MESSAGE, MIN_PK_DST, MIN_SIG_DST};
use commonware_cryptography_bls::bls12381::group::{G1, G2};
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, ptr};

macro_rules! bench_group {
    ($c:ident, $group:ident, $label:literal, $raw:ty, $hash:path, $compress:path, $size:literal, $dst:ident) => {{
        let hash = |message: &[u8], dst: &[u8]| {
            let mut point = <$raw>::default();
            // SAFETY: Each slice covers its stated length, the output is writable, and
            // a null augmentation pointer is allowed for an empty augmentation.
            unsafe {
                $hash(
                    &mut point,
                    message.as_ptr(),
                    message.len(),
                    dst.as_ptr(),
                    dst.len(),
                    ptr::null(),
                    0,
                );
            }
            point
        };
        let expected = hash(MESSAGE, $dst);
        let mut encoded = [0; $size];
        // SAFETY: The point is initialized and the output has the group's compressed size.
        unsafe { $compress(encoded.as_mut_ptr(), &expected) };
        assert_eq!($group::hash_to_curve(MESSAGE, $dst).to_bytes(), encoded);
        $c.bench_function(
            &format!("{}/group={} impl=native", module_path!(), $label),
            |b| b.iter(|| black_box($group::hash_to_curve(black_box(MESSAGE), $dst))),
        );
        $c.bench_function(
            &format!("{}/group={} impl=blst", module_path!(), $label),
            |b| b.iter(|| black_box(hash(black_box(MESSAGE), $dst))),
        );
    }};
}

fn bench(c: &mut Criterion) {
    bench_group!(
        c,
        G1,
        "g1",
        blst::blst_p1,
        blst::blst_hash_to_g1,
        blst::blst_p1_compress,
        48,
        MIN_SIG_DST
    );
    bench_group!(
        c,
        G2,
        "g2",
        blst::blst_p2,
        blst::blst_hash_to_g2,
        blst::blst_p2_compress,
        96,
        MIN_PK_DST
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
