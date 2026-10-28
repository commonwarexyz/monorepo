use super::utils::points;
use commonware_cryptography_bls12381::old::g1::G1;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [1, 8, 32, 128] {
        let encodings: Vec<[u8; 48]> = points(n).iter().map(G1::to_bytes).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("impl=bls12381 n={n}"), |b| {
            b.iter(|| black_box(G1::decode_many(&encodings).expect("valid")));
        });
        group.bench_function(format!("impl=blst n={n}"), |b| {
            b.iter(|| {
                let mut out = Vec::with_capacity(n);
                for encoding in &encodings {
                    let mut affine = blst::blst_p1_affine::default();
                    // SAFETY: valid pointers; the input buffer holds 48 bytes.
                    let status =
                        unsafe { blst::blst_p1_uncompress(&mut affine, encoding.as_ptr()) };
                    assert_eq!(status, blst::BLST_ERROR::BLST_SUCCESS);
                    // SAFETY: valid pointer to a decoded affine point.
                    assert!(unsafe { blst::blst_p1_affine_in_g1(&affine) });
                    out.push(affine);
                }
                black_box(out)
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_decode
}
