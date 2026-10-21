use super::utils::{points, scalar, to_blst};
use commonware_cryptography_bls12381::{g1::G1, scalar::Scalar};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

fn bench_msm(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [8, 32, 128, 512, 2048] {
        let points = points(n);
        let scalars: Vec<Scalar> = (0..n).map(|i| scalar(1000 + i as u64)).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("impl=bls12381 n={n}"), |b| {
            b.iter(|| black_box(G1::msm(&points, &scalars)));
        });

        let affine: Vec<blst::blst_p1_affine> = points
            .iter()
            .map(|p| {
                let mut out = blst::blst_p1_affine::default();
                // SAFETY: valid pointers to point structures.
                unsafe { blst::blst_p1_to_affine(&mut out, &to_blst(p)) };
                out
            })
            .collect();
        let bytes: Vec<[u8; 32]> = scalars
            .iter()
            .map(|s| {
                s.to_words()
                    .map(u64::to_le_bytes)
                    .concat()
                    .try_into()
                    .unwrap()
            })
            .collect();
        let point_ptrs = [affine.as_ptr(), core::ptr::null()];
        let scalar_ptrs = [bytes.as_ptr().cast::<u8>(), core::ptr::null()];
        // SAFETY: querying the scratch size has no preconditions.
        let scratch_len = unsafe { blst::blst_p1s_mult_pippenger_scratch_sizeof(n) } / 8;
        let mut scratch = vec![0u64; scratch_len];
        group.bench_function(format!("impl=blst n={n}"), |b| {
            b.iter(|| {
                let mut out = blst::blst_p1::default();
                // SAFETY: the pointer arrays are null-terminated, hold n elements, and the
                // scratch buffer has the size blst requested.
                unsafe {
                    blst::blst_p1s_mult_pippenger(
                        &mut out,
                        point_ptrs.as_ptr(),
                        n,
                        scalar_ptrs.as_ptr(),
                        255,
                        scratch.as_mut_ptr(),
                    );
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
    targets = bench_msm
}
