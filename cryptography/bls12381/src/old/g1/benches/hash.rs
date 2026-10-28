use commonware_cryptography_bls12381::old::g1::G1;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

const DST: &[u8] = b"BENCH_V01_BLS12381G1_XMD:SHA-256_SSWU_RO_";

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [1usize, 8, 32, 128] {
        let messages: Vec<[u8; 32]> = (0..n as u64)
            .map(|i| {
                let mut m = [0u8; 32];
                m[..8].copy_from_slice(&i.to_be_bytes());
                m
            })
            .collect();
        let refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("impl=bls12381 n={n}"), |b| {
            b.iter(|| black_box(G1::hash_many(DST, &refs)));
        });
        group.bench_function(format!("impl=blst n={n}"), |b| {
            b.iter(|| {
                let out: Vec<blst::blst_p1> = messages
                    .iter()
                    .map(|m| {
                        let mut out = blst::blst_p1::default();
                        // SAFETY: valid pointers and lengths; a null augmentation has length zero.
                        unsafe {
                            blst::blst_hash_to_g1(
                                &mut out,
                                m.as_ptr(),
                                m.len(),
                                DST.as_ptr(),
                                DST.len(),
                                core::ptr::null(),
                                0,
                            )
                        };
                        out
                    })
                    .collect();
                black_box(out)
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_hash
}
