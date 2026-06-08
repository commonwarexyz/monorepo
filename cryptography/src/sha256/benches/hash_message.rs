#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use aws_lc_rs::digest;
use commonware_cryptography::{Hasher, Sha256};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::hint::black_box;

fn bench_hash_message(c: &mut Criterion) {
    let mut sampler = StdRng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for message_length in cases.into_iter() {
        let mut msg = vec![0u8; message_length];
        sampler.fill_bytes(msg.as_mut_slice());
        let msg = msg.as_slice();
        c.bench_function(
            &format!("{}/impl=sha2 msg_len={}", module_path!(), msg.len()),
            |b| {
                b.iter(|| {
                    let mut hasher = Sha256::new();
                    hasher.update(black_box(msg));
                    black_box(hasher.finalize());
                });
            },
        );

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        c.bench_function(
            &format!(
                "{}/impl=aws_lc_rs_context msg_len={}",
                module_path!(),
                msg.len()
            ),
            |b| {
                b.iter(|| {
                    let mut hasher = digest::Context::new(&digest::SHA256);
                    hasher.update(black_box(msg));
                    black_box(hasher.finish());
                });
            },
        );

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        c.bench_function(
            &format!(
                "{}/impl=aws_lc_rs_oneshot msg_len={}",
                module_path!(),
                msg.len()
            ),
            |b| {
                b.iter(|| {
                    black_box(digest::digest(&digest::SHA256, black_box(msg)));
                });
            },
        );
    }
}

criterion_group!(benches, bench_hash_message);
