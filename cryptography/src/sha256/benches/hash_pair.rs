use commonware_cryptography::{Hasher, Sha256};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng as _;
use std::hint::black_box;

fn bench_hash_pair(c: &mut Criterion) {
    let mut rng = test_rng();
    for bytes in [128, 4096, 65536, 524288] {
        let mut left = vec![0u8; bytes];
        let mut right = vec![0u8; bytes];
        rng.fill_bytes(&mut left);
        rng.fill_bytes(&mut right);
        for paired in [false, true] {
            c.bench_function(
                &format!("{}/bytes={bytes} paired={paired}", module_path!()),
                |b| {
                    b.iter(|| {
                        let left = black_box(left.as_slice());
                        let right = black_box(right.as_slice());
                        black_box(if paired {
                            Sha256::hash_pair(&[left], &[right])
                        } else {
                            (Sha256::hash(&[left]), Sha256::hash(&[right]))
                        })
                    });
                },
            );
        }
    }
}

criterion_group!(benches, bench_hash_pair);
