use super::utils::{MESSAGE, MIN_PK_DST, MIN_SIG_DST};
use commonware_cryptography_bls::bls12381::signing::{SigningKey, min_pk, min_sig};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

macro_rules! bench_scheme {
    ($c:ident, $scheme:ident, $dst:ident) => {{
        let key = SigningKey::key_gen(&[42; 32], b"").unwrap();
        let reference = blst::$scheme::SecretKey::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!(
            $scheme::sign(&key, MESSAGE, $dst).to_bytes(),
            reference.sign(MESSAGE, $dst, b"").to_bytes(),
        );
        $c.bench_function(
            &format!(
                "{}/scheme={} impl=native",
                module_path!(),
                stringify!($scheme)
            ),
            |b| {
                b.iter(|| black_box($scheme::sign(black_box(&key), black_box(MESSAGE), $dst)));
            },
        );
        $c.bench_function(
            &format!(
                "{}/scheme={} impl=blst",
                module_path!(),
                stringify!($scheme)
            ),
            |b| {
                b.iter(|| black_box(black_box(&reference).sign(black_box(MESSAGE), $dst, b"")));
            },
        );
    }};
}

fn bench(c: &mut Criterion) {
    bench_scheme!(c, min_pk, MIN_PK_DST);
    bench_scheme!(c, min_sig, MIN_SIG_DST);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
