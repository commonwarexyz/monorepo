use commonware_cryptography::{
    Signer as _, Verifier as _,
    fn_dsa::{EllipsoidalFalcon512, FnDsa512, FnDsa1024, PrivateKey, Variant},
};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_variant<V: Variant>(c: &mut Criterion, profile: &str) {
    let mut rng = test_rng();
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    rng.fill(&mut msg);
    let signer = PrivateKey::<V>::random(&mut rng);
    let public_key = signer.public_key();
    let signature = signer.sign(namespace, &msg);
    c.bench_function(
        &format!(
            "{}/profile={} ns_len={} msg_len={}",
            module_path!(),
            profile,
            namespace.len(),
            msg.len()
        ),
        |b| {
            b.iter(|| black_box(public_key.verify(namespace, &msg, &signature)));
        },
    );
}

fn bench_signature_verification(c: &mut Criterion) {
    bench_variant::<FnDsa512>(c, "fn_dsa_512");
    bench_variant::<FnDsa1024>(c, "fn_dsa_1024");
    bench_variant::<EllipsoidalFalcon512>(c, "ellipsoidal_falcon_512");
}

criterion_group!(benches, bench_signature_verification);
