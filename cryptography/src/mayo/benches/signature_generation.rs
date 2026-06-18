use commonware_cryptography::{mayo, Signer as _};
use commonware_math::algebra::Random;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn bench_signature_generation(c: &mut Criterion) {
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    thread_rng().fill(&mut msg);

    macro_rules! bench_param {
        ($module:ident) => {
            c.bench_function(
                &format!(
                    "{}/param={} ns_len={} msg_len={}",
                    module_path!(),
                    stringify!($module),
                    namespace.len(),
                    msg.len()
                ),
                |b| {
                    b.iter_batched(
                        || mayo::$module::PrivateKey::random(&mut thread_rng()),
                        |private_key| {
                            black_box(private_key.sign(namespace, &msg));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        };
    }

    bench_param!(mayo1);
    bench_param!(mayo2);
    bench_param!(mayo3);
    bench_param!(mayo5);
}

criterion_group!(benches, bench_signature_generation);
