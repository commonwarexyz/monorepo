use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::deal_anonymous,
    primitives::{
        ops::threshold,
        sharing::Mode,
        variant::{MinSig, PartialSignature},
    },
};
use commonware_parallel::Sequential;
use commonware_utils::{N5f1, NZU32, test_rng};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_threshold_verify_aggregate(c: &mut Criterion) {
    let mut rng = test_rng();
    let namespace: &[u8] = b"benchmark";

    for n in [6, 16, 64] {
        let (sharing, shares) =
            deal_anonymous::<MinSig, N5f1>(&mut rng, Mode::NonZeroCounter, NZU32!(n));

        for distinct_messages in [1, n / 2, n] {
            let messages: Vec<_> = (0..n)
                .map(|i| format!("message-{}", i % distinct_messages).into_bytes())
                .collect();
            let partials: Vec<PartialSignature<MinSig>> = shares
                .iter()
                .zip(&messages)
                .map(|(share, message)| {
                    threshold::sign_message::<MinSig>(share, namespace, message)
                })
                .collect();
            let aggregate = threshold::aggregate_partial_signatures::<MinSig>(
                &sharing,
                partials
                    .iter()
                    .zip(&messages)
                    .map(|(partial, message)| (namespace, message.as_slice(), partial)),
                &Sequential,
            )
            .unwrap();

            c.bench_function(
                &format!(
                    "{}/participants={} distinct_messages={}",
                    module_path!(),
                    n,
                    distinct_messages
                ),
                |b| {
                    b.iter(|| {
                        let transcript =
                            partials.iter().zip(&messages).map(|(partial, message)| {
                                (partial.index, namespace, message.as_slice())
                            });
                        black_box(threshold::verify_partial_signature_aggregate::<MinSig>(
                            &sharing,
                            transcript,
                            &aggregate,
                            &Sequential,
                        ))
                        .unwrap();
                    });
                },
            );
        }
    }
}

criterion_group!(benches, bench_threshold_verify_aggregate);
