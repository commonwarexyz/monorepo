use commonware_cryptography::bls12381::{
    bte::{
        combine_partials, encrypt, respond_to_batch, verify_batch_response, BatchRequest, PublicKey,
    },
    dkg::ops::generate_shares,
    primitives::{
        poly::Eval,
        variant::{MinSig, Variant},
    },
};
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn benchmark_bte_decrypt(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let participants = 5u32;
    let threshold = quorum(participants);
    let (commitment, shares) =
        generate_shares::<_, MinSig>(&mut rng, None, participants, threshold);
    let public = PublicKey::<MinSig>::new(*commitment.constant());

    let messages: Vec<Vec<u8>> = (0..8)
        .map(|i| format!("batched-message-{i}").into_bytes())
        .collect();
    let ciphertexts = messages
        .iter()
        .map(|m| encrypt(&mut rng, &public, b"bench-label", m))
        .collect();
    let request = BatchRequest {
        ciphertexts,
        context: b"bench-context".to_vec(),
        threshold,
    };

    let responses: Vec<_> = shares
        .iter()
        .take(threshold as usize)
        .map(|share| respond_to_batch(&mut rng, share, &request))
        .collect();
    let evals: Vec<Eval<<MinSig as Variant>::Public>> = shares
        .iter()
        .take(threshold as usize)
        .map(|share| Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        })
        .collect();

    c.bench_function(module_path!(), |b| {
        b.iter_batched(
            || (request.clone(), responses.clone(), evals.clone()),
            |(request, responses, evals)| {
                let mut indices = Vec::with_capacity(responses.len());
                let mut partials = Vec::with_capacity(responses.len());
                for ((response, eval)) in responses.iter().zip(evals.iter()) {
                    let verified =
                        verify_batch_response(&public, &request, eval, response).unwrap();
                    indices.push(response.index);
                    partials.push(verified);
                }
                black_box(combine_partials(&request, &indices, &partials).unwrap());
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_bte_decrypt
}
