use commonware_cryptography::bls12381::{
    bte::{
        combine_partials, encrypt, respond_to_batch, verify_batch_response, BatchRequest,
        BatchResponse, PublicKey,
    },
    dkg::ops::generate_shares,
    primitives::{
        poly::Eval,
        variant::{MinSig, Variant},
    },
};
use commonware_utils::quorum;
use criterion::{criterion_group, BenchmarkId, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

const SIZES: [usize; 3] = [10, 100, 1000];
const PARTICIPANTS: [u32; 2] = [10, 100];
struct BenchData {
    request: BatchRequest<MinSig>,
    responses: Vec<BatchResponse<MinSig>>,
    evals: Vec<Eval<<MinSig as Variant>::Public>>,
}

fn build_data(size: usize, participants: u32, threshold: u32) -> BenchData {
    let mut rng = ChaCha20Rng::from_seed([size as u8; 32]);
    let (commitment, shares) =
        generate_shares::<_, MinSig>(&mut rng, None, participants, threshold);
    let public = PublicKey::<MinSig>::new(*commitment.constant());

    let ciphertexts: Vec<_> = (0..size)
        .map(|i| {
            let msg = format!("bench-msg-{i}").into_bytes();
            encrypt(&mut rng, &public, b"bench-label", &msg)
        })
        .collect();
    let request = BatchRequest::new(
        &public,
        ciphertexts,
        format!("bench-{size}").into_bytes(),
        threshold,
    );

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

    BenchData {
        request,
        responses,
        evals,
    }
}

fn benchmark_bte_decrypt(c: &mut Criterion) {
    for &participants in PARTICIPANTS.iter() {
        let threshold = quorum(participants);
        let datasets: Vec<_> = SIZES
            .iter()
            .map(|&size| (size, build_data(size, participants, threshold)))
            .collect();

        for (size, data) in datasets.iter() {
            let id = format!("bte_decrypt/n={participants}");
            c.bench_with_input(BenchmarkId::new(id, size), data, |b, data| {
                b.iter(|| {
                    let mut share_indices = Vec::with_capacity(data.responses.len());
                    let mut partials = Vec::with_capacity(data.responses.len());
                    for (response, eval) in data.responses.iter().zip(data.evals.iter()) {
                        let verified =
                            verify_batch_response(&data.request, eval, response).unwrap();
                        share_indices.push(response.index);
                        partials.push(verified);
                    }
                    black_box(combine_partials(&data.request, &share_indices, &partials).unwrap());
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_bte_decrypt
}
