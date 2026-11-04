use commonware_cryptography::bls12381::primitives::{
    group::Scalar,
    ops::{
        self,
        batch::{Claim, Term},
    },
    variant::{MinSig, Variant},
};
use commonware_math::algebra::{Additive, CryptoGroup, Random};
use commonware_parallel::Rayon;
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;

type Signature = <MinSig as Variant>::Signature;

const NAMESPACE: &[u8] = b"namespace";

/// Single-term claims from distinct signers over a few shared messages (grouped by message).
fn votes<'a>(count: usize, messages: &'a [[u8; 32]]) -> Vec<Claim<'a, MinSig>> {
    let mut rng = test_rng();
    (0..count)
        .map(|index| {
            let (private, public) = ops::keypair::<_, MinSig>(&mut rng);
            let message = &messages[index % messages.len()];
            Claim {
                signature: ops::sign_message::<MinSig>(&private, NAMESPACE, message),
                terms: vec![Term {
                    public,
                    namespace: NAMESPACE,
                    message,
                }],
            }
        })
        .collect()
}

/// Certificates from one key over distinct messages, then votes from distinct keys over one
/// message. The batch ties on keys and messages, but each half pairs cheaply its own way.
fn mixed<'a>(count: usize, messages: &'a [[u8; 32]]) -> Vec<Claim<'a, MinSig>> {
    // A seed other than the voters' keeps the certificate key distinct from theirs.
    let mut rng = TestRng::new(2);
    let (private, public) = ops::keypair::<_, MinSig>(&mut rng);
    let mut claims: Vec<_> = messages[..count]
        .iter()
        .map(|message| Claim {
            signature: ops::sign_message::<MinSig>(&private, NAMESPACE, message),
            terms: vec![Term {
                public,
                namespace: NAMESPACE,
                message,
            }],
        })
        .collect();
    claims.extend(votes(count, &messages[count..=count]));
    claims
}

/// Aggregate claims whose signers each sign a distinct message (grouped by public key).
fn aggregates<'a>(
    count: usize,
    signers: usize,
    messages: &'a [[u8; 32]],
) -> Vec<Claim<'a, MinSig>> {
    let mut rng = test_rng();
    let keys: Vec<_> = (0..signers)
        .map(|_| ops::keypair::<_, MinSig>(&mut rng))
        .collect();
    (0..count)
        .map(|claim| {
            let mut signature = Signature::zero();
            let mut terms = Vec::with_capacity(signers);
            for (signer, (private, public)) in keys.iter().enumerate() {
                let message = &messages[claim * signers + signer];
                signature += &ops::sign_message::<MinSig>(private, NAMESPACE, message);
                terms.push(Term {
                    public: *public,
                    namespace: NAMESPACE,
                    message,
                });
            }
            Claim { signature, terms }
        })
        .collect()
}

fn bench_batch_verify_claims(c: &mut Criterion) {
    let mut rng = test_rng();
    let messages: Vec<[u8; 32]> = (0..512)
        .map(|_| {
            let mut message = [0u8; 32];
            rng.fill(&mut message);
            message
        })
        .collect();
    let tweak = Signature::generator() * &Scalar::random(&mut rng);
    let cases = [
        ("votes", votes(50, &messages[..4]), [0, 1, 5]),
        ("votes", votes(200, &messages[..4]), [0, 1, 5]),
        ("aggregates", aggregates(8, 34, &messages), [0, 1, 2]),
        ("mixed", mixed(32, &messages), [0, 1, 2]),
    ];
    for concurrency in [1, 8] {
        let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
        for (shape, valid, invalid_counts) in &cases {
            for invalid in invalid_counts.iter().copied() {
                let mut claims = valid.clone();
                for claim in claims.iter_mut().rev().take(invalid) {
                    claim.signature += &tweak;
                }
                let mut verify_rng = TestRng::new(1);
                c.bench_function(
                    &format!(
                        "{}/shape={shape} claims={} invalid={invalid} conc={concurrency}",
                        module_path!(),
                        claims.len(),
                    ),
                    |b| {
                        b.iter(|| {
                            let failed =
                                ops::batch::verify_claims(&mut verify_rng, &claims, &strategy);
                            assert_eq!(failed.len(), invalid);
                        });
                    },
                );
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_verify_claims
}
