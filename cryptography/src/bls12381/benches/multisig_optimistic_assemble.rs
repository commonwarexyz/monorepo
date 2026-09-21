use super::optimistic_assemble::{BenchSubject, Case, bench_case};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{
        group::Private,
        ops::{compute_public, sign_proof_of_possession, verify_proof_of_possession},
        variant::{MinPk, MinSig, Variant},
    },
    certificate::{Attestation, Scheme as _},
    ed25519, impl_certificate_bls12381_multisig,
    sha256::Digest as Sha256Digest,
};
use commonware_math::algebra::Random;
use commonware_utils::{Faults, N3f1, TestRng, TryCollect, ordered::BiMap};
use criterion::{Criterion, criterion_group};

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_OPTIMISTIC_ASSEMBLE";
const POP_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_OPTIMISTIC_ASSEMBLE_POP";

impl_certificate_bls12381_multisig!(BenchSubject, Vec<u8>, N3f1);

type Multisig<V> = Scheme<ed25519::PublicKey, V>;

fn setup<V: Variant>(n: u32) -> (Multisig<V>, Vec<Attestation<Multisig<V>>>) {
    let identity_keys: Vec<_> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(u64::from(i)))
        .collect();
    let mut rng = TestRng::new(u64::from(n));
    let signing_keys: Vec<_> = (0..n).map(|_| Private::random(&mut rng)).collect();
    let signing_publics: Vec<_> = signing_keys.iter().map(compute_public::<V>).collect();

    for (private, public) in signing_keys.iter().zip(&signing_publics) {
        let proof = sign_proof_of_possession::<V>(private, POP_NAMESPACE);
        verify_proof_of_possession::<V>(public, POP_NAMESPACE, &proof)
            .expect("proof of possession must verify");
    }

    let participants: BiMap<_, _> = identity_keys
        .iter()
        .map(|key| key.public_key())
        .zip(signing_publics)
        .try_collect()
        .unwrap();
    let quorum = N3f1::quorum(n) as usize;
    let attestations = signing_keys
        .into_iter()
        .take(quorum + 1)
        .map(|private| {
            Scheme::signer(NAMESPACE, participants.clone(), private)
                .expect("signer must be a participant")
                .sign::<Sha256Digest>(BenchSubject)
                .unwrap()
        })
        .collect();

    (Scheme::verifier(NAMESPACE, participants), attestations)
}

fn bench_variant<V: Variant>(c: &mut Criterion, variant: &str) {
    for (n, quorum) in [(100, 67), (298, 199)] {
        assert_eq!(N3f1::quorum(n), quorum);
        let (scheme, attestations) = setup::<V>(n);
        for case in [Case::Valid, Case::Bad, Case::Spare, Case::Split] {
            bench_case::<_, Sha256Digest>(
                c,
                &format!(
                    "{}/variant={} n={} case={}",
                    module_path!(),
                    variant,
                    n,
                    case.name(),
                ),
                &scheme,
                BenchSubject,
                &attestations,
                quorum as usize,
                case,
            );
        }
    }
}

fn bench_multisig_optimistic_assemble(c: &mut Criterion) {
    bench_variant::<MinPk>(c, "MinPk");
    bench_variant::<MinSig>(c, "MinSig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_multisig_optimistic_assemble,
}
