use super::*;
use crate::{
    bls12381::primitives::group::{G1, Scalar},
    transcript::{Transcript, Version},
    zk::circuit::{CircuitIdx, Context, Var, build, build_with_values},
};
use commonware_codec::{Decode, Encode, RangeCfg};
use commonware_math::algebra::{CryptoGroup, Ring};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use std::sync::OnceLock;

const PROOF_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_TEST_PROOF";
const BAD_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_TEST_BAD_TRANSCRIPT";
const BATCH_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_TEST_BATCH";

struct Parameters {
    relation: Relation,
    layout: InputLayout,
    proving_key: ProvingKey,
    verifying_key: VerifyingKey,
}

struct Fixture {
    witness: Witness,
    claim: Claim,
    proof: Proof,
}

fn product_circuit<'ctx>(
    ctx: Context<'ctx, Scalar>,
    x_value: u64,
    y_value: u64,
    public_value: u64,
    offset: u64,
) -> Vec<Var<'ctx, Scalar>> {
    let x = Var::witness(ctx, move |_| Scalar::from(x_value));
    let y = Var::witness(ctx, move |_| Scalar::from(y_value));
    let public = Var::witness(ctx, move |_| Scalar::from(public_value));
    let product = x.clone() * &y;
    let expected = public.clone() + &Var::constant(ctx, Scalar::from(offset));
    product.assert_eq(&expected);
    vec![public, x, y]
}

fn compile_relation(offset: u64) -> (Relation, InputLayout) {
    let (circuit, indices) = build(|ctx| product_circuit(ctx, 0, 0, 0, offset));
    let layout = InputLayout::new(vec![indices[0]], vec![vec![indices[1], indices[2]]])
        .expect("fixture layout should be valid");
    let relation = Relation::compile(&circuit, &layout).expect("fixture relation should compile");
    (relation, layout)
}

fn parameters() -> &'static Parameters {
    static PARAMETERS: OnceLock<Parameters> = OnceLock::new();
    PARAMETERS.get_or_init(|| {
        let (relation, layout) = compile_relation(0);
        let (proving_key, verifying_key) =
            setup(&relation, &mut test_rng(), &Sequential).expect("fixture setup should succeed");
        Parameters {
            relation,
            layout,
            proving_key,
            verifying_key,
        }
    })
}

fn witness(
    relation: &Relation,
    layout: &InputLayout,
    x: u64,
    y: u64,
    public: u64,
    offset: u64,
    opening: u64,
) -> Witness {
    let (valued, indices) = build_with_values(|ctx| product_circuit(ctx, x, y, public, offset));
    assert_eq!(
        indices,
        [layout.public().to_vec(), layout.blocks().concat(),].concat(),
        "valued and unvalued fixture circuits should have identical layouts"
    );
    relation
        .witness(&valued, layout, vec![Opening::new(Scalar::from(opening))])
        .expect("fixture witness should compile")
}

fn fixture(x: u64, y: u64, public: u64, opening: u64, namespace: &'static [u8]) -> Fixture {
    let parameters = parameters();
    let witness = witness(
        &parameters.relation,
        &parameters.layout,
        x,
        y,
        public,
        0,
        opening,
    );
    let claim = witness
        .claim(parameters.proving_key.commitment_keys(), &Sequential)
        .expect("fixture claim should be constructed");
    let proof = prove(
        &mut test_rng(),
        &mut Transcript::new(namespace, Version::V1),
        &parameters.proving_key,
        &parameters.relation,
        &claim,
        &witness,
        &Sequential,
    )
    .expect("satisfied fixture should prove");
    Fixture {
        witness,
        claim,
        proof,
    }
}

fn verify_fixture(namespace: &'static [u8], claim: &Claim, proof: &Proof) -> bool {
    let parameters = parameters();
    verify(
        &mut Transcript::new(namespace, Version::V1),
        &parameters.verifying_key,
        claim,
        proof,
    )
}

fn verify_batch(namespace: &'static [u8], claims_and_proofs: &[(Claim, Proof)]) -> bool {
    let parameters = parameters();
    let mut transcripts = (0..claims_and_proofs.len())
        .map(|_| Transcript::new(namespace, Version::V1))
        .collect::<Vec<_>>();
    batch_verify(
        &mut test_rng(),
        &mut transcripts,
        &parameters.verifying_key,
        claims_and_proofs,
        &Sequential,
    )
}

#[test]
fn satisfied_assignment_proves_and_verifies() {
    let fixture = fixture(3, 4, 12, 9, PROOF_NAMESPACE);
    assert!(verify_fixture(
        PROOF_NAMESPACE,
        &fixture.claim,
        &fixture.proof
    ));
}

#[test]
fn committed_and_public_value_tampering_is_rejected() {
    let parameters = parameters();
    let fixture = fixture(3, 4, 12, 9, PROOF_NAMESPACE);

    let mut public_tampered = fixture.claim.clone();
    public_tampered.public_inputs[0] += &Scalar::one();
    assert!(!verify_fixture(
        PROOF_NAMESPACE,
        &public_tampered,
        &fixture.proof
    ));
    assert!(matches!(
        prove(
            &mut test_rng(),
            &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
            &parameters.proving_key,
            &parameters.relation,
            &public_tampered,
            &fixture.witness,
            &Sequential,
        ),
        Err(Error::ClaimMismatch)
    ));

    // This alternative committed vector is still a satisfied opening of the
    // same public product, so rejection specifically exercises commitment binding.
    let committed_tampered = witness(&parameters.relation, &parameters.layout, 2, 6, 12, 0, 9);
    let committed_tampered_claim = committed_tampered
        .claim(parameters.proving_key.commitment_keys(), &Sequential)
        .expect("tampered committed values should form a different claim");
    assert_ne!(
        fixture.claim.commitments[0],
        committed_tampered_claim.commitments[0]
    );
    assert!(!verify_fixture(
        PROOF_NAMESPACE,
        &committed_tampered_claim,
        &fixture.proof
    ));
    assert!(matches!(
        prove(
            &mut test_rng(),
            &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
            &parameters.proving_key,
            &parameters.relation,
            &fixture.claim,
            &committed_tampered,
            &Sequential,
        ),
        Err(Error::ClaimMismatch)
    ));
}

#[test]
fn commitment_and_opening_tampering_is_rejected() {
    let parameters = parameters();
    let fixture = fixture(3, 4, 12, 9, PROOF_NAMESPACE);

    let mut commitment_tampered = fixture.claim.clone();
    commitment_tampered.commitments[0] += &G1::generator();
    assert!(!verify_fixture(
        PROOF_NAMESPACE,
        &commitment_tampered,
        &fixture.proof
    ));

    let opening_tampered = witness(&parameters.relation, &parameters.layout, 3, 4, 12, 0, 10);
    assert!(matches!(
        prove(
            &mut test_rng(),
            &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
            &parameters.proving_key,
            &parameters.relation,
            &fixture.claim,
            &opening_tampered,
            &Sequential,
        ),
        Err(Error::ClaimMismatch)
    ));
}

#[test]
fn transcript_mismatch_is_rejected() {
    let fixture = fixture(3, 4, 12, 9, PROOF_NAMESPACE);
    assert!(!verify_fixture(
        BAD_NAMESPACE,
        &fixture.claim,
        &fixture.proof
    ));

    let mut verifier_transcript = Transcript::new(PROOF_NAMESPACE, Version::V1);
    verifier_transcript.commit(b"different prehistory".as_slice());
    assert!(!verify(
        &mut verifier_transcript,
        &parameters().verifying_key,
        &fixture.claim,
        &fixture.proof,
    ));
}

#[test]
fn relation_and_key_mismatch_are_rejected() {
    let parameters = parameters();
    let fixture = fixture(3, 4, 12, 9, PROOF_NAMESPACE);
    let (other_relation, _) = compile_relation(1);

    assert_ne!(parameters.relation.digest(), other_relation.digest());
    assert!(matches!(
        prove(
            &mut test_rng(),
            &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
            &parameters.proving_key,
            &other_relation,
            &fixture.claim,
            &fixture.witness,
            &Sequential,
        ),
        Err(Error::RelationMismatch)
    ));

    let mut alternate_rng = test_rng();
    let _ = Opening::random(&mut alternate_rng);
    let (_, alternate_verifying_key) = setup(&parameters.relation, &mut alternate_rng, &Sequential)
        .expect("alternate setup should succeed");
    assert_ne!(parameters.verifying_key, alternate_verifying_key);
    assert!(!verify(
        &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
        &alternate_verifying_key,
        &fixture.claim,
        &fixture.proof,
    ));
}

#[test]
fn proof_field_tampering_is_rejected() {
    let fixture = fixture(3, 4, 12, 9, PROOF_NAMESPACE);

    let mut t_tampered = fixture.proof.clone();
    t_tampered.t += &G1::generator();
    assert!(!verify_fixture(
        PROOF_NAMESPACE,
        &fixture.claim,
        &t_tampered
    ));

    let mut u_tampered = fixture.proof.clone();
    u_tampered.u += &G1::generator();
    assert!(!verify_fixture(
        PROOF_NAMESPACE,
        &fixture.claim,
        &u_tampered
    ));

    let mut evaluation_tampered = fixture.proof.clone();
    evaluation_tampered.v_a += &Scalar::one();
    assert!(!verify_fixture(
        PROOF_NAMESPACE,
        &fixture.claim,
        &evaluation_tampered
    ));
}

#[test]
fn unsatisfied_assignment_cannot_prove() {
    let parameters = parameters();
    let witness = witness(&parameters.relation, &parameters.layout, 3, 4, 13, 0, 9);
    let claim = witness
        .claim(parameters.proving_key.commitment_keys(), &Sequential)
        .expect("even an unsatisfied assignment has a well-formed claim");
    assert!(matches!(
        prove(
            &mut test_rng(),
            &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
            &parameters.proving_key,
            &parameters.relation,
            &claim,
            &witness,
            &Sequential,
        ),
        Err(Error::Unsatisfied)
    ));
}

#[test]
fn deterministic_batch_verification_accepts_valid_and_rejects_invalid_entries() {
    let entries = [(2, 5, 10, 3), (3, 7, 21, 4), (6, 6, 36, 5)]
        .into_iter()
        .map(|(x, y, public, opening)| {
            let fixture = fixture(x, y, public, opening, BATCH_NAMESPACE);
            (fixture.claim, fixture.proof)
        })
        .collect::<Vec<_>>();

    assert!(verify_batch(BATCH_NAMESPACE, &entries));
    assert!(verify_batch(BATCH_NAMESPACE, &entries));

    let mut invalid = entries.clone();
    invalid[1].1.v_a += &Scalar::one();
    assert!(!verify_batch(BATCH_NAMESPACE, &invalid));
    assert!(!verify_batch(BATCH_NAMESPACE, &invalid));

    let mut too_few_transcripts = vec![Transcript::new(BATCH_NAMESPACE, Version::V1)];
    assert!(!batch_verify(
        &mut test_rng(),
        &mut too_few_transcripts,
        &parameters().verifying_key,
        &entries,
        &Sequential,
    ));
}

#[test]
fn multi_block_claims_prove_and_verify() {
    let (circuit, indices) = build(|ctx| product_circuit(ctx, 0, 0, 0, 0));
    let layout = InputLayout::new(vec![indices[0]], vec![vec![indices[1]], vec![indices[2]]])
        .expect("multi-block layout is valid");
    let relation = Relation::compile(&circuit, &layout).expect("relation should compile");
    let (proving_key, verifying_key) =
        setup(&relation, &mut test_rng(), &Sequential).expect("setup should succeed");
    assert_eq!(relation.blocks(), &[1, 1]);

    let (valued, _) = build_with_values(|ctx| product_circuit(ctx, 3, 4, 12, 0));
    let witness = relation
        .witness(
            &valued,
            &layout,
            vec![
                Opening::new(Scalar::from(7u64)),
                Opening::new(Scalar::from(9u64)),
            ],
        )
        .expect("witness should compile");
    let claim = witness
        .claim(proving_key.commitment_keys(), &Sequential)
        .expect("claim should be constructed");
    let proof = prove(
        &mut test_rng(),
        &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
        &proving_key,
        &relation,
        &claim,
        &witness,
        &Sequential,
    )
    .expect("multi-block witness should prove");
    assert!(verify(
        &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
        &verifying_key,
        &claim,
        &proof,
    ));

    // Tampering either block's commitment breaks the proof.
    for block in 0..2 {
        let mut tampered = claim.clone();
        tampered.commitments[block] += &G1::generator();
        assert!(!verify(
            &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
            &verifying_key,
            &tampered,
            &proof,
        ));
    }

    let mut transcripts = vec![Transcript::new(PROOF_NAMESPACE, Version::V1)];
    assert!(batch_verify(
        &mut test_rng(),
        &mut transcripts,
        &verifying_key,
        &[(claim, proof)],
        &Sequential,
    ));

    assert!(matches!(
        relation.witness(&valued, &layout, vec![Opening::new(Scalar::from(1u64))]),
        Err(Error::OpeningCount {
            expected: 2,
            actual: 1,
        })
    ));
}

#[test]
fn identity_commitments_prove_and_verify() {
    // All-zero committed values with zero opening randomness commit to the
    // group identity, which is a legal claim (e.g. an emptied balance).
    let parameters = parameters();
    let witness = witness(&parameters.relation, &parameters.layout, 0, 0, 0, 0, 0);
    let claim = witness
        .claim(parameters.proving_key.commitment_keys(), &Sequential)
        .expect("identity commitment should be constructible");
    assert_eq!(claim.commitments[0], G1::zero());

    let encoded = claim.encode();
    let decoded = Claim::decode_cfg(
        encoded,
        &(
            RangeCfg::exact(claim.public_inputs.len()),
            RangeCfg::exact(claim.commitments.len()),
        ),
    )
    .expect("identity commitment should decode");
    assert_eq!(claim, decoded);

    let proof = prove(
        &mut test_rng(),
        &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
        &parameters.proving_key,
        &parameters.relation,
        &claim,
        &witness,
        &Sequential,
    )
    .expect("identity commitment should prove");
    assert!(verify(
        &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
        &parameters.verifying_key,
        &claim,
        &proof,
    ));
}

#[test]
fn decoded_proving_key_proves_and_verifies() {
    let parameters = parameters();

    let opening = Opening::new(Scalar::from(42u64));
    let decoded_opening = Opening::decode_cfg(opening.encode(), &()).expect("opening decodes");
    assert_eq!(opening, decoded_opening);
    assert_eq!(decoded_opening.scalar(), &Scalar::from(42u64));

    let decoded = ProvingKey::decode_cfg(
        parameters.proving_key.encode(),
        &(
            RangeCfg::exact(parameters.verifying_key.public_input_count()),
            RangeCfg::exact(parameters.verifying_key.blocks.len()),
        ),
    )
    .expect("proving key decodes");
    assert_eq!(parameters.proving_key, decoded);

    let witness = witness(&parameters.relation, &parameters.layout, 3, 4, 12, 0, 9);
    let claim = witness
        .claim(decoded.commitment_keys(), &Sequential)
        .expect("decoded commitment key should produce the claim");
    let proof = prove(
        &mut test_rng(),
        &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
        &decoded,
        &parameters.relation,
        &claim,
        &witness,
        &Sequential,
    )
    .expect("decoded proving key should prove");
    assert!(verify(
        &mut Transcript::new(PROOF_NAMESPACE, Version::V1),
        decoded.verifying_key(),
        &claim,
        &proof,
    ));
}

#[test]
fn malformed_input_layouts_are_rejected() {
    let (circuit, indices) = build(|ctx| product_circuit(ctx, 0, 0, 0, 0));
    let public = indices[0];
    let committed = indices[1];

    assert!(InputLayout::new(vec![public], Vec::new()).is_err());
    assert!(InputLayout::new(vec![public], vec![Vec::new()]).is_err());
    assert!(InputLayout::new(vec![public, public], vec![vec![committed]]).is_err());
    assert!(InputLayout::new(Vec::new(), vec![vec![committed], vec![committed]]).is_err());
    assert!(InputLayout::new(vec![committed], vec![vec![committed]]).is_err());
    assert!(InputLayout::new(Vec::new(), vec![vec![CircuitIdx::Constant(0)]]).is_err());

    let invalid_public =
        InputLayout::new(vec![CircuitIdx::Witness(u32::MAX)], vec![vec![committed]])
            .expect("layout construction defers circuit index validation");
    assert!(Relation::compile(&circuit, &invalid_public).is_err());

    let invalid_committed = InputLayout::new(Vec::new(), vec![vec![CircuitIdx::Node(u32::MAX)]])
        .expect("layout construction defers circuit index validation");
    assert!(Relation::compile(&circuit, &invalid_committed).is_err());
}

#[test]
fn claim_keys_and_proof_codec_roundtrip_with_bounded_decode() {
    let parameters = parameters();
    let fixture = fixture(3, 4, 12, 9, PROOF_NAMESPACE);

    let commitment_key = &parameters.proving_key.commitment_keys()[0];
    let encoded = commitment_key.encode();
    let decoded =
        CommitmentKey::decode_cfg(encoded.clone(), &RangeCfg::exact(commitment_key.len()))
            .expect("commitment key should decode at its exact basis bound");
    assert_eq!(commitment_key, &decoded);
    assert_eq!(decoded.encode(), encoded);
    assert!(
        CommitmentKey::decode_cfg(encoded, &RangeCfg::exact(commitment_key.len() - 1),).is_err()
    );

    let encoded = fixture.claim.encode();
    let decoded = Claim::decode_cfg(
        encoded.clone(),
        &(
            RangeCfg::exact(fixture.claim.public_inputs.len()),
            RangeCfg::exact(fixture.claim.commitments.len()),
        ),
    )
    .expect("claim should decode at its exact public-input bound");
    assert_eq!(fixture.claim, decoded);
    assert_eq!(decoded.encode(), encoded);
    assert!(
        Claim::decode_cfg(
            encoded,
            &(
                RangeCfg::exact(fixture.claim.public_inputs.len() - 1),
                RangeCfg::exact(fixture.claim.commitments.len()),
            ),
        )
        .is_err()
    );

    let encoded = fixture.proof.encode();
    let decoded = Proof::decode_cfg(encoded.clone(), &()).expect("proof should decode");
    assert_eq!(fixture.proof, decoded);
    assert_eq!(decoded.encode(), encoded);
    let mut truncated = encoded.to_vec();
    truncated.pop();
    assert!(Proof::decode_cfg(truncated.as_slice(), &()).is_err());

    let encoded = parameters.verifying_key.encode();
    let decoded = VerifyingKey::decode_cfg(
        encoded.clone(),
        &(
            RangeCfg::exact(parameters.verifying_key.public_input_count()),
            RangeCfg::exact(parameters.verifying_key.blocks.len()),
        ),
    )
    .expect("verification key should decode");
    assert_eq!(parameters.verifying_key, decoded);
    assert_eq!(decoded.encode(), encoded);
    assert!(
        VerifyingKey::decode_cfg(
            encoded,
            &(
                RangeCfg::exact(parameters.verifying_key.public_input_count() + 1),
                RangeCfg::exact(parameters.verifying_key.blocks.len()),
            ),
        )
        .is_err()
    );
}
