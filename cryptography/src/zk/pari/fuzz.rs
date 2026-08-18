//! Bounded fuzzing for Pari proving and verification.

use super::{InputLayout, Opening, ProvingKey, Relation, VerifyingKey, prove, setup, verify};
use crate::{
    bls12381::primitives::group::{G1, Scalar},
    transcript::{Transcript, Version},
    zk::circuit::{ValuedCircuit, Var, build_with_values},
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_math::algebra::{Additive, CryptoGroup};
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, test_rng};
use std::sync::OnceLock;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_FUZZ";
const BAD_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_FUZZ_BAD";
const CONTEXT: &[u8] = b"pari-fuzz-context";

struct Fixture {
    relation: Relation,
    proving_key: ProvingKey,
    verifying_key: VerifyingKey,
}

fn build_case(left: Scalar, right: Scalar) -> (ValuedCircuit<Scalar>, InputLayout) {
    let public = left.clone() * &left + &(right.clone() * &right);
    let (valued, indices) = build_with_values(move |ctx| {
        let left = Var::witness(ctx, |_| left);
        let right = Var::witness(ctx, |_| right);
        let public = Var::witness(ctx, |_| public);
        let sum = left.clone() * &left + &(right.clone() * &right);
        sum.assert_eq(&public);
        vec![public, left, right]
    });
    let layout = InputLayout::new(vec![indices[0]], vec![indices[1], indices[2]])
        .expect("fixed fuzz layout is valid");
    (valued, layout)
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (valued, layout) = build_case(Scalar::zero(), Scalar::zero());
        let relation = Relation::compile(&valued.circuit, &layout)
            .expect("fixed fuzz relation should compile");
        let (proving_key, verifying_key) = setup(&relation, &mut test_rng(), &Sequential)
            .expect("fixed fuzz relation should support setup");
        Fixture {
            relation,
            proving_key,
            verifying_key,
        }
    })
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    None,
    PublicInput,
    MissingPublicInput,
    ExtraPublicInput,
    Commitment,
    ProofT,
    ProofU,
    ProofValue,
    Transcript,
    VerifyingKey,
}

impl Arbitrary<'_> for Mutation {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=9)? {
            0 => Self::None,
            1 => Self::PublicInput,
            2 => Self::MissingPublicInput,
            3 => Self::ExtraPublicInput,
            4 => Self::Commitment,
            5 => Self::ProofT,
            6 => Self::ProofU,
            7 => Self::ProofValue,
            8 => Self::Transcript,
            9 => Self::VerifyingKey,
            _ => unreachable!("mutation out of range"),
        })
    }
}

/// A constant-size honest proof with an optional adversarial mutation.
#[derive(Debug)]
pub struct Plan {
    left: Scalar,
    right: Scalar,
    opening: Scalar,
    delta: Scalar,
    prover_seed: u64,
    mutation: Mutation,
}

impl Arbitrary<'_> for Plan {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            left: u.arbitrary()?,
            right: u.arbitrary()?,
            opening: u.arbitrary()?,
            delta: u.arbitrary()?,
            prover_seed: u.arbitrary()?,
            mutation: u.arbitrary()?,
        })
    }
}

impl Plan {
    /// Prove the fixed relation honestly and check the selected verification path.
    pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let Fixture {
            relation,
            proving_key,
            verifying_key,
        } = fixture();
        let (valued, layout) = build_case(self.left, self.right);
        let opening = if self.opening == Scalar::zero() {
            Scalar::from(1u64)
        } else {
            self.opening
        };
        let witness = relation
            .witness(&valued, &layout, Opening::new(opening))
            .expect("honest fuzz witness should match the fixed relation");
        let mut claim = witness
            .claim(proving_key.commitment_key(), &Sequential)
            .expect("honest fuzz claim should match its witness");

        let mut prover_rng = TestRng::new(self.prover_seed);
        let mut prover_transcript = Transcript::new(NAMESPACE, Version::V1);
        prover_transcript.commit(CONTEXT);
        let mut proof = prove(
            &mut prover_rng,
            &mut prover_transcript,
            proving_key,
            relation,
            &claim,
            &witness,
            &Sequential,
        )
        .expect("honest fuzz proof should succeed");

        let delta = if self.delta == Scalar::zero() {
            Scalar::from(1u64)
        } else {
            self.delta
        };
        let group_delta = G1::generator() * &delta;
        let mut verifying_key = verifying_key.clone();
        match self.mutation {
            Mutation::None | Mutation::Transcript => {}
            Mutation::PublicInput => claim.public_inputs[0] += &delta,
            Mutation::MissingPublicInput => claim.public_inputs.clear(),
            Mutation::ExtraPublicInput => claim.public_inputs.push(delta),
            Mutation::Commitment => claim.commitment += &group_delta,
            Mutation::ProofT => proof.t += &group_delta,
            Mutation::ProofU => proof.u += &group_delta,
            Mutation::ProofValue => proof.v_a += &delta,
            Mutation::VerifyingKey => verifying_key.alpha_g += &group_delta,
        }

        let namespace = if matches!(self.mutation, Mutation::Transcript) {
            BAD_NAMESPACE
        } else {
            NAMESPACE
        };
        let mut verifier_transcript = Transcript::new(namespace, Version::V1);
        verifier_transcript.commit(CONTEXT);
        let accepted = verify(&mut verifier_transcript, &verifying_key, &claim, &proof);
        assert_eq!(
            accepted,
            matches!(self.mutation, Mutation::None),
            "verification outcome for {:?}",
            self.mutation,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutations_match_verification() {
        let mutations = [
            Mutation::None,
            Mutation::PublicInput,
            Mutation::MissingPublicInput,
            Mutation::ExtraPublicInput,
            Mutation::Commitment,
            Mutation::ProofT,
            Mutation::ProofU,
            Mutation::ProofValue,
            Mutation::Transcript,
            Mutation::VerifyingKey,
        ];
        for (prover_seed, mutation) in mutations.into_iter().enumerate() {
            let plan = Plan {
                left: Scalar::from(3u64),
                right: Scalar::from(5u64),
                opening: Scalar::from(7u64),
                delta: Scalar::from(11u64),
                prover_seed: prover_seed as u64,
                mutation,
            };
            plan.run(&mut Unstructured::new(&[]))
                .expect("fixed plan does not consume trailing fuzz data");
        }
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use crate::zk::pari::{Claim, CommitmentKey, Opening, Proof, ProvingKey, VerifyingKey};
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<CommitmentKey> => 1024,
        CodecConformance<Claim> => 1024,
        CodecConformance<Opening> => 1024,
        CodecConformance<Proof> => 1024,
        CodecConformance<ProvingKey> => 1024,
        CodecConformance<VerifyingKey> => 1024,
    }
}
