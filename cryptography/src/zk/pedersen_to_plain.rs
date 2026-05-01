//! This module provides a proof that a plain commitment and a Pedersen
//! commitment share the same committed value.
//!
//! # What This Lets You Do
//!
//! This proof lets a prover link a transparent commitment `X = x * G` with a
//! hiding Pedersen commitment `C = x * G + x_blind * H`, showing that both use
//! the same committed value `x`.
//!
//! This is useful when one part of a protocol wants to work with a plain
//! commitment while another part wants the same value hidden behind a Pedersen
//! commitment. The proof lets the prover bridge those two views without
//! revealing either the committed value or the Pedersen blinding.
//!
//! Concretely, the prover shows knowledge of openings `(x, x_blind)` such that:
//!
//! - `X = x * G`, and
//! - `C = x * G + x_blind * H`.
//!
//! # Usage
//!
//! Construct a [`Setup`] with a value generator and an independent blinding
//! generator. Then create a [`Witness`] and derive its public [`Claim`] with
//! [`Witness::claim`].
//!
//! Given a [`Setup`], [`Claim`], and [`Witness`], call [`prove`] to create a
//! [`Proof`]. The proof is bound to the current [`Transcript`] state, so the
//! verifier must replay the same transcript history before calling [`verify`].
//!
//! [`verify`] checks the proof against a [`Synthetic`] setup, allowing for easy
//! batching with other proofs of this kind, or other proofs entirely. For example,
//! you can batch this proof with the result of [`crate::zk::bulletproofs`].
//!
//! ## Example
//!
//! ```rust
//! # use commonware_cryptography::{
//! #     bls12381::primitives::group::{G1, Scalar},
//! #     transcript::Transcript,
//! #     zk::pedersen_to_plain::{prove, verify, Setup, Witness},
//! # };
//! # use commonware_math::{
//! #     algebra::{Additive, CryptoGroup, HashToGroup},
//! #     synthetic::Synthetic,
//! # };
//! # use commonware_parallel::Sequential;
//! # use commonware_utils::test_rng;
//! # type F = Scalar;
//! # type G = G1;
//! let setup = Setup {
//!     value_generator: G::generator(),
//!     blinding_generator: G::hash_to_group(
//!         b"_COMMONWARE_CRYPTOGRAPHY_ZK_PEDERSEN_TO_PLAIN",
//!         b"blinding",
//!     ),
//! };
//!
//! let witness = Witness {
//!     value: F::from(3u64),
//!     blinding: F::from(5u64),
//! };
//! let claim = witness.claim(&setup);
//!
//! let mut prover_rng = test_rng();
//! let mut prover_transcript = Transcript::new(b"pedersen-to-plain-example");
//! prover_transcript.commit(b"context".as_slice());
//! let proof = prove(
//!     &mut prover_rng,
//!     &mut prover_transcript,
//!     &setup,
//!     &claim,
//!     &witness,
//! );
//!
//! let mut verifier_rng = test_rng();
//! let mut verifier_transcript = Transcript::new(b"pedersen-to-plain-example");
//! verifier_transcript.commit(b"context".as_slice());
//! let [g, h] = Synthetic::<F, G>::generators_array();
//! let synthetic_setup = Setup {
//!     value_generator: g,
//!     blinding_generator: h,
//! };
//! let valid = verify(
//!     &mut verifier_rng,
//!     &mut verifier_transcript,
//!     &synthetic_setup,
//!     &claim,
//!     proof,
//! )
//! .eval(
//!     &[setup.value_generator, setup.blinding_generator],
//!     &Sequential,
//! ) == G::zero();
//! assert!(valid);
//! ```

use crate::transcript::Transcript;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, Write};
use commonware_math::{
    algebra::{CryptoGroup, Field, Random, Space},
    synthetic::Synthetic,
};
use rand_core::CryptoRngCore;

/// Generators used by the proof system.
///
/// The blinding generator must not have a known discrete-log relationship
/// relative to the value generator.
#[derive(Clone, Debug, PartialEq)]
pub struct Setup<G> {
    /// The generator used in both the plain and Pedersen commitments.
    pub value_generator: G,
    /// The generator used only for the Pedersen blinding term.
    pub blinding_generator: G,
}

impl<G: Write> Write for Setup<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.value_generator.write(buf);
        self.blinding_generator.write(buf);
    }
}

impl<G: EncodeSize> EncodeSize for Setup<G> {
    fn encode_size(&self) -> usize {
        self.value_generator.encode_size() + self.blinding_generator.encode_size()
    }
}

impl<G: Read> Read for Setup<G>
where
    G::Cfg: Clone,
{
    type Cfg = G::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            value_generator: G::read_cfg(buf, cfg)?,
            blinding_generator: G::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<G> arbitrary::Arbitrary<'_> for Setup<G>
where
    G: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            value_generator: u.arbitrary()?,
            blinding_generator: u.arbitrary()?,
        })
    }
}

/// A prover-side witness for the relation.
#[derive(Clone, Debug, PartialEq)]
pub struct Witness<F> {
    pub value: F,
    pub blinding: F,
}

impl<F> Witness<F> {
    /// Create the public [`Claim`] corresponding to this witness.
    pub fn claim<G: Space<F>>(&self, setup: &Setup<G>) -> Claim<G> {
        let plain = setup.value_generator.clone() * &self.value;
        Claim {
            pedersen: plain.clone() + &(setup.blinding_generator.clone() * &self.blinding),
            plain,
        }
    }
}

/// The public statement for the protocol.
#[derive(Clone, Debug, PartialEq)]
pub struct Claim<G> {
    pub plain: G,
    pub pedersen: G,
}

impl<G: Write> Write for Claim<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.plain.write(buf);
        self.pedersen.write(buf);
    }
}

impl<G: EncodeSize> EncodeSize for Claim<G> {
    fn encode_size(&self) -> usize {
        self.plain.encode_size() + self.pedersen.encode_size()
    }
}

impl<G: Read> Read for Claim<G>
where
    G::Cfg: Clone,
{
    type Cfg = G::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            plain: G::read_cfg(buf, cfg)?,
            pedersen: G::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<G> arbitrary::Arbitrary<'_> for Claim<G>
where
    G: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            plain: u.arbitrary()?,
            pedersen: u.arbitrary()?,
        })
    }
}

/// A proof that the plain and Pedersen commitments share the same committed value.
#[derive(Clone, Debug, PartialEq)]
pub struct Proof<F, G> {
    plain_mask: G,
    pedersen_mask: G,
    value_response: F,
    blinding_response: F,
}

impl<F: Write, G: Write> Write for Proof<F, G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.plain_mask.write(buf);
        self.pedersen_mask.write(buf);
        self.value_response.write(buf);
        self.blinding_response.write(buf);
    }
}

impl<F: EncodeSize, G: EncodeSize> EncodeSize for Proof<F, G> {
    fn encode_size(&self) -> usize {
        self.plain_mask.encode_size()
            + self.pedersen_mask.encode_size()
            + self.value_response.encode_size()
            + self.blinding_response.encode_size()
    }
}

impl<F: Read, G: Read> Read for Proof<F, G>
where
    G::Cfg: Clone,
    F::Cfg: Clone,
{
    type Cfg = (G::Cfg, F::Cfg);

    fn read_cfg(buf: &mut impl Buf, (g_cfg, f_cfg): &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            plain_mask: G::read_cfg(buf, g_cfg)?,
            pedersen_mask: G::read_cfg(buf, g_cfg)?,
            value_response: F::read_cfg(buf, f_cfg)?,
            blinding_response: F::read_cfg(buf, f_cfg)?,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<F, G> arbitrary::Arbitrary<'_> for Proof<F, G>
where
    F: for<'a> arbitrary::Arbitrary<'a>,
    G: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            plain_mask: u.arbitrary()?,
            pedersen_mask: u.arbitrary()?,
            value_response: u.arbitrary()?,
            blinding_response: u.arbitrary()?,
        })
    }
}

/// Create a proof for a claimed witness.
///
/// This proves that the plain and Pedersen commitments in [`Claim`] open to
/// the same committed value, using the openings in [`Witness`].
///
/// This is a low-level constructor and assumes that `claim` and `witness`
/// correspond. It does not check that relationship for you.
pub fn prove<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    setup: &Setup<G>,
    claim: &Claim<G>,
    witness: &Witness<F>,
) -> Proof<F, G>
where
    Claim<G>: Encode,
{
    // We prove that the published commitments:
    //
    //   X = x G
    //   C = x G + x_blind H
    //
    // share the same committed value x. We do this with a single Schnorr-style
    // protocol over both equations. The prover samples masks k and k_blind,
    // sends:
    //
    //   K_plain = k G
    //   K_pedersen = k G + k_blind H
    //
    // derives a challenge e from the transcript, and responds with:
    //
    //   s = k + e x
    //   s_blind = k_blind + e x_blind
    //
    // The verifier can then check:
    //
    //   s G = K_plain + e X
    //   s G + s_blind H = K_pedersen + e C
    //
    // which is exactly what verify checks directly.
    transcript.commit(claim.encode());

    let value_mask = F::random(&mut *rng);
    let blinding_mask = F::random(&mut *rng);
    let plain_mask = setup.value_generator.clone() * &value_mask;
    let pedersen_mask = plain_mask.clone() + &(setup.blinding_generator.clone() * &blinding_mask);

    transcript.commit(plain_mask.encode());
    transcript.commit(pedersen_mask.encode());
    let challenge = F::random(transcript.noise(b"challenge"));

    Proof {
        plain_mask,
        pedersen_mask,
        value_response: value_mask + &(challenge.clone() * &witness.value),
        blinding_response: blinding_mask + &(challenge * &witness.blinding),
    }
}

/// Verify a [`Proof`] against a [`Claim`].
///
/// Returns `true` if the proof is valid for the current transcript state.
pub fn verify<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode + PartialEq>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    setup: &Setup<Synthetic<F, G>>,
    claim: &Claim<G>,
    proof: Proof<F, G>,
) -> Synthetic<F, G>
where
    Claim<G>: Encode,
{
    let Proof {
        plain_mask,
        pedersen_mask,
        value_response,
        blinding_response,
    } = proof;

    transcript.commit(claim.encode());
    transcript.commit(plain_mask.encode());
    transcript.commit(pedersen_mask.encode());
    let challenge = F::random(transcript.noise(b"challenge"));

    let plain_valid = Synthetic::concrete([
        (F::one(), plain_mask),
        (challenge.clone(), claim.plain.clone()),
    ]) - &(setup.value_generator.clone() * &value_response);
    let pedersen_valid = Synthetic::concrete([
        (F::one(), pedersen_mask),
        (challenge, claim.pedersen.clone()),
    ]) - &(setup.value_generator.clone() * &value_response)
        - &(setup.blinding_generator.clone() * &blinding_response);
    pedersen_valid + &(plain_valid * &F::random(&mut *rng))
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::{Claim, Proof, Setup};
    use commonware_codec::conformance::CodecConformance;
    use commonware_math::test::{F as TestF, G as TestG};

    commonware_conformance::conformance_tests! {
        CodecConformance<Setup<TestG>>,
        CodecConformance<Claim<TestG>>,
        CodecConformance<Proof<TestF, TestG>>,
    }
}

#[commonware_macros::stability(ALPHA)]
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::bls12381::primitives::group::{Scalar as F, G1 as G};
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::algebra::{Additive, CryptoGroup, HashToGroup};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use std::sync::OnceLock;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PEDERSEN_TO_PLAIN";
    const BAD_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PEDERSEN_TO_PLAIN_BUT_DIFFERENT";

    pub(super) fn test_setup() -> &'static Setup<G> {
        static TEST_SETUP: OnceLock<Setup<G>> = OnceLock::new();
        TEST_SETUP.get_or_init(|| Setup {
            value_generator: G::generator(),
            blinding_generator: G::hash_to_group(NAMESPACE, b"blinding generator"),
        })
    }

    struct Prover<'a> {
        setup: &'a Setup<G>,
        claim: Claim<G>,
        proof: Proof<F, G>,
        bad_namespace: bool,
        honest: bool,
    }

    impl<'a> Prover<'a> {
        fn new(setup: &'a Setup<G>, value: F, blinding: F) -> Self {
            let witness = Witness { value, blinding };
            let claim = witness.claim(setup);
            let proof = prove(
                &mut test_rng(),
                &mut Transcript::new(NAMESPACE),
                setup,
                &claim,
                &witness,
            );
            Self {
                setup,
                claim,
                proof,
                bad_namespace: false,
                honest: true,
            }
        }

        #[allow(clippy::missing_const_for_fn)]
        fn bad_namespace(&mut self) {
            self.honest = false;
            self.bad_namespace = true;
        }

        fn tweak_plain_claim(&mut self, delta: F) {
            if delta == F::zero() {
                return;
            }
            self.honest = false;
            self.claim.plain += &(self.setup.value_generator * &delta);
        }

        fn tweak_pedersen_claim(&mut self, value_delta: F, blinding_delta: F) {
            if value_delta == F::zero() && blinding_delta == F::zero() {
                return;
            }
            self.honest = false;
            self.claim.pedersen += &((self.setup.value_generator * &value_delta)
                + &(self.setup.blinding_generator * &blinding_delta));
        }

        fn tweak_mask(&mut self, tweak_plain: bool, delta: G) {
            if delta == G::zero() {
                return;
            }
            self.honest = false;
            if tweak_plain {
                self.proof.plain_mask += &delta;
            } else {
                self.proof.pedersen_mask += &delta;
            }
        }

        fn tweak_response(&mut self, tweak_value: bool, delta: F) {
            if delta == F::zero() {
                return;
            }
            self.honest = false;
            if tweak_value {
                self.proof.value_response += &delta;
            } else {
                self.proof.blinding_response += &delta;
            }
        }

        #[allow(clippy::missing_const_for_fn)]
        fn honest(&self) -> bool {
            self.honest
        }

        fn verify(self, rng: &mut impl CryptoRngCore) -> bool {
            let ns = if self.bad_namespace {
                BAD_NAMESPACE
            } else {
                NAMESPACE
            };
            let [g, h] = Synthetic::generators_array();
            verify(
                rng,
                &mut Transcript::new(ns),
                &Setup {
                    value_generator: g,
                    blinding_generator: h,
                },
                &self.claim,
                self.proof,
            )
            .eval(
                &[self.setup.value_generator, self.setup.blinding_generator],
                &Sequential,
            ) == G::zero()
        }
    }

    #[derive(Debug)]
    pub struct Plan {
        value: F,
        blinding: F,
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                value: u.arbitrary()?,
                blinding: u.arbitrary()?,
            })
        }
    }

    impl Plan {
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            let setup = test_setup();
            let mut prover = Prover::new(setup, self.value, self.blinding);
            if u.arbitrary::<bool>()? {
                match u.arbitrary::<u8>()? {
                    x if x < 51 => prover.tweak_plain_claim(u.arbitrary()?),
                    x if x < 102 => prover.tweak_pedersen_claim(u.arbitrary()?, u.arbitrary()?),
                    x if x < 153 => prover.tweak_mask(u.arbitrary()?, u.arbitrary()?),
                    x if x < 204 => prover.tweak_response(u.arbitrary()?, u.arbitrary()?),
                    _ => prover.bad_namespace(),
                }
            }
            match (prover.honest(), prover.verify(&mut test_rng())) {
                (true, true) | (false, false) => {}
                (true, false) => panic!("prover honest, but proof didn't verify"),
                (false, true) => panic!("prover malicious, but proof verifies"),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::{fuzz, Claim, Proof, Setup};
    use commonware_codec::{Decode, Encode};
    use commonware_invariants::minifuzz;
    use commonware_math::test::{F, G};

    fn assert_setup_roundtrip(setup: &Setup<G>) {
        let encoded = setup.encode();
        let decoded: Setup<G> =
            Setup::decode_cfg(encoded.clone(), &()).expect("setup should decode with unit cfg");
        assert_eq!(setup, &decoded);
        assert_eq!(decoded.encode(), encoded);
    }

    fn assert_claim_roundtrip(claim: &Claim<G>) {
        let encoded = claim.encode();
        let decoded: Claim<G> =
            Claim::decode_cfg(encoded.clone(), &()).expect("claim should decode with unit cfg");
        assert_eq!(claim, &decoded);
        assert_eq!(decoded.encode(), encoded);
    }

    fn assert_proof_roundtrip(proof: &Proof<F, G>) {
        let encoded = proof.encode();
        let decoded: Proof<F, G> = Proof::decode_cfg(encoded.clone(), &((), ()))
            .expect("proof should decode with unit cfg");
        assert_eq!(proof, &decoded);
        assert_eq!(decoded.encode(), encoded);
    }

    #[test]
    fn test_codec_roundtrip() {
        minifuzz::test(|u| {
            assert_setup_roundtrip(&u.arbitrary::<Setup<G>>()?);
            assert_claim_roundtrip(&u.arbitrary::<Claim<G>>()?);
            assert_proof_roundtrip(&u.arbitrary::<Proof<F, G>>()?);
            Ok(())
        });
    }

    #[test]
    fn test_fuzz() {
        minifuzz::test(|u| {
            u.arbitrary::<fuzz::Plan>()?.run(u)?;
            Ok(())
        });
    }
}
