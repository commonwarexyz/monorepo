//! Different variants of the BLS signature scheme.

use super::{
    group::{
        Scalar, SmallScalar, DST, G1, G1_MESSAGE, G1_PROOF_OF_POSSESSION, G2, G2_MESSAGE,
        G2_PROOF_OF_POSSESSION, GT,
    },
    Error,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blst::{blst_final_exp, blst_fp12, blst_miller_loop};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_macros::ready;
use commonware_math::algebra::{CryptoGroup, HashToGroup, Space};
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use core::{
    fmt::{Debug, Formatter},
    hash::Hash,
};
use rand_core::CryptoRngCore;

/// A specific instance of a signature scheme.
pub trait Variant: Clone + Send + Sync + Hash + Eq + Debug + 'static {
    /// The public key type.
    type Public: HashToGroup<Scalar = Scalar>
        + Space<SmallScalar>
        + FixedSize
        + Write
        + Read<Cfg = ()>
        + Debug
        + Hash
        + Copy;

    /// The signature type.
    type Signature: HashToGroup<Scalar = Scalar>
        + Space<SmallScalar>
        + FixedSize
        + Write
        + Read<Cfg = ()>
        + Debug
        + Hash
        + Copy;

    /// The domain separator tag (DST) for a proof of possession.
    const PROOF_OF_POSSESSION: DST;

    /// The domain separator tag (DST) for a message.
    const MESSAGE: DST;

    /// Verify the signature from the provided public key and pre-hashed message.
    fn verify(
        public: &Self::Public,
        hm: &Self::Signature,
        signature: &Self::Signature,
    ) -> Result<(), Error>;

    /// Verify a batch of signatures from the provided public keys and pre-hashed messages.
    fn batch_verify(
        rng: &mut impl CryptoRngCore,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
        strategy: &impl Strategy,
    ) -> Result<(), Error>;

    /// Compute the pairing `e(G1, G2) -> GT`.
    fn pairing(public: &Self::Public, signature: &Self::Signature) -> GT;
}

/// A [Variant] with a public key of type [G1] and a signature of type [G2].
#[derive(Clone, Hash, PartialEq, Eq)]
#[ready(0)]
pub struct MinPk {}

impl Variant for MinPk {
    type Public = G1;
    type Signature = G2;

    const PROOF_OF_POSSESSION: DST = G2_PROOF_OF_POSSESSION;
    const MESSAGE: DST = G2_MESSAGE;

    /// Verifies that `e(hm,pk)` is equal to `e(sig,G1::one())` using a single product check with
    /// a negated G1 generator (`e(hm,pk) * e(sig,-G1::one()) == 1`).
    fn verify(
        public: &Self::Public,
        hm: &Self::Signature,
        signature: &Self::Signature,
    ) -> Result<(), Error> {
        if !G2::multi_pairing_check(&[*hm], &[*public], signature, &-G1::generator()) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Verifies a set of signatures against their respective public keys and pre-hashed messages.
    ///
    /// This method is outperforms individual signature verification (`2` pairings per signature) by
    /// verifying a random linear combination of the public keys and signatures (`n+1` pairings and
    /// `2n` multiplications for `n` signatures).
    ///
    /// The verification equation for each signature `i` is:
    /// `e(hm_i,pk_i) == e(sig_i,G1::one())`,
    /// which is equivalent to checking if `e(hm_i,pk_i) * e(sig_i,-G1::one()) == 1`.
    ///
    /// To batch verify `n` such equations, we introduce random non-zero scalars `r_i` (for `i=1..n`).
    /// The batch verification checks if the product of these individual equations, each raised to the power
    /// of its respective `r_i`, equals one:
    /// `prod_i((e(hm_i,pk_i) * e(sig_i,-G1::one()))^{r_i}) == 1`
    ///
    /// Using the bilinearity of pairings, this can be rewritten (by moving `r_i` inside the pairings):
    /// `prod_i(e(hm_i,r_i * pk_i) * e(r_i * sig_i,-G1::one())) == 1`
    ///
    /// The second term `e(r_i * sig_i,-G1::one())` can be computed efficiently with Multi-Scalar Multiplication:
    /// `e(sum_i(r_i * sig_i),-G1::one())`
    ///
    /// Finally, we aggregate all pairings `e(hm_i,r_i * pk_i)` (`n`) and `e(sum_i(r_i * sig_i),-G1::one())` (`1`)
    /// into a single product in the target group `G_T`. If the result is the identity element in `G_T`,
    /// the batch verification succeeds.
    ///
    /// Source: <https://ethresear.ch/t/security-of-bls-batch-verification/10748>
    fn batch_verify(
        rng: &mut impl CryptoRngCore,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
        par: &impl Strategy,
    ) -> Result<(), Error> {
        // Ensure there is an equal number of public keys, messages, and signatures.
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Ok(());
        }

        // Generate 128-bit random scalars (sufficient for batch verification security).
        let scalars: Vec<SmallScalar> = (0..publics.len())
            .map(|_| SmallScalar::random(&mut *rng))
            .collect();

        let (s_agg, scaled_pks) = par.join(
            || G2::msm(signatures, &scalars, par),
            || par.map_collect_vec(publics.iter().zip(scalars.iter()), |(&pk, s)| pk * s),
        );
        if !G2::multi_pairing_check(hms, &scaled_pks, &s_agg, &-G1::generator()) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Compute the pairing `e(public, signature) -> GT`.
    fn pairing(public: &Self::Public, signature: &Self::Signature) -> GT {
        let p1_affine = public.as_blst_p1_affine();
        let p2_affine = signature.as_blst_p2_affine();

        let mut result = blst_fp12::default();
        let ptr = &raw mut result;
        // SAFETY: blst_final_exp supports in-place (ret==f). Raw pointer avoids aliased refs.
        unsafe {
            blst_miller_loop(ptr, &p2_affine, &p1_affine);
            blst_final_exp(ptr, ptr);
        }

        GT::from_blst_fp12(result)
    }
}

impl Debug for MinPk {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MinPk").finish()
    }
}

/// A [Variant] with a public key of type [G2] and a signature of type [G1].
#[derive(Clone, Hash, PartialEq, Eq)]
#[ready(0)]
pub struct MinSig {}

impl Variant for MinSig {
    type Public = G2;
    type Signature = G1;

    const PROOF_OF_POSSESSION: DST = G1_PROOF_OF_POSSESSION;
    const MESSAGE: DST = G1_MESSAGE;

    /// Verifies that `e(pk,hm)` is equal to `e(G2::one(),sig)` using a single product check with
    /// a negated G2 generator (`e(pk,hm) * e(-G2::one(),sig) == 1`).
    fn verify(
        public: &Self::Public,
        hm: &Self::Signature,
        signature: &Self::Signature,
    ) -> Result<(), Error> {
        if !G1::multi_pairing_check(&[*hm], &[*public], signature, &-G2::generator()) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Verifies a set of signatures against their respective public keys and pre-hashed messages.
    ///
    /// This method outperforms individual signature verification (`2` pairings per signature) by
    /// verifying a random linear combination of the public keys and signatures (`n+1` pairings and
    /// `2n` multiplications for `n` signatures).
    ///
    /// The verification equation for each signature `i` is:
    /// `e(pk_i,hm_i) == e(G2::one(),sig_i)`,
    /// which is equivalent to checking if `e(pk_i,hm_i) * e(-G2::one(),sig_i) == 1`.
    ///
    /// To batch verify `n` such equations, we introduce random non-zero scalars `r_i` (for `i=1..n`).
    /// The batch verification checks if the product of these individual equations, each effectively
    /// raised to the power of its respective `r_i`, equals one:
    /// `prod_i((e(pk_i,hm_i) * e(-G2::one(),sig_i))^{r_i}) == 1`
    ///
    /// Using the bilinearity of pairings, this can be rewritten (by moving `r_i` inside the pairings):
    /// `prod_i(e(r_i * pk_i,hm_i) * e(-G2::one(),r_i * sig_i)) == 1`
    ///
    /// The second term `e(-G2::one(),r_i * sig_i)` can be computed efficiently with Multi-Scalar Multiplication:
    /// `e(-G2::one(),sum_i(r_i * sig_i))`
    ///
    /// Finally, we aggregate all pairings `e(r_i * pk_i,hm_i)` (`n`) and `e(-G2::one(),sum_i(r_i * sig_i))` (`1`)
    /// into a single product in the target group `G_T`. If the result is the identity element in `G_T`,
    /// the batch verification succeeds.
    ///
    /// Source: <https://ethresear.ch/t/security-of-bls-batch-verification/10748>
    fn batch_verify(
        rng: &mut impl CryptoRngCore,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
        par: &impl Strategy,
    ) -> Result<(), Error> {
        // Ensure there is an equal number of public keys, messages, and signatures.
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Ok(());
        }

        // Generate 128-bit random scalars (sufficient for batch verification security).
        let scalars: Vec<SmallScalar> = (0..publics.len())
            .map(|_| SmallScalar::random(&mut *rng))
            .collect();

        let (s_agg, scaled_pks) = par.join(
            || G1::msm(signatures, &scalars, par),
            || par.map_collect_vec(publics.iter().zip(scalars.iter()), |(&pk, s)| pk * s),
        );
        if !G1::multi_pairing_check(hms, &scaled_pks, &s_agg, &-G2::generator()) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Compute the pairing `e(signature, public) -> GT`.
    fn pairing(public: &Self::Public, signature: &Self::Signature) -> GT {
        let p1_affine = signature.as_blst_p1_affine();
        let p2_affine = public.as_blst_p2_affine();

        let mut result = blst_fp12::default();
        let ptr = &raw mut result;
        // SAFETY: blst_final_exp supports in-place (ret==f). Raw pointer avoids aliased refs.
        unsafe {
            blst_miller_loop(ptr, &p2_affine, &p1_affine);
            blst_final_exp(ptr, ptr);
        }

        GT::from_blst_fp12(result)
    }
}

impl Debug for MinSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MinSig").finish()
    }
}

/// A partial signature.
///
/// c.f. [`super::ops`] for how to manipulate these.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[ready(0)]
pub struct PartialSignature<V: Variant> {
    pub index: Participant,
    pub value: V::Signature,
}

impl<V: Variant> Write for PartialSignature<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.value.write(buf);
    }
}

impl<V: Variant> Read for PartialSignature<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = Participant::read(buf)?;
        let value = V::Signature::read(buf)?;
        Ok(Self { index, value })
    }
}

impl<V: Variant> EncodeSize for PartialSignature<V> {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + V::Signature::SIZE
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant> arbitrary::Arbitrary<'a> for PartialSignature<V> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        use commonware_math::algebra::CryptoGroup;

        Ok(Self {
            index: u.arbitrary()?,
            value: <V::Signature as CryptoGroup>::generator() * &u.arbitrary::<Scalar>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{group::Scalar, ops};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{test_rng, NZUsize};

    fn batch_verify_correct<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = ops::keypair::<_, V>(&mut rng);
        let (private2, public2) = ops::keypair::<_, V>(&mut rng);
        let (private3, public3) = ops::keypair::<_, V>(&mut rng);

        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";
        let msg3: &[u8] = b"message 3";

        let sig1 = ops::sign_message::<V>(&private1, b"test", msg1);
        let sig2 = ops::sign_message::<V>(&private2, b"test", msg2);
        let sig3 = ops::sign_message::<V>(&private3, b"test", msg3);

        let hm1 = ops::hash_with_namespace::<V>(V::MESSAGE, b"test", msg1);
        let hm2 = ops::hash_with_namespace::<V>(V::MESSAGE, b"test", msg2);
        let hm3 = ops::hash_with_namespace::<V>(V::MESSAGE, b"test", msg3);

        V::batch_verify(
            &mut rng,
            &[public1, public2, public3],
            &[hm1, hm2, hm3],
            &[sig1, sig2, sig3],
            &Sequential,
        )
        .expect("valid batch should pass");

        let parallel = Rayon::new(NZUsize!(2)).unwrap();
        V::batch_verify(
            &mut rng,
            &[public1, public2, public3],
            &[hm1, hm2, hm3],
            &[sig1, sig2, sig3],
            &parallel,
        )
        .expect("valid batch should pass with parallel strategy");
    }

    #[test]
    fn test_batch_verify_correct() {
        batch_verify_correct::<MinPk>();
        batch_verify_correct::<MinSig>();
    }

    fn batch_verify_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = ops::keypair::<_, V>(&mut rng);
        let (private2, public2) = ops::keypair::<_, V>(&mut rng);

        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";

        let sig1 = ops::sign_message::<V>(&private1, b"test", msg1);
        let sig2 = ops::sign_message::<V>(&private2, b"test", msg2);

        let hm1 = ops::hash_with_namespace::<V>(V::MESSAGE, b"test", msg1);
        let hm2 = ops::hash_with_namespace::<V>(V::MESSAGE, b"test", msg2);

        // Forge signatures that cancel out: sig1' = sig1 - delta, sig2' = sig2 + delta
        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_sig1 = sig1 - &delta;
        let forged_sig2 = sig2 + &delta;

        // Individual verification should fail for forged signatures
        assert!(
            V::verify(&public1, &hm1, &forged_sig1).is_err(),
            "forged sig1 should be invalid individually"
        );
        assert!(
            V::verify(&public2, &hm2, &forged_sig2).is_err(),
            "forged sig2 should be invalid individually"
        );

        // Naive aggregate verification would accept forged signatures because:
        // sig1' + sig2' = (sig1 - delta) + (sig2 + delta) = sig1 + sig2
        let forged_agg = forged_sig1 + &forged_sig2;
        let valid_agg = sig1 + &sig2;
        assert_eq!(forged_agg, valid_agg, "aggregates should be equal");

        // batch_verify with random weights should reject forged signatures
        let result = V::batch_verify(
            &mut rng,
            &[public1, public2],
            &[hm1, hm2],
            &[forged_sig1, forged_sig2],
            &Sequential,
        );
        assert!(
            result.is_err(),
            "batch_verify should reject forged signatures"
        );

        // Valid signatures should still pass
        V::batch_verify(
            &mut rng,
            &[public1, public2],
            &[hm1, hm2],
            &[sig1, sig2],
            &Sequential,
        )
        .expect("valid signatures should pass batch_verify");
    }

    #[test]
    fn test_batch_verify_rejects_malleability() {
        batch_verify_rejects_malleability::<MinPk>();
        batch_verify_rejects_malleability::<MinSig>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PartialSignature<MinPk>>,
            CodecConformance<PartialSignature<MinSig>>,
        }
    }
}
