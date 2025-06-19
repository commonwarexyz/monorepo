//! Different variants of the BLS signature scheme.

use super::{
    group::{
        Point, DST, G1, G1_MESSAGE, G1_PROOF_OF_POSSESSION, G2, G2_MESSAGE, G2_PROOF_OF_POSSESSION,
    },
    Error,
};
use crate::bls12381::primitives::group::{Element, Scalar};
use blst::{Pairing as blst_pairing, BLS12_381_NEG_G1, BLS12_381_NEG_G2};
use commonware_codec::FixedSize;
use rand::{CryptoRng, RngCore};
use std::{fmt::Debug, hash::Hash};

/// A specific instance of a signature scheme.
pub trait Variant: Clone + Send + Sync + Hash + Eq + Debug + 'static {
    /// The public key type.
    type Public: Point + FixedSize + Debug + Hash + Copy + AsRef<Self::Public>;

    /// The signature type.
    type Signature: Point + FixedSize + Debug + Hash + Copy + AsRef<Self::Signature>;

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
    fn batch_verify<R: RngCore + CryptoRng>(
        rng: &mut R,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
    ) -> Result<(), Error>;
}

/// A [Variant] with a public key of type [G1] and a signature of type [G2].
#[derive(Clone, Hash, PartialEq, Eq)]
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
        // Create a pairing context
        //
        // We only handle pre-hashed messages, so we leave the domain separator tag (`DST`) empty.
        let mut pairing = blst_pairing::new(false, &[]);

        // Convert `sig` into affine and aggregate `e(sig,-G1::one())`
        let q = signature.as_blst_p2_affine();
        unsafe {
            pairing.raw_aggregate(&q, &BLS12_381_NEG_G1);
        }

        // Convert `pk` and `hm` into affine
        let p = public.as_blst_p1_affine();
        let q = hm.as_blst_p2_affine();

        // Aggregate `e(hm,pk)`
        pairing.raw_aggregate(&q, &p);

        // Finalize the pairing accumulation and verify the result
        //
        // If `finalverify()` returns `true`, it means `e(hm,pk) * e(sig,-G1::one()) == 1`. This
        // is equivalent to `e(hm,pk) == e(sig,G1::one())`.
        pairing.commit();
        if !pairing.finalverify(None) {
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
    fn batch_verify<R: RngCore + CryptoRng>(
        rng: &mut R,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
    ) -> Result<(), Error> {
        // Ensure there is an equal number of public keys, messages, and signatures.
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Ok(());
        }

        // Generate random non-zero scalars.
        let scalars: Vec<Scalar> = (0..publics.len())
            .map(|_| loop {
                let scalar = Scalar::rand(rng);
                if scalar != Scalar::zero() {
                    return scalar;
                }
            })
            .collect();

        // Compute S_agg = sum(r_i * sig_i) using Multi-Scalar Multiplication (MSM).
        let s_agg = G2::msm(signatures, &scalars);

        // Initialize pairing context. DST is empty as we use pre-hashed messages.
        let mut pairing = blst_pairing::new(false, &[]);

        // Aggregate the single term corresponding to signatures: e(-G1::one(),S_agg)
        let s_agg_affine = s_agg.as_blst_p2_affine();
        unsafe {
            pairing.raw_aggregate(&s_agg_affine, &BLS12_381_NEG_G1);
        }

        // Aggregate the `n` terms corresponding to public keys and messages: e(r_i * pk_i,hm_i)
        for i in 0..publics.len() {
            let mut scaled_pk = publics[i];
            scaled_pk.mul(&scalars[i]);
            let pk_affine = scaled_pk.as_blst_p1_affine();
            let hm_affine = hms[i].as_blst_p2_affine();
            pairing.raw_aggregate(&hm_affine, &pk_affine);
        }

        // Perform the final verification on the product of (n+1) pairing terms.
        pairing.commit();
        if !pairing.finalverify(None) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl Debug for MinPk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinPk").finish()
    }
}

/// A [Variant] with a public key of type [G2] and a signature of type [G1].
#[derive(Clone, Hash, PartialEq, Eq)]
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
        // Create a pairing context
        //
        // We only handle pre-hashed messages, so we leave the domain separator tag (`DST`) empty.
        let mut pairing = blst_pairing::new(false, &[]);

        // Convert `sig` into affine and aggregate `e(-G2::one(), sig)`
        let q = signature.as_blst_p1_affine();
        unsafe {
            pairing.raw_aggregate(&BLS12_381_NEG_G2, &q);
        }

        // Convert `pk` and `hm` into affine
        let p = public.as_blst_p2_affine();
        let q = hm.as_blst_p1_affine();

        // Aggregate `e(pk,hm)`
        pairing.raw_aggregate(&p, &q);

        // Finalize the pairing accumulation and verify the result
        //
        // If `finalverify()` returns `true`, it means `e(pk,hm) * e(-G2::one(),sig) == 1`. This
        // is equivalent to `e(pk,hm) == e(G2::one(),sig)`.
        pairing.commit();
        if !pairing.finalverify(None) {
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
    fn batch_verify<R: RngCore + CryptoRng>(
        rng: &mut R,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
    ) -> Result<(), Error> {
        // Ensure there is an equal number of public keys, messages, and signatures.
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Ok(());
        }

        // Generate random non-zero scalars.
        let scalars: Vec<Scalar> = (0..publics.len())
            .map(|_| loop {
                let scalar = Scalar::rand(rng);
                if scalar != Scalar::zero() {
                    return scalar;
                }
            })
            .collect();

        // Compute S_agg = sum(r_i * sig_i) using Multi-Scalar Multiplication (MSM).
        let s_agg = G1::msm(signatures, &scalars);

        // Initialize pairing context. DST is empty as we use pre-hashed messages.
        let mut pairing = blst_pairing::new(false, &[]);

        // Aggregate the single term corresponding to signatures: e(S_agg,-G2::one())
        let s_agg_affine = s_agg.as_blst_p1_affine();
        unsafe {
            pairing.raw_aggregate(&BLS12_381_NEG_G2, &s_agg_affine);
        }

        // Aggregate the `n` terms corresponding to public keys and messages: e(hm_i, r_i * pk_i)
        for i in 0..publics.len() {
            let mut scaled_pk = publics[i];
            scaled_pk.mul(&scalars[i]);
            let pk_affine = scaled_pk.as_blst_p2_affine();
            let hm_affine = hms[i].as_blst_p1_affine();
            pairing.raw_aggregate(&pk_affine, &hm_affine);
        }

        // Perform the final verification on the product of (n+1) pairing terms.
        pairing.commit();
        if !pairing.finalverify(None) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl Debug for MinSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinSig").finish()
    }
}
