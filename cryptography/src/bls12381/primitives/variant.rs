//! Different variants of the BLS signature scheme.

use super::group::{
    Point, DST, G1, G1_MESSAGE, G1_PROOF_OF_POSSESSION, G2, G2_MESSAGE, G2_PROOF_OF_POSSESSION,
};
use super::Error;
use crate::bls12381::primitives::group::{Element, Scalar, SCALAR_BITS};
use blst::{Pairing as blst_pairing, BLS12_381_NEG_G1, BLS12_381_NEG_G2};
use commonware_codec::FixedSize;
use rand::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::hash::Hash;

/// A specific instance of a signature scheme.
pub trait Variant: Clone + Send + Sync + Hash + Eq + Debug + 'static {
    /// The public key type.
    type Public: Point + FixedSize + Debug + Hash + Copy;

    /// The signature type.
    type Signature: Point + FixedSize + Debug + Hash + Copy;

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
    /// This method is outperforms individual signature verification by verifying a random linear
    /// combination of the public keys and signatures.
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
    /// Finally, we aggregate all pairings `e(hm_i,r_i * pk_i)` and `e(r_i * sig_i,-G1::one())`
    /// into a single product in the target group `G_T`. If the result is the identity element in `G_T`,
    /// the batch verification succeeds.
    ///
    /// Source: https://ethresear.ch/t/security-of-bls-batch-verification/10748
    fn batch_verify<R: RngCore + CryptoRng>(
        rng: &mut R,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
    ) -> Result<(), Error> {
        // Ensure there is an equal number of public keys, messages, and signatures
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Ok(());
        }

        // Create a pairing context
        //
        // We only handle pre-hashed messages, so we leave the domain separator tag (`DST`) empty.
        let mut pairing = blst_pairing::new(false, &[]);
        for i in 0..publics.len() {
            // Generate a non-zero random scalar `r_i`.
            //
            // This scalar is essential for the security of batch verification. It ensures that
            // multiple invalid signatures are extremely unlikely to combine in a way that
            // makes the overall batch check pass (i.e., they don't accidentally "cancel out").
            let r_i = loop {
                let scalar = Scalar::rand(rng);
                if scalar != Scalar::zero() {
                    break scalar;
                }
            };

            // Prepare the pairing term e(r_i * sig_i,-G1::one()).
            //
            // This corresponds to one part of the i-th term in the product: e(sig_i,-G1::one())^{r_i}.
            let mut scaled_sig = signatures[i];
            scaled_sig.mul(&r_i);
            let sig_affine = scaled_sig.as_blst_p2_affine();

            // Aggregate the term e(r_i * sig_i,-G1::one()) into the pairing context.
            unsafe {
                pairing.raw_aggregate(&sig_affine, &BLS12_381_NEG_G1);
            }

            // Prepare the pairing term e(hm_i, r_i * pk_i).
            //
            // This corresponds to the other part of the i-th term in the product: e(hm_i, pk_i)^{r_i}.
            let mut scaled_pk = publics[i];
            scaled_pk.mul(&r_i);
            let pk_affine = scaled_pk.as_blst_p1_affine();
            let hm_affine = hms[i].as_blst_p2_affine();

            // Aggregate the term e(hm_i,r_i * pk_i) into the pairing context.
            pairing.raw_aggregate(&hm_affine, &pk_affine);
        }

        // Perform the final verification.
        //
        // `finalverify` computes the product of all (2n) aggregated pairing terms:
        // prod_i(e(hm_i, r_i * pk_i) * e(r_i * sig_i,-G1::one()))
        //
        // It then checks if this resulting product in G_T is equal to the identity element.
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
    /// This method outperforms individual signature verification by verifying a random linear
    /// combination of the public keys and signatures.
    ///
    /// The verification equation for `MinSig` for each signature `i` is:
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
    /// Finally, we aggregate all pairings `e(r_i * pk_i,hm_i)` and `e(-G2::one(),r_i * sig_i)`
    /// into a single product in the target group `G_T`. If the result is the identity element in `G_T`,
    /// the batch verification succeeds.
    ///
    /// Source: https://ethresear.ch/t/security-of-bls-batch-verification/10748
    fn batch_verify<R: RngCore + CryptoRng>(
        rng: &mut R,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
    ) -> Result<(), Error> {
        // Ensure there is an equal number of public keys, messages, and signatures
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Ok(());
        }

        // Create a pairing context
        //
        // We only handle pre-hashed messages, so we leave the domain separator tag (`DST`) empty.
        let mut pairing = blst_pairing::new(false, &[]);
        for i in 0..publics.len() {
            // Generate a non-zero random scalar `r_i`.
            //
            // This scalar is essential for the security of batch verification. It ensures that
            // multiple invalid signatures are extremely unlikely to combine in a way that
            // makes the overall batch check pass (i.e., they don't accidentally "cancel out").
            let r_i = loop {
                let scalar = Scalar::rand(rng);
                if scalar != Scalar::zero() {
                    break scalar;
                }
            };

            // Prepare the pairing term e(-G2::one(),r_i * sig_i).
            //
            // This corresponds to one part of the i-th term in the product: e(-G2::one(),sig_i)^{r_i}.
            let mut scaled_sig = signatures[i];
            scaled_sig.mul(&r_i);
            let sig_p1_affine = scaled_sig.as_blst_p1_affine(); // Convert to G1 affine.

            // Aggregate the term e(-G2::one(),r_i * sig_i) into the pairing context.
            unsafe {
                pairing.raw_aggregate(&BLS12_381_NEG_G2, &sig_p1_affine);
            }

            // Prepare the pairing term e(r_i * pk_i,hm_i).
            //
            // This corresponds to the other part of the i-th term in the product: e(pk_i,hm_i)^{r_i}.
            let mut scaled_pk = publics[i];
            scaled_pk.mul(&r_i);
            let pk_p2_affine = scaled_pk.as_blst_p2_affine();
            let hm_p1_affine = hms[i].as_blst_p1_affine();

            // Aggregate the term e(r_i * pk_i,hm_i) into the pairing context.
            pairing.raw_aggregate(&pk_p2_affine, &hm_p1_affine);
        }

        // Perform the final verification.
        //
        // `finalverify` computes the product of all (2n) aggregated pairing terms:
        // prod_i(e(r_i * pk_i,hm_i) * e(-G2::one(),r_i * sig_i))
        //
        // It then checks if this resulting product in G_T is equal to the identity element.
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
