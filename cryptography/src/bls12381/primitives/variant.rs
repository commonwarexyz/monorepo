//! Different variants of the BLS signature scheme.

use crate::bls12381::primitives::group::{Element, Scalar, SCALAR_BITS};

use super::group::{
    Point, DST, G1, G1_MESSAGE, G1_PROOF_OF_POSSESSION, G2, G2_MESSAGE, G2_PROOF_OF_POSSESSION,
};
use super::Error;
use blst::{
    blst_p1, blst_p1_from_affine, Pairing as blst_pairing, BLS12_381_NEG_G1, BLS12_381_NEG_G2,
};
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

    fn batch_verify<R: RngCore + CryptoRng>(
        rng: &mut R,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
    ) -> Result<(), Error> {
        // Ensure arguments are populated correctly
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Ok(());
        }

        // Populate pairing context
        let mut neg_generator = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut neg_generator, &BLS12_381_NEG_G1) }
        let neg_generator = G1::from_blst_p1(neg_generator);
        let mut pairing = blst_pairing::new(false, &[]);
        for i in 0..publics.len() {
            // Generate a non-zero random scalar
            let scalar = loop {
                let scalar = Scalar::rand(rng);
                if scalar != Scalar::zero() {
                    break scalar;
                }
            };

            // Add item to context
            let mut neg_generator = neg_generator.clone();
            neg_generator.mul(&scalar);
            let sig_affine = signatures[i].as_blst_p2_affine();
            pairing.raw_aggregate(&sig_affine, &neg_generator.as_blst_p1_affine());

            let pk_affine = publics[i].as_blst_p1_affine();
            let mut hm = hms[i].clone();
            hm.mul(&scalar);
            pairing.raw_aggregate(&hm.as_blst_p2_affine(), &pk_affine);
        }
        pairing.commit();

        // Check validity
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

    fn batch_verify<R: RngCore + CryptoRng>(
        rng: &mut R,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl Debug for MinSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinSig").finish()
    }
}
