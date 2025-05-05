use std::fmt::Debug;

use super::group::{
    Element, Point, Scalar, DST, G1, G1_ELEMENT_BYTE_LENGTH, G1_MESSAGE, G1_PROOF_OF_POSSESSION,
    G2, G2_ELEMENT_BYTE_LENGTH, G2_MESSAGE, G2_PROOF_OF_POSSESSION,
};
use super::Error;
use blst::{Pairing as blst_pairing, BLS12_381_NEG_G1, BLS12_381_NEG_G2};
use commonware_codec::FixedSize;

pub type MinPkPublic = G1;

pub const MIN_PK_PUBLIC_LENGTH: usize = G1_ELEMENT_BYTE_LENGTH;

pub type MinPkSignature = G2;

pub const MIN_PK_SIGNATURE_LENGTH: usize = G2_ELEMENT_BYTE_LENGTH;

pub type MinSigPublic = G2;

pub const MIN_SIG_PUBLIC_LENGTH: usize = G2_ELEMENT_BYTE_LENGTH;

pub type MinSigSignature = G1;

pub const MIN_SIG_SIGNATURE_LENGTH: usize = G1_ELEMENT_BYTE_LENGTH;

pub trait Variant: Clone + 'static + Send + Sync {
    type Public: Point + FixedSize + Debug;
    type Signature: Point + FixedSize + Debug;

    const PROOF_OF_POSSESSION: DST;
    const MESSAGE: DST;

    /// Sign the provided payload with the private key.
    fn sign(private: &Scalar, dst: DST, payload: &[u8]) -> Self::Signature;

    fn verify_prehashed(
        public: &Self::Public,
        hm: &Self::Signature,
        signature: &Self::Signature,
    ) -> Result<(), Error>;

    /// Verify the signature from the provided public key.
    fn verify(
        public: &Self::Public,
        dst: DST,
        payload: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Error>;
}

#[derive(Clone)]
pub struct MinPk {}

impl Variant for MinPk {
    type Public = G1;
    type Signature = G2;

    const PROOF_OF_POSSESSION: DST = G1_PROOF_OF_POSSESSION;
    const MESSAGE: DST = G1_MESSAGE;

    fn sign(private: &Scalar, dst: DST, message: &[u8]) -> Self::Signature {
        let mut s = Self::Signature::zero();
        s.map(dst, message);
        s.mul(private);
        s
    }

    fn verify_prehashed(
        public: &Self::Public,
        hm: &Self::Signature,
        signature: &Self::Signature,
    ) -> Result<(), Error> {
        // Create a pairing context
        //
        // We only handle pre-hashed messages, so we leave the domain separator tag (`DST`) empty.
        let mut pairing = blst_pairing::new(false, &[]);

        // Convert `sig` into affine and aggregate `e(-G1::one(), sig)`
        let q = signature.as_blst_p2_affine();
        unsafe {
            pairing.raw_aggregate(&q, &BLS12_381_NEG_G1);
        }

        // Convert `pk` and `hm` into affine
        let p = public.as_blst_p1_affine();
        let q = hm.as_blst_p2_affine();

        // Aggregate `e(pk, hm)`
        pairing.raw_aggregate(&q, &p);

        // Finalize the pairing accumulation and verify the result
        //
        // If `finalverify()` returns `true`, it means `e(pk,hm) * e(-G1::one(),sig) == 1`. This
        // is equivalent to `e(pk,hm) == e(G1::one(),sig)`.
        pairing.commit();
        if !pairing.finalverify(None) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    fn verify(
        public: &Self::Public,
        dst: DST,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Error> {
        // Create hashed message `hm`
        let mut hm = Self::Signature::zero();
        hm.map(dst, message);

        // Verify the signature
        Self::verify_prehashed(public, &hm, signature)
    }
}

#[derive(Clone)]
pub struct MinSig {}

impl Variant for MinSig {
    type Public = G2;
    type Signature = G1;

    const PROOF_OF_POSSESSION: DST = G2_PROOF_OF_POSSESSION;
    const MESSAGE: DST = G2_MESSAGE;

    fn sign(private: &Scalar, dst: DST, message: &[u8]) -> Self::Signature {
        let mut s = Self::Signature::zero();
        s.map(dst, message);
        s.mul(private);
        s
    }

    fn verify_prehashed(
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

        // Aggregate `e(pk, hm)`
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

    fn verify(
        public: &Self::Public,
        dst: DST,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Error> {
        // Create hashed message `hm`
        let mut hm = Self::Signature::zero();
        hm.map(dst, message);

        // Verify the signature
        Self::verify_prehashed(public, &hm, signature)
    }
}
