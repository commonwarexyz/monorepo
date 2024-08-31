//! Digital signatures over the BLS12-381 curve.

use super::{
    group::{self, equal, Element, Point, Share},
    poly::{self, Eval},
    Error,
};
use rand::RngCore;

/// Returns a new keypair derived from the provided randomness.
pub fn keypair<R: RngCore>(rng: &mut R) -> (group::Private, group::Public) {
    let private = group::Private::rand(rng);
    let mut public = group::Public::one();
    public.mul(&private);
    (private, public)
}

/// Signs the provided message with the private key.
///
/// The message is hashed according to RFC 9380.
///
/// # Determinism
///
/// Signatures produced by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn sign(private: &group::Private, msg: &[u8]) -> group::Signature {
    let mut s = group::Signature::zero();
    s.map(msg);
    s.mul(private);
    s
}

/// Verifies the signature with the provided public key.
pub fn verify(
    public: &group::Public,
    msg: &[u8],
    signature: &group::Signature,
) -> Result<(), Error> {
    let mut hm = group::Signature::zero();
    hm.map(msg);
    if !equal(public, signature, &hm) {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

/// Signs the provided message with the key share.
pub fn partial_sign(private: &Share, msg: &[u8]) -> Eval<group::Signature> {
    let sig = sign(&private.private, msg);
    Eval {
        value: sig,
        index: private.index,
    }
}

/// Verifies the partial signature against the public polynomial.
pub fn partial_verify(
    public: &poly::Public,
    msg: &[u8],
    partial: &Eval<group::Signature>,
) -> Result<(), Error> {
    let public = public.evaluate(partial.index);
    verify(&public.value, msg, &partial.value)
}

/// Aggregates the partial signatures into a final signature.
///
/// # Determinism
///
/// Signatures recovered by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn aggregate(
    threshold: u32,
    partials: Vec<Eval<group::Signature>>,
) -> Result<group::Signature, Error> {
    let sigs = partials.len() as u32;
    if threshold > sigs {
        return Err(Error::NotEnoughPartialSignatures(threshold, sigs));
    }
    poly::Signature::recover(threshold, partials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{dkg::ops::generate_shares, primitives::group::DST_G2};
    use blst::BLST_ERROR;
    use rand::prelude::*;

    /// Verify that a given signature is valid according to `blst`.
    fn blst_verify(
        public: &group::Public,
        msg: &[u8],
        signature: &group::Signature,
    ) -> Result<(), BLST_ERROR> {
        let public = blst::min_pk::PublicKey::from_bytes(public.serialize().as_slice()).unwrap();
        let signature =
            blst::min_pk::Signature::from_bytes(signature.serialize().as_slice()).unwrap();
        match signature.verify(true, msg, DST_G2, &[], &public, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    #[test]
    fn test_single_compatibility() {
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let sig = sign(&private, msg);
        verify(&public, msg, &sig).expect("signature should be valid");
        blst_verify(&public, msg, &sig).expect("signature should be valid");
    }

    #[test]
    fn test_threshold_compatibility() {
        let (n, t) = (5, 4);
        let (public, shares) = generate_shares(None, n, t);
        let msg = &[1, 9, 6, 9];
        let partials: Vec<_> = shares.iter().map(|s| partial_sign(s, msg)).collect();
        for p in &partials {
            partial_verify(&public, msg, p).expect("signature should be valid");
        }
        let threshold_sig = aggregate(t, partials).unwrap();
        let threshold_pub = poly::public(&public);
        verify(&threshold_pub, msg, &threshold_sig).expect("signature should be valid");
        blst_verify(&threshold_pub, msg, &threshold_sig).expect("signature should be valid");
    }
}
