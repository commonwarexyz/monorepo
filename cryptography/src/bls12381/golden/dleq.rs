//! Discrete Log Equality (DLEQ) proofs for the Golden DKG protocol.
//!
//! A DLEQ proof demonstrates that two group elements share the same discrete logarithm
//! relative to different base points. Specifically, given points `G`, `H`, `A`, `B`,
//! a DLEQ proof shows that `log_G(A) = log_H(B)`.
//!
//! This is used in Golden DKG to prove that the Diffie-Hellman shared secret
//! `S_ij = sk_i * PK_j` was computed correctly, where:
//! - `G` is the group generator
//! - `PK_i = sk_i * G` is the prover's public key
//! - `PK_j` is the recipient's public key
//! - `S_ij = sk_i * PK_j` is the shared secret
//!
//! The proof shows `log_G(PK_i) = log_{PK_j}(S_ij)`, i.e., that the same secret key
//! was used to derive both the public key and the shared secret.
//!
//! # Construction
//!
//! The proof is a non-interactive Schnorr-style sigma protocol using Fiat-Shamir:
//!
//! 1. Prover chooses random `k` and computes `R1 = k*G`, `R2 = k*H`
//! 2. Challenge `c = H(G, H, A, B, R1, R2)`
//! 3. Response `s = k + c*x` where `x` is the secret
//! 4. Proof is `(c, s)`
//!
//! Verification checks:
//! - `s*G = R1 + c*A`
//! - `s*H = R2 + c*B`
//!
//! Which is equivalent to checking:
//! - `R1 = s*G - c*A`
//! - `R2 = s*H - c*B`
//! - `c = H(G, H, A, B, R1, R2)`

use super::DST_DLEQ_CHALLENGE;
use crate::bls12381::primitives::group::{Element, Point, Scalar, G1};
use crate::Hasher;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use rand_core::CryptoRngCore;

/// A DLEQ proof demonstrating equality of discrete logarithms.
///
/// Given points `G`, `H`, `A = x*G`, `B = x*H`, this proof demonstrates
/// that `log_G(A) = log_H(B) = x` without revealing `x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The challenge scalar.
    pub challenge: Scalar,
    /// The response scalar.
    pub response: Scalar,
}

impl Proof {
    /// Creates a new DLEQ proof.
    ///
    /// Proves that `log_G(A) = log_H(B) = secret`.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `secret` - The secret exponent `x` such that `A = x*G` and `B = x*H`
    /// * `g` - First base point
    /// * `h` - Second base point
    /// * `a` - First public point (`A = secret * G`)
    /// * `b` - Second public point (`B = secret * H`)
    ///
    /// # Panics
    ///
    /// This function will panic if the proof generation fails (should not happen
    /// with valid inputs).
    pub fn create<R: CryptoRngCore>(
        rng: &mut R,
        secret: &Scalar,
        g: &G1,
        h: &G1,
        a: &G1,
        b: &G1,
    ) -> Self {
        // Choose random nonce
        let k = Scalar::from_rand(rng);

        // Compute commitments R1 = k*G, R2 = k*H
        let mut r1 = *g;
        r1.mul(&k);
        let mut r2 = *h;
        r2.mul(&k);

        // Compute challenge
        let challenge = compute_challenge(g, h, a, b, &r1, &r2);

        // Compute response: s = k + c*x
        let mut response = challenge.clone();
        response.mul(secret);
        response.add(&k);

        Self {
            challenge,
            response,
        }
    }

    /// Verifies the DLEQ proof.
    ///
    /// Checks that `log_G(A) = log_H(B)`.
    ///
    /// # Arguments
    ///
    /// * `g` - First base point
    /// * `h` - Second base point
    /// * `a` - First public point
    /// * `b` - Second public point
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify(&self, g: &G1, h: &G1, a: &G1, b: &G1) -> bool {
        // Reconstruct R1 = s*G - c*A and R2 = s*H - c*B
        // We use multi-scalar multiplication for efficiency: R = s*G + (-c)*A

        let neg_c = negate_scalar(&self.challenge);

        let r1 = G1::msm(&[*g, *a], &[self.response.clone(), neg_c.clone()]);

        // Compute R2 = s*H + (-c)*B
        let r2 = G1::msm(&[*h, *b], &[self.response.clone(), neg_c]);

        // Recompute challenge and verify
        let expected_challenge = compute_challenge(g, h, a, b, &r1, &r2);

        self.challenge == expected_challenge
    }
}

/// Negates a scalar (computes -x mod r).
fn negate_scalar(x: &Scalar) -> Scalar {
    let mut result = Scalar::zero();
    result.sub(x);
    result
}

/// Computes the Fiat-Shamir challenge for a DLEQ proof.
fn compute_challenge(g: &G1, h: &G1, a: &G1, b: &G1, r1: &G1, r2: &G1) -> Scalar {
    let mut hasher = crate::Sha256::new();
    hasher.update(DST_DLEQ_CHALLENGE);
    hasher.update(&g.encode());
    hasher.update(&h.encode());
    hasher.update(&a.encode());
    hasher.update(&b.encode());
    hasher.update(&r1.encode());
    hasher.update(&r2.encode());
    let digest = hasher.finalize();

    // Map the hash to a scalar
    Scalar::map(DST_DLEQ_CHALLENGE, digest.as_ref())
}

/// Batch verifies multiple DLEQ proofs for the same prover public key.
///
/// This is useful in Golden DKG where a contributor provides DLEQ proofs
/// for each recipient, all sharing the same secret key.
///
/// # Arguments
///
/// * `g` - The group generator
/// * `prover_pk` - The prover's public key (`A = sk * G`)
/// * `proofs` - Iterator of `(recipient_pk, shared_secret, proof)` tuples
///
/// # Returns
///
/// `Ok(())` if all proofs are valid, `Err(recipient_index)` if a proof fails.
pub fn batch_verify<'a, I>(
    g: &G1,
    prover_pk: &G1,
    proofs: I,
) -> Result<(), u32>
where
    I: IntoIterator<Item = (u32, &'a G1, &'a G1, &'a Proof)>,
{
    for (recipient_idx, recipient_pk, shared_secret, proof) in proofs {
        if !proof.verify(g, recipient_pk, prover_pk, shared_secret) {
            return Err(recipient_idx);
        }
    }
    Ok(())
}

impl Write for Proof {
    fn write(&self, buf: &mut impl BufMut) {
        self.challenge.write(buf);
        self.response.write(buf);
    }
}

impl Read for Proof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let challenge = Scalar::read(buf)?;
        let response = Scalar::read(buf)?;
        Ok(Self {
            challenge,
            response,
        })
    }
}

impl FixedSize for Proof {
    const SIZE: usize = Scalar::SIZE * 2;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_dleq_proof_valid() {
        let mut rng = StdRng::seed_from_u64(42);

        // Create secret and points
        let secret = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut h = G1::one();
        let h_secret = Scalar::from_rand(&mut rng);
        h.mul(&h_secret);

        // Compute A = secret * G and B = secret * H
        let mut a = g.clone();
        a.mul(&secret);
        let mut b = h.clone();
        b.mul(&secret);

        // Create and verify proof
        let proof = Proof::create(&mut rng, &secret, &g, &h, &a, &b);
        assert!(proof.verify(&g, &h, &a, &b));
    }

    #[test]
    fn test_dleq_proof_wrong_secret() {
        let mut rng = StdRng::seed_from_u64(42);

        // Create secrets and points
        let secret1 = Scalar::from_rand(&mut rng);
        let secret2 = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut h = G1::one();
        let h_secret = Scalar::from_rand(&mut rng);
        h.mul(&h_secret);

        // Compute A = secret1 * G and B = secret2 * H (different secrets!)
        let mut a = g.clone();
        a.mul(&secret1);
        let mut b = h.clone();
        b.mul(&secret2);

        // Create proof with secret1
        let proof = Proof::create(&mut rng, &secret1, &g, &h, &a, &b);

        // Proof should fail because B was computed with secret2
        assert!(!proof.verify(&g, &h, &a, &b));
    }

    #[test]
    fn test_dleq_proof_tampered_challenge() {
        let mut rng = StdRng::seed_from_u64(42);

        // Create secret and points
        let secret = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut h = G1::one();
        let h_secret = Scalar::from_rand(&mut rng);
        h.mul(&h_secret);

        let mut a = g.clone();
        a.mul(&secret);
        let mut b = h.clone();
        b.mul(&secret);

        // Create valid proof
        let mut proof = Proof::create(&mut rng, &secret, &g, &h, &a, &b);

        // Tamper with challenge
        proof.challenge = Scalar::from_rand(&mut rng);

        // Verification should fail
        assert!(!proof.verify(&g, &h, &a, &b));
    }

    #[test]
    fn test_dleq_proof_tampered_response() {
        let mut rng = StdRng::seed_from_u64(42);

        // Create secret and points
        let secret = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut h = G1::one();
        let h_secret = Scalar::from_rand(&mut rng);
        h.mul(&h_secret);

        let mut a = g.clone();
        a.mul(&secret);
        let mut b = h.clone();
        b.mul(&secret);

        // Create valid proof
        let mut proof = Proof::create(&mut rng, &secret, &g, &h, &a, &b);

        // Tamper with response
        proof.response = Scalar::from_rand(&mut rng);

        // Verification should fail
        assert!(!proof.verify(&g, &h, &a, &b));
    }

    #[test]
    fn test_dleq_proof_codec_roundtrip() {
        use commonware_codec::DecodeExt;

        let mut rng = StdRng::seed_from_u64(42);

        let secret = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut h = G1::one();
        h.mul(&Scalar::from_rand(&mut rng));
        let mut a = g.clone();
        a.mul(&secret);
        let mut b = h.clone();
        b.mul(&secret);

        let proof = Proof::create(&mut rng, &secret, &g, &h, &a, &b);
        let encoded = proof.encode();
        let decoded = Proof::decode(encoded).unwrap();

        assert_eq!(proof, decoded);
        assert!(decoded.verify(&g, &h, &a, &b));
    }

    #[test]
    fn test_batch_verify_all_valid() {
        let mut rng = StdRng::seed_from_u64(42);

        // Prover's key
        let secret = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut prover_pk = g.clone();
        prover_pk.mul(&secret);

        // Multiple recipients
        let n = 5;
        let mut proofs_data = Vec::new();

        for i in 0..n {
            // Recipient's public key
            let recipient_secret = Scalar::from_rand(&mut rng);
            let mut recipient_pk = g.clone();
            recipient_pk.mul(&recipient_secret);

            // Shared secret
            let mut shared_secret = recipient_pk.clone();
            shared_secret.mul(&secret);

            // Create proof
            let proof = Proof::create(&mut rng, &secret, &g, &recipient_pk, &prover_pk, &shared_secret);

            proofs_data.push((i as u32, recipient_pk, shared_secret, proof));
        }

        // Batch verify
        let result = batch_verify(
            &g,
            &prover_pk,
            proofs_data
                .iter()
                .map(|(idx, rpk, ss, proof)| (*idx, rpk, ss, proof)),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_batch_verify_one_invalid() {
        let mut rng = StdRng::seed_from_u64(42);

        // Prover's key
        let secret = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut prover_pk = g.clone();
        prover_pk.mul(&secret);

        // Multiple recipients
        let n = 5;
        let bad_idx = 2;
        let mut proofs_data = Vec::new();

        for i in 0..n {
            let recipient_secret = Scalar::from_rand(&mut rng);
            let mut recipient_pk = g.clone();
            recipient_pk.mul(&recipient_secret);

            let mut shared_secret = recipient_pk.clone();
            if i == bad_idx {
                // Use wrong secret for bad proof
                let wrong_secret = Scalar::from_rand(&mut rng);
                shared_secret.mul(&wrong_secret);
            } else {
                shared_secret.mul(&secret);
            }

            // Create proof (will be invalid for bad_idx because shared_secret is wrong)
            let proof = Proof::create(&mut rng, &secret, &g, &recipient_pk, &prover_pk, &shared_secret);

            proofs_data.push((i as u32, recipient_pk, shared_secret, proof));
        }

        // Batch verify should fail at bad_idx
        let result = batch_verify(
            &g,
            &prover_pk,
            proofs_data
                .iter()
                .map(|(idx, rpk, ss, proof)| (*idx, rpk, ss, proof)),
        );
        assert_eq!(result, Err(bad_idx as u32));
    }
}
