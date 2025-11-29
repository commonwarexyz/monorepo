//! Inner Product Argument (IPA) for Bulletproofs.
//!
//! This implements the logarithmic-size inner product argument from
//! the Bulletproofs paper (Bunz et al., 2018).
//!
//! Given generators G, H (vectors) and a commitment P, the prover
//! demonstrates knowledge of vectors a, b such that:
//! - P = <a, G> + <b, H> + <a, b> * U
//! - <a, b> = c (the claimed inner product)
//!
//! The proof size is O(log n) group elements.

use super::commitment::{hash_to_g1_with_label, inner_product, msm, Generators};
use super::transcript::Transcript;
use crate::bls12381::primitives::group::{Element, Scalar, G1};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};

/// An inner product argument proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Left fold points (one per round).
    pub l_vec: Vec<G1>,
    /// Right fold points (one per round).
    pub r_vec: Vec<G1>,
    /// Final scalar a.
    pub a: Scalar,
    /// Final scalar b.
    pub b: Scalar,
}

impl Write for Proof {
    fn write(&self, buf: &mut impl BufMut) {
        // Write number of rounds
        buf.put_u32_le(self.l_vec.len() as u32);
        for l in &self.l_vec {
            l.write(buf);
        }
        for r in &self.r_vec {
            r.write(buf);
        }
        self.a.write(buf);
        self.b.write(buf);
    }
}

impl Read for Proof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let rounds = buf.get_u32_le() as usize;
        if rounds > 32 {
            return Err(CodecError::Invalid("IPA", "too many rounds"));
        }

        let mut l_vec = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            l_vec.push(G1::read(buf)?);
        }

        let mut r_vec = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            r_vec.push(G1::read(buf)?);
        }

        let a = Scalar::read(buf)?;
        let b = Scalar::read(buf)?;

        Ok(Self { l_vec, r_vec, a, b })
    }
}

impl Proof {
    /// Computes the encoded size of a proof with the given number of rounds.
    pub fn size_for_rounds(rounds: usize) -> usize {
        4 + rounds * G1::SIZE * 2 + Scalar::SIZE * 2
    }

    /// Creates an inner product argument proof.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Fiat-Shamir transcript
    /// * `gens` - The generators (G, H vectors and blinding)
    /// * `u` - The generator for the inner product term
    /// * `a` - The first vector
    /// * `b` - The second vector
    ///
    /// # Returns
    ///
    /// A proof that <a, b> equals the inner product, along with the claimed value.
    pub fn create(
        transcript: &mut Transcript,
        gens: &Generators,
        u: &G1,
        mut a: Vec<Scalar>,
        mut b: Vec<Scalar>,
    ) -> (Self, Scalar) {
        assert_eq!(a.len(), b.len(), "vectors must have same length");
        assert!(a.len().is_power_of_two(), "length must be power of two");
        assert!(
            a.len() <= gens.size(),
            "vectors too large for generators"
        );

        let mut g_vec = gens.g_vec[..a.len()].to_vec();
        let mut h_vec = gens.h_vec[..a.len()].to_vec();

        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();

        // Compute and commit to the inner product
        let c = inner_product(&a, &b);
        transcript.append_scalar(b"inner_product", &c);

        // Iteratively halve the vectors
        while a.len() > 1 {
            let n = a.len() / 2;

            // Split vectors
            let (a_lo, a_hi) = a.split_at(n);
            let (b_lo, b_hi) = b.split_at(n);
            let (g_lo, g_hi) = g_vec.split_at(n);
            let (h_lo, h_hi) = h_vec.split_at(n);

            // Compute cross terms
            let c_l = inner_product(a_hi, b_lo);
            let c_r = inner_product(a_lo, b_hi);

            // Compute L and R points
            // L = <a_hi, G_lo> + <b_lo, H_hi> + c_L * U
            let mut l = msm(a_hi, g_lo);
            l.add(&msm(b_lo, h_hi));
            let mut u_cl = u.clone();
            u_cl.mul(&c_l);
            l.add(&u_cl);

            // R = <a_lo, G_hi> + <b_hi, H_lo> + c_R * U
            let mut r = msm(a_lo, g_hi);
            r.add(&msm(b_hi, h_lo));
            let mut u_cr = u.clone();
            u_cr.mul(&c_r);
            r.add(&u_cr);

            l_vec.push(l.clone());
            r_vec.push(r.clone());

            // Get challenge
            transcript.append_point(b"L", &l);
            transcript.append_point(b"R", &r);
            let x = transcript.challenge_scalar(b"x");

            // Compute x_inv
            let x_inv = scalar_inv(&x);

            // Fold vectors
            a = fold_scalars(a_lo, a_hi, &x);
            b = fold_scalars(b_lo, b_hi, &x_inv);
            g_vec = fold_points(g_lo, g_hi, &x_inv);
            h_vec = fold_points(h_lo, h_hi, &x);
        }

        let proof = Proof {
            l_vec,
            r_vec,
            a: a[0].clone(),
            b: b[0].clone(),
        };

        (proof, c)
    }

    /// Verifies an inner product argument proof.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Fiat-Shamir transcript (must match prover's)
    /// * `gens` - The generators
    /// * `u` - The generator for the inner product term
    /// * `p` - The commitment P = <a, G> + <b, H> + c * U
    /// * `c` - The claimed inner product value
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        gens: &Generators,
        u: &G1,
        p: &G1,
        c: &Scalar,
    ) -> bool {
        let n = 1 << self.l_vec.len();
        if n > gens.size() {
            return false;
        }

        // Commit to the inner product
        transcript.append_scalar(b"inner_product", c);

        // Collect challenges
        let mut challenges = Vec::with_capacity(self.l_vec.len());
        for (l, r) in self.l_vec.iter().zip(self.r_vec.iter()) {
            transcript.append_point(b"L", l);
            transcript.append_point(b"R", r);
            challenges.push(transcript.challenge_scalar(b"x"));
        }

        // Compute challenge products for each index
        let challenges_inv: Vec<Scalar> = challenges.iter().map(scalar_inv).collect();

        // Compute the final generator g' and h'
        let s = compute_s_vec(&challenges);
        let s_inv: Vec<Scalar> = s.iter().map(scalar_inv).collect();

        // g' = <s_inv, G>
        let g_prime = msm(&s_inv, &gens.g_vec[..n]);
        // h' = <s, H>
        let h_prime = msm(&s, &gens.h_vec[..n]);

        // Compute the expected commitment
        // P' = P + sum(x_i * L_i + x_i^{-1} * R_i)
        // Note: Uses linear challenges, not squared, based on our L/R definitions
        let mut p_prime = p.clone();
        for (i, (l, r)) in self.l_vec.iter().zip(self.r_vec.iter()).enumerate() {
            let mut l_term = l.clone();
            l_term.mul(&challenges[i]); // x * L
            p_prime.add(&l_term);

            let mut r_term = r.clone();
            r_term.mul(&challenges_inv[i]); // x^{-1} * R
            p_prime.add(&r_term);
        }

        // Verify: P' = a * g' + b * h' + (a * b) * U
        let mut expected = g_prime;
        expected.mul(&self.a);

        let mut h_term = h_prime;
        h_term.mul(&self.b);
        expected.add(&h_term);

        let mut ab = self.a.clone();
        ab.mul(&self.b);
        let mut u_term = u.clone();
        u_term.mul(&ab);
        expected.add(&u_term);

        p_prime == expected
    }
}

/// Computes the multiplicative inverse of a scalar.
fn scalar_inv(s: &Scalar) -> Scalar {
    s.inverse().expect("scalar should be non-zero")
}

/// Folds two scalar vectors using challenge x:
/// result[i] = lo[i] + x * hi[i]
fn fold_scalars(lo: &[Scalar], hi: &[Scalar], x: &Scalar) -> Vec<Scalar> {
    lo.iter()
        .zip(hi.iter())
        .map(|(l, h)| {
            let mut result = h.clone();
            result.mul(x);
            result.add(l);
            result
        })
        .collect()
}

/// Folds two point vectors using challenge x:
/// result[i] = lo[i] + x * hi[i]
fn fold_points(lo: &[G1], hi: &[G1], x: &Scalar) -> Vec<G1> {
    lo.iter()
        .zip(hi.iter())
        .map(|(l, h)| {
            let mut result = h.clone();
            result.mul(x);
            result.add(l);
            result
        })
        .collect()
}

/// Computes the s vector for verification.
///
/// For the IPA verification, we need:
/// - g' = <s_inv, G> where s_inv[i] is the product of x_j^{-1} for bits set in i
/// - h' = <s, H> where s[i] is the product of x_j for bits set in i
///
/// So s[i] = product of x_j for each bit j that is set in i.
fn compute_s_vec(challenges: &[Scalar]) -> Vec<Scalar> {
    let n = 1 << challenges.len();
    let mut s = vec![Scalar::one(); n];

    for (j, x) in challenges.iter().enumerate() {
        // The bit position corresponding to challenge j
        // First challenge (j=0) corresponds to MSB, last challenge to LSB
        let bit_pos = challenges.len() - 1 - j;
        for i in 0..n {
            // If bit at position bit_pos of i is set, multiply by x
            if (i >> bit_pos) & 1 == 1 {
                s[i].mul(x);
            }
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_ipa_basic() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 4;

        let gens = Generators::new(n);
        let u = hash_to_g1_with_label(b"IPA", b"U");

        // Create random vectors
        let a: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();
        let b: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();

        // Compute commitment P = <a, G> + <b, H> + <a,b> * U
        let c = inner_product(&a, &b);
        let mut p = gens.commit_inner_product(&a, &b);
        let mut u_c = u.clone();
        u_c.mul(&c);
        p.add(&u_c);

        // Create proof
        let mut prover_transcript = Transcript::new(b"test_ipa");
        let (proof, claimed_c) = Proof::create(&mut prover_transcript, &gens, &u, a, b);

        assert_eq!(c, claimed_c);

        // Verify proof
        let mut verifier_transcript = Transcript::new(b"test_ipa");
        assert!(proof.verify(&mut verifier_transcript, &gens, &u, &p, &c));
    }

    #[test]
    fn test_ipa_larger() {
        let mut rng = StdRng::seed_from_u64(123);
        let n = 16;

        let gens = Generators::new(n);
        let u = hash_to_g1_with_label(b"IPA", b"U");

        let a: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();
        let b: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();

        let c = inner_product(&a, &b);
        let mut p = gens.commit_inner_product(&a, &b);
        let mut u_c = u.clone();
        u_c.mul(&c);
        p.add(&u_c);

        let mut prover_transcript = Transcript::new(b"test_ipa");
        let (proof, _) = Proof::create(&mut prover_transcript, &gens, &u, a, b);

        let mut verifier_transcript = Transcript::new(b"test_ipa");
        assert!(proof.verify(&mut verifier_transcript, &gens, &u, &p, &c));
    }

    #[test]
    fn test_ipa_wrong_inner_product() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 4;

        let gens = Generators::new(n);
        let u = hash_to_g1_with_label(b"IPA", b"U");

        let a: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();
        let b: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();

        let c = inner_product(&a, &b);
        let mut p = gens.commit_inner_product(&a, &b);
        let mut u_c = u.clone();
        u_c.mul(&c);
        p.add(&u_c);

        let mut prover_transcript = Transcript::new(b"test_ipa");
        let (proof, _) = Proof::create(&mut prover_transcript, &gens, &u, a, b);

        // Try to verify with wrong inner product
        let wrong_c = Scalar::from_rand(&mut rng);
        let mut verifier_transcript = Transcript::new(b"test_ipa");
        assert!(!proof.verify(&mut verifier_transcript, &gens, &u, &p, &wrong_c));
    }
}
