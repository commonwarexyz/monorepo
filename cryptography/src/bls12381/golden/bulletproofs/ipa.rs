//! Inner Product Argument (IPA) for Bulletproofs.
//!
//! This implements the improved inner product argument from
//! the Bulletproofs paper (Bunz et al., 2018), Section 2.
//!
//! Given generators G, H (vectors) and a commitment P, the prover
//! demonstrates knowledge of vectors a, b such that:
//! - P = g^a · h^b · u^<a,b>
//!
//! The proof size is O(log n) group elements.
//!
//! ## Protocol (from paper Section 2.1)
//!
//! Round j (dimension n, reducing to n' = n/2):
//! 1. Prover computes:
//!    - c_L = <a[0:n'], b[n':]>
//!    - c_R = <a[n':], b[0:n']>
//!    - L = g[n':]^a[0:n'] · h[0:n']^b[n':] · u^c_L
//!    - R = g[0:n']^a[n':] · h[n':]^b[0:n'] · u^c_R
//! 2. Prover sends L, R
//! 3. Verifier sends random challenge x
//! 4. Both compute:
//!    - g' = g[0:n']^(x^-1) ∘ g[n':]^x
//!    - h' = h[0:n']^x ∘ h[n':]^(x^-1)
//!    - P' = L^(x^2) · P · R^(x^-2)
//! 5. Prover computes:
//!    - a' = a[0:n'] · x + a[n':] · x^-1
//!    - b' = b[0:n'] · x^-1 + b[n':] · x
//! 6. Recurse with (g', h', u, P'; a', b')

use super::commitment::{inner_product, msm, Generators};
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
    /// * `gens` - The generators (g, h vectors)
    /// * `u` - The generator for the inner product term
    /// * `a` - The first vector
    /// * `b` - The second vector
    ///
    /// # Returns
    ///
    /// A proof that <a, b> equals the claimed inner product, along with the value.
    pub fn create(
        transcript: &mut Transcript,
        gens: &Generators,
        u: &G1,
        mut a: Vec<Scalar>,
        mut b: Vec<Scalar>,
    ) -> (Self, Scalar) {
        assert_eq!(a.len(), b.len(), "vectors must have same length");
        assert!(a.len().is_power_of_two(), "length must be power of two");
        assert!(a.len() <= gens.size(), "vectors too large for generators");

        let n = a.len();
        let mut g_vec = gens.g_vec[..n].to_vec();
        let mut h_vec = gens.h_vec[..n].to_vec();

        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();

        // Compute and commit to the inner product
        let c = inner_product(&a, &b);
        transcript.append_scalar(b"inner_product", &c);

        // Iteratively halve the vectors
        while a.len() > 1 {
            let n_half = a.len() / 2;

            // Split vectors: [0:n'] and [n':]
            let (a_lo, a_hi) = a.split_at(n_half);
            let (b_lo, b_hi) = b.split_at(n_half);
            let (g_lo, g_hi) = g_vec.split_at(n_half);
            let (h_lo, h_hi) = h_vec.split_at(n_half);

            // Compute cross terms (per paper):
            // c_L = <a[0:n'], b[n':]> = <a_lo, b_hi>
            // c_R = <a[n':], b[0:n']> = <a_hi, b_lo>
            let c_l = inner_product(a_lo, b_hi);
            let c_r = inner_product(a_hi, b_lo);

            // L = g[n':]^a[0:n'] · h[0:n']^b[n':] · u^c_L
            //   = <a_lo, g_hi> + <b_hi, h_lo> + c_L * u
            let mut l = msm(a_lo, g_hi);
            l.add(&msm(b_hi, h_lo));
            let mut u_cl = u.clone();
            u_cl.mul(&c_l);
            l.add(&u_cl);

            // R = g[0:n']^a[n':] · h[n':]^b[0:n'] · u^c_R
            //   = <a_hi, g_lo> + <b_lo, h_hi> + c_R * u
            let mut r = msm(a_hi, g_lo);
            r.add(&msm(b_lo, h_hi));
            let mut u_cr = u.clone();
            u_cr.mul(&c_r);
            r.add(&u_cr);

            l_vec.push(l.clone());
            r_vec.push(r.clone());

            // Get challenge
            transcript.append_point(b"L", &l);
            transcript.append_point(b"R", &r);
            let x = transcript.challenge_scalar(b"x");
            let x_inv = scalar_inv(&x);

            // Fold vectors (per paper):
            // a' = a[0:n'] · x + a[n':] · x^-1 = a_lo * x + a_hi * x_inv
            // b' = b[0:n'] · x^-1 + b[n':] · x = b_lo * x_inv + b_hi * x
            a = fold_scalars_symmetric(a_lo, a_hi, &x, &x_inv);
            b = fold_scalars_symmetric(b_lo, b_hi, &x_inv, &x);

            // g' = g[0:n']^(x^-1) ∘ g[n':]^x
            // h' = h[0:n']^x ∘ h[n':]^(x^-1)
            g_vec = fold_points_symmetric(g_lo, g_hi, &x_inv, &x);
            h_vec = fold_points_symmetric(h_lo, h_hi, &x, &x_inv);
        }

        let proof = Proof {
            l_vec,
            r_vec,
            a: a[0].clone(),
            b: b[0].clone(),
        };

        (proof, c)
    }

    /// Creates an inner product argument proof with explicit generators.
    ///
    /// This variant allows passing modified generator vectors (e.g., h' = h_i * y^(-i)
    /// for R1CS proofs).
    ///
    /// # Arguments
    ///
    /// * `transcript` - Fiat-Shamir transcript
    /// * `g_vec` - The g generators
    /// * `h_vec` - The h generators (may be modified, e.g., h' for R1CS)
    /// * `u` - The generator for the inner product term
    /// * `a` - The first vector
    /// * `b` - The second vector
    pub fn create_with_gens(
        transcript: &mut Transcript,
        g_vec: &[G1],
        h_vec: &[G1],
        u: &G1,
        mut a: Vec<Scalar>,
        mut b: Vec<Scalar>,
    ) -> (Self, Scalar) {
        assert_eq!(a.len(), b.len(), "vectors must have same length");
        assert!(a.len().is_power_of_two(), "length must be power of two");
        assert_eq!(a.len(), g_vec.len(), "vector length must match generators");
        assert_eq!(a.len(), h_vec.len(), "vector length must match generators");

        let mut g_vec = g_vec.to_vec();
        let mut h_vec = h_vec.to_vec();

        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();

        // Compute and commit to the inner product
        let c = inner_product(&a, &b);
        transcript.append_scalar(b"inner_product", &c);

        // Iteratively halve the vectors
        while a.len() > 1 {
            let n_half = a.len() / 2;

            // Split vectors: [0:n'] and [n':]
            let (a_lo, a_hi) = a.split_at(n_half);
            let (b_lo, b_hi) = b.split_at(n_half);
            let (g_lo, g_hi) = g_vec.split_at(n_half);
            let (h_lo, h_hi) = h_vec.split_at(n_half);

            // Compute cross terms (per paper):
            let c_l = inner_product(a_lo, b_hi);
            let c_r = inner_product(a_hi, b_lo);

            // L = g[n':]^a[0:n'] · h[0:n']^b[n':] · u^c_L
            let mut l = msm(a_lo, g_hi);
            l.add(&msm(b_hi, h_lo));
            let mut u_cl = u.clone();
            u_cl.mul(&c_l);
            l.add(&u_cl);

            // R = g[0:n']^a[n':] · h[n':]^b[0:n'] · u^c_R
            let mut r = msm(a_hi, g_lo);
            r.add(&msm(b_lo, h_hi));
            let mut u_cr = u.clone();
            u_cr.mul(&c_r);
            r.add(&u_cr);

            l_vec.push(l.clone());
            r_vec.push(r.clone());

            // Get challenge
            transcript.append_point(b"L", &l);
            transcript.append_point(b"R", &r);
            let x = transcript.challenge_scalar(b"x");
            let x_inv = scalar_inv(&x);

            // Fold vectors
            a = fold_scalars_symmetric(a_lo, a_hi, &x, &x_inv);
            b = fold_scalars_symmetric(b_lo, b_hi, &x_inv, &x);
            g_vec = fold_points_symmetric(g_lo, g_hi, &x_inv, &x);
            h_vec = fold_points_symmetric(h_lo, h_hi, &x, &x_inv);
        }

        let proof = Proof {
            l_vec,
            r_vec,
            a: a[0].clone(),
            b: b[0].clone(),
        };

        (proof, c)
    }

    /// Verifies an inner product argument proof with explicit generators.
    ///
    /// This variant allows passing modified generator vectors.
    pub fn verify_with_gens(
        &self,
        transcript: &mut Transcript,
        g_vec: &[G1],
        h_vec: &[G1],
        u: &G1,
        p: &G1,
        c: &Scalar,
    ) -> bool {
        let n = 1 << self.l_vec.len();
        if n != g_vec.len() || n != h_vec.len() {
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

        let challenges_inv: Vec<Scalar> = challenges.iter().map(scalar_inv).collect();

        // Compute s vector for generator folding
        let s = compute_s_vec(&challenges, &challenges_inv);

        // g' = <s^-1, g>, h' = <s, h>
        let s_inv: Vec<Scalar> = s.iter().map(scalar_inv).collect();
        let g_prime = msm(&s_inv, g_vec);
        let h_prime = msm(&s, h_vec);

        // Compute P' = P + sum(x_j^2 * L_j + x_j^-2 * R_j)
        let mut p_prime = p.clone();
        for (j, (l, r)) in self.l_vec.iter().zip(self.r_vec.iter()).enumerate() {
            let mut x_sq = challenges[j].clone();
            x_sq.mul(&challenges[j]);

            let mut x_inv_sq = challenges_inv[j].clone();
            x_inv_sq.mul(&challenges_inv[j]);

            let mut l_term = l.clone();
            l_term.mul(&x_sq);
            p_prime.add(&l_term);

            let mut r_term = r.clone();
            r_term.mul(&x_inv_sq);
            p_prime.add(&r_term);
        }

        // Verify: P' = a * g' + b * h' + (a * b) * u
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

    /// Verifies an inner product argument proof.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Fiat-Shamir transcript (must match prover's)
    /// * `gens` - The generators
    /// * `u` - The generator for the inner product term
    /// * `p` - The commitment P = g^a · h^b · u^<a,b>
    /// * `c` - The claimed inner product <a, b>
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

        let challenges_inv: Vec<Scalar> = challenges.iter().map(scalar_inv).collect();

        // Compute s vector for generator folding (per paper Section 2.2)
        // s_i = product of x_j^{b(i,j)} where b(i,j) = 1 if bit j of (i-1) is 1, else -1
        // This means: if bit is set, multiply by x; else multiply by x_inv
        let s = compute_s_vec(&challenges, &challenges_inv);

        // g' = <s^-1, g> (element-wise: g_i gets multiplied by s_i^-1)
        // h' = <s, h> (element-wise: h_i gets multiplied by s_i)
        let s_inv: Vec<Scalar> = s.iter().map(scalar_inv).collect();
        let g_prime = msm(&s_inv, &gens.g_vec[..n]);
        let h_prime = msm(&s, &gens.h_vec[..n]);

        // Compute P' = P + sum(x_j^2 * L_j + x_j^-2 * R_j) per paper
        let mut p_prime = p.clone();
        for (j, (l, r)) in self.l_vec.iter().zip(self.r_vec.iter()).enumerate() {
            let mut x_sq = challenges[j].clone();
            x_sq.mul(&challenges[j]);

            let mut x_inv_sq = challenges_inv[j].clone();
            x_inv_sq.mul(&challenges_inv[j]);

            let mut l_term = l.clone();
            l_term.mul(&x_sq);
            p_prime.add(&l_term);

            let mut r_term = r.clone();
            r_term.mul(&x_inv_sq);
            p_prime.add(&r_term);
        }

        // Verify: P' = a * g' + b * h' + (a * b) * u
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

/// Folds two scalar vectors with symmetric scaling: result[i] = lo[i] * x_lo + hi[i] * x_hi
fn fold_scalars_symmetric(lo: &[Scalar], hi: &[Scalar], x_lo: &Scalar, x_hi: &Scalar) -> Vec<Scalar> {
    lo.iter()
        .zip(hi.iter())
        .map(|(l, h)| {
            let mut result = l.clone();
            result.mul(x_lo);
            let mut h_term = h.clone();
            h_term.mul(x_hi);
            result.add(&h_term);
            result
        })
        .collect()
}

/// Folds two point vectors with symmetric scaling: result[i] = lo[i] * x_lo + hi[i] * x_hi
fn fold_points_symmetric(lo: &[G1], hi: &[G1], x_lo: &Scalar, x_hi: &Scalar) -> Vec<G1> {
    lo.iter()
        .zip(hi.iter())
        .map(|(l, h)| {
            let mut result = l.clone();
            result.mul(x_lo);
            let mut h_term = h.clone();
            h_term.mul(x_hi);
            result.add(&h_term);
            result
        })
        .collect()
}

/// Computes the s vector for verification (per paper Section 2.2).
///
/// For each index i, s[i] = product over all rounds j of:
///   x_j^-1 if bit j of i is set
///   x_j if bit j of i is not set
///
/// This is derived from tracing through the symmetric folding:
/// g' = g_lo * x^-1 + g_hi * x, so g_hi gets x and g_lo gets x^-1.
/// After all rounds, the coefficient of g_i has x_j if in "lo" half (bit not set),
/// and x_j^-1 if in "hi" half (bit set).
fn compute_s_vec(challenges: &[Scalar], challenges_inv: &[Scalar]) -> Vec<Scalar> {
    let k = challenges.len();
    let n = 1 << k;
    let mut s = vec![Scalar::one(); n];

    for i in 0..n {
        for j in 0..k {
            // Bit position: j=0 is MSB (first challenge), j=k-1 is LSB (last challenge)
            let bit_pos = k - 1 - j;
            if (i >> bit_pos) & 1 == 1 {
                // In "hi" half for this round: multiply by x_inv
                s[i].mul(&challenges_inv[j]);
            } else {
                // In "lo" half for this round: multiply by x
                s[i].mul(&challenges[j]);
            }
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::golden::bulletproofs::commitment::hash_to_g1_with_label;
    use crate::bls12381::primitives::group::Element;

    fn random_scalar(seed: u64) -> Scalar {
        Scalar::map(b"TEST_SCALAR", &seed.to_le_bytes())
    }

    #[test]
    fn test_ipa_basic() {
        let n = 4;
        let gens = Generators::new(n);
        let u = hash_to_g1_with_label(b"IPA", b"U");

        // Create test vectors
        let a: Vec<Scalar> = (0..n as u64).map(|i| random_scalar(i)).collect();
        let b: Vec<Scalar> = (0..n as u64).map(|i| random_scalar(i + 100)).collect();

        // Compute commitment P = <a, g> + <b, h> + <a,b> * u
        let c = inner_product(&a, &b);
        let mut p = msm(&a, &gens.g_vec[..n]);
        p.add(&msm(&b, &gens.h_vec[..n]));
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
        let n = 16;
        let gens = Generators::new(n);
        let u = hash_to_g1_with_label(b"IPA", b"U");

        let a: Vec<Scalar> = (0..n as u64).map(|i| random_scalar(i * 7)).collect();
        let b: Vec<Scalar> = (0..n as u64).map(|i| random_scalar(i * 11 + 50)).collect();

        let c = inner_product(&a, &b);
        let mut p = msm(&a, &gens.g_vec[..n]);
        p.add(&msm(&b, &gens.h_vec[..n]));
        let mut u_c = u.clone();
        u_c.mul(&c);
        p.add(&u_c);

        let mut prover_transcript = Transcript::new(b"test_ipa");
        let (proof, claimed_c) = Proof::create(&mut prover_transcript, &gens, &u, a, b);
        assert_eq!(c, claimed_c);

        let mut verifier_transcript = Transcript::new(b"test_ipa");
        assert!(proof.verify(&mut verifier_transcript, &gens, &u, &p, &c));
    }

    #[test]
    fn test_ipa_wrong_inner_product() {
        let n = 4;
        let gens = Generators::new(n);
        let u = hash_to_g1_with_label(b"IPA", b"U");

        let a: Vec<Scalar> = (0..n as u64).map(|i| random_scalar(i)).collect();
        let b: Vec<Scalar> = (0..n as u64).map(|i| random_scalar(i + 100)).collect();

        let c = inner_product(&a, &b);
        let mut p = msm(&a, &gens.g_vec[..n]);
        p.add(&msm(&b, &gens.h_vec[..n]));
        let mut u_c = u.clone();
        u_c.mul(&c);
        p.add(&u_c);

        let mut prover_transcript = Transcript::new(b"test_ipa");
        let (proof, _) = Proof::create(&mut prover_transcript, &gens, &u, a, b);

        // Try to verify with wrong inner product
        let mut wrong_c = c.clone();
        wrong_c.add(&Scalar::one());

        let mut verifier_transcript = Transcript::new(b"test_ipa");
        assert!(!proof.verify(&mut verifier_transcript, &gens, &u, &p, &wrong_c));
    }
}
