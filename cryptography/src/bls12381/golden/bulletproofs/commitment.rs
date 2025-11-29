//! Pedersen commitments for Bulletproofs.
//!
//! Provides vector Pedersen commitments used in the inner product argument.

use crate::bls12381::primitives::group::{Element, Point, Scalar, G1};

/// Generators for Pedersen commitments.
///
/// For a vector commitment to (a_1, ..., a_n) with blinding r, we compute:
/// C = r * H + sum(a_i * G_i)
#[derive(Clone)]
pub struct Generators {
    /// The blinding generator H.
    pub h: G1,
    /// The vector generators G_1, ..., G_n.
    pub g_vec: Vec<G1>,
    /// Additional vector generators for inner product arguments.
    pub h_vec: Vec<G1>,
}

impl Generators {
    /// Creates generators for the given vector size.
    ///
    /// Generators are derived deterministically using hash-to-curve.
    pub fn new(size: usize) -> Self {
        let h = hash_to_generator(b"BULLETPROOFS_H");

        let g_vec: Vec<G1> = (0..size)
            .map(|i| {
                let mut label = b"BULLETPROOFS_G_".to_vec();
                label.extend_from_slice(&(i as u32).to_le_bytes());
                hash_to_generator(&label)
            })
            .collect();

        let h_vec: Vec<G1> = (0..size)
            .map(|i| {
                let mut label = b"BULLETPROOFS_H_VEC_".to_vec();
                label.extend_from_slice(&(i as u32).to_le_bytes());
                hash_to_generator(&label)
            })
            .collect();

        Self { h, g_vec, h_vec }
    }

    /// Returns the size of the generators.
    pub fn size(&self) -> usize {
        self.g_vec.len()
    }

    /// Commits to a vector of scalars with a blinding factor.
    ///
    /// Computes: C = blinding * H + sum(values[i] * G[i])
    pub fn commit(&self, values: &[Scalar], blinding: &Scalar) -> G1 {
        assert!(
            values.len() <= self.g_vec.len(),
            "too many values for generators"
        );

        let mut result = self.h.clone();
        result.mul(blinding);

        for (v, g) in values.iter().zip(self.g_vec.iter()) {
            let mut term = g.clone();
            term.mul(v);
            result.add(&term);
        }

        result
    }

    /// Computes an inner product commitment for vectors a and b.
    ///
    /// Computes: P = sum(a[i] * G[i]) + sum(b[i] * H[i])
    pub fn commit_inner_product(&self, a: &[Scalar], b: &[Scalar]) -> G1 {
        assert_eq!(a.len(), b.len(), "vectors must have same length");
        assert!(
            a.len() <= self.g_vec.len(),
            "vectors too large for generators"
        );

        let mut result = G1::zero();

        for (ai, gi) in a.iter().zip(self.g_vec.iter()) {
            let mut term = gi.clone();
            term.mul(ai);
            result.add(&term);
        }

        for (bi, hi) in b.iter().zip(self.h_vec.iter()) {
            let mut term = hi.clone();
            term.mul(bi);
            result.add(&term);
        }

        result
    }
}

/// Domain separation tag for Bulletproofs generators.
const DST_BULLETPROOFS: &[u8] = b"GOLDEN_BULLETPROOFS_V1";

/// Derives a generator point from a label using hash-to-curve.
fn hash_to_generator(label: &[u8]) -> G1 {
    let mut point = G1::zero();
    point.map(DST_BULLETPROOFS, label);
    point
}

/// Hash-to-curve function for G1 with a sub-label.
///
/// The DST must be a static string. The sub-label is combined with
/// the message for domain separation within that DST.
pub fn hash_to_g1_with_label(sub_label: &[u8], msg: &[u8]) -> G1 {
    let mut combined = sub_label.to_vec();
    combined.extend_from_slice(msg);
    let mut point = G1::zero();
    point.map(DST_BULLETPROOFS, &combined);
    point
}

/// Computes the inner product of two scalar vectors.
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len(), "vectors must have same length");

    let mut result = Scalar::zero();
    for (ai, bi) in a.iter().zip(b.iter()) {
        let mut term = ai.clone();
        term.mul(bi);
        result.add(&term);
    }
    result
}

/// Computes a multi-scalar multiplication: sum(scalars[i] * points[i]).
pub fn msm(scalars: &[Scalar], points: &[G1]) -> G1 {
    assert_eq!(scalars.len(), points.len(), "mismatched lengths");

    let mut result = G1::zero();
    for (s, p) in scalars.iter().zip(points.iter()) {
        let mut term = p.clone();
        term.mul(s);
        result.add(&term);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_generators_deterministic() {
        let g1 = Generators::new(8);
        let g2 = Generators::new(8);

        assert_eq!(g1.h, g2.h);
        assert_eq!(g1.g_vec, g2.g_vec);
        assert_eq!(g1.h_vec, g2.h_vec);
    }

    #[test]
    fn test_commitment_hiding() {
        let gens = Generators::new(4);
        let mut rng = StdRng::seed_from_u64(42);

        let values: Vec<Scalar> = (0..4).map(|_| Scalar::from_rand(&mut rng)).collect();
        let blind1 = Scalar::from_rand(&mut rng);
        let blind2 = Scalar::from_rand(&mut rng);

        let c1 = gens.commit(&values, &blind1);
        let c2 = gens.commit(&values, &blind2);

        // Different blindings should give different commitments
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_inner_product() {
        let mut rng = StdRng::seed_from_u64(42);

        let a: Vec<Scalar> = (0..4).map(|_| Scalar::from_rand(&mut rng)).collect();
        let b: Vec<Scalar> = (0..4).map(|_| Scalar::from_rand(&mut rng)).collect();

        let ip = inner_product(&a, &b);

        // Verify manually
        let mut expected = Scalar::zero();
        for i in 0..4 {
            let mut term = a[i].clone();
            term.mul(&b[i]);
            expected.add(&term);
        }

        assert_eq!(ip, expected);
    }
}
