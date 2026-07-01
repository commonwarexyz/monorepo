use crate::bls12381::primitives::group::{Scalar, G1, G2};
use commonware_math::algebra::{Additive, CryptoGroup, Random, Ring};
use rand_core::CryptoRngCore;
use std::iter;

use super::utils::{lagrange_interp_eval, Domain};

/// Common Reference String (KZG parameters) for batch threshold encryption.
///
/// Reusable across different committees/public keys.
#[derive(Clone)]
pub struct CRS {
    /// Powers of g in G1: [g, g*tau, g*tau^2, ...].
    pub powers_of_g: Vec<G1>,
    /// h * tau in G2.
    pub htau: G2,
    /// Preprocessed Toeplitz matrix for FK22 amortized KZG openings.
    pub y: Vec<G1>,
}

/// Committee public key for batch threshold encryption.
///
/// Derived from a committee secret key `sk` and the KZG trapdoor `tau`.
#[derive(Clone, Copy)]
pub struct PublicKey {
    /// [sk]_2 = h * sk.
    pub hsk: G2,
    /// [sk*tau]_2 = h * (sk * tau).
    pub hsk_tau: G2,
}

/// Dealer sets up the CRS and distributes secret shares.
///
/// Assumes the shares are evaluated at points (1..=n) and the secret key
/// is stored at the evaluation point 0.
#[derive(Clone)]
pub struct Dealer {
    batch_size: usize,
    n: usize,
    t: usize, // t+1 parties need to agree to decrypt
    sk: Scalar,
}

impl Dealer {
    pub fn new(batch_size: usize, n: usize, t: usize, rng: &mut impl CryptoRngCore) -> Self {
        Self {
            batch_size,
            n,
            t,
            sk: Scalar::random(&mut *rng),
        }
    }

    pub fn get_pk(&self) -> G2 {
        G2::generator() * &self.sk
    }

    pub fn setup(&mut self, rng: &mut impl CryptoRngCore) -> (CRS, PublicKey, Vec<Scalar>) {
        // Sample tau and compute its powers
        let tau = Scalar::random(&mut *rng);
        let powers_of_tau: Vec<Scalar> =
            iter::successors(Some(Scalar::one()), |p| Some(p.clone() * &tau))
                .take(self.batch_size)
                .collect();

        // Generators
        let g = G1::generator();
        let h = G2::generator();

        // Compute powers of g: [g*tau^0, g*tau^1, ...]
        let powers_of_g: Vec<G1> = powers_of_tau.iter().map(|t| g * t).collect();

        // Compute the Toeplitz matrix preprocessing for FK22
        let mut top_tau = powers_of_tau.clone();
        top_tau.truncate(self.batch_size);
        top_tau.reverse();
        top_tau.resize(2 * self.batch_size, Scalar::zero());

        let top_domain = Domain::new(2 * self.batch_size);
        let top_tau = top_domain.fft(&top_tau);

        // Compute y = g * top_tau[i] for each i
        let y: Vec<G1> = top_tau.iter().map(|t| g * t).collect();

        // Generate secret sharing polynomial: sk_poly[0] = sk, rest random
        let mut sk_poly = vec![Scalar::zero(); self.t + 1];
        sk_poly[0] = self.sk.clone();
        for i in 1..self.t {
            sk_poly[i] = Scalar::random(&mut *rng);
        }

        // Evaluate at share points (1..=n)
        let share_domain: Vec<Scalar> = (1..=self.n)
            .map(|i| Scalar::from_u64(i as u64))
            .collect();

        // Polynomial is defined at negative indices (0..=t)
        let eval_domain: Vec<Scalar> = (0..=self.t)
            .map(|i| -Scalar::from_u64(i as u64))
            .collect();

        let sk_shares = lagrange_interp_eval(&eval_domain, &share_domain, &sk_poly);

        let hsk = h * &self.sk;
        let crs = CRS {
            powers_of_g,
            htau: h * &tau,
            y,
        };
        let pk = PublicKey {
            hsk,
            hsk_tau: hsk * &tau,
        };

        (crs, pk, sk_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::test_rng;

    #[test]
    fn test_dealer() {
        let mut rng = test_rng();
        let batch_size = 1 << 5;
        let n = 1 << 4;
        let t = n / 2 - 1;

        let mut dealer = Dealer::new(batch_size, n, t, &mut rng);
        let (crs, pk, sk_shares) = dealer.setup(&mut rng);

        let share_domain: Vec<Scalar> = (1..=n)
            .map(|i| Scalar::from_u64(i as u64))
            .collect();
        let should_be_sk =
            lagrange_interp_eval(&share_domain, &[Scalar::zero()], &sk_shares)[0].clone();
        assert_eq!(dealer.sk, should_be_sk);

        let should_be_pk = G2::generator() * &should_be_sk;
        assert_eq!(pk.hsk, should_be_pk);

        let g_sk_shares: Vec<G2> = sk_shares
            .iter()
            .map(|ski| G2::generator() * ski)
            .collect();

        let interp_pk =
            lagrange_interp_eval(&share_domain, &[Scalar::zero()], &g_sk_shares)[0];
        assert_eq!(pk.hsk, interp_pk);

        assert_eq!(crs.powers_of_g.len(), batch_size);
        assert_eq!(sk_shares.len(), n);
    }
}
