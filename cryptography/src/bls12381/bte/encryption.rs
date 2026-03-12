use crate::bls12381::primitives::group::{Scalar, G1, G2};
use commonware_math::algebra::{CryptoGroup, Random};
use rand_core::CryptoRngCore;

use super::utils::{hash_g1, hash_gt, pairing, xor, Transcript};

/// Domain separation tag for hashing to scalar in BTE.
const DST_HASH_TO_SCALAR: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_BTE_HASH_TO_SCALAR";

/// Domain separation tag for challenge derivation in BTE.
const DST_CHALLENGE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_BTE_CHALLENGE";

/// Zero-knowledge proof of knowledge for alpha, beta, and s.
#[derive(Clone)]
pub struct DLogProof {
    pub c: Scalar,
    pub z_alpha: Scalar,
    pub z_beta: Scalar,
    pub z_s: Scalar,
}

/// A ciphertext in the batch threshold encryption scheme.
#[derive(Clone)]
pub struct Ciphertext {
    pub ct1: [u8; 32],
    pub ct2: G2,
    pub ct3: G2,
    pub ct4: G2,
    pub gs: G1,
    pub x: Scalar,
    pub pi: DLogProof,
}

/// Build the Fiat-Shamir transcript for a ciphertext and its proof commitments.
fn build_transcript(
    ct1: &[u8; 32],
    ct2: &G2,
    ct3: &G2,
    ct4: &G2,
    gs: &G1,
    x: &Scalar,
    k2: &G2,
    k3: &G2,
    k4: &G2,
    k_s: &G1,
) -> Transcript {
    let mut ts = Transcript::new();
    ts.append(b"ct1", ct1);
    ts.append_g2(b"ct2", ct2);
    ts.append_g2(b"ct3", ct3);
    ts.append_g2(b"ct4", ct4);
    ts.append_g1(b"gs", gs);
    ts.append_scalar(b"x", x);
    ts.append_g2(b"k2", k2);
    ts.append_g2(b"k3", k3);
    ts.append_g2(b"k4", k4);
    ts.append_g1(b"k_s", k_s);
    ts
}

/// Derive a challenge scalar from the transcript state.
fn derive_challenge(ts: &Transcript) -> Scalar {
    let mut c_bytes = [0u8; 64];
    ts.challenge_bytes(&mut c_bytes);
    Scalar::map(DST_CHALLENGE, &c_bytes)
}

impl Ciphertext {
    /// Verify the zero-knowledge proof in this ciphertext.
    ///
    /// # Panics
    ///
    /// Panics if the proof does not verify.
    pub fn verify(&self, htau: G2, pk: G2) {
        let g = G1::generator();
        let h = G2::generator();

        // Recover k values from proof
        let minus_c = -self.pi.c.clone();
        let recovered_k2 =
            (htau - &(h * &self.x)) * &self.pi.z_alpha + &(self.ct2 * &minus_c);
        let recovered_k3 =
            h * &self.pi.z_alpha + &(pk * &self.pi.z_beta) + &(self.ct3 * &minus_c);
        let recovered_k4 = h * &self.pi.z_beta + &(self.ct4 * &minus_c);
        let recovered_k_s = g * &self.pi.z_s + &(self.gs * &minus_c);

        let ts = build_transcript(
            &self.ct1,
            &self.ct2,
            &self.ct3,
            &self.ct4,
            &self.gs,
            &self.x,
            &recovered_k2,
            &recovered_k3,
            &recovered_k4,
            &recovered_k_s,
        );

        let c = derive_challenge(&ts);
        assert_eq!(self.pi.c, c);
    }
}

/// Encrypt a 32-byte message using batch threshold encryption.
pub fn encrypt(
    msg: [u8; 32],
    x: Scalar,
    hid: G1,
    htau: G2,
    pk: G2,
    rng: &mut impl CryptoRngCore,
) -> Ciphertext {
    let g = G1::generator();
    let h = G2::generator();

    // Random s, compute gs = g*s, hash to get tg
    let s = Scalar::random(&mut *rng);
    let gs = g * &s;
    let tg = {
        let hgs = hash_g1(&gs);
        Scalar::map(DST_HASH_TO_SCALAR, &hgs)
    };

    // Compute mask: e(H(id) - g*tg, h)^alpha
    let alpha = Scalar::random(&mut *rng);
    let beta = Scalar::random(&mut *rng);
    let mask = pairing(&(hid - &(g * &tg)), &h).scalar_mul(&alpha);
    let hmask = hash_gt(&mask);

    // XOR msg and hmask
    let ct1: [u8; 32] = xor(&msg, &hmask).as_slice().try_into().unwrap();
    let ct2 = (htau - &(h * &x)) * &alpha;
    let ct3 = h * &alpha + &(pk * &beta);
    let ct4 = h * &beta;

    // ZK proof of knowledge of alpha, beta, and s
    let r_alpha = Scalar::random(&mut *rng);
    let r_beta = Scalar::random(&mut *rng);
    let r_s = Scalar::random(&mut *rng);

    let k2 = (htau - &(h * &x)) * &r_alpha;
    let k3 = h * &r_alpha + &(pk * &r_beta);
    let k4 = h * &r_beta;
    let k_s = g * &r_s;

    let ts = build_transcript(&ct1, &ct2, &ct3, &ct4, &gs, &x, &k2, &k3, &k4, &k_s);

    // Fiat-Shamir challenge
    let c = derive_challenge(&ts);

    let z_alpha = r_alpha + &(c.clone() * &alpha);
    let z_beta = r_beta + &(c.clone() * &beta);
    let z_s = r_s + &(c.clone() * &s);

    let pi = DLogProof {
        c,
        z_alpha,
        z_beta,
        z_s,
    };

    Ciphertext {
        ct1,
        ct2,
        ct3,
        ct4,
        gs,
        x,
        pi,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::bte::dealer::Dealer;
    use crate::bls12381::bte::utils::Domain;
    use commonware_utils::test_rng;

    #[test]
    fn test_encryption() {
        let mut rng = test_rng();

        let batch_size = 1 << 5;
        let n = 1 << 4;
        let tx_domain = Domain::new(batch_size);

        let mut dealer = Dealer::new(batch_size, n, n / 2 - 1, &mut rng);
        let (crs, _) = dealer.setup(&mut rng);
        let pk = dealer.get_pk();

        let msg = [1u8; 32];
        let x = tx_domain.group_gen();

        let hid = G1::generator() * &Scalar::random(&mut rng);
        let ct = encrypt(msg, x, hid, crs.htau, pk, &mut rng);

        ct.verify(crs.htau, pk);
    }
}
