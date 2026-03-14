use crate::bls12381::primitives::{
    group::{Scalar, GT},
    variant::Variant,
};
use crate::{Hasher, Sha256};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use commonware_math::algebra::{Additive, CryptoGroup, Random, Space};
use rand_core::CryptoRngCore;
use std::collections::HashMap;
use std::ops::Neg;

/// Encrypted message from a small message space {0, ..., 2^k - 1}.
///
/// The VRF committee samples a random gamma and publishes `pk^gamma` and
/// `H(id)^{gamma^{-1}}` for each target identity. Callers pass these
/// pre-processed values to encrypt/decrypt/verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<V: Variant> {
    /// Commitment u = alpha * G.
    pub u: V::Public,
    /// Encrypted message c = (alpha + m) * H(id)^{gamma^{-1}}.
    pub c: V::Signature,
}

/// Hash a GT element to a 32-byte key for table lookup.
fn hash_gt(gt: &GT) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&gt.as_slice());
    hasher.finalize().0
}

/// Discrete log lookup table mapping hashed GT elements to messages.
///
/// Stores `H(base^m) -> m` for `m in 0..2^k` where
/// `base = e(pk^gamma, H(id)^{gamma^{-1}})`.
///
/// This table is reused across all decryptions for the same target.
pub type Table = HashMap<[u8; 32], u64>;

/// Precompute a discrete log lookup table for decryption.
pub fn build_table<V: Variant>(public: &V::Public, h_id: &V::Signature, k: u32) -> Table {
    assert!(k <= 20, "message space too large");
    let size = 1usize << k;
    let mut table = HashMap::with_capacity(size);
    let base = V::pairing(public, h_id);
    let mut acc = GT::one();
    for m in 0..size {
        table.insert(hash_gt(&acc), m as u64);
        acc = acc.mul(&base);
    }
    table
}

/// Encrypt a message from {0, ..., 2^k - 1} for a given target.
///
/// The message m is encrypted as:
/// - u = alpha * G
/// - c = (alpha + m) * h_id
///
/// # Arguments
/// * `h_id_gamma` - The pre-processed target point `H(id)^{gamma^{-1}}` from the
///   committee. This cannot be computed locally.
/// * `message` - The message to encrypt (must be < 2^k).
pub fn encrypt<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    h_id_gamma: &V::Signature,
    message: u64,
) -> Ciphertext<V> {
    // Sample random alpha
    let alpha = Scalar::random(rng);

    // u = alpha * G
    let mut u = V::Public::generator();
    u *= &alpha;

    // c = (alpha + m) * H(id)^{gamma^{-1}}
    let m_scalar = Scalar::from_u64(message);
    let scalar = alpha + &m_scalar;
    let mut c = *h_id_gamma;
    c *= &scalar;

    Ciphertext { u, c }
}

/// Decrypt a ciphertext using the public key, signature, and a precomputed
/// lookup table.
///
/// Computes `e(pk^gamma, c) * e(-u, sig_id)` and looks up the hashed result
/// in the table to recover the message.
///
/// # Arguments
/// * `pk_gamma` - The gamma-modified public key `pk^gamma`.
/// * `signature` - The BLS signature over the target identity.
/// * `table` - Precomputed lookup table from [build_table].
pub fn decrypt<V: Variant>(
    pk_gamma: &V::Public,
    signature: &V::Signature,
    table: &Table,
    ciphertext: &Ciphertext<V>,
) -> Option<u64> {
    let lhs = V::pairing(pk_gamma, &ciphertext.c);
    let rhs = V::pairing(&ciphertext.u.neg(), signature);
    let target = lhs.mul(&rhs);
    table.get(&hash_gt(&target)).copied()
}

/// Batch-verify that claimed decryptions are correct for a set of ciphertexts.
///
/// All ciphertexts must be encrypted to the same target. Messages are from
/// {0, ..., 2^k - 1}.
///
/// The verification equation:
///
/// ```text
/// e(pk^gamma, Σ c_i*r_i - (Σ r_i*m_i)*h_id) * e(-Σ u_i*r_i, sig_id) == 1
/// ```
///
/// Uses one [V::Signature] MSM, one [V::Public] MSM, and two pairings.
///
/// # Arguments
/// * `public` - The gamma-modified public key `pk^gamma`.
/// * `signature` - The BLS signature over the target identity.
/// * `h_id_gamma` - The pre-processed target point `H(id)^{gamma^{-1}}`.
pub fn verify_decryption<R, V>(
    rng: &mut R,
    pk_gamma: &V::Public,
    signature: &V::Signature,
    h_id_gamma: &V::Signature,
    ciphertexts: &[Ciphertext<V>],
    messages: &[u64],
) -> bool
where
    R: CryptoRngCore,
    V: Variant,
    V::Public: Space<Scalar>,
    V::Signature: Space<Scalar>,
{
    assert_eq!(ciphertexts.len(), messages.len());
    if ciphertexts.is_empty() {
        return true;
    }

    let n = ciphertexts.len();

    // Sample random challenge scalars
    let t0 = std::time::Instant::now();
    let challenges: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut *rng)).collect();
    let t_challenges = t0.elapsed();

    // V::Signature MSM: Σ c_i * r_i
    let t0 = std::time::Instant::now();
    let c_points: Vec<V::Signature> = ciphertexts.iter().map(|ct| ct.c).collect();
    let c_agg = V::Signature::msm(&c_points, &challenges, &commonware_parallel::Sequential);
    let t_sig_msm = t0.elapsed();

    // V::Public MSM: Σ u_i * r_i
    let t0 = std::time::Instant::now();
    let u_points: Vec<V::Public> = ciphertexts.iter().map(|ct| ct.u).collect();
    let u_agg = V::Public::msm(&u_points, &challenges, &commonware_parallel::Sequential);
    let t_pub_msm = t0.elapsed();

    // Scalar sum: s = Σ r_i * m_i
    let t0 = std::time::Instant::now();
    let mut msg_scalar = Scalar::zero();
    for (r, &m) in challenges.iter().zip(messages.iter()) {
        let m_scalar = Scalar::from_u64(m);
        msg_scalar = msg_scalar + &(r.clone() * &m_scalar);
    }

    // sig_term = Σ c_i*r_i - (Σ r_i*m_i)*h_id
    let mut msg_term = *h_id_gamma;
    msg_term *= &(-msg_scalar);
    let sig_term = c_agg + &msg_term;
    let t_scalar = t0.elapsed();

    // Check: e(pk^gamma, sig_term) * e(-u_agg, sig_id) == 1
    let t0 = std::time::Instant::now();
    let lhs = V::pairing(pk_gamma, &sig_term);
    let rhs = V::pairing(&u_agg.neg(), signature);
    let result = lhs.mul(&rhs).is_one();
    let t_pairing = t0.elapsed();

    println!(
        "  verify_decryption(n={n}): challenges={t_challenges:.2?}, sig_msm={t_sig_msm:.2?}, pub_msm={t_pub_msm:.2?}, scalar={t_scalar:.2?}, pairing={t_pairing:.2?}",
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{ops, ops::hash_with_namespace, variant::MinPk};
    use commonware_utils::test_rng;
    use std::time::Instant;

    /// Compute H(id)^{gamma^{-1}} for tests (gamma = 1).
    fn test_h_id(namespace: &[u8], target: &[u8]) -> <MinPk as Variant>::Signature {
        hash_with_namespace::<MinPk>(MinPk::MESSAGE, namespace, target)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 200u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let k = 4; // message space {0, ..., 15}
        let table = build_table::<MinPk>(&master_public, &h_id, k);

        for m in 0..1u64 << k {
            let ct = encrypt::<_, MinPk>(&mut rng, &h_id, m);
            let result = decrypt::<MinPk>(&master_public, &signature, &table, &ct);
            assert_eq!(result, Some(m), "failed for m={m}");
        }
    }

    #[test]
    fn test_decrypt_wrong_signature() {
        let mut rng = test_rng();
        let (_, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let (wrong_secret, _) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 210u64.to_be_bytes();
        let wrong_signature = ops::sign_message::<MinPk>(&wrong_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let table = build_table::<MinPk>(&master_public, &h_id, 4);
        let ct = encrypt::<_, MinPk>(&mut rng, &h_id, 7);
        assert_eq!(
            decrypt::<MinPk>(&master_public, &wrong_signature, &table, &ct),
            None
        );
    }

    #[test]
    fn test_verify_decryption_valid() {
        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 300u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let k = 4;
        let table = build_table::<MinPk>(&master_public, &h_id, k);
        let msgs: Vec<u64> = vec![0, 5, 15, 3, 11];
        let ciphertexts: Vec<_> = msgs
            .iter()
            .map(|&m| encrypt::<_, MinPk>(&mut rng, &h_id, m))
            .collect();

        // Verify decryptions are correct
        for (ct, &m) in ciphertexts.iter().zip(msgs.iter()) {
            assert_eq!(
                decrypt::<MinPk>(&master_public, &signature, &table, ct),
                Some(m)
            );
        }

        assert!(verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &signature,
            &h_id,
            &ciphertexts,
            &msgs,
        ));
    }

    #[test]
    fn test_verify_decryption_wrong_message() {
        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 400u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let msgs: Vec<u64> = vec![1, 2, 3];
        let ciphertexts: Vec<_> = msgs
            .iter()
            .map(|&m| encrypt::<_, MinPk>(&mut rng, &h_id, m))
            .collect();

        let wrong_msgs: Vec<u64> = vec![1, 4, 3];
        assert!(!verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &signature,
            &h_id,
            &ciphertexts,
            &wrong_msgs,
        ));
    }

    #[test]
    fn test_verify_decryption_wrong_signature() {
        let mut rng = test_rng();
        let (_, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let (wrong_secret, _) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 500u64.to_be_bytes();
        let wrong_signature = ops::sign_message::<MinPk>(&wrong_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let msgs: Vec<u64> = vec![5, 10];
        let ciphertexts: Vec<_> = msgs
            .iter()
            .map(|&m| encrypt::<_, MinPk>(&mut rng, &h_id, m))
            .collect();

        assert!(!verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &wrong_signature,
            &h_id,
            &ciphertexts,
            &msgs,
        ));
    }

    fn bench_individual_vs_batch(n: usize, k: u32) {
        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 600u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let max_msg = 1u64 << k;
        let table = build_table::<MinPk>(&master_public, &h_id, k);

        let msgs: Vec<u64> = (0..n).map(|i| (i as u64) % max_msg).collect();
        let ciphertexts: Vec<_> = msgs
            .iter()
            .map(|&m| encrypt::<_, MinPk>(&mut rng, &h_id, m))
            .collect();

        // Individual decryption
        let start = Instant::now();
        for (ct, &expected) in ciphertexts.iter().zip(msgs.iter()) {
            let result = decrypt::<MinPk>(&master_public, &signature, &table, ct);
            assert_eq!(result, Some(expected));
        }
        let individual = start.elapsed();

        // Batch verification
        let start = Instant::now();
        let valid = verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &signature,
            &h_id,
            &ciphertexts,
            &msgs,
        );
        let batch = start.elapsed();
        assert!(valid);

        println!(
            "n={n} k={k}: individual={individual:.2?} ({:.2?}/ct), batch={batch:.2?} ({:.2?}/ct), speedup={:.1}x",
            individual / n as u32,
            batch / n as u32,
            individual.as_secs_f64() / batch.as_secs_f64(),
        );
    }

    #[test]
    fn test_bench_individual_vs_batch() {
        for &n in &[100, 1000, 10000, 100000] {
            for &k in &[1, 16] {
                bench_individual_vs_batch(n, k);
            }
        }
    }
}
