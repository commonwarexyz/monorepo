use crate::bls12381::primitives::{group::Scalar, variant::Variant};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use commonware_math::algebra::{Additive, CryptoGroup, Random, Ring, Space};
use rand_core::CryptoRngCore;
use std::ops::Neg;

/// Encrypted bit.
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

/// Encrypt a single bit for a given target.
///
/// The bit m in {0, 1} is encrypted as:
/// - u = alpha * G
/// - c = (alpha + m) * h_id
///
/// # Arguments
/// * `public` - The gamma-modified public key `pk^gamma` from the committee.
/// * `h_id` - The pre-processed target point `H(id)^{gamma^{-1}}` from the
///   committee. This cannot be computed locally.
pub fn encrypt_bit<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    h_id: &V::Signature,
    bit: bool,
) -> Ciphertext<V> {
    // Sample random alpha
    let alpha = Scalar::random(rng);

    // u = alpha * G
    let mut u = V::Public::generator();
    u *= &alpha;

    // c = (alpha + m) * H(id)^{gamma^{-1}}
    let scalar = if bit { alpha + &Scalar::one() } else { alpha };
    let mut c = *h_id;
    c *= &scalar;

    Ciphertext { u, c }
}

/// Decrypt a bit ciphertext using the public key and signature over the target.
///
/// Computes e(pk^gamma, c) * e(-u, sig_id) and checks:
/// - result == identity -> 0
/// - result == e(pk^gamma, H(id)^{gamma^{-1}}) -> 1
/// - Otherwise -> None (invalid)
///
/// # Arguments
/// * `public` - The gamma-modified public key `pk^gamma`.
/// * `signature` - The BLS signature over the target identity.
/// * `h_id` - The pre-processed target point `H(id)^{gamma^{-1}}`.
pub fn decrypt_bit<V: Variant>(
    public: &V::Public,
    signature: &V::Signature,
    h_id: &V::Signature,
    ciphertext: &Ciphertext<V>,
) -> Option<bool> {
    let lhs = V::pairing(public, &ciphertext.c);
    let rhs = V::pairing(&ciphertext.u.neg(), signature);
    let m = lhs.mul(&rhs);

    if m.is_one() {
        Some(false)
    } else {
        let base = V::pairing(public, h_id);
        if m == base {
            Some(true)
        } else {
            None
        }
    }
}

/// Batch-verify that claimed decryptions are correct for a set of ciphertexts.
///
/// All ciphertexts must be encrypted to the same target. Messages are bits
/// (0 or 1).
///
/// The verification equation:
///
/// ```text
/// e(pk^gamma, Σ c_i*r_i - (Σ r_i*m_i)*H(id)^{gamma^{-1}}) * e(-Σ u_i*r_i, sig_id) == 1
/// ```
///
/// Uses one [V::Signature] MSM, one [V::Public] MSM, and two pairings.
///
/// # Arguments
/// * `public` - The gamma-modified public key `pk^gamma`.
/// * `signature` - The BLS signature over the target identity.
/// * `h_id` - The pre-processed target point `H(id)^{gamma^{-1}}`.
pub fn verify_decryption<R, V>(
    rng: &mut R,
    public: &V::Public,
    signature: &V::Signature,
    h_id: &V::Signature,
    ciphertexts: &[Ciphertext<V>],
    messages: &[bool],
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

    // Scalar sum: s = Σ_{m_i=1} r_i
    let t0 = std::time::Instant::now();
    let mut msg_scalar = Scalar::zero();
    for (r, &m) in challenges.iter().zip(messages.iter()) {
        if m {
            msg_scalar = msg_scalar + r;
        }
    }

    // sig_term = Σ c_i*r_i - (Σ r_i*m_i)*H(id)^{gamma^{-1}}
    let mut msg_term = *h_id;
    msg_term *= &(-msg_scalar);
    let sig_term = c_agg + &msg_term;
    let t_scalar = t0.elapsed();

    // Check: e(pk^gamma, sig_term) * e(-u_agg, sig_id) == 1
    let t0 = std::time::Instant::now();
    let lhs = V::pairing(public, &sig_term);
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

    /// Compute H(id)^{gamma^{-1}} for tests.
    ///
    /// In production this is provided by the VRF committee. Here we just
    /// use the raw hash (gamma = 1).
    fn test_h_id(namespace: &[u8], target: &[u8]) -> <MinPk as Variant>::Signature {
        hash_with_namespace::<MinPk>(MinPk::MESSAGE, namespace, target)
    }

    #[test]
    fn test_encrypt_decrypt_bit() {
        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 200u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        // Encrypt and decrypt bit = 0
        let ct0 = encrypt_bit::<_, MinPk>(&mut rng, &h_id, false);
        assert_eq!(
            decrypt_bit::<MinPk>(&master_public, &signature, &h_id, &ct0),
            Some(false)
        );

        // Encrypt and decrypt bit = 1
        let ct1 = encrypt_bit::<_, MinPk>(&mut rng, &h_id, true);
        assert_eq!(
            decrypt_bit::<MinPk>(&master_public, &signature, &h_id, &ct1),
            Some(true)
        );
    }

    #[test]
    fn test_decrypt_bit_wrong_signature() {
        let mut rng = test_rng();
        let (_, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let (wrong_secret, _) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 210u64.to_be_bytes();
        let wrong_signature = ops::sign_message::<MinPk>(&wrong_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let ct = encrypt_bit::<_, MinPk>(&mut rng, &h_id, true);
        assert_eq!(
            decrypt_bit::<MinPk>(&master_public, &wrong_signature, &h_id, &ct),
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

        let bits = [true, false, true, true, false];
        let ciphertexts: Vec<_> = bits
            .iter()
            .map(|&b| encrypt_bit::<_, MinPk>(&mut rng, &h_id, b))
            .collect();

        assert!(verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &signature,
            &h_id,
            &ciphertexts,
            &bits,
        ));
    }

    #[test]
    fn test_verify_decryption_wrong_message() {
        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 400u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let bits = [true, false, true];
        let ciphertexts: Vec<_> = bits
            .iter()
            .map(|&b| encrypt_bit::<_, MinPk>(&mut rng, &h_id, b))
            .collect();

        // Flip one bit
        let wrong_bits = [true, true, true];
        assert!(!verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &signature,
            &h_id,
            &ciphertexts,
            &wrong_bits,
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

        let bits = [true, false];
        let ciphertexts: Vec<_> = bits
            .iter()
            .map(|&b| encrypt_bit::<_, MinPk>(&mut rng, &h_id, b))
            .collect();

        assert!(!verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &wrong_signature,
            &h_id,
            &ciphertexts,
            &bits,
        ));
    }

    fn bench_individual_vs_batch(n: usize) {
        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 600u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let bits: Vec<bool> = (0..n).map(|i| i % 3 != 0).collect();
        let ciphertexts: Vec<_> = bits
            .iter()
            .map(|&b| encrypt_bit::<_, MinPk>(&mut rng, &h_id, b))
            .collect();

        // Individual decryption
        let start = Instant::now();
        for (ct, &expected) in ciphertexts.iter().zip(bits.iter()) {
            let result = decrypt_bit::<MinPk>(&master_public, &signature, &h_id, ct);
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
            &bits,
        );
        let batch = start.elapsed();
        assert!(valid);

        println!(
            "n={n}: individual={individual:.2?} ({:.2?}/ct), batch={batch:.2?} ({:.2?}/ct), speedup={:.1}x",
            individual / n as u32,
            batch / n as u32,
            individual.as_secs_f64() / batch.as_secs_f64(),
        );
    }

    #[test]
    fn test_bench_individual_vs_batch() {
        for &n in &[10, 100, 1000] {
            bench_individual_vs_batch(n);
        }
    }

    fn bench_parallel_individual_vs_batch(n: usize) {
        use rayon::prelude::*;

        let mut rng = test_rng();
        let (master_secret, master_public) = ops::keypair::<_, MinPk>(&mut rng);
        let target = 700u64.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&master_secret, b"_TLE_", &target);
        let h_id = test_h_id(b"_TLE_", &target);

        let bits: Vec<bool> = (0..n).map(|i| i % 3 != 0).collect();
        let ciphertexts: Vec<_> = bits
            .iter()
            .map(|&b| encrypt_bit::<_, MinPk>(&mut rng, &h_id, b))
            .collect();

        // Parallel individual decryption
        let start = Instant::now();
        let results: Vec<_> = ciphertexts
            .par_iter()
            .map(|ct| decrypt_bit::<MinPk>(&master_public, &signature, &h_id, ct))
            .collect();
        let parallel_individual = start.elapsed();
        for (result, &expected) in results.iter().zip(bits.iter()) {
            assert_eq!(*result, Some(expected));
        }

        // Batch verification
        let start = Instant::now();
        let valid = verify_decryption::<_, MinPk>(
            &mut rng,
            &master_public,
            &signature,
            &h_id,
            &ciphertexts,
            &bits,
        );
        let batch = start.elapsed();
        assert!(valid);

        println!(
            "n={n}: parallel_individual={parallel_individual:.2?} ({:.2?}/ct), batch={batch:.2?} ({:.2?}/ct), speedup={:.1}x",
            parallel_individual / n as u32,
            batch / n as u32,
            parallel_individual.as_secs_f64() / batch.as_secs_f64(),
        );
    }

    #[test]
    fn test_bench_parallel_individual_vs_batch() {
        for &n in &[500, 5000] {
            bench_parallel_individual_vs_batch(n);
        }
    }
}
