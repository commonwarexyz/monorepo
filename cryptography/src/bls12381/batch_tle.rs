//! Batch verification of Timelock Encryption (TLE) decryptions.
//!
//! Uses the Fujisaki-Okamoto transform from [tle] with a "Different Witnesses"
//! batch verification technique. Instead of verifying each decryption
//! individually (1 pairing per ciphertext), batch verification requires only:
//!
//! * One G1-MSM of size B
//! * One GT-MSM of size B
//! * One pairing evaluation (for `e(pk, H(id))`)
//! * O(B) hash evaluations
//!
//! # Flow
//!
//! 1. Decryptor runs [decrypt] on each ciphertext, producing the message
//!    and a [Hint] `(K, P)`.
//! 2. Decryptor publishes the hints alongside the claimed messages.
//! 3. Verifier runs [verify_decryption] with the ciphertexts, hints,
//!    and public parameters to batch-check correctness.

use crate::bls12381::{
    primitives::{
        group::{Scalar, SmallScalar, GT},
        ops::hash_with_namespace,
        variant::Variant,
    },
    tle::{self, Block},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use commonware_math::algebra::{Additive, CryptoGroup, Space};
use rand_core::CryptoRngCore;

/// Hint produced during decryption for batch verification.
///
/// Contains the intermediate values needed to verify a decryption
/// without recomputing the pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    /// The recovered random key K (sigma in FO terminology).
    pub k: Block,
    /// The pairing element P = alpha * e(pk, H(id)).
    pub p: GT,
}

/// Decrypt a ciphertext and produce a [Hint] for batch verification.
///
/// This performs the same decryption as [tle::decrypt] but additionally
/// returns the intermediate pairing element `P = e(ct_0, sigma_id)` needed
/// for batch verification.
///
/// # Returns
/// * `Some((message, hint))` if decryption succeeds
/// * `None` if the FO consistency check fails
pub fn decrypt<V: Variant>(
    signature: &V::Signature,
    ciphertext: &tle::Ciphertext<V>,
) -> Option<(Block, Hint)> {
    // P = e(ct_0, sigma_id)
    let p = V::pairing(&ciphertext.u, signature);

    // K = ct_1 XOR H_K(P)
    let h_k = tle::hash::h2(&p);
    let k = tle::xor(&ciphertext.v, &h_k);

    // msg = ct_2 XOR H_M(K)
    let h_m = tle::hash::h4(&k);
    let msg = tle::xor(&ciphertext.w, &h_m);

    // alpha = H_R(K, msg)
    let alpha = tle::hash::h3(&k, msg.as_ref());

    // Check ct_0 = alpha * G
    let mut expected_u = V::Public::generator();
    expected_u *= &alpha;
    if ciphertext.u != expected_u {
        return None;
    }

    Some((msg, Hint { k, p }))
}

/// Batch-verify that the given hints are consistent with the ciphertexts.
///
/// All ciphertexts must be encrypted to the same target. The verification
/// checks three conditions:
///
/// 1. **G1 check**: `sum(r_i * ct_0_i) == (sum(r_i * alpha_i)) * G`
/// 2. **GT check**: `sum(r_i * P_i) == (sum(r_i * alpha_i)) * e(pk, H(id))`
/// 3. **Hash check**: `ct_1_i == H_K(P_i) XOR K_i` for all i
///
/// Where `alpha_i = H_R(K_i, msg_i)` and `msg_i = ct_2_i XOR H_M(K_i)`.
///
/// # Cost
/// One G1-MSM(B), one GT-MSM(B), one pairing, and O(B) hash evaluations.
pub fn verify_decryption<R, V>(
    rng: &mut R,
    public: &V::Public,
    target: (&[u8], &[u8]),
    ciphertexts: &[tle::Ciphertext<V>],
    hints: &[Hint],
) -> bool
where
    R: CryptoRngCore,
    V: Variant,
    V::Public: Space<Scalar> + Space<SmallScalar>,
{
    assert_eq!(ciphertexts.len(), hints.len());
    let n = ciphertexts.len();
    if n == 0 {
        return true;
    }

    // Step 1: Recover alphas from hints
    let mut alphas = Vec::with_capacity(n);
    for (ct, hint) in ciphertexts.iter().zip(hints.iter()) {
        let h_m = tle::hash::h4(&hint.k);
        let msg = tle::xor(&ct.w, &h_m);
        let alpha = tle::hash::h3(&hint.k, msg.as_ref());
        alphas.push(alpha);
    }

    // Step 2: Sample 128-bit random challenges (sufficient for batch security)
    let challenges: Vec<SmallScalar> =
        (0..n).map(|_| SmallScalar::random(&mut *rng)).collect();

    // Compute shared scalar: s = sum(r_i * alpha_i)
    let mut s = Scalar::zero();
    for (r, alpha) in challenges.iter().zip(alphas.iter()) {
        s += &(r * alpha);
    }

    // Step 3: G1 check — sum(r_i * ct_0_i) == s * G
    let ct0_points: Vec<V::Public> = ciphertexts.iter().map(|ct| ct.u).collect();
    let lhs_g1 = V::Public::msm(&ct0_points, &challenges, &commonware_parallel::Sequential);
    let mut rhs_g1 = V::Public::generator();
    rhs_g1 *= &s;
    if lhs_g1 != rhs_g1 {
        return false;
    }

    // Step 4: GT check — sum(r_i * P_i) == s * e(pk, H(id))
    let p_points: Vec<GT> = hints.iter().map(|h| h.p).collect();
    let lhs_gt = GT::msm(&p_points, &challenges, &commonware_parallel::Sequential);
    let (namespace, target_bytes) = target;
    let q_id = hash_with_namespace::<V>(V::MESSAGE, namespace, target_bytes);
    let pk_h_id = V::pairing(public, &q_id);
    let rhs_gt = pk_h_id * &s;
    if lhs_gt != rhs_gt {
        return false;
    }

    // Step 5: Hash consistency — ct_1_i == H_K(P_i) XOR K_i
    for (ct, hint) in ciphertexts.iter().zip(hints.iter()) {
        let h_k = tle::hash::h2(&hint.p);
        let expected_v = tle::xor(&hint.k, &h_k);
        if ct.v != expected_v {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{ops, variant::MinPk};
    use commonware_macros::test_group;
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;
    use std::time::Instant;

    const NAMESPACE: &[u8] = b"_TLE_";

    fn setup(
        rng: &mut impl CryptoRngCore,
        target_val: u64,
    ) -> (
        <MinPk as Variant>::Public,
        <MinPk as Variant>::Signature,
        [u8; 8],
    ) {
        let (secret, public) = ops::keypair::<_, MinPk>(rng);
        let target = target_val.to_be_bytes();
        let signature = ops::sign_message::<MinPk>(&secret, NAMESPACE, &target);
        (public, signature, target)
    }

    #[test]
    fn test_decrypt_produces_valid_hint() {
        let mut rng = test_rng();
        let (public, signature, target) = setup(&mut rng, 100);
        let msg = Block::new(*b"Hello, batch TLE! 32 bytes here!");

        let ct = tle::encrypt::<_, MinPk>(&mut rng, public, (NAMESPACE, &target), &msg);

        let (decrypted, hint) = decrypt::<MinPk>(&signature, &ct).expect("decryption should work");
        assert_eq!(decrypted, msg);

        // Hint should be consistent
        let h_k = tle::hash::h2(&hint.p);
        assert_eq!(ct.v, tle::xor(&hint.k, &h_k));
    }

    #[test]
    fn test_decrypt_wrong_signature() {
        let mut rng = test_rng();
        let (public, _, target) = setup(&mut rng, 200);
        let (wrong_secret, _) = ops::keypair::<_, MinPk>(&mut rng);
        let wrong_sig = ops::sign_message::<MinPk>(&wrong_secret, NAMESPACE, &target);

        let msg = Block::new(*b"Secret message padded to 32bytes");
        let ct = tle::encrypt::<_, MinPk>(&mut rng, public, (NAMESPACE, &target), &msg);

        assert!(decrypt::<MinPk>(&wrong_sig, &ct).is_none());
    }

    #[test]
    fn test_verify_decryption_valid() {
        let mut rng = test_rng();
        let (public, signature, target) = setup(&mut rng, 300);

        let messages: Vec<Block> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                Block::new(bytes)
            })
            .collect();

        let ciphertexts: Vec<_> = messages
            .iter()
            .map(|m| tle::encrypt::<_, MinPk>(&mut rng, public, (NAMESPACE, &target), m))
            .collect();

        let hints: Vec<_> = ciphertexts
            .iter()
            .map(|ct| {
                let (_, hint) = decrypt::<MinPk>(&signature, ct).unwrap();
                hint
            })
            .collect();

        assert!(verify_decryption::<_, MinPk>(
            &mut rng,
            &public,
            (NAMESPACE, &target),
            &ciphertexts,
            &hints,
        ));
    }

    #[test]
    fn test_verify_decryption_wrong_key() {
        let mut rng = test_rng();
        let (public, signature, target) = setup(&mut rng, 400);

        let msg = Block::new(*b"Testing wrong key detection!!!!!");
        let ct = tle::encrypt::<_, MinPk>(&mut rng, public, (NAMESPACE, &target), &msg);
        let (_, mut hint) = decrypt::<MinPk>(&signature, &ct).unwrap();

        // Tamper with K
        let mut k_bytes = [0u8; 32];
        k_bytes.copy_from_slice(hint.k.as_ref());
        k_bytes[0] ^= 0xFF;
        hint.k = Block::new(k_bytes);

        assert!(!verify_decryption::<_, MinPk>(
            &mut rng,
            &public,
            (NAMESPACE, &target),
            &[ct],
            &[hint],
        ));
    }

    #[test]
    fn test_verify_decryption_wrong_p() {
        let mut rng = test_rng();
        let (public, signature, target) = setup(&mut rng, 500);

        let msg = Block::new(*b"Testing wrong P detection!!!!!!!");
        let ct = tle::encrypt::<_, MinPk>(&mut rng, public, (NAMESPACE, &target), &msg);
        let (_, mut hint) = decrypt::<MinPk>(&signature, &ct).unwrap();

        // Tamper with P by multiplying with a random scalar
        let s = Scalar::random(&mut rng);
        hint.p = hint.p * &s;

        assert!(!verify_decryption::<_, MinPk>(
            &mut rng,
            &public,
            (NAMESPACE, &target),
            &[ct],
            &[hint],
        ));
    }

    #[test]
    fn test_verify_decryption_wrong_signature() {
        let mut rng = test_rng();
        let (public, _, target) = setup(&mut rng, 600);
        let (wrong_secret, _) = ops::keypair::<_, MinPk>(&mut rng);
        let wrong_sig = ops::sign_message::<MinPk>(&wrong_secret, NAMESPACE, &target);

        let msg = Block::new(*b"Wrong sig batch test 32 bytes!!!");
        let ct = tle::encrypt::<_, MinPk>(&mut rng, public, (NAMESPACE, &target), &msg);

        // Decrypt with wrong signature produces a hint that won't verify
        // (decrypt itself may return None, but if it somehow returns Some,
        // batch verify should catch it)
        if let Some((_, hint)) = decrypt::<MinPk>(&wrong_sig, &ct) {
            assert!(!verify_decryption::<_, MinPk>(
                &mut rng,
                &public,
                (NAMESPACE, &target),
                &[ct],
                &[hint],
            ));
        }
    }

    #[test]
    fn test_verify_decryption_empty() {
        let mut rng = test_rng();
        let (public, _, target) = setup(&mut rng, 700);
        assert!(verify_decryption::<_, MinPk>(
            &mut rng,
            &public,
            (NAMESPACE, &target),
            &[],
            &[],
        ));
    }

    #[test_group("slow")]
    #[test]
    fn test_bench_individual_vs_batch() {
        let mut rng = test_rng();

        for &n in &[100, 1000, 10000, 100000] {
            let (public, signature, target) = setup(&mut rng, 800);

            let messages: Vec<Block> = (0..n)
                .map(|i| {
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    Block::new(bytes)
                })
                .collect();

            let ciphertexts: Vec<_> = messages
                .iter()
                .map(|m| tle::encrypt::<_, MinPk>(&mut rng, public, (NAMESPACE, &target), m))
                .collect();

            // Individual decryption
            let start = Instant::now();
            let hints: Vec<_> = ciphertexts
                .iter()
                .zip(messages.iter())
                .map(|(ct, expected_msg)| {
                    let (msg, hint) = decrypt::<MinPk>(&signature, ct).unwrap();
                    assert_eq!(&msg, expected_msg);
                    hint
                })
                .collect();
            let individual = start.elapsed();

            // Batch verification
            let start = Instant::now();
            let valid = verify_decryption::<_, MinPk>(
                &mut rng,
                &public,
                (NAMESPACE, &target),
                &ciphertexts,
                &hints,
            );
            let batch = start.elapsed();
            assert!(valid);

            eprintln!(
                "n={n}: individual={individual:.2?} ({:.2?}/ct), batch={batch:.2?} ({:.2?}/ct), speedup={:.1}x",
                individual / n as u32,
                batch / n as u32,
                individual.as_secs_f64() / batch.as_secs_f64(),
            );
        }
    }
}
