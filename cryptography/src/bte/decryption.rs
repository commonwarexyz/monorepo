use crate::bls12381::primitives::group::{Scalar, SmallScalar, G1, G2, GT};
use commonware_math::algebra::{Additive, CryptoGroup, Space};
use commonware_parallel::Sequential;
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

use super::{
    dealer::{PublicKey, CRS},
    encryption::{compute_tg, hash_hm, hash_hr, Ciphertext},
    utils::{lagrange_interp_eval, open_all_values, xor, Domain},
};

/// A secret key share for threshold decryption.
pub struct SecretKey {
    sk_share: Scalar,
}

impl SecretKey {
    pub fn new(sk_share: Scalar) -> Self {
        SecretKey { sk_share }
    }

    pub fn get_pk(&self) -> G2 {
        G2::generator() * &self.sk_share
    }

    /// Compute a partial decryption for a batch of ciphertexts.
    ///
    /// Returns sigma_j = sk_j * (H_G(eid) - com).
    pub fn partial_decrypt(&self, ct: &[Ciphertext], hid: G1, crs: &CRS) -> G1 {
        let batch_size = crs.powers_of_g.len();
        let tx_domain = Domain::new(batch_size);

        let fevals: Vec<Scalar> = (0..batch_size).map(|i| compute_tg(&ct[i].gs)).collect();

        let fcoeffs = tx_domain.ifft(&fevals);
        let com = G1::msm(&crs.powers_of_g, &fcoeffs, &Sequential);
        let delta = hid - &com;

        delta * &self.sk_share
    }
}

/// Aggregate partial decryptions into sigma = sk * (H_G(eid) - com).
pub fn aggregate_partial_decryptions(partial_decryptions: &BTreeMap<usize, G1>) -> G1 {
    let mut evals = Vec::new();
    let mut eval_points = Vec::new();
    for (&key, &value) in partial_decryptions.iter() {
        evals.push(value);
        eval_points.push(Scalar::from_u64(key as u64));
    }

    lagrange_interp_eval(&eval_points, &[Scalar::zero()], &evals)[0]
}

/// Result of decrypting a single ciphertext, including hints for batch verification.
pub struct Decrypted {
    pub msg: [u8; 32],
    pub key: [u8; 32],
    pub hint: GT,
}

/// Decrypt all ciphertexts in a batch using the FO transform.
///
/// For each ciphertext, recovers K from ct1, then msg from ct4, verifies
/// ct3 = [alpha]_2, and returns (msg, K, P) where P is the GT pairing hint
/// for batch verification.
pub fn decrypt_all(sigma: G1, ct: &[Ciphertext], crs: &CRS) -> Vec<Decrypted> {
    let batch_size = ct.len();
    let h = G2::generator();
    let tx_domain = Domain::new(batch_size);

    let fevals: Vec<Scalar> = (0..batch_size).map(|i| compute_tg(&ct[i].gs)).collect();
    let fcoeffs = tx_domain.ifft(&fevals);

    let pi = open_all_values(&crs.y, &fcoeffs, &tx_domain);

    let mut results = Vec::with_capacity(batch_size);
    for i in 0..batch_size {
        // P_i = e(pi_i, ct2_i) + e(sigma, ct3_i)
        let p = GT::multi_pairing(&[(pi[i], ct[i].ct2), (sigma, ct[i].ct3)]);

        // K_i = ct1 XOR H(P_i)
        let h_p = *blake3::hash(&p.as_slice()).as_bytes();
        let key: [u8; 32] = xor(&ct[i].ct1, &h_p).as_slice().try_into().unwrap();

        // msg_i = ct4 XOR H_M(K_i)
        let msg: [u8; 32] = xor(&ct[i].ct4, &hash_hm(&key))
            .as_slice()
            .try_into()
            .unwrap();

        // Verify ct3 = [alpha]_2
        let alpha = hash_hr(&key, &msg);
        assert_eq!(ct[i].ct3, h * &alpha, "FO check failed at index {i}");

        results.push(Decrypted {
            msg,
            key,
            hint: p,
        });
    }

    results
}

/// Batch-verify a set of decrypted ciphertexts using the FO transform hints.
///
/// Given B ciphertexts and their decryption hints (K_i, P_i), verifies:
/// 1. Per-ciphertext: ct1_i = H(P_i) XOR K_i
/// 2. G2 batch check: random linear combination of ct2 and ct3
/// 3. GT batch check: random linear combination of P_i against a single pairing
pub fn batch_verify(
    ct: &[Ciphertext],
    decrypted: &[Decrypted],
    hid: G1,
    pk: &PublicKey,
    rng: &mut impl CryptoRngCore,
) -> bool {
    let batch_size = ct.len();
    assert_eq!(decrypted.len(), batch_size);
    let g = G1::generator();
    let h = G2::generator();

    // Step 1: per-ciphertext scalar checks; recover alpha_i and tg_i
    let mut alphas = Vec::with_capacity(batch_size);
    let mut tgs = Vec::with_capacity(batch_size);
    for i in 0..batch_size {
        let tg = compute_tg(&ct[i].gs);
        tgs.push(tg);

        // msg_i = ct4 XOR H_M(K_i)
        let msg: [u8; 32] = xor(&ct[i].ct4, &hash_hm(&decrypted[i].key))
            .as_slice()
            .try_into()
            .unwrap();

        // alpha_i = H_R(K_i, msg_i)
        let alpha = hash_hr(&decrypted[i].key, &msg);
        alphas.push(alpha);

        // Verify ct1_i = H(P_i) XOR K_i
        let h_p = *blake3::hash(&decrypted[i].hint.as_slice()).as_bytes();
        let expected_ct1: [u8; 32] = xor(&decrypted[i].key, &h_p).as_slice().try_into().unwrap();
        if ct[i].ct1 != expected_ct1 {
            return false;
        }
    }

    // Step 2: sample 128-bit challenges and batch-check ct2 and ct3
    // LHS: sum_i r_i * ct3_i + sum_i r_{B+i} * ct2_i
    // RHS: c1 * h + c2 * hsk_tau - c3 * hsk
    let r: Vec<SmallScalar> = (0..2 * batch_size)
        .map(|_| SmallScalar::random(&mut *rng))
        .collect();

    let mut c1 = Scalar::zero();
    let mut c2 = Scalar::zero();
    let mut c3 = Scalar::zero();
    for i in 0..batch_size {
        let ri_alpha = &r[i] * &alphas[i];
        c1 += &ri_alpha;
        let rbi_alpha = &r[batch_size + i] * &alphas[i];
        c2 += &rbi_alpha;
        let rbi_alpha_x = rbi_alpha * &ct[i].x;
        c3 += &rbi_alpha_x;
    }

    let mut g2_bases = Vec::with_capacity(2 * batch_size);
    let mut g2_scalars = Vec::with_capacity(2 * batch_size);
    for i in 0..batch_size {
        g2_bases.push(ct[i].ct3);
        g2_scalars.push(r[i].clone());
    }
    for i in 0..batch_size {
        g2_bases.push(ct[i].ct2);
        g2_scalars.push(r[batch_size + i].clone());
    }
    let lhs_g2 = G2::msm(&g2_bases, &g2_scalars, &Sequential);
    let rhs_g2 = h * &c1 + &(pk.hsk_tau * &c2) - &(pk.hsk * &c3);

    if lhs_g2 != rhs_g2 {
        return false;
    }

    // Step 3: batch-check shared secrets in GT
    // LHS: sum_i r_i * P_i (GT linear combination)
    // RHS: e(c1 * hid - c4 * g, hsk)
    let mut c4 = Scalar::zero();
    for i in 0..batch_size {
        let ri_alpha_tg = &r[i] * &alphas[i] * &tgs[i];
        c4 += &ri_alpha_tg;
    }

    let gt_hints: Vec<GT> = decrypted.iter().map(|d| d.hint).collect();
    let r_first_b = &r[..batch_size];
    let lhs_gt = GT::msm(&gt_hints, r_first_b, &Sequential);
    let rhs_gt = GT::pairing(&(hid * &c1 - &(g * &c4)), &pk.hsk);

    lhs_gt == rhs_gt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bte::dealer::Dealer;
    use crate::bte::encryption::encrypt;
    use crate::bte::utils::Domain;
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_utils::test_rng;

    #[test]
    fn test_end_to_end_decrypt() {
        let mut rng = test_rng();
        let batch_size = 1 << 5;
        let n = 1 << 3;

        let mut dealer = Dealer::new(batch_size, n, n / 2 - 1, &mut rng);
        let (crs, pk, sk_shares) = dealer.setup(&mut rng);

        let secret_keys: Vec<SecretKey> = sk_shares
            .iter()
            .map(|sk| SecretKey::new(sk.clone()))
            .collect();

        let tx_domain = Domain::new(batch_size);

        let msg = [1u8; 32];
        let hid = G1::generator() * &Scalar::random(&mut rng);

        let ct: Vec<Ciphertext> = (0..batch_size)
            .map(|i| encrypt(msg, tx_domain.element(i), hid, &pk, &mut rng))
            .collect();

        let mut partial_decryptions: BTreeMap<usize, G1> = BTreeMap::new();
        for i in 0..n / 2 {
            let partial = secret_keys[i].partial_decrypt(&ct, hid, &crs);
            partial_decryptions.insert(i + 1, partial);
        }

        let sigma = aggregate_partial_decryptions(&partial_decryptions);
        let decrypted = decrypt_all(sigma, &ct, &crs);
        for i in 0..batch_size {
            assert_eq!(msg, decrypted[i].msg);
        }
    }

    #[test]
    fn test_end_to_end_distinct_messages() {
        let mut rng = test_rng();
        let batch_size = 1 << 4;
        let n = 1 << 3;

        let mut dealer = Dealer::new(batch_size, n, n / 2 - 1, &mut rng);
        let (crs, pk, sk_shares) = dealer.setup(&mut rng);

        let secret_keys: Vec<SecretKey> = sk_shares
            .iter()
            .map(|sk| SecretKey::new(sk.clone()))
            .collect();

        let tx_domain = Domain::new(batch_size);
        let hid = G1::generator() * &Scalar::random(&mut rng);

        let msgs: Vec<[u8; 32]> = (0..batch_size)
            .map(|i| {
                let mut m = [0u8; 32];
                m[0] = i as u8;
                m[1] = 0xAB;
                m
            })
            .collect();

        let ct: Vec<Ciphertext> = (0..batch_size)
            .map(|i| encrypt(msgs[i], tx_domain.element(i), hid, &pk, &mut rng))
            .collect();

        let mut partial_decryptions: BTreeMap<usize, G1> = BTreeMap::new();
        for i in 0..n / 2 {
            let partial = secret_keys[i].partial_decrypt(&ct, hid, &crs);
            partial_decryptions.insert(i + 1, partial);
        }

        let sigma = aggregate_partial_decryptions(&partial_decryptions);
        let decrypted = decrypt_all(sigma, &ct, &crs);
        for i in 0..batch_size {
            assert_eq!(msgs[i], decrypted[i].msg, "mismatch at index {i}");
        }
    }

    #[test]
    fn test_batch_verify() {
        let mut rng = test_rng();
        let batch_size = 1 << 4;
        let n = 1 << 3;

        let mut dealer = Dealer::new(batch_size, n, n / 2 - 1, &mut rng);
        let (crs, pk, sk_shares) = dealer.setup(&mut rng);

        let secret_keys: Vec<SecretKey> = sk_shares
            .iter()
            .map(|sk| SecretKey::new(sk.clone()))
            .collect();

        let tx_domain = Domain::new(batch_size);
        let hid = G1::generator() * &Scalar::random(&mut rng);

        let msgs: Vec<[u8; 32]> = (0..batch_size)
            .map(|i| {
                let mut m = [0u8; 32];
                m[0] = i as u8;
                m
            })
            .collect();

        let ct: Vec<Ciphertext> = (0..batch_size)
            .map(|i| encrypt(msgs[i], tx_domain.element(i), hid, &pk, &mut rng))
            .collect();

        let mut partial_decryptions: BTreeMap<usize, G1> = BTreeMap::new();
        for i in 0..n / 2 {
            let partial = secret_keys[i].partial_decrypt(&ct, hid, &crs);
            partial_decryptions.insert(i + 1, partial);
        }

        let sigma = aggregate_partial_decryptions(&partial_decryptions);
        let decrypted = decrypt_all(sigma, &ct, &crs);

        // Batch verify should pass
        assert!(batch_verify(&ct, &decrypted, hid, &pk, &mut rng));
    }

    #[test]
    fn test_batch_verify_tampered_key() {
        let mut rng = test_rng();
        let batch_size = 1 << 3;
        let n = 1 << 3;

        let mut dealer = Dealer::new(batch_size, n, n / 2 - 1, &mut rng);
        let (crs, pk, sk_shares) = dealer.setup(&mut rng);

        let secret_keys: Vec<SecretKey> = sk_shares
            .iter()
            .map(|sk| SecretKey::new(sk.clone()))
            .collect();

        let tx_domain = Domain::new(batch_size);
        let hid = G1::generator() * &Scalar::random(&mut rng);

        let ct: Vec<Ciphertext> = (0..batch_size)
            .map(|i| encrypt([i as u8; 32], tx_domain.element(i), hid, &pk, &mut rng))
            .collect();

        let mut partial_decryptions: BTreeMap<usize, G1> = BTreeMap::new();
        for i in 0..n / 2 {
            let partial = secret_keys[i].partial_decrypt(&ct, hid, &crs);
            partial_decryptions.insert(i + 1, partial);
        }

        let sigma = aggregate_partial_decryptions(&partial_decryptions);
        let mut decrypted = decrypt_all(sigma, &ct, &crs);

        // Tamper with one key
        decrypted[0].key[0] ^= 0xFF;

        // Batch verify should fail
        assert!(!batch_verify(&ct, &decrypted, hid, &pk, &mut rng));
    }

    #[test]
    #[ignore]
    fn bench_decrypt_vs_verify() {
        use std::time::Instant;

        let n = 1 << 4;
        let iters = 3;
        let h = G2::generator();

        println!(
            "\n{:>10} {:>10} {:>10} {:>10} | {:>10} {:>8}",
            "batch", "fk22(ms)", "pair(ms)", "dec(ms)", "verify(ms)", "ratio"
        );
        println!("{}", "-".repeat(70));

        for lg in 2..=12 {
            let batch_size = 1 << lg;
            let mut rng = test_rng();
            let tx_domain = Domain::new(batch_size);

            let mut dealer = Dealer::new(batch_size, n, n / 2 - 1, &mut rng);
            let (crs, pk, sk_shares) = dealer.setup(&mut rng);

            let secret_keys: Vec<SecretKey> = sk_shares
                .iter()
                .map(|sk| SecretKey::new(sk.clone()))
                .collect();

            let hid = G1::generator() * &Scalar::random(&mut rng);

            let ct: Vec<Ciphertext> = (0..batch_size)
                .map(|i| {
                    let mut m = [0u8; 32];
                    m[0] = i as u8;
                    encrypt(m, tx_domain.element(i), hid, &pk, &mut rng)
                })
                .collect();

            let mut partial_decryptions: BTreeMap<usize, G1> = BTreeMap::new();
            for i in 0..n / 2 {
                let partial = secret_keys[i].partial_decrypt(&ct, hid, &crs);
                partial_decryptions.insert(i + 1, partial);
            }
            let sigma = aggregate_partial_decryptions(&partial_decryptions);

            // Warmup
            let decrypted = decrypt_all(sigma, &ct, &crs);
            assert!(batch_verify(&ct, &decrypted, hid, &pk, &mut rng));

            // Time decrypt_all with breakdown
            let mut fk22_total = 0.0f64;
            let mut pair_total = 0.0f64;
            for _ in 0..iters {
                let fevals: Vec<Scalar> =
                    (0..batch_size).map(|i| compute_tg(&ct[i].gs)).collect();

                let start = Instant::now();
                let fcoeffs = tx_domain.ifft(&fevals);
                let pi = open_all_values(&crs.y, &fcoeffs, &tx_domain);
                fk22_total += start.elapsed().as_secs_f64() * 1000.0;

                let start = Instant::now();
                for i in 0..batch_size {
                    let p = GT::multi_pairing(&[(pi[i], ct[i].ct2), (sigma, ct[i].ct3)]);
                    let h_p = *blake3::hash(&p.as_slice()).as_bytes();
                    let key: [u8; 32] =
                        xor(&ct[i].ct1, &h_p).as_slice().try_into().unwrap();
                    let msg: [u8; 32] =
                        xor(&ct[i].ct4, &hash_hm(&key)).as_slice().try_into().unwrap();
                    let alpha = hash_hr(&key, &msg);
                    assert_eq!(ct[i].ct3, h * &alpha);
                    std::hint::black_box((&key, &msg));
                }
                pair_total += start.elapsed().as_secs_f64() * 1000.0;
            }
            let fk22_ms = fk22_total / iters as f64;
            let pair_ms = pair_total / iters as f64;
            let decrypt_ms = fk22_ms + pair_ms;

            // Time batch_verify
            let start = Instant::now();
            for _ in 0..iters {
                let _ = batch_verify(&ct, &decrypted, hid, &pk, &mut rng);
            }
            let verify_ms = start.elapsed().as_secs_f64() * 1000.0 / iters as f64;

            println!(
                "{:>10} {:>10.2} {:>10.2} {:>10.2} | {:>10.2} {:>8.2}x",
                batch_size, fk22_ms, pair_ms, decrypt_ms, verify_ms, decrypt_ms / verify_ms
            );
        }
    }
}
