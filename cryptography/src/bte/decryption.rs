use crate::bls12381::primitives::group::{Scalar, G1, G2, GT};
use commonware_codec::Encode;
use commonware_math::algebra::{Additive, CryptoGroup, Space};
use commonware_parallel::Sequential;
use std::collections::BTreeMap;

use super::{
    dealer::CRS,
    encryption::Ciphertext,
    utils::{lagrange_interp_eval, open_all_values, xor, Domain},
};

/// Domain separation tag for hashing G1 to scalar in BTE decryption.
const DST_HASH_TO_SCALAR: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_BTE_HASH_TO_SCALAR";

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
    pub fn partial_decrypt(&self, ct: &[Ciphertext], hid: G1, pk: G2, crs: &CRS) -> G1 {
        let batch_size = crs.powers_of_g.len();
        for i in 0..batch_size {
            ct[i].verify(crs.htau, pk);
        }

        let tx_domain = Domain::new(batch_size);

        let fevals: Vec<Scalar> = (0..batch_size)
            .map(|i| {
                let tg_bytes = *blake3::hash(ct[i].gs.encode().as_ref()).as_bytes();
                Scalar::map(DST_HASH_TO_SCALAR, &tg_bytes)
            })
            .collect();

        let fcoeffs = tx_domain.ifft(&fevals);
        let com = G1::msm(&crs.powers_of_g, &fcoeffs, &Sequential);
        let delta = hid - &com;

        delta * &self.sk_share
    }
}

/// Aggregate partial decryptions into a signature on H(id)/com.
pub fn aggregate_partial_decryptions(partial_decryptions: &BTreeMap<usize, G1>) -> G1 {
    let mut evals = Vec::new();
    let mut eval_points = Vec::new();
    for (&key, &value) in partial_decryptions.iter() {
        evals.push(value);
        eval_points.push(Scalar::from_u64(key as u64));
    }

    lagrange_interp_eval(&eval_points, &[Scalar::zero()], &evals)[0]
}

/// Decrypt all ciphertexts in a batch.
pub fn decrypt_all(sigma: G1, ct: &[Ciphertext], hid: G1, crs: &CRS) -> Vec<[u8; 32]> {
    let batch_size = ct.len();

    let tx_domain = Domain::new(batch_size);

    // Compute fevals by hashing gs of the ciphertexts
    let fevals: Vec<Scalar> = (0..batch_size)
        .map(|i| {
            let tg_bytes = *blake3::hash(ct[i].gs.encode().as_ref()).as_bytes();
            Scalar::map(DST_HASH_TO_SCALAR, &tg_bytes)
        })
        .collect();

    let fcoeffs = tx_domain.ifft(&fevals);

    let com = G1::msm(&crs.powers_of_g, &fcoeffs, &Sequential);
    let delta = hid - &com;

    // Use FK22 to get all the KZG proofs in O(n log n) time
    let pi = open_all_values(&crs.y, &fcoeffs, &tx_domain);

    // Decrypt each ciphertext: m = ct1 xor H(e(pi, ct2) * e(delta, ct3) * e(-sigma, ct4))
    let neg_sigma = -sigma;
    let mut m = vec![[0u8; 32]; batch_size];
    for i in 0..batch_size {
        let mask = GT::multi_pairing(&[(pi[i], ct[i].ct2), (delta, ct[i].ct3), (neg_sigma, ct[i].ct4)]);

        let hmask = *blake3::hash(&mask.as_slice()).as_bytes();
        m[i] = xor(&ct[i].ct1, &hmask).as_slice().try_into().unwrap();
    }

    m
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
        let (crs, sk_shares) = dealer.setup(&mut rng);

        let secret_keys: Vec<SecretKey> = sk_shares
            .iter()
            .map(|sk| SecretKey::new(sk.clone()))
            .collect();

        let tx_domain = Domain::new(batch_size);

        let msg = [1u8; 32];
        let hid = G1::generator() * &Scalar::random(&mut rng);
        let pk = dealer.get_pk();

        let ct: Vec<Ciphertext> = (0..batch_size)
            .map(|i| encrypt(msg, tx_domain.element(i), hid, crs.htau, pk, &mut rng))
            .collect();

        let mut partial_decryptions: BTreeMap<usize, G1> = BTreeMap::new();
        for i in 0..n / 2 {
            let partial = secret_keys[i].partial_decrypt(&ct, hid, pk, &crs);
            partial_decryptions.insert(i + 1, partial);
        }

        let sigma = aggregate_partial_decryptions(&partial_decryptions);
        let messages = decrypt_all(sigma, &ct, hid, &crs);
        for i in 0..batch_size {
            assert_eq!(msg, messages[i]);
        }
    }
}
