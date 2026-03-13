use crate::bls12381::primitives::group::{Scalar, G1, G2, GT};
use commonware_codec::Encode;
use commonware_math::algebra::{CryptoGroup, Random};
use rand_core::CryptoRngCore;

use super::dealer::PublicKey;
use super::utils::xor;

/// Domain separation tag for hashing to scalar (used for tg computation).
const DST_HASH_TO_SCALAR: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_BTE_HASH_TO_SCALAR";
/// Domain separation for H_M: key -> message mask.
const DST_HM: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_BTE_HM";
/// Domain separation for H_R: (key, msg) -> randomness alpha.
const DST_HR: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_BTE_HR";

/// Compute H_M(key): hash a 32-byte key to a 32-byte message mask.
pub(crate) fn hash_hm(key: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_HM);
    h.update(key);
    *h.finalize().as_bytes()
}

/// Compute H_R(key, msg): derive the randomness scalar alpha from key and message.
pub(crate) fn hash_hr(key: &[u8; 32], msg: &[u8; 32]) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(DST_HR);
    h.update(key);
    h.update(msg);
    let preimage = *h.finalize().as_bytes();
    Scalar::map(DST_HASH_TO_SCALAR, &preimage)
}

/// Compute tg = H_F(S) from a G1 commitment S.
pub(crate) fn compute_tg(gs: &G1) -> Scalar {
    let hgs = *blake3::hash(gs.encode().as_ref()).as_bytes();
    Scalar::map(DST_HASH_TO_SCALAR, &hgs)
}

/// A ciphertext in the batch threshold encryption scheme with FO transform.
///
/// ct1 = H(mask) XOR K, ct2 = alpha * [sk*(tau - x)]_2,
/// ct3 = alpha * h, ct4 = H_M(K) XOR msg.
#[derive(Clone)]
pub struct Ciphertext {
    pub ct1: [u8; 32],
    pub ct2: G2,
    pub ct3: G2,
    pub ct4: [u8; 32],
    pub gs: G1,
    pub x: Scalar,
}

/// Encrypt a 32-byte message using batch threshold encryption with the FO transform.
///
/// Samples a random key K, derives alpha = H_R(K, msg), and produces a ciphertext
/// where ct1 encrypts K (not msg directly) and ct4 = H_M(K) XOR msg.
pub fn encrypt(
    msg: [u8; 32],
    x: Scalar,
    hid: G1,
    pk: &PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Ciphertext {
    let g = G1::generator();
    let h = G2::generator();

    let s = Scalar::random(&mut *rng);
    let gs = g * &s;
    let tg = compute_tg(&gs);

    // Sample random key K and derive alpha = H_R(K, msg)
    let key: [u8; 32] = {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        k
    };
    let alpha = hash_hr(&key, &msg);

    // mask = e(H_G(eid) - [tg]_1, [sk]_2)^alpha
    let mask = GT::pairing(&(hid - &(g * &tg)), &pk.hsk).scalar_mul(&alpha);
    let hmask = *blake3::hash(&mask.as_slice()).as_bytes();

    // ct1 = H(mask) XOR K (encrypts the key, not the message)
    let ct1: [u8; 32] = xor(&key, &hmask).as_slice().try_into().unwrap();
    // ct2 = alpha * [sk*(tau - x)]_2
    let ct2 = (pk.hsk_tau - &(pk.hsk * &x)) * &alpha;
    // ct3 = alpha * h
    let ct3 = h * &alpha;
    // ct4 = H_M(K) XOR msg
    let ct4: [u8; 32] = xor(&msg, &hash_hm(&key)).as_slice().try_into().unwrap();

    Ciphertext {
        ct1,
        ct2,
        ct3,
        ct4,
        gs,
        x,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bte::dealer::Dealer;
    use crate::bte::utils::Domain;
    use commonware_utils::test_rng;

    #[test]
    fn test_encryption() {
        let mut rng = test_rng();

        let batch_size = 1 << 5;
        let n = 1 << 4;
        let tx_domain = Domain::new(batch_size);

        let mut dealer = Dealer::new(batch_size, n, n / 2 - 1, &mut rng);
        let (_, pk, _) = dealer.setup(&mut rng);

        let msg = [1u8; 32];
        let x = tx_domain.group_gen();

        let hid = G1::generator() * &Scalar::random(&mut rng);
        let ct = encrypt(msg, x, hid, &pk, &mut rng);

        // Verify ct3 = [alpha]_2 by re-deriving alpha from ct
        // (Not possible without K, but we can at least verify the ciphertext is well-formed)
        assert_ne!(ct.ct1, [0u8; 32]);
        assert_ne!(ct.ct4, [0u8; 32]);
    }
}
