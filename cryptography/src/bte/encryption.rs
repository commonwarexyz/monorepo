use crate::bls12381::primitives::group::{Scalar, G1, G2, GT};
use commonware_codec::Encode;
use commonware_math::algebra::{CryptoGroup, Random};
use rand_core::CryptoRngCore;

use super::utils::xor;

/// Domain separation tag for hashing to scalar in BTE.
const DST_HASH_TO_SCALAR: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_BTE_HASH_TO_SCALAR";

/// A ciphertext in the batch threshold encryption scheme.
#[derive(Clone)]
pub struct Ciphertext {
    pub ct1: [u8; 32],
    pub ct2: G2,
    pub ct3: G2,
    pub ct4: G2,
    pub gs: G1,
    pub x: Scalar,
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
        let hgs = *blake3::hash(gs.encode().as_ref()).as_bytes();
        Scalar::map(DST_HASH_TO_SCALAR, &hgs)
    };

    // Compute mask: e(H(id) - g*tg, h)^alpha
    let alpha = Scalar::random(&mut *rng);
    let beta = Scalar::random(&mut *rng);
    let mask = GT::pairing(&(hid - &(g * &tg)), &h).scalar_mul(&alpha);
    let hmask = *blake3::hash(&mask.as_slice()).as_bytes();

    // XOR msg and hmask
    let ct1: [u8; 32] = xor(&msg, &hmask).as_slice().try_into().unwrap();
    let ct2 = (htau - &(h * &x)) * &alpha;
    let ct3 = h * &alpha + &(pk * &beta);
    let ct4 = h * &beta;

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
        let (crs, _) = dealer.setup(&mut rng);
        let pk = dealer.get_pk();

        let msg = [1u8; 32];
        let x = tx_domain.group_gen();

        let hid = G1::generator() * &Scalar::random(&mut rng);
        let _ct = encrypt(msg, x, hid, crs.htau, pk, &mut rng);
    }
}
