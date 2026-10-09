use super::{codec, message_representative_from_hash, public_key_hash};
use fn_dsa_comm::{hash_to_point, mq};

const LOGN: u32 = 9;
const DEGREE: usize = 512;
const MODULUS: i64 = 12289;
const SQUARED_NORM_LIMIT: u64 = 1_225_250_136;

/// An ellipsoidal Falcon public key prepared for integer verification.
pub struct VerifyingKey {
    h: [u16; DEGREE],
    hashed_key: [u8; 64],
}

impl VerifyingKey {
    pub(crate) fn decode(raw: &[u8]) -> Option<Self> {
        // The wire key already contains the NTT of h; only its zero convention changes.
        let mut h = codec::decode_public_key(raw)?;
        mq::mqpoly_ext_to_int(LOGN, &mut h);
        Some(Self {
            h,
            hashed_key: public_key_hash(raw),
        })
    }

    pub(crate) fn verify(&self, payload: &[u8], sig: &[u8]) -> bool {
        let Some((salt, s)) = codec::decode_signature(sig) else {
            return false;
        };
        let mu = message_representative_from_hash(&self.hashed_key, payload);
        let mut c = [0u16; DEGREE];
        hash_to_point(&salt, &mu, &mut c);
        verify_vector(&self.h, c, &s)
    }
}

fn verify_vector(h: &[u16; DEGREE], mut c: [u16; DEGREE], s: &[i16; DEGREE]) -> bool {
    let mut product = [0u16; DEGREE];
    mq::mqpoly_signed_to_ext(LOGN, s, &mut product);
    mq::mqpoly_ext_to_int(LOGN, &mut product);
    mq::mqpoly_int_to_NTT(LOGN, &mut product);
    mq::mqpoly_mul_ntt(LOGN, &mut product, h);
    mq::mqpoly_NTT_to_int(LOGN, &mut product);
    mq::mqpoly_ext_to_int(LOGN, &mut c);
    mq::mqpoly_sub_int(LOGN, &mut c, &product);
    mq::mqpoly_int_to_ext(LOGN, &mut c);

    // Canonical signatures have |s| <= 972; centered residuals have |r| <= 6144.
    // Their complete weighted squared norm is below 2^40.
    let mut norm = 0u64;
    for (residual, coefficient) in c.into_iter().zip(s) {
        let mut residual = i64::from(residual);
        if residual > MODULUS / 2 {
            residual -= MODULUS;
        }
        let coefficient = i64::from(*coefficient);
        norm += (residual * residual) as u64 + 1296 * (coefficient * coefficient) as u64;
    }
    norm <= SQUARED_NORM_LIMIT
}

#[cfg(test)]
mod tests {
    use super::{super::SIGNATURE_SIZE, *};

    fn constant_key(value: u16) -> VerifyingKey {
        VerifyingKey::decode(&codec::encode_public_key(&[value; DEGREE])).unwrap()
    }

    #[test]
    fn exact_norm_boundary() {
        let key = constant_key(0);
        let mut s = [0; DEGREE];
        s[0] = 972;
        let mut c = [0; DEGREE];
        c[0] = 900;
        c[1] = 6;
        c[2] = 6;
        assert!(verify_vector(&key.h, c, &s));
        c[3] = 1;
        assert!(!verify_vector(&key.h, c, &s));
    }

    #[test]
    fn rejects_norm_overflow() {
        let key = constant_key(0);
        let mut s = [0; DEGREE];
        s[..4].fill(972);
        assert!(!verify_vector(&key.h, [0; DEGREE], &s));
        s.fill(972);
        assert!(!verify_vector(&key.h, [6144; DEGREE], &s));
    }

    #[test]
    fn centered_residuals_allow_modular_wrap() {
        let key = constant_key(1);
        let mut s = [0; DEGREE];
        s[0] = 1;
        let mut c = [0; DEGREE];
        c[..13].fill(10000);
        c[0] += 1;
        assert!(verify_vector(&key.h, c, &s));
    }

    #[test]
    fn wire_key_remains_in_ntt_domain() {
        let mut h = [0; DEGREE];
        h[0] = 2;
        h[1] = 3;
        h[511] = 4;
        mq::mqpoly_ext_to_int(LOGN, &mut h);
        mq::mqpoly_int_to_NTT(LOGN, &mut h);
        mq::mqpoly_int_to_ext(LOGN, &mut h);
        let key = VerifyingKey::decode(&codec::encode_public_key(&h)).unwrap();

        let mut s = [0; DEGREE];
        s[1] = 972;
        let mut c = [0; DEGREE];
        c[0] = 12289 - 3888;
        c[1] = 1944;
        c[2] = 2916;
        assert!(verify_vector(&key.h, c, &s));

        c[0] = 0;
        assert!(!verify_vector(&key.h, c, &s));
    }

    #[test]
    fn public_verifier_rejects_malformed_signatures() {
        let key = constant_key(0);
        for len in 0..SIGNATURE_SIZE {
            assert!(!key.verify(b"message", &[0; SIGNATURE_SIZE][..len]));
        }
        assert!(!key.verify(b"message", &[0; SIGNATURE_SIZE]));
        assert!(!key.verify(b"message", &[0; SIGNATURE_SIZE + 1]));
    }
}
