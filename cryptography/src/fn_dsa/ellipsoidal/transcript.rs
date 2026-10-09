use sha3::{
    Shake256, Shake256Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

// Key generation and signing arithmetic are part of this versioned transcript.
// A change that can select a different signature must use a new version.
const DOMAIN: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ELLIPSOIDAL_FALCON512_V1_";

fn transcript(operation: &[u8], fields: &[&[u8]]) -> Shake256Reader {
    let mut hash = Shake256::default();
    hash.update(DOMAIN);
    hash.update(operation);
    hash.update(&[0]);
    for field in fields {
        hash.update(field);
    }
    hash.finalize_xof()
}

/// A non-cloneable SHAKE stream whose state is cleared by the hash implementation.
pub(super) struct Randomness {
    reader: Shake256Reader,
}

impl Randomness {
    pub(super) fn from_seed(seed: &[u8]) -> Self {
        let mut hash = Shake256::default();
        hash.update(seed);
        Self {
            reader: hash.finalize_xof(),
        }
    }

    pub(super) fn for_keygen(seed: &[u8; 32]) -> Self {
        Self {
            reader: transcript(b"KEYGEN", &[seed]),
        }
    }

    pub(super) fn fill(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }

    pub(super) fn u8(&mut self) -> u8 {
        let mut bytes = Zeroizing::new([0; 1]);
        self.fill(&mut *bytes);
        bytes[0]
    }

    pub(super) fn u16(&mut self) -> u16 {
        let mut bytes = Zeroizing::new([0; 2]);
        self.fill(&mut *bytes);
        u16::from_le_bytes(*bytes)
    }

    pub(super) fn u64(&mut self) -> u64 {
        let mut bytes = Zeroizing::new([0; 8]);
        self.fill(&mut *bytes);
        u64::from_le_bytes(*bytes)
    }
}

impl fn_dsa_comm::RngCore for Randomness {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = Zeroizing::new([0; 4]);
        self.fill(&mut *bytes);
        u32::from_le_bytes(*bytes)
    }

    fn next_u64(&mut self) -> u64 {
        self.u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fn_dsa_comm::RngError> {
        self.fill(dest);
        Ok(())
    }
}

pub(super) fn public_key_hash(key: &[u8]) -> [u8; 64] {
    let mut out = [0; 64];
    transcript(b"PK_HASH", &[key]).read(&mut out);
    out
}

pub(super) fn message_representative_from_hash(key_hash: &[u8; 64], payload: &[u8]) -> [u8; 64] {
    let mut out = [0; 64];
    transcript(
        b"MU",
        &[key_hash, &(payload.len() as u64).to_le_bytes(), payload],
    )
    .read(&mut out);
    out
}

pub(super) fn signing_seed(canonical_key: &[u8], key_hash: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0; 32]);
    transcript(b"SIGN_SEED", &[canonical_key, key_hash]).read(&mut *out);
    out
}

pub(super) fn attempt(
    seed: &[u8; 32],
    mu: &[u8; 64],
    counter: u64,
) -> ([u8; 40], Zeroizing<[u8; 40]>) {
    let counter = counter.to_le_bytes();
    let mut salt = [0; 40];
    let mut sampler_seed = Zeroizing::new([0; 40]);
    transcript(b"SALT", &[seed, mu, &counter]).read(&mut salt);
    transcript(b"SAMPLER", &[seed, mu, &counter]).read(&mut *sampler_seed);
    (salt, sampler_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_stream_matches_reference_shake() {
        let mut ours = Randomness::from_seed(b"ellipsoidal stream");
        let mut reference = fn_dsa_comm::shake::SHAKE256::new();
        reference.inject(b"ellipsoidal stream");
        reference.flip();
        let mut expected = [0; 257];
        reference.extract(&mut expected);
        assert_eq!(ours.u8(), expected[0]);
        assert_eq!(
            ours.u16(),
            u16::from_le_bytes(expected[1..3].try_into().unwrap())
        );
        assert_eq!(
            ours.u64(),
            u64::from_le_bytes(expected[3..11].try_into().unwrap())
        );
        let mut rest = [0; 246];
        ours.fill(&mut rest);
        assert_eq!(rest, expected[11..]);
    }

    #[test]
    fn transcripts_match_independent_shake_vectors() {
        // Python hashlib independently computes these byte-framed SHAKE vectors.
        let mut public = [0x37; 897];
        public[0] = 0xe1;
        let mut secret = [0xa7; 3073];
        secret[0] = 0xe3;
        let mut stream = [0; 32];
        Randomness::for_keygen(&[0x5c; 32]).fill(&mut stream);
        let key_hash = public_key_hash(&public);
        let mu = message_representative_from_hash(&key_hash, b"\0ellipsoidal\xff transcript\0");
        let seed = signing_seed(&secret, &key_hash);
        let (salt, sampler) = attempt(&seed, &mu, 0x0123_4567_89ab_cdef);
        assert_eq!(
            stream,
            [
                0xbb, 0xd2, 0xe6, 0x83, 0x26, 0x7d, 0x3b, 0x5b, 0xd6, 0xa3, 0xd7, 0x18, 0xf2, 0xf5,
                0x4a, 0x23, 0x4b, 0x34, 0x00, 0x6a, 0x9b, 0xbb, 0xb3, 0xd9, 0xdd, 0xd3, 0xfa, 0x49,
                0xf0, 0x7a, 0xd6, 0x11,
            ]
        );
        assert_eq!(
            key_hash,
            [
                0xf0, 0x3c, 0x70, 0x72, 0x96, 0x01, 0x3c, 0x51, 0x7e, 0x7c, 0x05, 0x86, 0xae, 0x37,
                0x0e, 0x1d, 0x76, 0xe1, 0xfb, 0xff, 0x31, 0xae, 0x38, 0x50, 0x83, 0x63, 0xa3, 0xf3,
                0xb1, 0x38, 0xc9, 0x77, 0x9c, 0x05, 0xd7, 0x9e, 0x5b, 0xb3, 0xd0, 0x4b, 0x22, 0x34,
                0x92, 0x01, 0xdd, 0x12, 0xa5, 0x93, 0x97, 0xc8, 0x3a, 0x10, 0x19, 0xfb, 0x8f, 0x93,
                0x2c, 0x70, 0xcb, 0x6f, 0x19, 0xc3, 0xd1, 0xa1,
            ]
        );
        assert_eq!(
            mu,
            [
                0x95, 0x9b, 0xa5, 0x64, 0x26, 0x51, 0xea, 0x5a, 0x78, 0x00, 0xab, 0x6a, 0xb0, 0x00,
                0xd8, 0xe5, 0x75, 0x33, 0xab, 0xb9, 0x48, 0xd3, 0x77, 0x43, 0xb7, 0x5b, 0x2d, 0x56,
                0xa7, 0xc8, 0x60, 0x07, 0x91, 0x1b, 0x7c, 0x70, 0x7c, 0x17, 0xb4, 0xa7, 0x1f, 0x39,
                0x0d, 0xb0, 0xa8, 0x69, 0x69, 0x67, 0x64, 0xa8, 0xd9, 0xb0, 0xa1, 0x86, 0x33, 0x54,
                0xb6, 0xe9, 0x03, 0x8e, 0x2c, 0xcf, 0x20, 0x47,
            ]
        );
        assert_eq!(
            *seed,
            [
                0x28, 0x4f, 0x91, 0x5c, 0xb3, 0xa4, 0x16, 0xd4, 0xed, 0x0e, 0xe5, 0x90, 0x1a, 0x0c,
                0x32, 0xec, 0x31, 0xda, 0x9f, 0x33, 0x6c, 0x5d, 0xe9, 0x06, 0xd4, 0xcf, 0x50, 0xa6,
                0x8b, 0x7f, 0x35, 0x9a,
            ]
        );
        assert_eq!(
            salt,
            [
                0xdb, 0xa7, 0xb8, 0xe8, 0xfe, 0x3f, 0x87, 0xcc, 0x1b, 0x63, 0x53, 0xe0, 0xe1, 0x8d,
                0x98, 0xd2, 0x2a, 0x83, 0x2f, 0x3e, 0xd7, 0x4d, 0x4c, 0x0b, 0xd9, 0x62, 0xa0, 0x4f,
                0x10, 0x8b, 0xb7, 0x57, 0x42, 0x14, 0x06, 0xc8, 0x80, 0x9d, 0x58, 0x7b,
            ]
        );
        assert_eq!(
            *sampler,
            [
                0x40, 0xc7, 0x66, 0x8e, 0x55, 0xf0, 0x54, 0x86, 0x0f, 0xb5, 0x7c, 0xd0, 0xc8, 0x47,
                0xf8, 0x6f, 0xad, 0x0b, 0x5d, 0x60, 0x60, 0xcb, 0x5a, 0x6f, 0xdc, 0xaf, 0x6d, 0xd5,
                0x3d, 0x56, 0xc4, 0x43, 0xbf, 0x64, 0xda, 0x9b, 0x9d, 0x02, 0x6e, 0x59,
            ]
        );
    }

    #[test]
    fn transcripts_bind_key_message_counter_and_operation() {
        let key_hash = public_key_hash(&[0; 897]);
        let mu = message_representative_from_hash(&key_hash, b"message");
        assert_ne!(
            mu,
            message_representative_from_hash(&key_hash, b"message\0")
        );
        assert_ne!(
            mu,
            message_representative_from_hash(&public_key_hash(&[1; 897]), b"message")
        );
        let seed = signing_seed(&[1; 3073], &key_hash);
        let (salt, sampler) = attempt(&seed, &mu, 0);
        assert_ne!(salt, *sampler);
        assert_ne!(salt, attempt(&seed, &mu, 1).0);
        assert_ne!(salt, attempt(&[3; 32], &mu, 0).0);
        assert_eq!((salt, *sampler), {
            let (s, r) = attempt(&seed, &mu, 0);
            (s, *r)
        });
    }
}
