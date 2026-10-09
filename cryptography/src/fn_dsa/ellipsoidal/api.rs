use super::{
    PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
    alloc::{vec, vec::Vec},
    codec, kgen,
    sign::Prepared,
    transcript,
};
use fn_dsa_comm::{hash_to_point, mq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SECRET_KEY_HEADER: u8 = 0xE3;
const SECRET_KEY_SIZE: usize = 3073;
const MAX_SIGNING_ATTEMPTS: u64 = 1024;

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct KeyMaterial {
    pub(super) f: [i8; 512],
    pub(super) g: [i8; 512],
    pub(super) big_f: [i16; 512],
    pub(super) big_g: [i16; 512],
}

impl KeyMaterial {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![0; SECRET_KEY_SIZE]);
        out[0] = SECRET_KEY_HEADER;
        for i in 0..512 {
            out[1 + i] = self.f[i] as u8;
            out[513 + i] = self.g[i] as u8;
            out[1025 + 2 * i..1027 + 2 * i].copy_from_slice(&self.big_f[i].to_le_bytes());
            out[2049 + 2 * i..2051 + 2 * i].copy_from_slice(&self.big_g[i].to_le_bytes());
        }
        out
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != SECRET_KEY_SIZE || raw[0] != SECRET_KEY_HEADER {
            return None;
        }
        let mut key = Self {
            f: [0; 512],
            g: [0; 512],
            big_f: [0; 512],
            big_g: [0; 512],
        };
        for i in 0..512 {
            key.f[i] = raw[1 + i] as i8;
            key.g[i] = raw[513 + i] as i8;
            key.big_f[i] = i16::from_le_bytes(raw[1025 + 2 * i..1027 + 2 * i].try_into().ok()?);
            key.big_g[i] = i16::from_le_bytes(raw[2049 + 2 * i..2051 + 2 * i].try_into().ok()?);
        }
        Some(key)
    }

    fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut h = [0; 512];
        let mut scratch = Zeroizing::new([0; 512]);
        mq::mqpoly_div_small_nttx(9, &self.f, &self.g, &mut h, &mut *scratch);
        codec::encode_public_key(&h)
    }
}

pub(in super::super) fn keygen(seed: &[u8; 32]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let mut rng = transcript::Randomness::for_keygen(seed);
    let key = kgen::generate(&mut rng);
    (key.encode(), key.public_key().to_vec())
}

pub(in super::super) fn sign(raw: &[u8], payload: &[u8], out: &mut [u8]) -> Option<()> {
    if out.len() != SIGNATURE_SIZE {
        return None;
    }
    let key = KeyMaterial::decode(raw)?;
    let prepared = Prepared::new(&key)?;
    let key_hash = transcript::public_key_hash(&key.public_key());
    let mu = transcript::message_representative_from_hash(&key_hash, payload);
    let signing_seed = transcript::signing_seed(raw, &key_hash);
    for counter in 0..MAX_SIGNING_ATTEMPTS {
        let (salt, sampler_seed) = transcript::attempt(&signing_seed, &mu, counter);
        let mut target = [0; 512];
        hash_to_point(&salt, &mu, &mut target);
        if let Some(Some(vector)) = prepared.sample(&target, &sampler_seed)
            && codec::encode_signature(&salt, &vector, out).is_some()
        {
            return Some(());
        }
    }
    None
}

pub(in super::super) fn signature_is_well_formed(raw: &[u8]) -> bool {
    codec::decode_signature(raw).is_some()
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
