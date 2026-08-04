//! Ed25519 signing keys, signatures, and verification.

use crate::{
    signing::{self, Scalar},
    simplified::{G, GAffine},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, Write};
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::union_unique;
use rand_core::CryptoRng;
use sha2::{
    Digest,
    digest::{FixedOutput, Update},
};

/// An Ed25519 signing key.
pub struct SigningKey {
    /// When serializing, we want to just write the seed, so we keep it around.
    seed: [u8; 32],
    /// The private prefix we use to derive a deterministic nonce for each message.
    #[allow(dead_code)]
    prefix: [u8; 32],
    /// The pruned, unreduced secret scalar we use for group operations.
    scalar_le_bytes: [u8; 32],
}

// Private methods.
impl SigningKey {
    fn from_seed(seed: [u8; 32]) -> Self {
        // Following: https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5.
        // The first half becomes our secret scalar material, while the second half
        // is the private prefix we use to derive deterministic nonces.
        let h: [u8; 64] = sha2::Sha512::new().chain(seed).finalize_fixed().into();
        let mut scalar_le_bytes: [u8; 32] = h[..32].try_into().expect("h is 64 bytes");
        let prefix: [u8; 32] = h[32..].try_into().expect("h is 64 bytes");
        // We want the integer represented by these little-endian bytes to be a
        // multiple of the curve's cofactor, 8, so we "clamp" it by zeroing its
        // three least-significant bits. This is part of Ed25519 key derivation too,
        // not just key exchange.
        scalar_le_bytes[0] &= 0b1111_1000;
        // We also want the scalar to fit in 255 bits, so we unset bit 255. This
        // doesn't put it below L; scalar-field arithmetic still has to reduce it
        // modulo L.
        scalar_le_bytes[31] &= 0b0111_1111;
        // The RFC also requires us to set bit 254, giving the scalar a fixed 255-bit
        // length. Among other things, this forces scalar-multiplication implementations
        // that start at the highest set bit to use the same number of iterations. It
        // doesn't make a variable-time implementation safe by itself.
        scalar_le_bytes[31] |= 0b0100_0000;
        Self {
            seed,
            prefix,
            scalar_le_bytes,
        }
    }
}

impl Random for SigningKey {
    fn random(mut rng: impl rand_core::CryptoRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }
}

impl Write for SigningKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.seed.write(buf);
    }
}

impl FixedSize for SigningKey {
    const SIZE: usize = 32;
}

impl Read for SigningKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self::from_seed(<[u8; Self::SIZE]>::read_cfg(buf, cfg)?))
    }
}

// Public methods.
impl SigningKey {
    /// The verifying key associated with this signing key.
    ///
    /// Signatures produced by this signing key can be verified using this public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let point = GAffine::BASEPOINT.to_extended().scalar_mul(
            (0..256)
                .rev()
                .map(|i| self.scalar_le_bytes[i / 8] >> (i % 8) & 1 == 1),
        );
        VerifyingKey {
            bytes: point.to_bytes(),
            point: Some(point),
        }
    }
}

/// A public key used to check signatures.
#[derive(Clone)]
pub struct VerifyingKey {
    /// The canonical encoding of the point.
    ///
    /// When deserializing, we just have the bytes, deferring parsing of them until
    /// signature verification, so that we can more efficiently parse them in batch.
    bytes: [u8; 32],
    /// If available, the point associated with these bytes.
    point: Option<G>,
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for VerifyingKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl FixedSize for VerifyingKey {
    const SIZE: usize = 32;
}

impl Read for VerifyingKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            bytes: <[u8; Self::SIZE]>::read_cfg(buf, cfg)?,
            point: None,
        })
    }
}

// Public methods.
impl VerifyingKey {
    /// Verifies `sig` over the namespaced message.
    #[must_use]
    pub fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Signature) -> bool {
        let r_bytes: [u8; 32] = sig.bytes[..32].try_into().expect("signature is 64 bytes");
        let s_bytes: [u8; 32] = sig.bytes[32..].try_into().expect("signature is 64 bytes");
        let Some(s) = Scalar::from_canonical_bytes(&s_bytes) else {
            return false;
        };
        let Some(r) = GAffine::decompress(&r_bytes) else {
            return false;
        };
        let a = match self.point {
            Some(point) => point,
            None => {
                let Some(point) = GAffine::decompress(&self.bytes) else {
                    return false;
                };
                point.to_extended()
            }
        };

        let msg = union_unique(namespace, msg);
        let digest: [u8; 64] = sha2::Sha512::new()
            .chain(r_bytes)
            .chain(self.bytes)
            .chain(&msg)
            .finalize_fixed()
            .into();
        let k = Scalar::from_bytes_mod_order_wide(&digest);

        let sb = GAffine::BASEPOINT.to_extended().scalar_mul(s.bits_be());
        let ka = a.scalar_mul(k.bits_be());
        sb.add(ka.add_mixed(r).negate())
            .mul_by_cofactor()
            .is_identity()
    }
}

/// An object demonstrating that the owner of a [`VerifyingKey`] approved a message.
#[derive(Clone)]
pub struct Signature {
    bytes: [u8; 64],
}

/// A batch verification context.
pub struct BatchVerifier {
    items: Vec<(Vec<u8>, VerifyingKey, signing::Signature)>,
}

impl BatchVerifier {
    /// Creates a verifier with space for `capacity` signatures.
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Queues a signature for verification over the namespaced message.
    pub fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &VerifyingKey,
        signature: &Signature,
    ) {
        self.items.push((
            union_unique(namespace, message),
            public_key.clone(),
            signing::Signature::from_bytes(signature.bytes),
        ));
    }

    /// Check all the signatures in the batch.
    ///
    /// This returns true precisely when all the signatures in the batch are valid.
    #[must_use]
    pub fn verify(self, rng: &mut impl CryptoRng, strategy: &impl Strategy) -> bool {
        let items = self.items.iter().map(|(message, public_key, signature)| {
            (&public_key.bytes, signature, message.as_slice())
        });
        signing::verify_batch_bytes(rng, items, strategy)
    }
}
