use crate::{Kem, Secret};
use commonware_codec::{Buf, FixedSize, Read, ReadExt, Write};
use rand_core::CryptoRng;

/// A shared secret derived from X25519 key exchange, zeroized on drop.
pub(crate) type SharedSecret = Secret<x25519_dalek::SharedSecret>;

/// An ephemeral X25519 public key used during SAKE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralPublicKey {
    inner: x25519_dalek::PublicKey,
}

impl Write for EphemeralPublicKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(self.inner.as_bytes());
    }
}

impl FixedSize for EphemeralPublicKey {
    // There's not a good constant anywhere in the x25519_dalek crate for this.
    const SIZE: usize = 32;
}

impl Read for EphemeralPublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let bytes: [u8; 32] = ReadExt::read(buf)?;
        Ok(Self {
            inner: bytes.into(),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for EphemeralPublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: [u8; 32] = u.arbitrary()?;
        Ok(Self {
            inner: bytes.into(),
        })
    }
}

/// An ephemeral X25519 secret key used during SAKE.
pub struct SecretKey {
    inner: Secret<x25519_dalek::EphemeralSecret>,
}

impl zeroize::ZeroizeOnDrop for SecretKey {}

/// Ephemeral X25519 key encapsulation.
///
/// Non-contributory exchanges are rejected during encapsulation and decapsulation.
/// Encapsulation keys and ciphertexts must be authenticated by the enclosing protocol.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct X25519;

impl Kem for X25519 {
    type DecapsulationKey = SecretKey;
    type EncapsulationKey = EphemeralPublicKey;
    type Ciphertext = EphemeralPublicKey;
    type SharedSecret = x25519_dalek::SharedSecret;

    fn generate(&self, rng: impl CryptoRng) -> (SecretKey, EphemeralPublicKey) {
        let secret = SecretKey::new(rng);
        let public = secret.public();
        (secret, public)
    }

    fn encapsulate(
        &self,
        rng: impl CryptoRng,
        ek: &EphemeralPublicKey,
    ) -> Option<(EphemeralPublicKey, Secret<Self::SharedSecret>)> {
        let (secret, public) = self.generate(rng);
        let shared = secret.exchange(ek)?;
        Some((public, shared))
    }

    fn decapsulate(
        &self,
        dk: SecretKey,
        ct: &EphemeralPublicKey,
    ) -> Option<Secret<Self::SharedSecret>> {
        dk.exchange(ct)
    }
}

impl SecretKey {
    /// Generates a new random ephemeral secret key.
    pub(crate) fn new(mut rng: impl CryptoRng) -> Self {
        Self {
            inner: Secret::new(x25519_dalek::EphemeralSecret::random_from_rng(&mut rng)),
        }
    }

    /// Derives the corresponding public key.
    pub(crate) fn public(&self) -> EphemeralPublicKey {
        self.inner.expose(|secret| EphemeralPublicKey {
            inner: x25519_dalek::PublicKey::from(secret),
        })
    }

    /// Performs X25519 key exchange with another public key.
    /// Returns None if the exchange is non-contributory.
    pub(crate) fn exchange(self, other: &EphemeralPublicKey) -> Option<SharedSecret> {
        let secret = self.inner.expose_unwrap();
        let out = secret.diffie_hellman(&other.inner);
        if !out.was_contributory() {
            return None;
        }
        Some(Secret::new(out))
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<EphemeralPublicKey>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_utils::test_rng;

    #[test]
    fn non_contributory_exchange() {
        let mut rng = test_rng();
        for bytes in [[0; 32], {
            let mut one = [0; 32];
            one[0] = 1;
            one
        }] {
            let invalid =
                EphemeralPublicKey::decode(commonware_codec::Copying(bytes.as_slice())).unwrap();
            assert!(X25519.encapsulate(&mut rng, &invalid).is_none());
            let (dk, _) = X25519.generate(&mut rng);
            assert!(X25519.decapsulate(dk, &invalid).is_none());
        }
    }

    #[test]
    fn roundtrip() {
        let mut rng = test_rng();
        let (dk, ek) = X25519.generate(&mut rng);
        let (ct, shared) = X25519.encapsulate(&mut rng, &ek).unwrap();
        let received = X25519.decapsulate(dk, &ct).unwrap();
        shared.expose(|sent| {
            received.expose(|received| assert_eq!(sent.as_bytes(), received.as_bytes()));
        });
    }
}
