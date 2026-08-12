//! X25519 key exchange.
//!
//! Each party generates a fresh [`SecretKey`], sends the corresponding [`PublicKey`] to the
//! other, and combines its secret key with the other party's public key to derive the same
//! [`SharedSecret`]:
//!
//! ```
//! use commonware_cryptography_curve25519::key_exchange::SecretKey;
//! use commonware_math::algebra::Random;
//!
//! let mut rng = commonware_utils::test_rng();
//! let alice = SecretKey::random(&mut rng);
//! let bob = SecretKey::random(&mut rng);
//! let (alice_public, bob_public) = (alice.public_key(), bob.public_key());
//! let alice_shared = alice.exchange(&bob_public).expect("honest key is contributory");
//! let bob_shared = bob.exchange(&alice_public).expect("honest key is contributory");
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```

use crate::curve::montgomery;
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, Write};
use commonware_math::algebra::Random;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// The u-coordinate of the X25519 base point.
const BASEPOINT_U: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 9;
    bytes
};

/// A secret key, usable for exactly one key exchange.
///
/// Keys can only be generated freshly at random, and [`Self::exchange`] consumes the key, so a
/// key cannot be used across sessions. There is deliberately no way to serialize one: forward
/// secrecy relies on secret keys not outliving their exchange. Secret material is zeroized when
/// the key is dropped.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl Random for SecretKey {
    fn random(mut rng: impl rand_core::CryptoRng) -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut bytes[..]);
        Self { bytes: *bytes }
    }
}

// Public methods.
impl SecretKey {
    /// The public key to send to the other party.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            bytes: montgomery::x25519(&self.bytes, &BASEPOINT_U),
        }
    }

    /// Performs a key exchange with the other party's public key, consuming this key.
    ///
    /// This returns `None` when the other party's key is a low-order point, which would force
    /// the result to a value everybody can compute. An honestly generated public key fails
    /// with negligible probability, so a failure means the other party misbehaved.
    pub fn exchange(self, other: &PublicKey) -> Option<SharedSecret> {
        let bytes = Zeroizing::new(montgomery::x25519(&self.bytes, &other.bytes));
        if *bytes == [0; 32] {
            return None;
        }
        Some(SharedSecret { bytes: *bytes })
    }
}

/// A public key another party can use to perform a key exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The little-endian u-coordinate of a point on the Montgomery form of the curve.
    ///
    /// Every 32-byte string is accepted: X25519 processes any coordinate, and misbehavior
    /// surfaces as a failed [`SecretKey::exchange`] rather than a decoding error.
    bytes: [u8; 32],
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = 32;
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            bytes: <[u8; Self::SIZE]>::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            bytes: u.arbitrary()?,
        })
    }
}

/// The secret both parties derive from a key exchange.
///
/// The bytes are a curve point coordinate, not a uniformly random string: feed them into a
/// key-derivation function bound to the protocol context rather than using them directly as
/// a cipher key. The bytes are zeroized when the shared secret is dropped.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    /// The raw bytes of the shared secret.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{PublicKey, SecretKey, SharedSecret};
    use commonware_formatting::hex;
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;
    use rand_core::Rng;

    #[test]
    fn rfc7748_diffie_hellman_vector() {
        // Test vectors from RFC 7748, section 6.1.
        let alice = SecretKey {
            bytes: hex!("0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        };
        let bob = SecretKey {
            bytes: hex!("0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
        };
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();
        assert_eq!(
            alice_public.bytes,
            hex!("0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_public.bytes,
            hex!("0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let expected = hex!("0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(
            alice
                .exchange(&bob_public)
                .expect("contributory")
                .as_bytes(),
            &expected
        );
        assert_eq!(
            bob.exchange(&alice_public)
                .expect("contributory")
                .as_bytes(),
            &expected
        );
    }

    #[test]
    fn exchange_is_commutative() {
        let mut rng = test_rng();
        for _ in 0..8 {
            let alice = SecretKey::random(&mut rng);
            let bob = SecretKey::random(&mut rng);
            let (alice_public, bob_public) = (alice.public_key(), bob.public_key());
            let alice_shared = alice.exchange(&bob_public).expect("contributory");
            let bob_shared = bob.exchange(&alice_public).expect("contributory");
            assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        }
    }

    #[test]
    fn secret_types_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<SecretKey>();
        assert_zeroize_on_drop::<SharedSecret>();
        assert!(core::mem::needs_drop::<SecretKey>());
        assert!(core::mem::needs_drop::<SharedSecret>());
    }

    #[test]
    fn low_order_public_keys_are_rejected() {
        // Every low-order point on the curve and its twist, plus the non-canonical encodings
        // of the first two, forces the exchange output to zero.
        let low_order = [
            // The identity, u = 0.
            hex!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // u = 1, of order 4.
            hex!("0x0100000000000000000000000000000000000000000000000000000000000000"),
            // A point of order 8 on the curve.
            hex!("0xe0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            // A point of order 8 on the twist.
            hex!("0x5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            // u = p - 1, of order 4 on the twist.
            hex!("0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            // u = p, a non-canonical encoding of 0.
            hex!("0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            // u = p + 1, a non-canonical encoding of 1.
            hex!("0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];
        let mut rng = test_rng();
        for bytes in low_order {
            let secret = SecretKey::random(&mut rng);
            assert!(secret.exchange(&PublicKey { bytes }).is_none());
        }
    }

    #[test]
    fn matches_reference_implementation() {
        let mut rng = test_rng();
        for _ in 0..16 {
            let mut secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut secret_bytes);
            let mut u = [0u8; 32];
            rng.fill_bytes(&mut u);

            let secret = SecretKey {
                bytes: secret_bytes,
            };
            assert_eq!(
                secret.public_key().bytes,
                x25519_dalek::x25519(secret_bytes, x25519_dalek::X25519_BASEPOINT_BYTES)
            );
            let shared = secret
                .exchange(&PublicKey { bytes: u })
                .expect("random coordinate is contributory");
            assert_eq!(shared.as_bytes(), &x25519_dalek::x25519(secret_bytes, u));
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::PublicKey;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PublicKey>,
        }
    }
}
