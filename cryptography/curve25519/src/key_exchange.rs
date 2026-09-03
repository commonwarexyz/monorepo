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

use crate::curve::{F, montgomery};
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use core::fmt::{self, Debug, Display};
use subtle::ConstantTimeEq;
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
    /// Constructs a secret key from raw scalar bytes for test-vector checks.
    #[cfg(test)]
    pub(crate) const fn from_raw(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

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
        SharedSecret::from_x25519(montgomery::x25519(&self.bytes, &other.bytes))
    }
}

/// A public key another party can use to perform a key exchange.
///
/// Equality compares decoded u-coordinates. Distinct encodings that X25519 processes as the same
/// field element therefore compare equal, while serialization preserves the original bytes.
#[derive(Clone)]
pub struct PublicKey {
    /// The little-endian u-coordinate of a point on the Montgomery form of the curve.
    ///
    /// Every 32-byte string is accepted: X25519 processes any coordinate, and misbehavior
    /// surfaces as a failed [`SecretKey::exchange`] rather than a decoding error.
    bytes: [u8; 32],
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        F::from_bytes(&self.bytes).eq(&F::from_bytes(&other.bytes))
    }
}

impl Eq for PublicKey {}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
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
/// Values are only constructed from contributory exchanges; X25519's all-zero output is
/// rejected.
///
/// The bytes are a curve point coordinate, not a uniformly random string: feed them into a
/// key-derivation function bound to the protocol context rather than using them directly as
/// a cipher key. The bytes are zeroized when the shared secret is dropped.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    fn from_x25519(bytes: [u8; 32]) -> Option<Self> {
        let bytes = Zeroizing::new(bytes);

        // X25519 exposes only whether the result is all zero. Compare every byte before branching
        // on that public classification.
        if bool::from(bytes.ct_eq(&[0; 32])) {
            return None;
        }
        Some(Self { bytes: *bytes })
    }

    /// The raw bytes of the shared secret.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{BASEPOINT_U, PublicKey, SecretKey, SharedSecret};
    use commonware_formatting::hex;

    #[test]
    fn secret_types_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<SecretKey>();
        assert_zeroize_on_drop::<SharedSecret>();
        assert!(core::mem::needs_drop::<SecretKey>());
        assert!(core::mem::needs_drop::<SharedSecret>());
    }

    #[test]
    fn public_key_equality_uses_decoded_coordinates() {
        let mut basepoint_with_high_bit = BASEPOINT_U;
        basepoint_with_high_bit[31] |= 0x80;
        let mut one = [0u8; 32];
        one[0] = 1;

        let aliases = [
            (BASEPOINT_U, basepoint_with_high_bit),
            (
                [0; 32],
                hex!("0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            ),
            (
                one,
                hex!("0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            ),
        ];

        for (canonical_bytes, alias_bytes) in aliases {
            let canonical = PublicKey {
                bytes: canonical_bytes,
            };
            let alias = PublicKey { bytes: alias_bytes };
            assert_eq!(canonical, alias);
            assert_ne!(canonical.as_ref(), alias.as_ref());

            let canonical_shared = SecretKey { bytes: [42; 32] }.exchange(&canonical);
            let alias_shared = SecretKey { bytes: [42; 32] }.exchange(&alias);
            match (canonical_shared, alias_shared) {
                (Some(canonical), Some(alias)) => {
                    assert_eq!(canonical.as_bytes(), alias.as_bytes());
                }
                (None, None) => {}
                _ => panic!("equivalent coordinates must produce equivalent exchanges"),
            }
        }

        assert_ne!(PublicKey { bytes: [0; 32] }, PublicKey { bytes: one });
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
        for bytes in low_order {
            let secret = SecretKey::from_raw([42; 32]);
            assert!(secret.exchange(&PublicKey { bytes }).is_none());
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
