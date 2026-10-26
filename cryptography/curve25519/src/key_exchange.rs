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

use crate::{
    STACK_SCRUB_BYTES,
    curve::{F, montgomery},
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use bytes::BufMut;
use commonware_codec::{Buf, FixedSize, Read, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use core::fmt::{self, Debug, Display};
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing, zeroize_stack};

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
/// the key is dropped, and both operations clear the stack they used before returning, within
/// the limits described in the [crate documentation](crate#zeroization).
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
        let mut public = PublicKey { bytes: [0; 32] };
        montgomery::x25519(&self.bytes, &BASEPOINT_U, &mut public.bytes);
        zeroize_stack::<STACK_SCRUB_BYTES>();
        public
    }

    /// Performs a key exchange with the other party's public key, consuming this key.
    ///
    /// This returns `None` when the other party's key is a low-order point, which would force
    /// the result to a value everybody can compute. Keys produced by [`Self::public_key`] never
    /// cause this failure.
    pub fn exchange(self, other: &PublicKey) -> Option<SharedSecret> {
        let shared = self.shared_secret(other);
        zeroize_stack::<STACK_SCRUB_BYTES>();
        shared
    }

    /// The exchange itself, kept out of line so that [`Self::exchange`] can clear its frames,
    /// which hold the per-byte results of the contributory check as well as the ladder's state.
    #[inline(never)]
    fn shared_secret(&self, other: &PublicKey) -> Option<SharedSecret> {
        let mut shared = SharedSecret {
            bytes: Box::new(Zeroizing::new([0; 32])),
        };
        montgomery::x25519(&self.bytes, &other.bytes, &mut shared.bytes);

        // X25519 exposes only whether the result is all zero. Compare every byte before branching
        // on that public classification.
        bool::from(!shared.bytes.ct_eq(&[0; 32])).then_some(shared)
    }
}

/// A public key another party can use to perform a key exchange.
///
/// Equality compares decoded u-coordinates. Distinct encodings that X25519 processes as the same
/// field element therefore compare equal, while serialization preserves the original bytes.
/// Protocol transcripts should bind the transmitted bytes available through [`AsRef`].
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
/// key-derivation function bound to the protocol context rather than using them directly as a
/// cipher key. The bytes live in one heap allocation that is zeroized when the shared secret is
/// dropped, so a move copies only a pointer.
pub struct SharedSecret {
    bytes: Box<Zeroizing<[u8; 32]>>,
}

// The boxed buffer zeroizes itself when the shared secret drops it.
impl ZeroizeOnDrop for SharedSecret {}

impl SharedSecret {
    /// The raw bytes of the shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
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
            // u = 0, the point (0, 0) of order 2.
            hex!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // u = 1, of order 4.
            hex!("0x0100000000000000000000000000000000000000000000000000000000000000"),
            // A point of order 8 on the curve.
            hex!("0xe0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            // Another point of order 8 on the curve.
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

    /// The key exchange clears the dead stack it used: the probes find neither the secret key,
    /// its clamped form, the shared secret, nor the contributory check's comparison of its bytes,
    /// the scrub ran in both operations, and it reaches below the deepest frame of either.
    #[cfg(all(not(debug_assertions), not(miri)))]
    mod stack {
        use super::super::{PublicKey, SecretKey};
        use crate::{
            STACK_SCRUB_BYTES,
            curve::montgomery,
            test::stack::{contains, depth, probe, scrubbed},
        };

        /// The scalar as the ladder clamps it.
        fn clamped(scalar: &[u8; 32]) -> [u8; 32] {
            let mut clamped = *scalar;
            clamped[0] &= 0b1111_1000;
            clamped[31] &= 0b0111_1111;
            clamped[31] |= 0b0100_0000;
            clamped
        }

        /// The radix-`2^51` limbs of a canonical field element encoding, as held in memory.
        fn limbs(bytes: &[u8; 32]) -> [u8; 40] {
            let bit = |i: usize| u64::from((bytes[i / 8] >> (i % 8)) & 1);
            let mut limbs = [0u8; 40];
            for (index, limb) in limbs.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                let value = (0..51)
                    .filter(|offset| index * 51 + offset < 256)
                    .fold(0u64, |value, offset| {
                        value | bit(index * 51 + offset) << offset
                    });
                *limb = value.to_le_bytes();
            }
            limbs
        }

        /// The per-byte results of the contributory check on `bytes`, as every run of six `u32`
        /// flags with at least two set, in both orders. A compiler that spills the comparison
        /// stores such runs, and a run with fewer set flags would also match ordinary stack
        /// contents.
        fn comparison_patterns(bytes: &[u8; 32]) -> Vec<Vec<u8>> {
            let flags: Vec<u32> = bytes.iter().map(|&byte| u32::from(byte == 0)).collect();
            flags
                .windows(6)
                .filter(|window| window.iter().sum::<u32>() >= 2)
                .flat_map(|window| {
                    let encode = |flags: &mut dyn Iterator<Item = &u32>| -> Vec<u8> {
                        flags.flat_map(|flag| flag.to_le_bytes()).collect()
                    };
                    [encode(&mut window.iter()), encode(&mut window.iter().rev())]
                })
                .collect()
        }

        /// A secret key whose exchange with `other` has two zero bytes among its first sixteen,
        /// close enough together for [`comparison_patterns`] to produce a pattern from them.
        fn secret_with_zero_bytes(other: &PublicKey) -> [u8; 32] {
            (0u64..)
                .map(|i| {
                    let mut secret = [7u8; 32];
                    secret[..8].copy_from_slice(&i.to_le_bytes());
                    secret
                })
                .find(|secret| {
                    let shared = SecretKey::from_raw(*secret).exchange(other).unwrap();
                    let mut head = [1u8; 32];
                    head[..16].copy_from_slice(&shared.as_bytes()[..16]);
                    !comparison_patterns(&head).is_empty()
                })
                .unwrap()
        }

        fn assert_clear(span: &[u8], secrets: &[&[u8]]) {
            for (i, secret) in secrets.iter().enumerate() {
                assert!(!contains(span, secret), "secret {i} remains on the stack");
            }
            assert!(
                scrubbed(span, STACK_SCRUB_BYTES),
                "the operation did not scrub"
            );
        }

        #[test]
        fn exchange_leaves_no_secret_on_the_stack() {
            let other = SecretKey::from_raw([43; 32]).public_key();
            let secret = secret_with_zero_bytes(&other);

            let key = SecretKey::from_raw(secret);
            let (public, span) = probe(|| key.public_key());
            assert_clear(&span, &[&secret, &clamped(&secret)]);

            let (shared, span) = probe(move || key.exchange(&other).unwrap());
            let bytes = shared.as_bytes();
            let (clamped, limbs, patterns) =
                (clamped(&secret), limbs(bytes), comparison_patterns(bytes));
            let mut secrets = vec![&secret[..], &clamped[..], bytes, &limbs[..]];
            secrets.extend(patterns.iter().map(Vec::as_slice));
            assert_clear(&span, &secrets);

            // The other party derives the same secret, so the probe saw a real exchange.
            let theirs = SecretKey::from_raw([43; 32]).exchange(&public).unwrap();
            assert_eq!(theirs.as_bytes(), bytes);
        }

        #[test]
        fn scrub_covers_key_exchange() {
            let mut out = [0u8; 32];
            let reached = depth(&probe(|| montgomery::x25519(&[42; 32], &[9; 32], &mut out)).1);
            assert!(
                reached <= STACK_SCRUB_BYTES,
                "X25519 reached {reached} bytes below the caller"
            );

            let key = SecretKey::from_raw([42; 32]);
            let other = SecretKey::from_raw([43; 32]).public_key();
            let reached = depth(&probe(|| key.shared_secret(&other)).1);
            assert!(
                reached <= STACK_SCRUB_BYTES,
                "the exchange reached {reached} bytes below the caller"
            );
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
