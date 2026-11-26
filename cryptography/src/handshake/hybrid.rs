//! Hybrid key encapsulation mechanism.
//!
//! [Hybrid] composes two [Kem]s conjunctively: encapsulation runs both
//! mechanisms and the shared secret is `SHA-256(DOMAIN || len(a) || a || len(b) || b)`
//! over the component secrets. Recovering the shared secret requires defeating
//! **both** component KEMs — if either holds, the combined secret holds.
//!
//! The canonical instantiation, [X25519MlKem768], pairs classical X25519 with
//! post-quantum ML-KEM-768 so that a handshake stays secure if elliptic-curve
//! Diffie-Hellman falls to a future (quantum or classical) break AND if the
//! lattice KEM is found flawed — `max(A, B)` security, not `min`.

use crate::{handshake::sake::X25519, ml_kem::MlKem768, sha256::Sha256, Hasher, Kem, Secret};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, Write};
use commonware_macros::stability;
#[cfg(feature = "arbitrary")]
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRng;
#[cfg(feature = "arbitrary")]
use rand_core::SeedableRng as _;

/// Domain separator for the hybrid shared-secret combiner.
const DOMAIN: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_HYBRID_KEM";

/// A [Kem] that is the conjunction of two component KEMs.
///
/// Encapsulation and decapsulation run both mechanisms; the [Kem::SharedSecret]
/// is a domain-separated SHA-256 digest of the two component secrets, so an
/// attacker must break both to recover it. If either component rejects its
/// input, the composite operation fails (or, for components with implicit
/// rejection, produces a secret the enclosing handshake cannot confirm).
#[stability(ALPHA)]
#[derive(Clone, Debug, Default)]
pub struct Hybrid<A, B> {
    /// First component KEM.
    pub a: A,
    /// Second component KEM.
    pub b: B,
}

impl<A, B> Hybrid<A, B> {
    /// Creates a hybrid KEM from two component KEMs.
    pub const fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

/// X25519 + ML-KEM-768: classical security AND post-quantum security.
///
/// Encapsulation keys are 1216 bytes (32 + 1184); ciphertexts are 1120 bytes
/// (32 + 1088).
#[stability(ALPHA)]
pub type X25519MlKem768 = Hybrid<X25519, MlKem768>;

/// Composite decapsulation key; each component key zeroizes on drop.
#[stability(ALPHA)]
pub struct DecapsulationKey<A: Kem, B: Kem> {
    a: A::DecapsulationKey,
    b: B::DecapsulationKey,
}

// The component decapsulation keys zeroize themselves on drop.
impl<A: Kem, B: Kem> zeroize::ZeroizeOnDrop for DecapsulationKey<A, B> {}

/// Composite encapsulation key: `A || B` concatenated encodings.
#[stability(ALPHA)]
#[derive(Clone, Debug)]
pub struct EncapsulationKey<A: Kem, B: Kem> {
    a: A::EncapsulationKey,
    b: B::EncapsulationKey,
}

impl<A: Kem, B: Kem> PartialEq for EncapsulationKey<A, B> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<A: Kem, B: Kem> Eq for EncapsulationKey<A, B> {}

impl<A: Kem, B: Kem> EncapsulationKey<A, B> {
    /// The first component encapsulation key.
    pub const fn a(&self) -> &A::EncapsulationKey {
        &self.a
    }
    /// The second component encapsulation key.
    pub const fn b(&self) -> &B::EncapsulationKey {
        &self.b
    }
}

impl<A: Kem, B: Kem> Write for EncapsulationKey<A, B> {
    fn write(&self, buf: &mut impl BufMut) {
        self.a.write(buf);
        self.b.write(buf);
    }
}

impl<A: Kem, B: Kem> Read for EncapsulationKey<A, B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            a: A::EncapsulationKey::read_cfg(buf, &())?,
            b: B::EncapsulationKey::read_cfg(buf, &())?,
        })
    }
}

impl<A: Kem, B: Kem> FixedSize for EncapsulationKey<A, B> {
    const SIZE: usize = A::EncapsulationKey::SIZE + B::EncapsulationKey::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<A, B> arbitrary::Arbitrary<'_> for EncapsulationKey<A, B>
where
    A: Kem + Default,
    B: Kem + Default,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let rng = ChaCha20Rng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(Hybrid::<A, B>::default().generate(rng).1)
    }
}

/// Composite ciphertext: `A || B` concatenated encodings.
#[stability(ALPHA)]
#[derive(Clone, Debug)]
pub struct Ciphertext<A: Kem, B: Kem> {
    a: A::Ciphertext,
    b: B::Ciphertext,
}

impl<A: Kem, B: Kem> PartialEq for Ciphertext<A, B> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<A: Kem, B: Kem> Eq for Ciphertext<A, B> {}

impl<A: Kem, B: Kem> Ciphertext<A, B> {
    /// The first component ciphertext.
    pub const fn a(&self) -> &A::Ciphertext {
        &self.a
    }
    /// The second component ciphertext.
    pub const fn b(&self) -> &B::Ciphertext {
        &self.b
    }
}

impl<A: Kem, B: Kem> Write for Ciphertext<A, B> {
    fn write(&self, buf: &mut impl BufMut) {
        self.a.write(buf);
        self.b.write(buf);
    }
}

impl<A: Kem, B: Kem> Read for Ciphertext<A, B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            a: A::Ciphertext::read_cfg(buf, &())?,
            b: B::Ciphertext::read_cfg(buf, &())?,
        })
    }
}

impl<A: Kem, B: Kem> FixedSize for Ciphertext<A, B> {
    const SIZE: usize = A::Ciphertext::SIZE + B::Ciphertext::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<A, B> arbitrary::Arbitrary<'_> for Ciphertext<A, B>
where
    A: Kem + Default,
    B: Kem + Default,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut rng = ChaCha20Rng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let kem = Hybrid::<A, B>::default();
        let (_, ek) = kem.generate(&mut rng);
        kem.encapsulate(&mut rng, &ek)
            .map(|(ct, _)| ct)
            .ok_or(arbitrary::Error::IncorrectFormat)
    }
}

/// Combines two component shared secrets into the hybrid shared secret.
///
/// Length prefixes keep the encoding injective for secrets of arbitrary size.
fn combine(a: &[u8], b: &[u8]) -> [u8; 32] {
    let (al, bl) = (a.len() as u32, b.len() as u32);
    Sha256::hash(&[DOMAIN, &al.to_le_bytes(), a, &bl.to_le_bytes(), b]).0
}

impl<A: Kem, B: Kem> Kem for Hybrid<A, B> {
    type DecapsulationKey = DecapsulationKey<A, B>;
    type EncapsulationKey = EncapsulationKey<A, B>;
    type Ciphertext = Ciphertext<A, B>;
    type SharedSecret = [u8; 32];

    fn generate(
        &self,
        mut rng: impl CryptoRng,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (a_dk, a_ek) = self.a.generate(&mut rng);
        let (b_dk, b_ek) = self.b.generate(&mut rng);
        (
            DecapsulationKey { a: a_dk, b: b_dk },
            EncapsulationKey { a: a_ek, b: b_ek },
        )
    }

    fn encapsulate(
        &self,
        mut rng: impl CryptoRng,
        ek: &Self::EncapsulationKey,
    ) -> Option<(Self::Ciphertext, Secret<Self::SharedSecret>)> {
        let (a_ct, a_ss) = self.a.encapsulate(&mut rng, &ek.a)?;
        let (b_ct, b_ss) = self.b.encapsulate(&mut rng, &ek.b)?;
        let shared = a_ss.expose(|a| b_ss.expose(|b| combine(a.as_ref(), b.as_ref())));
        Some((Ciphertext { a: a_ct, b: b_ct }, Secret::new(shared)))
    }

    fn decapsulate(
        &self,
        dk: Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Option<Secret<Self::SharedSecret>> {
        let a_ss = self.a.decapsulate(dk.a, &ct.a)?;
        let b_ss = self.b.decapsulate(dk.b, &ct.b)?;
        let shared = a_ss.expose(|a| b_ss.expose(|b| combine(a.as_ref(), b.as_ref())));
        Some(Secret::new(shared))
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<EncapsulationKey<X25519, MlKem768>>,
        CodecConformance<Ciphertext<X25519, MlKem768>>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::test_rng;

    const KEM: X25519MlKem768 = Hybrid {
        a: X25519,
        b: MlKem768,
    };

    #[test]
    fn roundtrip() {
        let mut rng = test_rng();
        let (dk, ek) = KEM.generate(&mut rng);
        let (ct, sent) = KEM.encapsulate(&mut rng, &ek).unwrap();
        let received = KEM.decapsulate(dk, &ct).unwrap();
        sent.expose(|s| received.expose(|r| assert_eq!(s, r)));
    }

    #[test]
    fn x25519_rejection_propagates() {
        // An all-zero X25519 component is non-contributory; the composite
        // encapsulation key and ciphertext must be rejected outright.
        let mut rng = test_rng();
        let mut raw_ek = vec![0u8; EncapsulationKey::<X25519, MlKem768>::SIZE];
        raw_ek[32..].copy_from_slice(&{
            let (_, ek) = MlKem768.generate(&mut rng);
            ek.encode()
        });
        let ek =
            EncapsulationKey::<X25519, MlKem768>::decode(commonware_codec::Copying(&raw_ek[..]))
                .unwrap();
        assert!(KEM.encapsulate(&mut rng, &ek).is_none());

        let (dk, _) = KEM.generate(&mut rng);
        let mut raw_ct = vec![0u8; Ciphertext::<X25519, MlKem768>::SIZE];
        raw_ct[32..].copy_from_slice(&{
            let (_, ek) = MlKem768.generate(&mut rng);
            MlKem768.encapsulate(&mut rng, &ek).unwrap().0.encode()
        });
        let ct = Ciphertext::<X25519, MlKem768>::decode(commonware_codec::Copying(&raw_ct[..]))
            .unwrap();
        assert!(KEM.decapsulate(dk, &ct).is_none());
    }

    #[test]
    fn mlkem_tamper_yields_wrong_secret() {
        // ML-KEM rejects implicitly: a corrupted ciphertext decapsulates to an
        // unrelated component secret, so the composite secret differs (the
        // enclosing handshake's confirmation is what rejects the peer).
        let mut rng = test_rng();
        let (dk, ek) = KEM.generate(&mut rng);
        let (ct, sent) = KEM.encapsulate(&mut rng, &ek).unwrap();
        let mut raw = ct.encode().to_vec();
        raw[Ciphertext::<X25519, MlKem768>::SIZE - 1] ^= 0x01;
        let tampered =
            Ciphertext::<X25519, MlKem768>::decode(commonware_codec::Copying(&raw[..])).unwrap();
        let received = KEM.decapsulate(dk, &tampered).unwrap();
        sent.expose(|s| received.expose(|r| assert_ne!(s, r)));
    }

    #[test]
    fn codec_roundtrip() {
        let mut rng = test_rng();
        let (_, ek) = KEM.generate(&mut rng);
        let decoded = EncapsulationKey::<X25519, MlKem768>::decode(commonware_codec::Copying(
            &ek.encode()[..],
        ))
        .unwrap();
        assert_eq!(ek, decoded);
        let (ct, _) = KEM.encapsulate(&mut rng, &decoded).unwrap();
        let decoded_ct = Ciphertext::<X25519, MlKem768>::decode(commonware_codec::Copying(
            &ct.encode()[..],
        ))
        .unwrap();
        assert_eq!(ct, decoded_ct);
    }
}
