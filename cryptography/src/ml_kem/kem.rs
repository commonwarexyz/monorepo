use crate::{Kem, Secret};
use ::ml_kem::{Decapsulate as _, Encapsulate as _, KeyExport as _, KeyInit as _};
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_macros::stability;
use core::{
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
};
#[cfg(feature = "arbitrary")]
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRng;
#[cfg(feature = "arbitrary")]
use rand_core::SeedableRng as _;
#[cfg(feature = "std")]
use std::sync::Arc;
use zeroize::Zeroizing;

const ENCAPSULATION_KEY_LENGTH: usize = 1184;
const CIPHERTEXT_LENGTH: usize = 1088;

/// Secret 64-byte seed used to reconstruct an ML-KEM-768 decapsulation key.
///
/// The seed and reconstructed key zeroize on drop. Seeds must contain uniformly random bytes.
#[stability(ALPHA)]
pub type DecapsulationKey = Secret<[u8; 64]>;

/// An ML-KEM-768 shared secret, zeroized on drop.
#[stability(ALPHA)]
pub type SharedSecret = Secret<[u8; 32]>;

/// ML-KEM-768, an IND-CCA2 KEM providing NIST security category 3.
#[stability(ALPHA)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MlKem768;

impl Kem for MlKem768 {
    type DecapsulationKey = DecapsulationKey;
    type EncapsulationKey = EncapsulationKey;
    type Ciphertext = Ciphertext;
    type SharedSecret = [u8; 32];

    fn generate(&self, mut rng: impl CryptoRng) -> (DecapsulationKey, EncapsulationKey) {
        let mut seed = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(&mut *seed);
        let expanded = ::ml_kem::DecapsulationKey768::new((&*seed).into());
        let key = expanded.encapsulation_key().clone();
        let raw = key.to_bytes().into();
        (
            Secret::new(*seed),
            EncapsulationKey(Arc::new(EncapsulationKeyInner { raw, key })),
        )
    }

    fn encapsulate(
        &self,
        mut rng: impl CryptoRng,
        ek: &EncapsulationKey,
    ) -> Option<(Ciphertext, SharedSecret)> {
        let (ct, shared) = ek.0.key.encapsulate_with_rng(&mut rng);
        let shared = Zeroizing::new(shared);
        Some((Ciphertext(ct.into()), Secret::new((*shared).into())))
    }

    fn decapsulate(&self, dk: DecapsulationKey, ct: &Ciphertext) -> Option<SharedSecret> {
        // The upstream expanded key owns heap allocations and zeroizes them on drop.
        let expanded = dk.expose(|seed| ::ml_kem::DecapsulationKey768::new(seed.into()));
        let shared = Zeroizing::new(expanded.decapsulate((&ct.0).into()));
        Some(Secret::new((*shared).into()))
    }
}

struct EncapsulationKeyInner {
    raw: [u8; ENCAPSULATION_KEY_LENGTH],
    key: ::ml_kem::EncapsulationKey768,
}

/// Validated ML-KEM-768 encapsulation key, encoded as 1184 bytes.
///
/// Clones share the validated key and its precomputed public state.
#[stability(ALPHA)]
#[derive(Clone)]
pub struct EncapsulationKey(Arc<EncapsulationKeyInner>);

impl PartialEq for EncapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.raw == other.0.raw
    }
}

impl Eq for EncapsulationKey {}

impl Hash for EncapsulationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.raw.hash(state);
    }
}

impl AsRef<[u8]> for EncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.0.raw
    }
}

impl Debug for EncapsulationKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(self))
    }
}

impl Write for EncapsulationKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.raw.write(buf);
    }
}

impl Read for EncapsulationKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let key = ::ml_kem::EncapsulationKey768::new((&raw).into())
            .map_err(|_| CodecError::Invalid("ml_kem", "invalid encapsulation key"))?;
        Ok(Self(Arc::new(EncapsulationKeyInner { raw, key })))
    }
}

impl FixedSize for EncapsulationKey {
    const SIZE: usize = ENCAPSULATION_KEY_LENGTH;
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for EncapsulationKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let rng = ChaCha20Rng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(MlKem768.generate(rng).1)
    }
}

/// ML-KEM-768 ciphertext, encoded as 1088 bytes.
///
/// Every encoding of this length is accepted. Authenticity is established by confirming the
/// shared secret returned by decapsulation.
#[stability(ALPHA)]
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Ciphertext([u8; CIPHERTEXT_LENGTH]);

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Ciphertext {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(self))
    }
}

impl Write for Ciphertext {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Ciphertext {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(<[u8; Self::SIZE]>::read(buf)?))
    }
}

impl FixedSize for Ciphertext {
    const SIZE: usize = CIPHERTEXT_LENGTH;
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Ciphertext {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut rng = ChaCha20Rng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let (_, ek) = MlKem768.generate(&mut rng);
        Ok(MlKem768.encapsulate(&mut rng, &ek).unwrap().0)
    }
}
