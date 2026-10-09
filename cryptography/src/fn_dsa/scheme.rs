use crate::Secret;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec, vec::Vec};
use bytes::{BufMut, Bytes, BytesMut};
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, Write, util::at_least};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_utils::{Array, Span, union_unique};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
};
use ctutils::CtEq as _;
use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator as _,
    KeyPairGenerator512, KeyPairGenerator1024, RngError, SHAKE256, SigningKey as _, SigningKey512,
    SigningKey1024, VerifyingKey as _, VerifyingKey512, VerifyingKey1024, sign_key_size,
    signature_size, vrfy_key_size,
};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::sync::Arc;
use zeroize::Zeroizing;

const NAME: &str = "fn_dsa";
const PRIVATE_KEY_LENGTH: usize = 32;

/// Length of the signature header byte and the hash-to-point nonce that precede the compressed
/// signature vector.
const SIGNATURE_PREFIX_LENGTH: usize = 1 + 40;

/// Largest standard degree, used to size the standard signature decoder's scratch buffer.
const MAX_DEGREE: usize = 1 << FN_DSA_LOGN_1024;

mod sealed {
    use super::PRIVATE_KEY_LENGTH;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use zeroize::Zeroizing;

    /// Owns each profile's key material, signing, and canonical encoding rules.
    pub trait Sealed {
        const PUBLIC_KEY_SIZE: usize;
        const SIGNATURE_SIZE: usize;
        const PUBLIC_KEY_HEADER: u8;
        const SIGNATURE_HEADER: u8;
        type VerifyingKey: Send + Sync + 'static;

        fn keygen(seed: &[u8; PRIVATE_KEY_LENGTH]) -> (Zeroizing<Vec<u8>>, Vec<u8>);
        fn sign(secret: &[u8], payload: &[u8], out: &mut [u8]) -> Option<()>;
        fn decode_public_key(raw: &[u8]) -> Option<Self::VerifyingKey>;
        fn verify(key: &Self::VerifyingKey, payload: &[u8], signature: &[u8]) -> bool;
        fn signature_is_well_formed(raw: &[u8]) -> bool;
    }
}

/// A Falcon signing profile.
///
/// The trait is sealed: it is implemented only by [FnDsa512], [FnDsa1024], and
/// [EllipsoidalFalcon512].
pub trait Variant: sealed::Sealed + Copy + Debug + Ord + Hash + Send + Sync + 'static {}

/// FN-DSA with degree 512 (Falcon-512, NIST security category 1).
///
/// Public keys are 897 bytes and signatures 666 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FnDsa512;

/// FN-DSA with degree 1024 (Falcon-1024, NIST security category 5).
///
/// Public keys are 1793 bytes and signatures 1280 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FnDsa1024;

macro_rules! standard_variant {
    ($variant:ty, $logn:expr, $keygen:ty, $signing:ty, $verifying:ty) => {
        impl sealed::Sealed for $variant {
            const PUBLIC_KEY_SIZE: usize = vrfy_key_size($logn);
            const SIGNATURE_SIZE: usize = signature_size($logn);
            const PUBLIC_KEY_HEADER: u8 = $logn as u8;
            const SIGNATURE_HEADER: u8 = 0x30 | $logn as u8;
            type VerifyingKey = $verifying;

            fn keygen(seed: &[u8; PRIVATE_KEY_LENGTH]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
                let mut secret = Zeroizing::new(vec![0u8; sign_key_size($logn)]);
                let mut public = vec![0u8; Self::PUBLIC_KEY_SIZE];
                <$keygen>::default().keygen(
                    $logn,
                    &mut SeedRng::new(seed),
                    &mut secret,
                    &mut public,
                );
                (secret, public)
            }

            fn sign(secret: &[u8], payload: &[u8], out: &mut [u8]) -> Option<()> {
                let mut key = <$signing>::decode(secret)?;
                key.sign(&mut ZeroRng, &DOMAIN_NONE, &HASH_ID_RAW, payload, out)
            }

            fn decode_public_key(raw: &[u8]) -> Option<Self::VerifyingKey> {
                <$verifying>::decode(raw)
            }

            fn verify(key: &Self::VerifyingKey, payload: &[u8], signature: &[u8]) -> bool {
                key.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, payload)
            }

            fn signature_is_well_formed(raw: &[u8]) -> bool {
                if raw.len() != Self::SIGNATURE_SIZE || raw[0] != Self::SIGNATURE_HEADER {
                    return false;
                }
                let mut s2 = [0i16; MAX_DEGREE];
                fn_dsa_comm::codec::comp_decode(
                    &raw[SIGNATURE_PREFIX_LENGTH..],
                    &mut s2[..1 << $logn],
                )
            }
        }

        impl Variant for $variant {}
    };
}

standard_variant!(
    FnDsa512,
    FN_DSA_LOGN_512,
    KeyPairGenerator512,
    SigningKey512,
    VerifyingKey512
);
standard_variant!(
    FnDsa1024,
    FN_DSA_LOGN_1024,
    KeyPairGenerator1024,
    SigningKey1024,
    VerifyingKey1024
);

/// Experimental degree-512 ellipsoidal Falcon profile.
///
/// This profile has distinct key and signature encodings and is not standard FN-DSA.
/// It has no assigned NIST security category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EllipsoidalFalcon512;

impl sealed::Sealed for EllipsoidalFalcon512 {
    const PUBLIC_KEY_SIZE: usize = super::ellipsoidal::PUBLIC_KEY_SIZE;
    const SIGNATURE_SIZE: usize = super::ellipsoidal::SIGNATURE_SIZE;
    const PUBLIC_KEY_HEADER: u8 = super::ellipsoidal::PUBLIC_KEY_HEADER;
    const SIGNATURE_HEADER: u8 = super::ellipsoidal::SIGNATURE_HEADER;
    type VerifyingKey = super::ellipsoidal::VerifyingKey;

    fn keygen(seed: &[u8; PRIVATE_KEY_LENGTH]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        super::ellipsoidal::keygen(seed)
    }

    fn sign(secret: &[u8], payload: &[u8], out: &mut [u8]) -> Option<()> {
        super::ellipsoidal::sign(secret, payload, out)
    }

    fn decode_public_key(raw: &[u8]) -> Option<Self::VerifyingKey> {
        Self::VerifyingKey::decode(raw)
    }

    fn verify(key: &Self::VerifyingKey, payload: &[u8], signature: &[u8]) -> bool {
        key.verify(payload, signature)
    }

    fn signature_is_well_formed(raw: &[u8]) -> bool {
        super::ellipsoidal::signature_is_well_formed(raw)
    }
}

impl Variant for EllipsoidalFalcon512 {}

/// Expands a seed into the byte stream that fn-dsa key generation consumes.
struct SeedRng(SHAKE256);

impl SeedRng {
    fn new(seed: &[u8; PRIVATE_KEY_LENGTH]) -> Self {
        let mut shake = SHAKE256::new();
        shake.inject(seed);
        shake.flip();
        Self(shake)
    }
}

/// Supplies the all-zero signing randomness of the deterministic signing mode.
struct ZeroRng;

macro_rules! impl_rng {
    ($rng:ty, |$self:ident, $dest:ident| $fill:expr) => {
        impl fn_dsa::CryptoRng for $rng {}

        impl fn_dsa::RngCore for $rng {
            fn next_u32(&mut self) -> u32 {
                let mut bytes = [0u8; 4];
                self.fill_bytes(&mut bytes);
                u32::from_le_bytes(bytes)
            }

            fn next_u64(&mut self) -> u64 {
                let mut bytes = [0u8; 8];
                self.fill_bytes(&mut bytes);
                u64::from_le_bytes(bytes)
            }

            fn fill_bytes(&mut $self, $dest: &mut [u8]) {
                $fill
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
    };
}

impl_rng!(SeedRng, |self, dest| self.0.extract(dest));
impl_rng!(ZeroRng, |self, dest| dest.fill(0));

/// A private key for a Falcon profile.
///
/// The key is identified by its 32-byte seed. The encoded signing key and the derived
/// [PublicKey] are computed once when the key is created or decoded and are shared between
/// clones.
#[derive(Clone)]
pub struct PrivateKey<V: Variant> {
    seed: Secret<[u8; PRIVATE_KEY_LENGTH]>,
    // The encoded signing key is zeroized on drop.
    signing_key: Arc<Zeroizing<Vec<u8>>>,
    public_key: PublicKey<V>,
}

impl<V: Variant> PrivateKey<V> {
    /// Generates the key pair determined by a seed.
    fn expand(seed: &[u8; PRIVATE_KEY_LENGTH]) -> Self {
        let (signing_key, verifying_key) = V::keygen(seed);
        let public_key =
            PublicKey::new(verifying_key).expect("generated verifying keys always decode");
        Self {
            seed: Secret::new(*seed),
            signing_key: Arc::new(signing_key),
            public_key,
        }
    }
}

impl<V: Variant> crate::PrivateKey for PrivateKey<V> {}

impl<V: Variant> crate::Signer for PrivateKey<V> {
    type Signature = Signature<V>;
    type PublicKey = PublicKey<V>;

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        let payload = union_unique(namespace, msg);

        // Each profile owns its per-call signing scratch; cloned keys share only immutable bytes.
        let mut raw = vec![0u8; Signature::<V>::SIZE];
        V::sign(&self.signing_key, &payload, &mut raw)
            .expect("signing with a generated key cannot fail");
        Signature {
            raw: Bytes::from(raw),
            _variant: PhantomData,
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }
}

impl<V: Variant> Random for PrivateKey<V> {
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
        rng.fill_bytes(seed.as_mut_slice());
        Self::expand(&seed)
    }
}

impl<V: Variant> Write for PrivateKey<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.seed.expose(|seed| buf.put_slice(seed));
    }
}

impl<V: Variant> Read for PrivateKey<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, PRIVATE_KEY_LENGTH)?;
        let mut seed = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
        buf.copy_to_slice(seed.as_mut_slice());
        Ok(Self::expand(&seed))
    }
}

impl<V: Variant> FixedSize for PrivateKey<V> {
    const SIZE: usize = PRIVATE_KEY_LENGTH;
}

impl<V: Variant> PartialEq for PrivateKey<V> {
    fn eq(&self, other: &Self) -> bool {
        self.seed.expose(|a| {
            other
                .seed
                .expose(|b| a.as_slice().ct_eq(b.as_slice()).into())
        })
    }
}

impl<V: Variant> Eq for PrivateKey<V> {}

impl<V: Variant> Debug for PrivateKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

impl<V: Variant> Display for PrivateKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for PrivateKey<V> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let seed = Zeroizing::new(u.arbitrary::<[u8; PRIVATE_KEY_LENGTH]>()?);
        Ok(Self::expand(&seed))
    }
}

/// A public key for a Falcon profile.
///
/// Equality, ordering, and hashing use the encoded key. Decoding enforces the profile's
/// canonical encoding rules and converts the key to the form verification uses once.
/// Clones share the decoded key.
#[derive(Clone)]
pub struct PublicKey<V: Variant> {
    inner: Arc<PublicKeyInner<V>>,
}

struct PublicKeyInner<V: Variant> {
    raw: Vec<u8>,
    key: V::VerifyingKey,
}

impl<V: Variant> PublicKey<V> {
    fn new(raw: Vec<u8>) -> Option<Self> {
        let key = V::decode_public_key(&raw)?;
        Some(Self {
            inner: Arc::new(PublicKeyInner { raw, key }),
        })
    }
}

impl<V: Variant> From<PrivateKey<V>> for PublicKey<V> {
    fn from(value: PrivateKey<V>) -> Self {
        value.public_key
    }
}

impl<V: Variant> crate::PublicKey for PublicKey<V> {}

impl<V: Variant> crate::Verifier for PublicKey<V> {
    type Signature = Signature<V>;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        V::verify(&self.inner.key, &union_unique(namespace, msg), &sig.raw)
    }
}

impl<V: Variant> Write for PublicKey<V> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.inner.raw);
    }
}

impl<V: Variant> Read for PublicKey<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;
        let mut raw = vec![0u8; Self::SIZE];
        buf.copy_to_slice(&mut raw);
        Self::new(raw).ok_or(CodecError::Invalid(NAME, "Invalid PublicKey"))
    }
}

impl<V: Variant> FixedSize for PublicKey<V> {
    const SIZE: usize = V::PUBLIC_KEY_SIZE;
}

impl<V: Variant> Span for PublicKey<V> {}

impl<V: Variant> Array for PublicKey<V> {}

impl<V: Variant> PartialEq for PublicKey<V> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.raw == other.inner.raw
    }
}

impl<V: Variant> Eq for PublicKey<V> {}

impl<V: Variant> Ord for PublicKey<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.raw.cmp(&other.inner.raw)
    }
}

impl<V: Variant> PartialOrd for PublicKey<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: Variant> Hash for PublicKey<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.raw.hash(state);
    }
}

impl<V: Variant> AsRef<[u8]> for PublicKey<V> {
    fn as_ref(&self) -> &[u8] {
        &self.inner.raw
    }
}

impl<V: Variant> Deref for PublicKey<V> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner.raw
    }
}

impl<V: Variant> Debug for PublicKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.inner.raw))
    }
}

impl<V: Variant> Display for PublicKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.inner.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for PublicKey<V> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(PrivateKey::<V>::arbitrary(u)?.public_key)
    }
}

/// A signature for a Falcon profile.
///
/// Decoding enforces the profile's canonical encoding rules. Verification checks validity for
/// the signed message. Decoding copies the signature out of its buffer: signatures outlive the
/// messages that carry them, so a retained signature must not keep a pooled network buffer alive.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature<V: Variant> {
    raw: Bytes,
    _variant: PhantomData<V>,
}

impl<V: Variant> crate::Signature for Signature<V> {}

impl<V: Variant> Write for Signature<V> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.raw);
    }
}

impl<V: Variant> Read for Signature<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;
        let mut raw = BytesMut::zeroed(Self::SIZE);
        buf.copy_to_slice(&mut raw);
        let raw = raw.freeze();
        if !V::signature_is_well_formed(&raw) {
            return Err(CodecError::Invalid(NAME, "Invalid Signature"));
        }
        Ok(Self {
            raw,
            _variant: PhantomData,
        })
    }
}

impl<V: Variant> FixedSize for Signature<V> {
    const SIZE: usize = V::SIGNATURE_SIZE;
}

impl<V: Variant> Span for Signature<V> {}

impl<V: Variant> Array for Signature<V> {}

impl<V: Variant> AsRef<[u8]> for Signature<V> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl<V: Variant> Deref for Signature<V> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl<V: Variant> Debug for Signature<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl<V: Variant> Display for Signature<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Signature<V> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer as _;

        let private_key = PrivateKey::<V>::arbitrary(u)?;
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<u8>, _>>()?;
        Ok(private_key.sign(&[], &message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signer as _, Verifier as _};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::test_rng;
    use rand::RngExt as _;

    const NAMESPACE: &[u8] = b"test-namespace";
    const MESSAGE: &[u8] = b"test message";

    fn private_key<V: Variant>(seed: u8) -> PrivateKey<V> {
        PrivateKey::decode([seed; PRIVATE_KEY_LENGTH].as_slice().to_vec()).unwrap()
    }

    fn signature_bytes<V: Variant>() -> Vec<u8> {
        private_key::<V>(1).sign(NAMESPACE, MESSAGE).to_vec()
    }

    fn sign_and_verify<V: Variant>() {
        let mut rng = test_rng();
        let private_key = PrivateKey::<V>::random(&mut rng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(NAMESPACE, MESSAGE);
        assert!(public_key.verify(NAMESPACE, MESSAGE, &signature));

        assert!(!public_key.verify(b"other-namespace", MESSAGE, &signature));
        assert!(!public_key.verify(NAMESPACE, b"other message", &signature));
        assert!(!public_key.verify(b"", MESSAGE, &signature));
        let other = PrivateKey::<V>::random(&mut rng).public_key();
        assert_ne!(public_key, other);
        assert!(!other.verify(NAMESPACE, MESSAGE, &signature));
    }

    fn namespace_is_bound<V: Variant>() {
        // The namespace is length-prefixed, so moving bytes between namespace and message changes
        // the signed payload.
        let private_key = private_key::<V>(1);
        let signature = private_key.sign(b"ab", b"c");
        assert!(!private_key.public_key().verify(b"a", b"bc", &signature));
    }

    fn verify_rejects_tampered_signature<V: Variant>() {
        let public_key = private_key::<V>(1).public_key();
        let mut raw = signature_bytes::<V>();

        // Flipping a bit of the nonce keeps the encoding valid but changes the hashed target.
        raw[1] ^= 1;
        let signature = Signature::<V>::decode(raw).unwrap();
        assert!(!public_key.verify(NAMESPACE, MESSAGE, &signature));
    }

    fn verify_accepts_randomized_signature<V: Variant, K: fn_dsa::SigningKey>() {
        let private_key = private_key::<V>(1);
        let public_key = private_key.public_key();
        let deterministic = private_key.sign(NAMESPACE, MESSAGE);

        // Sign the same payload with non-zero signing randomness.
        let payload = union_unique(NAMESPACE, MESSAGE);
        let mut key = K::decode(&private_key.signing_key).unwrap();
        let mut raw = vec![0u8; Signature::<V>::SIZE];
        key.sign(
            &mut SeedRng::new(&[7; PRIVATE_KEY_LENGTH]),
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            &payload,
            &mut raw,
        )
        .unwrap();
        let randomized = Signature::<V>::decode(raw).unwrap();

        assert_ne!(randomized, deterministic);
        assert!(public_key.verify(NAMESPACE, MESSAGE, &randomized));
        assert!(!public_key.verify(NAMESPACE, b"other message", &randomized));
    }

    fn codec_private_key<V: Variant>() {
        let original = PrivateKey::<V>::random(test_rng());
        let encoded = original.encode();
        assert_eq!(encoded.len(), PRIVATE_KEY_LENGTH);
        assert_eq!(PrivateKey::<V>::SIZE, PRIVATE_KEY_LENGTH);

        let decoded = PrivateKey::<V>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(original.public_key(), decoded.public_key());

        assert!(PrivateKey::<V>::decode(vec![0u8; PRIVATE_KEY_LENGTH - 1]).is_err());
        assert!(PrivateKey::<V>::decode(vec![0u8; PRIVATE_KEY_LENGTH + 1]).is_err());
    }

    fn codec_public_key<V: Variant>() {
        let original = PrivateKey::<V>::random(test_rng()).public_key();
        let encoded = original.encode();
        assert_eq!(encoded.len(), PublicKey::<V>::SIZE);
        assert_eq!(encoded[0], V::PUBLIC_KEY_HEADER);

        let decoded = PublicKey::<V>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.as_ref(), original.as_ref());

        assert!(matches!(
            PublicKey::<V>::decode(vec![V::PUBLIC_KEY_HEADER; PublicKey::<V>::SIZE - 1]),
            Err(CodecError::EndOfBuffer)
        ));
        assert!(matches!(
            PublicKey::<V>::decode(
                original
                    .encode()
                    .iter()
                    .copied()
                    .chain([0])
                    .collect::<Vec<_>>()
            ),
            Err(CodecError::ExtraData(1))
        ));
    }

    fn decode_public_key_rejects_malformed_encodings<V: Variant>() {
        let invalid = |raw: Vec<u8>| {
            assert!(matches!(
                PublicKey::<V>::decode(raw),
                Err(CodecError::Invalid(NAME, "Invalid PublicKey"))
            ));
        };
        let valid = private_key::<V>(1).public_key().to_vec();

        // Header bytes of the other degree, of a signing key, and of a toy degree.
        for header in [
            V::PUBLIC_KEY_HEADER ^ 0x03,
            0x50 | V::PUBLIC_KEY_HEADER,
            0x08,
        ] {
            let mut raw = valid.clone();
            raw[0] = header;
            invalid(raw);
        }

        // A coefficient that is not reduced modulo q (the first one encodes to 2^14 - 1).
        let mut raw = valid;
        raw[1] = 0xFF;
        raw[2] |= 0x3F;
        invalid(raw);

        // All ones.
        let mut raw = vec![0xFF; PublicKey::<V>::SIZE];
        raw[0] = V::PUBLIC_KEY_HEADER;
        invalid(raw);

        // The zero polynomial is a valid encoding that verifies no signature.
        let mut raw = vec![0; PublicKey::<V>::SIZE];
        raw[0] = V::PUBLIC_KEY_HEADER;
        let zero = PublicKey::<V>::decode(raw).unwrap();
        let signature = private_key::<V>(1).sign(NAMESPACE, MESSAGE);
        assert!(!zero.verify(NAMESPACE, MESSAGE, &signature));
    }

    fn codec_signature<V: Variant>() {
        let original = private_key::<V>(1).sign(NAMESPACE, MESSAGE);
        let encoded = original.encode();
        assert_eq!(encoded.len(), Signature::<V>::SIZE);
        assert_eq!(encoded[0], V::SIGNATURE_HEADER);

        let decoded = Signature::<V>::decode(encoded.clone()).unwrap();
        assert_eq!(original, decoded);

        // Decoding copies out of the input allocation so the input can be released.
        assert_ne!(decoded.as_ref().as_ptr(), encoded.as_ref().as_ptr());
    }

    fn decode_signature_rejects_wrong_length<V: Variant>() {
        let raw = signature_bytes::<V>();
        assert!(matches!(
            Signature::<V>::decode(raw[..Signature::<V>::SIZE - 1].to_vec()),
            Err(CodecError::EndOfBuffer)
        ));
        let mut extended = raw;
        extended.push(0);
        assert!(matches!(
            Signature::<V>::decode(extended),
            Err(CodecError::ExtraData(1))
        ));
    }

    fn decode_signature_rejects_malformed_encodings<V: Variant>() {
        let invalid = |raw: Vec<u8>| {
            assert!(matches!(
                Signature::<V>::decode(raw),
                Err(CodecError::Invalid(NAME, "Invalid Signature"))
            ));
        };
        let valid = signature_bytes::<V>();

        // Header bytes of the other degree and without the signature tag.
        for header in [V::SIGNATURE_HEADER ^ 0x03, V::PUBLIC_KEY_HEADER] {
            let mut raw = valid.clone();
            raw[0] = header;
            invalid(raw);
        }

        // Uniformly random bytes after a valid header.
        let mut raw = vec![0u8; Signature::<V>::SIZE];
        test_rng().fill(raw.as_mut_slice());
        raw[0] = valid[0];
        invalid(raw);

        // A zero vector body (no terminating bit for the first coefficient).
        let mut raw = valid.clone();
        raw[SIGNATURE_PREFIX_LENGTH..].fill(0);
        invalid(raw);

        // A first coefficient encoded as negative zero.
        let mut raw = valid.clone();
        raw[SIGNATURE_PREFIX_LENGTH] = 0x01;
        raw[SIGNATURE_PREFIX_LENGTH + 1] = 0x01;
        invalid(raw);

        // A non-zero padding byte.
        let mut raw = valid;
        let last = raw.len() - 1;
        assert_eq!(raw[last], 0);
        raw[last] = 1;
        invalid(raw);
    }

    fn determinism<V: Variant>() {
        // The same seed yields the same key pair.
        let a = private_key::<V>(7);
        let b = private_key::<V>(7);
        assert_eq!(a, b);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a, private_key::<V>(8));
        assert_ne!(a.public_key(), private_key::<V>(8).public_key());
        assert_eq!(PrivateKey::<V>::from_seed(3), PrivateKey::<V>::from_seed(3));
        assert_ne!(PrivateKey::<V>::from_seed(3), PrivateKey::<V>::from_seed(4));

        // Signing is deterministic.
        assert_eq!(a.sign(NAMESPACE, MESSAGE), b.sign(NAMESPACE, MESSAGE));
        assert_ne!(a.sign(NAMESPACE, MESSAGE), a.sign(NAMESPACE, b"other"));
    }

    #[cfg(feature = "std")]
    fn concurrent_clones<V: Variant>() {
        let key = private_key::<V>(7);
        let expected = key.sign(NAMESPACE, MESSAGE);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let clone = key.clone();
                    assert!(Arc::ptr_eq(&key.signing_key, &clone.signing_key));
                    assert!(Arc::ptr_eq(&key.public_key.inner, &clone.public_key.inner));
                    scope.spawn(move || clone.sign(NAMESPACE, MESSAGE))
                })
                .collect();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), expected);
            }
        });
    }

    #[test]
    fn profile_key_encodings_are_distinct() {
        let standard = private_key::<FnDsa512>(1).public_key().encode();
        let ellipsoidal = private_key::<EllipsoidalFalcon512>(1).public_key().encode();
        assert!(PublicKey::<EllipsoidalFalcon512>::decode(standard).is_err());
        assert!(PublicKey::<FnDsa512>::decode(ellipsoidal).is_err());
    }

    #[test]
    fn standard_512_encodings() {
        verify_accepts_randomized_signature::<FnDsa512, SigningKey512>();
        decode_public_key_rejects_malformed_encodings::<FnDsa512>();
        decode_signature_rejects_malformed_encodings::<FnDsa512>();
    }

    #[test]
    fn standard_1024_encodings() {
        verify_accepts_randomized_signature::<FnDsa1024, SigningKey1024>();
        decode_public_key_rejects_malformed_encodings::<FnDsa1024>();
        decode_signature_rejects_malformed_encodings::<FnDsa1024>();
    }

    fn private_key_redacted<V: Variant>() {
        let private_key = PrivateKey::<V>::random(test_rng());
        let seed = commonware_formatting::hex(&private_key.encode());
        let debug = format!("{:?}", private_key);
        let display = format!("{}", private_key);
        assert!(debug.contains("REDACTED"));
        assert!(display.contains("REDACTED"));
        assert!(!debug.contains(&seed));
        assert!(!display.contains(&seed));
    }

    fn from_private_key_to_public_key<V: Variant>() {
        let private_key = PrivateKey::<V>::random(test_rng());
        assert_eq!(private_key.public_key(), PublicKey::from(private_key));
    }

    crate::fn_dsa::variant_tests!(
        sign_and_verify,
        namespace_is_bound,
        verify_rejects_tampered_signature,
        codec_private_key,
        codec_public_key,
        codec_signature,
        decode_signature_rejects_wrong_length,
        determinism,
        #[cfg(feature = "std")]
        concurrent_clones,
        private_key_redacted,
        from_private_key_to_public_key,
    );

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PrivateKey<FnDsa512>> => 1024,
            CodecConformance<PrivateKey<FnDsa1024>> => 1024,
            CodecConformance<PrivateKey<EllipsoidalFalcon512>> => 1024,
            CodecConformance<PublicKey<FnDsa512>> => 1024,
            CodecConformance<PublicKey<FnDsa1024>> => 1024,
            CodecConformance<PublicKey<EllipsoidalFalcon512>> => 1024,
            CodecConformance<Signature<FnDsa512>> => 1024,
            CodecConformance<Signature<FnDsa1024>> => 1024,
            CodecConformance<Signature<EllipsoidalFalcon512>> => 1024,
        }
    }
}
