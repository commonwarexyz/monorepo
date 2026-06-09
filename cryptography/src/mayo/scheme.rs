macro_rules! impl_mayo {
    ($module:ident, $parameter_set:ident, $name:literal) => {
        #[doc = concat!($name, " implementation of the [crate::Signer] and [crate::Verifier] traits.")]
        pub mod $module {
            use crate::Secret;
            #[cfg(not(feature = "std"))]
            use alloc::borrow::Cow;
            use bytes::{Buf, BufMut};
            use commonware_codec::{
                Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write,
            };
            use commonware_formatting::Hex;
            use commonware_math::algebra::Random;
            use commonware_parallel::Strategy;
            use commonware_utils::{union_unique, Array, Span};
            use core::{
                cmp::Ordering,
                fmt::{Debug, Display},
                hash::{Hash, Hasher},
                ops::Deref,
            };
            use rand_core::CryptoRngCore;
            use sriracha_mayo::{$parameter_set, ParameterSet};
            #[cfg(feature = "std")]
            use std::borrow::Cow;
            use zeroize::Zeroizing;

            const SCHEME_NAME: &str = $name;
            const PRIVATE_KEY_LENGTH: usize = <$parameter_set as ParameterSet>::SECRET_KEY_BYTES;
            const PUBLIC_KEY_LENGTH: usize = <$parameter_set as ParameterSet>::PUBLIC_KEY_BYTES;
            const SIGNATURE_LENGTH: usize = <$parameter_set as ParameterSet>::SIGNATURE_BYTES;

            #[doc = concat!($name, " Private Key.")]
            ///
            /// Holds the compact secret seed and the public key derived from it. The
            /// seed alone determines the keypair, so only the seed is serialized and
            /// the public key is re-derived on decode (one MAYO key expansion).
            #[derive(Clone, Debug)]
            pub struct PrivateKey {
                seed: Secret<[u8; PRIVATE_KEY_LENGTH]>,
                public: PublicKey,
            }

            impl crate::PrivateKey for PrivateKey {}

            impl crate::Signer for PrivateKey {
                type Signature = Signature;
                type PublicKey = PublicKey;

                fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
                    self.sign_inner(Some(namespace), msg)
                }

                fn public_key(&self) -> Self::PublicKey {
                    self.public.clone()
                }
            }

            impl PrivateKey {
                /// Derives the keypair determined by `seed`.
                fn from_seed_bytes(
                    seed: &[u8; PRIVATE_KEY_LENGTH],
                ) -> Result<Self, sriracha_mayo::Error> {
                    let (public, _) = sriracha_mayo::SecretKey::<$parameter_set>::from_seed(seed)?;
                    Ok(Self {
                        seed: Secret::new(*seed),
                        public: PublicKey { key: public },
                    })
                }

                /// Signs the payload, panicking if MAYO-C fails to produce a signature
                /// (which only happens if per-signature salt generation fails).
                #[inline(always)]
                fn sign_inner(&self, namespace: Option<&[u8]>, msg: &[u8]) -> Signature {
                    let payload = namespace
                        .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
                        .unwrap_or_else(|| Cow::Borrowed(msg));
                    let signature = self
                        .seed
                        .expose(|seed| {
                            let secret = sriracha_mayo::SecretKey::<$parameter_set>::try_from(
                                seed.as_slice(),
                            )
                            .expect("seed length matches the parameter set");
                            secret.sign(&payload)
                        })
                        .expect("MAYO signing failed");
                    Signature { signature }
                }
            }

            impl Random for PrivateKey {
                fn random(mut rng: impl CryptoRngCore) -> Self {
                    let (public, secret) =
                        sriracha_mayo::SecretKey::<$parameter_set>::random(&mut rng)
                            .expect("MAYO keypair generation failed");
                    let mut seed = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
                    seed.copy_from_slice(secret.as_ref());
                    Self {
                        seed: Secret::new(*seed),
                        public: PublicKey { key: public },
                    }
                }
            }

            impl Write for PrivateKey {
                fn write(&self, buf: &mut impl BufMut) {
                    self.seed.expose(|seed| seed.write(buf));
                }
            }

            impl Read for PrivateKey {
                type Cfg = ();

                fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
                    let raw = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
                    let result = Self::from_seed_bytes(&raw);
                    #[cfg(feature = "std")]
                    let key = result.map_err(|e| CodecError::Wrapped(SCHEME_NAME, e.into()))?;
                    #[cfg(not(feature = "std"))]
                    let key = result.map_err(|e| {
                        CodecError::Wrapped(SCHEME_NAME, alloc::format!("{:?}", e).into())
                    })?;

                    Ok(key)
                }
            }

            impl FixedSize for PrivateKey {
                const SIZE: usize = PRIVATE_KEY_LENGTH;
            }

            impl Display for PrivateKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{:?}", self)
                }
            }

            #[cfg(feature = "arbitrary")]
            impl arbitrary::Arbitrary<'_> for PrivateKey {
                fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                    use rand::{rngs::StdRng, SeedableRng};

                    let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
                    Ok(Self::random(&mut rand))
                }
            }

            #[cfg(test)]
            impl PartialEq for PrivateKey {
                fn eq(&self, other: &Self) -> bool {
                    self.seed
                        .expose(|seed1| other.seed.expose(|seed2| seed1 == seed2))
                        && self.public == other.public
                }
            }

            #[doc = concat!($name, " Public Key.")]
            #[derive(Clone, Eq, PartialEq, FixedArray)]
            pub struct PublicKey {
                key: sriracha_mayo::PublicKey<$parameter_set>,
            }

            impl From<PrivateKey> for PublicKey {
                fn from(value: PrivateKey) -> Self {
                    value.public
                }
            }

            impl crate::PublicKey for PublicKey {}

            impl crate::Verifier for PublicKey {
                type Signature = Signature;

                fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
                    self.verify_inner(Some(namespace), msg, sig)
                }
            }

            impl PublicKey {
                #[inline(always)]
                fn verify_inner(
                    &self,
                    namespace: Option<&[u8]>,
                    msg: &[u8],
                    sig: &Signature,
                ) -> bool {
                    let payload = namespace
                        .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
                        .unwrap_or_else(|| Cow::Borrowed(msg));
                    sig.signature.verify(&self.key, &payload)
                }
            }

            impl Ord for PublicKey {
                fn cmp(&self, other: &Self) -> Ordering {
                    self.key.as_ref().cmp(other.key.as_ref())
                }
            }

            impl PartialOrd for PublicKey {
                fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                    Some(self.cmp(other))
                }
            }

            impl Hash for PublicKey {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    self.key.as_ref().hash(state);
                }
            }

            impl Write for PublicKey {
                fn write(&self, buf: &mut impl BufMut) {
                    buf.put_slice(self.key.as_ref());
                }
            }

            impl Read for PublicKey {
                type Cfg = ();

                fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
                    let raw = <[u8; Self::SIZE]>::read(buf)?;
                    let result = sriracha_mayo::PublicKey::try_from(raw.as_slice());
                    #[cfg(feature = "std")]
                    let key = result.map_err(|e| CodecError::Wrapped(SCHEME_NAME, e.into()))?;
                    #[cfg(not(feature = "std"))]
                    let key = result.map_err(|e| {
                        CodecError::Wrapped(SCHEME_NAME, alloc::format!("{:?}", e).into())
                    })?;

                    Ok(Self { key })
                }
            }

            impl FixedSize for PublicKey {
                const SIZE: usize = PUBLIC_KEY_LENGTH;
            }

            impl Span for PublicKey {}

            impl Array for PublicKey {}

            impl AsRef<[u8]> for PublicKey {
                fn as_ref(&self) -> &[u8] {
                    self.key.as_ref()
                }
            }

            impl Deref for PublicKey {
                type Target = [u8];
                fn deref(&self) -> &[u8] {
                    self.key.as_ref()
                }
            }

            impl Debug for PublicKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", Hex(self))
                }
            }

            impl Display for PublicKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", Hex(self))
                }
            }

            #[cfg(feature = "arbitrary")]
            impl arbitrary::Arbitrary<'_> for PublicKey {
                fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                    use crate::Signer;

                    let private_key = PrivateKey::arbitrary(u)?;
                    Ok(private_key.public_key())
                }
            }

            #[doc = concat!($name, " Signature.")]
            ///
            /// MAYO signing draws a fresh salt for every signature, so two signatures
            /// over the same message by the same key differ. Verification is
            /// deterministic.
            #[derive(Clone, Eq, PartialEq, FixedArray)]
            pub struct Signature {
                signature: sriracha_mayo::Signature<$parameter_set>,
            }

            impl crate::Signature for Signature {}

            impl Ord for Signature {
                fn cmp(&self, other: &Self) -> Ordering {
                    self.signature.as_ref().cmp(other.signature.as_ref())
                }
            }

            impl PartialOrd for Signature {
                fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                    Some(self.cmp(other))
                }
            }

            impl Hash for Signature {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    self.signature.as_ref().hash(state);
                }
            }

            impl Write for Signature {
                fn write(&self, buf: &mut impl BufMut) {
                    buf.put_slice(self.signature.as_ref());
                }
            }

            impl Read for Signature {
                type Cfg = ();

                fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
                    let raw = <[u8; Self::SIZE]>::read(buf)?;
                    let signature = sriracha_mayo::Signature::try_from(raw.as_slice())
                        .expect("length matches the parameter set");
                    Ok(Self { signature })
                }
            }

            impl FixedSize for Signature {
                const SIZE: usize = SIGNATURE_LENGTH;
            }

            impl Span for Signature {}

            impl Array for Signature {}

            impl AsRef<[u8]> for Signature {
                fn as_ref(&self) -> &[u8] {
                    self.signature.as_ref()
                }
            }

            impl Deref for Signature {
                type Target = [u8];
                fn deref(&self) -> &[u8] {
                    self.signature.as_ref()
                }
            }

            impl Debug for Signature {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", Hex(self))
                }
            }

            impl Display for Signature {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", Hex(self))
                }
            }

            #[cfg(feature = "arbitrary")]
            impl arbitrary::Arbitrary<'_> for Signature {
                fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                    // MAYO signing is salted, so signing inside Arbitrary would not be
                    // reproducible. Any byte string of the correct length decodes, so
                    // generate raw bytes instead.
                    let raw = u.arbitrary::<[u8; SIGNATURE_LENGTH]>()?;
                    let signature = sriracha_mayo::Signature::try_from(raw.as_slice())
                        .expect("length matches the parameter set");
                    Ok(Self { signature })
                }
            }

            #[doc = concat!($name, " Batch Verifier.")]
            ///
            /// MAYO verification expands the compact public key into a much larger
            /// internal representation before checking. The batch caches each expanded
            /// key, so verifying many signatures from the same signer amortizes the
            /// expansion. This is an exact verifier (every tuple is checked
            /// individually), so the randomness and strategy passed to `verify` are
            /// unused.
            pub struct Batch {
                verifier: sriracha_mayo::BatchVerifier<$parameter_set>,
            }

            impl crate::BatchVerifier for Batch {
                type PublicKey = PublicKey;

                fn new() -> Self {
                    Self {
                        verifier: sriracha_mayo::BatchVerifier::new(),
                    }
                }

                fn add(
                    &mut self,
                    namespace: &[u8],
                    message: &[u8],
                    public_key: &PublicKey,
                    signature: &Signature,
                ) -> bool {
                    self.add_inner(Some(namespace), message, public_key, signature)
                }

                fn verify<R: CryptoRngCore>(self, _: &mut R, _: &impl Strategy) -> bool {
                    self.verifier.verify()
                }
            }

            impl Batch {
                #[inline(always)]
                fn add_inner(
                    &mut self,
                    namespace: Option<&[u8]>,
                    message: &[u8],
                    public_key: &PublicKey,
                    signature: &Signature,
                ) -> bool {
                    let payload = namespace
                        .map(|namespace| Cow::Owned(union_unique(namespace, message)))
                        .unwrap_or_else(|| Cow::Borrowed(message));
                    self.verifier
                        .add(&public_key.key, payload, &signature.signature)
                        .is_ok()
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use crate::{BatchVerifier as _, Signer as _, Verifier as _};
                use commonware_codec::{DecodeExt, Encode};
                use commonware_parallel::Sequential;
                use commonware_utils::{test_rng, test_rng_seeded};

                #[test]
                fn test_sign_and_verify() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let public_key = private_key.public_key();
                    let namespace = b"test_namespace";
                    let message = b"test_message";
                    let signature = private_key.sign(namespace, message);
                    assert!(public_key.verify(namespace, message, &signature));
                    assert!(!public_key.verify(namespace, b"wrong_message", &signature));
                    assert!(!public_key.verify(b"wrong_namespace", message, &signature));
                }

                #[test]
                fn test_empty_namespace_and_message() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let public_key = private_key.public_key();
                    let signature = private_key.sign(b"", b"");
                    assert!(public_key.verify(b"", b"", &signature));
                }

                #[test]
                fn test_wrong_key_fails() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let other_public_key = PrivateKey::random(&mut test_rng_seeded(1)).public_key();
                    let namespace = b"test_namespace";
                    let message = b"test_message";
                    let signature = private_key.sign(namespace, message);
                    assert!(!other_public_key.verify(namespace, message, &signature));
                }

                #[test]
                fn test_codec_private_key() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let encoded = private_key.encode();
                    assert_eq!(encoded.len(), PrivateKey::SIZE);
                    let decoded = PrivateKey::decode(encoded).unwrap();
                    assert_eq!(private_key, decoded);
                    assert_eq!(private_key.public_key(), decoded.public_key());
                }

                #[test]
                fn test_codec_public_key() {
                    let public_key = PrivateKey::random(&mut test_rng()).public_key();
                    let encoded = public_key.encode();
                    assert_eq!(encoded.len(), PUBLIC_KEY_LENGTH);
                    let decoded = PublicKey::decode(encoded).unwrap();
                    assert_eq!(public_key, decoded);
                }

                #[test]
                fn test_codec_signature() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let public_key = private_key.public_key();
                    let namespace = b"test_namespace";
                    let message = b"test_message";
                    let signature = private_key.sign(namespace, message);
                    let encoded = signature.encode();
                    assert_eq!(encoded.len(), SIGNATURE_LENGTH);
                    let decoded = Signature::decode(encoded).unwrap();
                    assert_eq!(signature, decoded);
                    assert!(public_key.verify(namespace, message, &decoded));
                }

                #[test]
                fn test_decode_invalid_length_fails() {
                    assert!(PublicKey::decode(vec![0u8; 1024].as_ref()).is_err());
                    assert!(Signature::decode(vec![0u8; 1024].as_ref()).is_err());
                }

                #[test]
                fn test_zero_signature_fails() {
                    let public_key = PrivateKey::random(&mut test_rng()).public_key();
                    let zero_sig = Signature::decode(vec![0u8; Signature::SIZE].as_ref()).unwrap();
                    assert!(!public_key.verify_inner(None, b"test_message", &zero_sig));
                }

                #[test]
                fn test_corrupted_signature_fails() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let public_key = private_key.public_key();
                    let message = b"test_message";
                    let signature = private_key.sign_inner(None, message);
                    let mut corrupted = signature.encode().to_vec();
                    corrupted[0] ^= 0x01;
                    let corrupted = Signature::decode(corrupted.as_ref()).unwrap();
                    assert!(!public_key.verify_inner(None, message, &corrupted));
                }

                #[test]
                fn test_keypair_derivation_deterministic() {
                    let private_key_1 = PrivateKey::random(&mut test_rng());
                    let private_key_2 = PrivateKey::random(&mut test_rng());
                    assert_eq!(private_key_1, private_key_2);
                    assert_eq!(private_key_1.public_key(), private_key_2.public_key());
                }

                #[test]
                fn test_batch_verify_valid() {
                    let private_key_1 = PrivateKey::random(&mut test_rng());
                    let private_key_2 = PrivateKey::random(&mut test_rng_seeded(1));
                    let namespace = b"test_namespace";
                    let message_1 = b"first_message";
                    let message_2 = b"second_message";

                    let mut batch = Batch::new();
                    assert!(batch.add(
                        namespace,
                        message_1,
                        &private_key_1.public_key(),
                        &private_key_1.sign(namespace, message_1)
                    ));
                    assert!(batch.add(
                        namespace,
                        message_2,
                        &private_key_1.public_key(),
                        &private_key_1.sign(namespace, message_2)
                    ));
                    assert!(batch.add(
                        namespace,
                        message_1,
                        &private_key_2.public_key(),
                        &private_key_2.sign(namespace, message_1)
                    ));
                    assert!(batch.verify(&mut test_rng(), &Sequential));
                }

                #[test]
                fn test_batch_verify_invalid() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let namespace = b"test_namespace";
                    let message = b"test_message";
                    let signature = private_key.sign(namespace, message);

                    let mut batch = Batch::new();
                    assert!(batch.add(namespace, message, &private_key.public_key(), &signature));
                    assert!(batch.add(
                        namespace,
                        b"wrong_message",
                        &private_key.public_key(),
                        &signature
                    ));
                    assert!(!batch.verify(&mut test_rng(), &Sequential));
                }

                #[test]
                fn test_batch_verify_empty() {
                    let batch = Batch::new();
                    assert!(batch.verify(&mut test_rng(), &Sequential));
                }

                #[test]
                fn test_private_key_redacted() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    let debug = format!("{:?}", private_key);
                    let display = format!("{}", private_key);
                    assert!(debug.contains("REDACTED"));
                    assert!(display.contains("REDACTED"));
                }

                #[test]
                fn test_from_private_key_to_public_key() {
                    let private_key = PrivateKey::random(&mut test_rng());
                    assert_eq!(private_key.public_key(), PublicKey::from(private_key));
                }

                #[cfg(feature = "arbitrary")]
                mod conformance {
                    use super::*;
                    use commonware_codec::conformance::CodecConformance;

                    commonware_conformance::conformance_tests! {
                        CodecConformance<PrivateKey> => 256,
                        CodecConformance<PublicKey> => 256,
                        CodecConformance<Signature> => 1024,
                    }
                }
            }
        }
    };
}

impl_mayo!(mayo1, Mayo1, "MAYO-1");
impl_mayo!(mayo2, Mayo2, "MAYO-2");
impl_mayo!(mayo3, Mayo3, "MAYO-3");
impl_mayo!(mayo5, Mayo5, "MAYO-5");
