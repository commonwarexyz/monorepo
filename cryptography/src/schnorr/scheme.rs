#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::Random;
use commonware_utils::{hex, union_unique, Array, Span};
use core::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
use k256::schnorr::{
    signature::{Signer as K256Signer, Verifier as K256Verifier},
    SigningKey, VerifyingKey,
};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::borrow::Cow;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CURVE_NAME: &str = "secp256k1-schnorr";
const PRIVATE_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// Schnorr Private Key over secp256k1.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    raw: [u8; PRIVATE_KEY_LENGTH],
    #[zeroize(skip)]
    key: SigningKey,
}

impl crate::PrivateKey for PrivateKey {}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        self.sign_inner(Some(namespace), msg)
    }

    fn public_key(&self) -> Self::PublicKey {
        let verifying_key = *self.key.verifying_key();
        let raw = verifying_key.to_bytes();
        Self::PublicKey {
            raw: raw.into(),
            key: verifying_key,
        }
    }
}

impl PrivateKey {
    #[inline(always)]
    fn sign_inner(&self, namespace: Option<&[u8]>, msg: &[u8]) -> Signature {
        let payload = namespace
            .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
            .unwrap_or_else(|| Cow::Borrowed(msg));
        let sig: k256::schnorr::Signature = K256Signer::sign(&self.key, &payload);
        Signature::from(sig)
    }
}

impl Random for PrivateKey {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        let key = SigningKey::random(&mut rng);
        let raw = key.to_bytes().into();
        Self { raw, key }
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let result = SigningKey::from_bytes(&raw);
        #[cfg(feature = "std")]
        let key = result.map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        #[cfg(not(feature = "std"))]
        let key = result
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, alloc::format!("{:?}", e).into()))?;

        Ok(Self { raw, key })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = PRIVATE_KEY_LENGTH;
}

impl Span for PrivateKey {}

impl Array for PrivateKey {}

impl Eq for PrivateKey {}

impl Hash for PrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PrivateKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
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

/// Schnorr Public Key over secp256k1 (x-only, 32 bytes as per BIP-340).
#[derive(Clone)]
pub struct PublicKey {
    raw: [u8; PUBLIC_KEY_LENGTH],
    key: VerifyingKey,
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        let verifying_key = *value.key.verifying_key();
        let raw = verifying_key.to_bytes();
        Self {
            raw: raw.into(),
            key: verifying_key,
        }
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
    fn verify_inner(&self, namespace: Option<&[u8]>, msg: &[u8], sig: &Signature) -> bool {
        let payload = namespace
            .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
            .unwrap_or_else(|| Cow::Borrowed(msg));
        K256Verifier::verify(&self.key, &payload, &sig.signature).is_ok()
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let result = VerifyingKey::from_bytes(&raw);
        #[cfg(feature = "std")]
        let key = result.map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        #[cfg(not(feature = "std"))]
        let key = result
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, alloc::format!("{:?}", e).into()))?;

        Ok(Self { raw, key })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use commonware_math::algebra::Random;
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        Ok(private_key.public_key())
    }
}

/// Schnorr Signature over secp256k1 (64 bytes as per BIP-340).
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; SIGNATURE_LENGTH],
    signature: k256::schnorr::Signature,
}

impl crate::Signature for Signature {}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let result = k256::schnorr::Signature::try_from(raw.as_slice());
        #[cfg(feature = "std")]
        let signature = result.map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        #[cfg(not(feature = "std"))]
        let signature = result
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, alloc::format!("{:?}", e).into()))?;

        Ok(Self { raw, signature })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = SIGNATURE_LENGTH;
}

impl Span for Signature {}

impl Array for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for Signature {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<k256::schnorr::Signature> for Signature {
    fn from(value: k256::schnorr::Signature) -> Self {
        let raw = value.to_bytes();
        Self {
            raw,
            signature: value,
        }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use commonware_math::algebra::Random;
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(private_key.sign(&[], &message))
    }
}

/// BIP-340 test vectors sourced from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signer as _, Verifier as _};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_math::algebra::Random;
    use rand::rngs::OsRng;

    fn test_key_derivation_and_signing(
        private_key: &PrivateKey,
        expected_public_key: &PublicKey,
        message: &[u8],
    ) {
        // Verify public key derivation matches the expected value
        assert_eq!(private_key.public_key(), *expected_public_key);
        // Verify signing and verification works with this key pair
        let computed_signature = private_key.sign_inner(None, message);
        assert!(expected_public_key.verify_inner(None, message, &computed_signature));
    }

    fn parse_private_key(private_key: &str) -> PrivateKey {
        PrivateKey::decode(
            commonware_utils::from_hex_formatted(private_key)
                .unwrap()
                .as_ref(),
        )
        .unwrap()
    }

    fn parse_public_key(public_key: &str) -> PublicKey {
        PublicKey::decode(
            commonware_utils::from_hex_formatted(public_key)
                .unwrap()
                .as_ref(),
        )
        .unwrap()
    }

    fn parse_signature(signature: &str) -> Signature {
        Signature::decode(
            commonware_utils::from_hex_formatted(signature)
                .unwrap()
                .as_ref(),
        )
        .unwrap()
    }

    // BIP-340 Test Vector 0
    fn vector_0() -> (PrivateKey, PublicKey, Vec<u8>, Signature) {
        (
            parse_private_key("0000000000000000000000000000000000000000000000000000000000000003"),
            parse_public_key("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
            commonware_utils::from_hex_formatted(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            parse_signature(
                "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215
                 25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            ),
        )
    }

    // BIP-340 Test Vector 1
    fn vector_1() -> (PrivateKey, PublicKey, Vec<u8>, Signature) {
        (
            parse_private_key("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"),
            parse_public_key("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            commonware_utils::from_hex_formatted(
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            )
            .unwrap(),
            parse_signature(
                "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341
                 8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            ),
        )
    }

    // BIP-340 Test Vector 2
    fn vector_2() -> (PrivateKey, PublicKey, Vec<u8>, Signature) {
        (
            parse_private_key("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"),
            parse_public_key("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"),
            commonware_utils::from_hex_formatted(
                "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            )
            .unwrap(),
            parse_signature(
                "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B
                 AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            ),
        )
    }

    // BIP-340 Test Vector 3
    fn vector_3() -> (PrivateKey, PublicKey, Vec<u8>, Signature) {
        (
            parse_private_key("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
            parse_public_key("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
            commonware_utils::from_hex_formatted(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )
            .unwrap(),
            parse_signature(
                "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC
                 97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            ),
        )
    }

    #[test]
    fn test_codec_private_key() {
        let private_key = parse_private_key(
            "0000000000000000000000000000000000000000000000000000000000000003",
        );
        let encoded = private_key.encode();
        assert_eq!(encoded.len(), PRIVATE_KEY_LENGTH);
        let decoded = PrivateKey::decode(encoded).unwrap();
        assert_eq!(private_key, decoded);
    }

    #[test]
    fn test_codec_public_key() {
        let public_key =
            parse_public_key("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        let encoded = public_key.encode();
        assert_eq!(encoded.len(), PUBLIC_KEY_LENGTH);
        let decoded = PublicKey::decode(encoded).unwrap();
        assert_eq!(public_key, decoded);
    }

    #[test]
    fn test_codec_signature() {
        let signature = parse_signature(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215
             25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        );
        let encoded = signature.encode();
        assert_eq!(encoded.len(), SIGNATURE_LENGTH);
        let decoded = Signature::decode(encoded).unwrap();
        assert_eq!(signature, decoded);
    }

    #[test]
    fn bip340_test_vector_0() {
        let (private_key, public_key, message, _signature) = vector_0();
        test_key_derivation_and_signing(&private_key, &public_key, &message);
    }

    #[test]
    fn bip340_test_vector_1() {
        let (private_key, public_key, message, _signature) = vector_1();
        test_key_derivation_and_signing(&private_key, &public_key, &message);
    }

    #[test]
    fn bip340_test_vector_2() {
        let (private_key, public_key, message, _signature) = vector_2();
        test_key_derivation_and_signing(&private_key, &public_key, &message);
    }

    #[test]
    fn bip340_test_vector_3() {
        let (private_key, public_key, message, _signature) = vector_3();
        test_key_derivation_and_signing(&private_key, &public_key, &message);
    }

    // Sanity check the test infra rejects bad signatures
    #[test]
    fn bad_signature_fails() {
        let (_, public_key, message, _) = vector_0();
        let private_key_2 = PrivateKey::random(&mut OsRng);
        let bad_signature = private_key_2.sign_inner(None, message.as_ref());
        assert!(!public_key.verify_inner(None, &message, &bad_signature));
    }

    // Sanity check the test infra rejects non-matching messages
    #[test]
    fn different_message_fails() {
        let (_, public_key, _, signature) = vector_0();
        let different_message = b"this is a different message";
        assert!(!public_key.verify_inner(None, different_message, &signature));
    }

    #[test]
    fn test_random_sign_and_verify() {
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let message = b"test message";
        let namespace = b"test_namespace";

        let signature = private_key.sign(namespace, message);
        assert!(public_key.verify(namespace, message, &signature));
    }

    #[test]
    fn test_wrong_namespace_fails() {
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let message = b"test message";
        let namespace = b"correct_namespace";
        let wrong_namespace = b"wrong_namespace";

        let signature = private_key.sign(namespace, message);
        assert!(!public_key.verify(wrong_namespace, message, &signature));
    }

    #[test]
    fn test_wrong_message_fails() {
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let message = b"test message";
        let wrong_message = b"wrong message";
        let namespace = b"test_namespace";

        let signature = private_key.sign(namespace, message);
        assert!(!public_key.verify(namespace, wrong_message, &signature));
    }

    #[test]
    fn test_signature_determinism() {
        let private_key_1 = PrivateKey::from_seed(42);
        let private_key_2 = PrivateKey::from_seed(42);
        let namespace = b"test_namespace";
        let message = b"test_message";

        let signature_1 = private_key_1.sign(namespace, message);
        let signature_2 = private_key_2.sign(namespace, message);

        assert_eq!(private_key_1.public_key(), private_key_2.public_key());
        assert_eq!(signature_1, signature_2);
    }

    #[test]
    fn test_invalid_public_key() {
        // All zeros is not a valid public key
        let result = PublicKey::decode(vec![0u8; PUBLIC_KEY_LENGTH].as_ref());
        assert!(result.is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PrivateKey>,
            CodecConformance<PublicKey>,
            CodecConformance<Signature>,
        }
    }
}
