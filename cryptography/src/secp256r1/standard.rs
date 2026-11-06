cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::borrow::Cow;
    } else {
        use alloc::borrow::Cow;
    }
}
use super::common::{
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PrivateKeyInner, PublicKeyInner,
    impl_private_key_wrapper, impl_public_key_wrapper,
};
use crate::{Encoding, Malformed};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use bytes::BufMut;
use commonware_codec::{FixedSize, Write};
use commonware_formatting::Hex;
use commonware_utils::union_unique;
use core::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use p256::ecdsa::signature::Verifier;
use p256::{ecdsa::signature::Signer, elliptic_curve::scalar::IsHigh};

const SIGNATURE_LENGTH: usize = 64; // R || S

/// Secp256r1 Private Key.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKey(PrivateKeyInner);

impl_private_key_wrapper!(PrivateKey);

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        self.sign_inner(Some(namespace), msg)
    }

    fn public_key(&self) -> Self::PublicKey {
        PublicKey(PublicKeyInner::from_private_key(&self.0))
    }
}

impl PrivateKey {
    #[inline(always)]
    fn sign_inner(&self, namespace: Option<&[u8]>, msg: &[u8]) -> Signature {
        let payload = namespace.map_or(Cow::Borrowed(msg), |namespace| {
            Cow::Owned(union_unique(namespace, msg))
        });
        let signature: p256::ecdsa::Signature = self.0.key.expose(|key| key.sign(&payload));
        let signature = signature.normalize_s();
        Signature::try_from(signature).expect("freshly signed signature is valid")
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        Self(PublicKeyInner::from_private_key(&value.0))
    }
}

/// Secp256r1 Public Key.
///
/// A key is built from its [PublicKeyBytes], which must encode a compressed SEC1 point on the
/// curve. P-256 has cofactor one, so every key has prime order.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PublicKey(PublicKeyInner);

impl_public_key_wrapper!(PublicKey);

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        self.verify_inner(Some(namespace), msg, sig)
    }
}

impl PublicKey {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[inline(always)]
    fn verify_inner(&self, namespace: Option<&[u8]>, msg: &[u8], sig: &Signature) -> bool {
        let payload = namespace.map_or(Cow::Borrowed(msg), |namespace| {
            Cow::Owned(union_unique(namespace, msg))
        });
        self.0.key.verify(&payload, &sig.signature).is_ok()
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[inline(always)]
    fn verify_inner(&self, namespace: Option<&[u8]>, msg: &[u8], sig: &Signature) -> bool {
        let payload = namespace.map_or(Cow::Borrowed(msg), |namespace| {
            Cow::Owned(union_unique(namespace, msg))
        });
        let uncompressed = self.0.to_uncompressed();
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &uncompressed);
        public_key.verify(&payload, &sig.raw).is_ok()
    }
}

/// The encoding of a Secp256r1 signature, as `R || S`.
pub type SignatureBytes = Encoding<Signature, SIGNATURE_LENGTH>;

/// Secp256r1 Signature.
///
/// A signature is built from its [SignatureBytes], which must encode `r` and `s` in `[1, n)`
/// with `s` in the lower half of the curve order, so every signature is in its low-`s` form.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; SIGNATURE_LENGTH],
    signature: p256::ecdsa::Signature,
}

impl TryFrom<SignatureBytes> for Signature {
    type Error = Malformed;

    fn try_from(bytes: SignatureBytes) -> Result<Self, Malformed> {
        let raw = *bytes.as_array();
        let signature = p256::ecdsa::Signature::from_slice(&raw).map_err(|_| Malformed)?;

        // Reject any signatures with a `s` value in the upper half of the curve order.
        if signature.s().is_high().into() {
            return Err(Malformed);
        }
        Ok(Self { raw, signature })
    }
}

impl From<Signature> for SignatureBytes {
    fn from(signature: Signature) -> Self {
        Self::new(signature.raw)
    }
}

impl TryFrom<p256::ecdsa::Signature> for Signature {
    type Error = Malformed;

    fn try_from(value: p256::ecdsa::Signature) -> Result<Self, Malformed> {
        Self::try_from(SignatureBytes::new(value.to_bytes().into()))
    }
}

impl crate::Validated for Signature {
    type Bytes = SignatureBytes;
}

impl crate::Signature for Signature {}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl FixedSize for Signature {
    const SIZE: usize = SIGNATURE_LENGTH;
}

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

impl Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use commonware_math::algebra::Random;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey(PrivateKeyInner::random(&mut rand));
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(private_key.sign(&[], &message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signer as _, Verifier as _, secp256r1::common::tests::*};
    use commonware_codec::{Copying, DecodeExt, Encode, Error as CodecError};
    use p256::elliptic_curve::scalar::IsHigh;
    use rstest::rstest;

    const NAMESPACE: &[u8] = b"test-namespace";

    /// Decodes the encoding of a public key and builds the key from it.
    fn convert_public_key(encoded: &[u8]) -> Result<PublicKey, Malformed> {
        PublicKey::try_from(PublicKeyBytes::decode(Copying(encoded)).unwrap())
    }

    /// Decodes the encoding of a signature and builds the signature from it.
    fn convert_signature(encoded: &[u8]) -> Result<Signature, Malformed> {
        Signature::try_from(SignatureBytes::decode(Copying(encoded)).unwrap())
    }

    #[test]
    fn test_codec_private_key() {
        let original = PrivateKey(create_private_key());
        let encoded = original.encode();
        assert_eq!(encoded.len(), PRIVATE_KEY_LENGTH);

        let decoded = PrivateKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_public_key() {
        let private_key = PrivateKey(create_private_key());
        let original = PublicKey::from(private_key);

        let encoded = original.encode();
        assert_eq!(encoded.len(), PUBLIC_KEY_LENGTH);

        let decoded = convert_public_key(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(PublicKeyBytes::from(decoded).as_ref(), encoded.as_ref());
    }

    #[test]
    fn test_codec_signature() {
        let private_key = PrivateKey(create_private_key());
        let original = private_key.sign(NAMESPACE, "Hello World".as_bytes());

        let encoded = original.encode();
        assert_eq!(encoded.len(), SIGNATURE_LENGTH);

        let decoded = convert_signature(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(SignatureBytes::from(decoded).as_ref(), encoded.as_ref());
    }

    #[test]
    fn test_codec_signature_invalid() {
        let (_, sig, ..) = vector_sig_verification_5();
        assert_eq!(convert_signature(&sig), Err(Malformed));
    }

    #[test]
    fn test_scheme_sign() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_formatting::from_hex(
                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
            )
            .unwrap(),
        )
        .unwrap();
        let public_key: PublicKey = private_key.clone().into();
        let message = commonware_formatting::from_hex(
            "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045e
            e2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf
            9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8",
        )
        .unwrap();
        let signature = private_key.sign(NAMESPACE, &message);
        assert_eq!(SIGNATURE_LENGTH, signature.len());
        assert!(public_key.verify(NAMESPACE, &message, &signature));
    }

    #[test]
    fn test_decode_zero_signature_fails() {
        assert_eq!(convert_signature(&[0u8; SIGNATURE_LENGTH]), Err(Malformed));
    }

    #[test]
    fn test_decode_high_s_signature_fails() {
        let (inner, _) = vector_keypair_1();
        let private_key = PrivateKey(inner);
        let message = b"edge";
        let signature = private_key.sign(NAMESPACE, message);
        let mut bad_signature = signature.to_vec();
        bad_signature[32] |= 0x80;
        assert_eq!(convert_signature(&bad_signature), Err(Malformed));
    }

    #[test]
    fn test_decode_zero_r_signature_fails() {
        let (inner, _) = vector_keypair_1();
        let private_key = PrivateKey(inner);
        let message = b"edge";
        let signature = private_key.sign(NAMESPACE, message);
        let mut bad_signature = signature.to_vec();
        for b in bad_signature.iter_mut().take(32) {
            *b = 0x00;
        }
        bad_signature[32] = 1;
        assert_eq!(convert_signature(&bad_signature), Err(Malformed));
    }

    #[test]
    fn test_rfc6979() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_formatting::from_hex(
                "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            )
            .unwrap(),
        )
        .unwrap();

        let (message, exp_sig) = (
            b"sample",
            p256::ecdsa::Signature::from_slice(
                &commonware_formatting::from_hex(
                    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
                    f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let signature = private_key.sign_inner(None, message);
        assert_eq!(signature.to_vec(), exp_sig.normalize_s().to_vec());

        let (message, exp_sig) = (
            b"test",
            p256::ecdsa::Signature::from_slice(
                &commonware_formatting::from_hex(
                    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367
                    019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
                )
                .unwrap(),
            )
            .unwrap(),
        );

        let signature = private_key.sign_inner(None, message);
        assert_eq!(signature.to_vec(), exp_sig.to_vec());
    }

    #[test]
    fn test_scheme_validate_public_key_too_long() {
        let qx_hex = "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f";
        let qy_hex = "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f";

        let uncompressed_public_key = parse_public_key_as_uncompressed_vector(qx_hex, qy_hex);
        let public_key = PublicKeyBytes::decode(uncompressed_public_key);
        assert!(matches!(public_key, Err(CodecError::ExtraData(32))));

        let mut compressed_public_key = parse_public_key_as_compressed_vector(qx_hex, qy_hex);
        compressed_public_key.push(0u8);
        let public_key = PublicKeyBytes::decode(compressed_public_key);
        assert!(matches!(public_key, Err(CodecError::ExtraData(1))));

        let compressed_public_key = parse_public_key_as_compressed_vector(qx_hex, qy_hex);
        assert!(convert_public_key(&compressed_public_key).is_ok());
    }

    #[test]
    fn test_scheme_verify_signature_r0() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_formatting::from_hex(
                "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357",
            )
            .unwrap(),
        )
        .unwrap();
        let message = b"sample";
        let signature = private_key.sign_inner(None, message);
        let (_, s) = signature.split_at(32);
        let mut signature: Vec<u8> = vec![0x00; 32];
        signature.extend_from_slice(s);

        assert_eq!(convert_signature(&signature), Err(Malformed));
    }

    #[test]
    fn test_scheme_verify_signature_s0() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_formatting::from_hex(
                "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357",
            )
            .unwrap(),
        )
        .unwrap();
        let message = b"sample";
        let signature = private_key.sign_inner(None, message);
        let (r, _) = signature.split_at(32);
        let s: Vec<u8> = vec![0x00; 32];
        let mut signature = r.to_vec();
        signature.extend(s);

        assert_eq!(convert_signature(&signature), Err(Malformed));
    }

    #[rstest]
    #[case(vector_keypair_1())]
    #[case(vector_keypair_2())]
    #[case(vector_keypair_3())]
    #[case(vector_keypair_4())]
    #[case(vector_keypair_5())]
    #[case(vector_keypair_6())]
    #[case(vector_keypair_7())]
    #[case(vector_keypair_8())]
    #[case(vector_keypair_9())]
    #[case(vector_keypair_10())]
    fn test_keypairs(#[case] (inner_priv, inner_pub): (PrivateKeyInner, PublicKeyInner)) {
        let private_key = PrivateKey(inner_priv);
        let public_key = PublicKey::from(private_key);
        let exp_public_key = PublicKey(inner_pub);
        assert_eq!(exp_public_key, public_key);
        assert!(public_key.len() == PUBLIC_KEY_LENGTH);
    }

    #[rstest]
    #[case(1, vector_public_key_validation_1())]
    #[case(3, vector_public_key_validation_3())]
    #[case(4, vector_public_key_validation_4())]
    #[case(5, vector_public_key_validation_5())]
    #[case(6, vector_public_key_validation_6())]
    #[case(7, vector_public_key_validation_7())]
    #[case(8, vector_public_key_validation_8())]
    #[case(9, vector_public_key_validation_9())]
    #[case(10, vector_public_key_validation_10())]
    #[case(12, vector_public_key_validation_12())]
    fn test_public_key_validation(
        #[case] n: usize,
        #[case] (public_key, exp_valid): (Vec<u8>, bool),
    ) {
        let res = PublicKeyBytes::decode(public_key)
            .ok()
            .and_then(|bytes| PublicKey::try_from(bytes).ok());
        assert_eq!(exp_valid, res.is_some(), "vector_public_key_validation_{n}");
    }

    fn vector_sig_verification_1() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_1_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_2() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_2_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_3() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_3_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_4() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_4_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_5() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_5_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_6() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_6_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_7() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_7_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_8() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_8_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_9() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_9_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_10() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_10_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_11() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_11_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_12() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_12_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_13() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_13_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_14() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_14_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    fn vector_sig_verification_15() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_15_raw();
        (PublicKey(public_key), sig.to_vec(), message, expected)
    }

    #[rstest]
    #[case(vector_sig_verification_1())]
    #[case(vector_sig_verification_2())]
    #[case(vector_sig_verification_3())]
    #[case(vector_sig_verification_4())]
    #[case(vector_sig_verification_5())]
    #[case(vector_sig_verification_6())]
    #[case(vector_sig_verification_7())]
    #[case(vector_sig_verification_8())]
    #[case(vector_sig_verification_9())]
    #[case(vector_sig_verification_10())]
    #[case(vector_sig_verification_11())]
    #[case(vector_sig_verification_12())]
    #[case(vector_sig_verification_13())]
    #[case(vector_sig_verification_14())]
    #[case(vector_sig_verification_15())]
    fn test_signature_verification(
        #[case] (public_key, sig, message, expected): (PublicKey, Vec<u8>, Vec<u8>, bool),
    ) {
        let expected = if expected {
            let mut ecdsa_signature = p256::ecdsa::Signature::from_slice(&sig).unwrap();
            if ecdsa_signature.s().is_high().into() {
                assert_eq!(convert_signature(&sig), Err(Malformed));

                ecdsa_signature = ecdsa_signature.normalize_s();
            }
            let signature = Signature::try_from(ecdsa_signature).unwrap();
            public_key.verify_inner(None, &message, &signature)
        } else {
            convert_signature(&sig)
                .ok()
                .is_none_or(|signature| !public_key.verify_inner(None, &message, &signature))
        };
        assert!(expected);
    }

    #[test]
    fn validation_contract() {
        // Keys that must fail to decode: an uncompressed SEC1 tag, a compressed tag with `x`
        // above the field modulus, a zero tag, and a compressed tag with the off-curve `x = 1`.
        let mut uncompressed_tag = [0u8; 33];
        uncompressed_tag[0] = 0x04;
        let mut x_too_large = [0xffu8; 33];
        x_too_large[0] = 0x02;
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 1;
        crate::assert_validation_contract::<PrivateKey>(
            &[&uncompressed_tag, &x_too_large, &[0; 33], &off_curve],
            |honest| {
                // Signatures that must be rejected: the honest signature in its high form with
                // `s` replaced by `n - s`, the all-zero encoding with `r = 0`, and the honest
                // signature with `s` above the curve order.
                let mut s_high = honest.to_vec();
                negate_scalar(&mut s_high[32..]);
                let mut s_too_large = honest.to_vec();
                s_too_large[32..].fill(0xff);
                vec![s_high, vec![0; 64], s_too_large]
            },
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PublicKeyBytes> => 1024,
            CodecConformance<SignatureBytes> => 1024,
        }
    }
}
