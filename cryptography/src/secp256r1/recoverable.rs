cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::borrow::Cow;
    } else {
        use alloc::borrow::Cow;
    }
}
use super::common::{
    impl_private_key_wrapper, impl_public_key_wrapper, PrivateKeyInner, PublicKeyInner, CURVE_NAME,
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_utils::{hex, union_unique, Array, Span};
use core::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
use ecdsa::RecoveryId;
use p256::{ecdsa::VerifyingKey, elliptic_curve::scalar::IsHigh};

const BASE_SIGNATURE_LENGTH: usize = 64; // R || S
const SIGNATURE_LENGTH: usize = 1 + BASE_SIGNATURE_LENGTH; // RecoveryId || R || S

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
        let (mut signature, mut recovery_id) = self
            .0
            .key
            .sign_recoverable(&payload)
            .expect("signing must succeed");

        // The signing algorithm generates k, then calculates r <- x(k * G). Normalizing s by negating it is equivalent
        // to negating k. This has no effect on x(k * G) but y(-k * G) = -y(k * G), hence the need to flip the bit if
        // we move s into the lower half of the curve order.
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
            recovery_id = RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced());
        }

        Signature::new(signature, recovery_id)
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        Self(PublicKeyInner::from_private_key(&value.0))
    }
}

/// Secp256r1 Public Key.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicKey(PublicKeyInner);

impl_public_key_wrapper!(PublicKey);

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        self.verify_inner(Some(namespace), msg, sig)
    }
}

impl PublicKey {
    #[inline(always)]
    fn verify_inner(&self, namespace: Option<&[u8]>, msg: &[u8], sig: &Signature) -> bool {
        let Some(recovered_signer) = sig.recover_signer_inner(namespace, msg) else {
            return false;
        };
        &recovered_signer == self
    }
}

/// Secp256r1 Signature with recovery ID.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; SIGNATURE_LENGTH],
    recovery_id: RecoveryId,
    signature: p256::ecdsa::Signature,
}

impl Signature {
    fn new(signature: p256::ecdsa::Signature, recovery_id: RecoveryId) -> Self {
        let mut raw = [0u8; SIGNATURE_LENGTH];
        raw[0] = recovery_id.to_byte();
        raw[1..].copy_from_slice(signature.to_bytes().as_slice());

        Self {
            raw,
            recovery_id,
            signature,
        }
    }
}

impl crate::Signature for Signature {}

impl crate::Recoverable for Signature {
    type PublicKey = PublicKey;

    fn recover_signer(&self, namespace: &[u8], msg: &[u8]) -> Option<Self::PublicKey> {
        self.recover_signer_inner(Some(namespace), msg)
    }
}

impl Signature {
    #[inline(always)]
    fn recover_signer_inner(&self, namespace: Option<&[u8]>, msg: &[u8]) -> Option<PublicKey> {
        let payload = namespace.map_or(Cow::Borrowed(msg), |namespace| {
            Cow::Owned(union_unique(namespace, msg))
        });

        VerifyingKey::recover_from_msg(payload.as_ref(), &self.signature, self.recovery_id)
            .ok()
            .map(|k| PublicKey(PublicKeyInner::from(k)))
    }
}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let recovery_id = RecoveryId::from_byte(raw[0])
            .ok_or_else(|| CodecError::Invalid(CURVE_NAME, "RecoveryId out of range"))?;
        let result = p256::ecdsa::Signature::from_slice(&raw[1..]);
        #[cfg(feature = "std")]
        let signature = result.map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        #[cfg(not(feature = "std"))]
        let signature = result
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, alloc::format!("{:?}", e).into()))?;
        // Reject any signatures with a `s` value in the upper half of the curve order.
        if signature.s().is_high().into() {
            return Err(CodecError::Invalid(CURVE_NAME, "Signature S is high"));
        }
        Ok(Self {
            raw,
            signature,
            recovery_id,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{secp256r1::common::tests::*, Recoverable, Signer as _, Verifier as _};
    use bytes::Bytes;
    use commonware_codec::{DecodeExt, Encode};
    use ecdsa::RecoveryId;
    use p256::elliptic_curve::scalar::IsHigh;
    use rstest::rstest;

    const NAMESPACE: &[u8] = b"test-namespace";

    fn encode_signature_with_recovery(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &p256::ecdsa::Signature,
    ) -> Vec<u8> {
        let recovery_id = RecoveryId::trial_recovery_from_msg(verifying_key, message, signature)
            .unwrap_or_else(|_| RecoveryId::new(false, false));
        Signature::new(*signature, recovery_id).encode().to_vec()
    }

    #[test]
    fn test_recover_signer_flipped_y_parity_fails() {
        let private_key = PrivateKey(create_private_key());
        let expected_public_key = private_key.public_key();
        let message = b"recover with no namespace";

        let mut signature = private_key.sign(NAMESPACE, message);

        signature.recovery_id = RecoveryId::new(
            !signature.recovery_id.is_y_odd(),
            signature.recovery_id.is_x_reduced(),
        );

        let recovered = signature.recover_signer(NAMESPACE, message);

        assert_ne!(
            recovered,
            Some(expected_public_key),
            "flipped y-parity must fail recovery"
        );

        assert!(!private_key
            .public_key()
            .verify(NAMESPACE, message, &signature));
    }

    #[test]
    fn test_recover_signer_with_namespace() {
        let private_key = PrivateKey(create_private_key());
        let expected_public_key = private_key.public_key();
        let message = b"recover with namespace";

        let signature = private_key.sign(NAMESPACE, message);
        let recovered = signature.recover_signer(NAMESPACE, message);
        assert_eq!(recovered, Some(expected_public_key));
    }

    #[test]
    fn test_recover_signer_mismatched_message_does_not_match_public_key() {
        let private_key = PrivateKey(create_private_key());
        let original_message = b"recover with namespace";
        let expected_public_key = private_key.public_key();
        let signature = private_key.sign(NAMESPACE, original_message);

        let recovered = signature.recover_signer(NAMESPACE, b"different message");
        assert_ne!(
            recovered,
            Some(expected_public_key),
            "mismatched message must not recover the original public key"
        );
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

        let decoded = PublicKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_signature() {
        let private_key = PrivateKey(create_private_key());
        let original = private_key.sign(NAMESPACE, "Hello World".as_bytes());

        let encoded = original.encode();
        assert_eq!(encoded.len(), SIGNATURE_LENGTH);

        let decoded = Signature::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_signature_invalid() {
        let (_, sig, ..) = vector_sig_verification_5();
        let result = Signature::decode(Bytes::from(sig));
        assert!(result.is_err());
    }

    #[test]
    fn test_scheme_sign() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_utils::from_hex_formatted(
                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
            )
            .unwrap()
            .as_ref(),
        )
        .unwrap();
        let public_key: PublicKey = private_key.clone().into();
        let message = commonware_utils::from_hex_formatted(
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
        let result = Signature::decode(vec![0u8; SIGNATURE_LENGTH].as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_high_s_signature_fails() {
        let (inner, _) = vector_keypair_1();
        let private_key = PrivateKey(inner);
        let message = b"edge";
        let signature = private_key.sign(NAMESPACE, message);
        let mut bad_signature = signature.to_vec();
        bad_signature[33] |= 0x80;
        assert!(Signature::decode(bad_signature.as_ref()).is_err());
    }

    #[test]
    fn test_decode_zero_r_signature_fails() {
        let (inner, _) = vector_keypair_1();
        let private_key = PrivateKey(inner);
        let message = b"edge";
        let signature = private_key.sign(NAMESPACE, message);
        let mut bad_signature = signature.to_vec();
        for b in bad_signature.iter_mut().skip(1).take(32) {
            *b = 0x00;
        }
        bad_signature[33] = 1;
        assert!(Signature::decode(bad_signature.as_ref()).is_err());
    }

    #[test]
    fn test_rfc6979() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_utils::from_hex_formatted(
                "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            )
            .unwrap()
            .as_ref(),
        )
        .unwrap();

        let (message, exp_sig) = (
            b"sample",
            p256::ecdsa::Signature::from_slice(
                &commonware_utils::from_hex_formatted(
                    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
                    f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let signature = private_key.sign_inner(None, message);
        assert_eq!(
            signature.signature.to_bytes().to_vec(),
            exp_sig.normalize_s().unwrap().to_bytes().to_vec()
        );

        let (message, exp_sig) = (
            b"test",
            p256::ecdsa::Signature::from_slice(
                &commonware_utils::from_hex_formatted(
                    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367
                    019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
                )
                .unwrap(),
            )
            .unwrap(),
        );

        let signature = private_key.sign_inner(None, message);
        assert_eq!(
            signature.signature.to_bytes().to_vec(),
            exp_sig.to_bytes().to_vec()
        );
    }

    #[test]
    fn test_scheme_validate_public_key_too_long() {
        let qx_hex = "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f";
        let qy_hex = "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f";

        let uncompressed_public_key = parse_public_key_as_uncompressed_vector(qx_hex, qy_hex);
        let public_key = PublicKey::decode(uncompressed_public_key.as_ref());
        assert!(matches!(public_key, Err(CodecError::Invalid(_, _))));

        let mut compressed_public_key = parse_public_key_as_compressed_vector(qx_hex, qy_hex);
        compressed_public_key.push(0u8);
        let public_key = PublicKey::decode(compressed_public_key.as_ref());
        assert!(matches!(public_key, Err(CodecError::ExtraData(1))));

        let compressed_public_key = parse_public_key_as_compressed_vector(qx_hex, qy_hex);
        let public_key = PublicKey::decode(compressed_public_key.as_ref());
        assert!(public_key.is_ok());
    }

    #[test]
    fn test_scheme_verify_signature_r0() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_utils::from_hex_formatted(
                "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357",
            )
            .unwrap()
            .as_ref(),
        )
        .unwrap();
        let message = b"sample";
        let signature = private_key.sign(NAMESPACE, message);
        let mut signature = signature.to_vec();
        signature[1..33].fill(0);

        assert!(Signature::decode(signature.as_ref()).is_err());
    }

    #[test]
    fn test_scheme_verify_signature_s0() {
        let private_key: PrivateKey = PrivateKey::decode(
            commonware_utils::from_hex_formatted(
                "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357",
            )
            .unwrap()
            .as_ref(),
        )
        .unwrap();
        let message = b"sample";
        let signature = private_key.sign(NAMESPACE, message);
        let mut signature = signature.to_vec();
        signature[33..].fill(0);

        assert!(Signature::decode(signature.as_ref()).is_err());
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
        let res = PublicKey::decode(public_key.as_ref());
        assert_eq!(exp_valid, res.is_ok(), "vector_public_key_validation_{n}");
    }

    fn vector_sig_verification_1() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_1_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_2() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_2_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_3() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_3_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_4() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_4_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_5() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_5_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_6() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_6_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_7() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_7_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_8() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_8_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_9() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_9_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_10() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_10_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_11() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_11_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_12() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_12_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_13() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_13_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_14() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_14_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
    }

    fn vector_sig_verification_15() -> (PublicKey, Vec<u8>, Vec<u8>, bool) {
        let (public_key, sig, message, expected) = vector_sig_verification_15_raw();
        let encoded = encode_signature_with_recovery(&public_key.key, &message, &sig);
        (PublicKey(public_key), encoded, message, expected)
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
            let mut ecdsa_signature = p256::ecdsa::Signature::from_slice(&sig[1..]).unwrap();
            if ecdsa_signature.s().is_high().into() {
                assert!(Signature::decode(sig.as_ref()).is_err());
                assert!(Signature::decode(Bytes::from(sig)).is_err());

                if let Some(normalized_sig) = ecdsa_signature.normalize_s() {
                    ecdsa_signature = normalized_sig;
                }
            }
            let recovery_id =
                RecoveryId::trial_recovery_from_msg(&public_key.0.key, &message, &ecdsa_signature)
                    .expect("recovery id");
            let signature = Signature::new(ecdsa_signature, recovery_id);
            public_key.verify_inner(None, &message, &signature)
        } else {
            let tf_res = Signature::decode(sig.as_ref());
            let dc_res = Signature::decode(Bytes::from(sig));
            if tf_res.is_err() && dc_res.is_err() {
                true
            } else {
                let f1 = !public_key.verify_inner(None, &message, &tf_res.unwrap());
                let f2 = !public_key.verify_inner(None, &message, &dc_res.unwrap());
                f1 && f2
            }
        };
        assert!(expected);
    }
}
