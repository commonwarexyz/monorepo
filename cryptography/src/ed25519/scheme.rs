use crate::{
    BatchEntry, BatchVerifier, Secret,
    ed25519::core::{self as ed_core, VerificationKey},
};
#[cfg(not(feature = "std"))]
use alloc::borrow::{Cow, ToOwned};
#[cfg(all(not(feature = "std"), feature = "arbitrary"))]
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span, union_unique};
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::borrow::{Cow, ToOwned};
use zeroize::Zeroizing;

const CURVE_NAME: &str = "ed25519";
const PRIVATE_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// Ed25519 Private Key.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    key: Secret<ed_core::SigningKey>,
}

impl crate::PrivateKey for PrivateKey {}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        self.sign_inner(Some(namespace), msg)
    }

    fn public_key(&self) -> Self::PublicKey {
        self.key.expose(|key| Self::PublicKey {
            key: key.verification_key().to_owned(),
        })
    }
}

impl PrivateKey {
    #[inline(always)]
    fn sign_inner(&self, namespace: Option<&[u8]>, msg: &[u8]) -> Signature {
        let payload = namespace
            .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
            .unwrap_or_else(|| Cow::Borrowed(msg));
        self.key.expose(|key| Signature::from(key.sign(&payload)))
    }
}

impl Random for PrivateKey {
    fn random(rng: impl CryptoRng) -> Self {
        let key = ed_core::SigningKey::new(rng);
        Self {
            key: Secret::new(key),
        }
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.expose(|key| key.as_bytes().write(buf));
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
        let key = ed_core::SigningKey::from(*raw);
        Ok(Self {
            key: Secret::new(key),
        })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = PRIVATE_KEY_LENGTH;
}

impl From<ed_core::SigningKey> for PrivateKey {
    fn from(key: ed_core::SigningKey) -> Self {
        Self {
            key: Secret::new(key),
        }
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PrivateKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(Self::random(&mut rand))
    }
}

#[cfg(test)]
impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.key
            .expose(|key1| other.key.expose(|key2| key1.as_bytes() == key2.as_bytes()))
    }
}

/// Ed25519 Public Key.
///
/// Equality, ordering, and hashing use the original encoding. Distinct encodings of the same
/// curve point are distinct keys.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, FixedArray)]
pub struct PublicKey {
    key: ed_core::VerificationKey,
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        value.key.expose(|key| Self {
            key: key.verification_key(),
        })
    }
}

impl crate::PublicKey for PublicKey {}

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        self.verify_inner(Some(namespace), msg, sig)
    }
}

impl BatchVerifier for PublicKey {
    fn verify_batch<'a, R, T, F>(
        rng: &mut R,
        items: &'a [T],
        project: F,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        T: Sync,
        F: Fn(usize, &'a T) -> BatchEntry<'a, Self> + Sync,
    {
        ed_core::batch::verify_projected(
            rng,
            items,
            |i, item| {
                let entry = project(i, item);
                (
                    &entry.public_key.key,
                    ed_core::Signature::from(entry.signature.raw),
                    Some(entry.namespace),
                    entry.message,
                )
            },
            strategy,
        )
        .is_ok()
    }
}

impl PublicKey {
    #[inline(always)]
    fn verify_inner(&self, namespace: Option<&[u8]>, msg: &[u8], sig: &Signature) -> bool {
        let payload = namespace
            .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
            .unwrap_or_else(|| Cow::Borrowed(msg));
        self.key
            .verify(&ed_core::Signature::from(sig.raw), &payload)
            .is_ok()
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.as_bytes().write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let result = VerificationKey::try_from(raw);
        #[cfg(feature = "std")]
        let key = result.map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        #[cfg(not(feature = "std"))]
        let key = result
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, alloc::format!("{:?}", e).into()))?;

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
        use commonware_math::algebra::Random;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        Ok(private_key.public_key())
    }
}

/// Ed25519 Signature.
///
/// Signatures from honestly generated keys are *non-malleable*: an adversary
/// with access to many messages and signatures, verifying against an honestly
/// generated public key, cannot find a new signature which will verify, even by
/// tampering or modifying the signatures that it has seen previously.
///
/// Like any signature, it's also not possible to have a signature that verifies against
/// one message also verify against another. This property does not hold for maliciously
/// generated public keys. In particular, it's possible to craft public keys (which would
/// otherwise not be honestly generatable) for which a signature will verify against any message.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, FixedArray)]
pub struct Signature {
    raw: [u8; SIGNATURE_LENGTH],
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
        Ok(Self { raw })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = SIGNATURE_LENGTH;
}

impl Span for Signature {}

impl Array for Signature {}

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

impl From<ed_core::Signature> for Signature {
    fn from(value: ed_core::Signature) -> Self {
        let raw = value.to_bytes();
        Self { raw }
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
        let private_key = PrivateKey::random(&mut rand);
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(private_key.sign(&[], &message))
    }
}

/// Test vectors sourced from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signer as _;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_math::algebra::Random;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, test_rng};

    fn test_sign_and_verify(
        private_key: PrivateKey,
        public_key: PublicKey,
        message: &[u8],
        signature: Signature,
    ) {
        let computed_signature = private_key.sign_inner(None, message);
        assert_eq!(computed_signature, signature);
        assert!(public_key.verify_inner(None, message, &computed_signature));
    }

    fn parse_private_key(private_key: &str) -> PrivateKey {
        PrivateKey::decode(commonware_formatting::from_hex(private_key).unwrap()).unwrap()
    }

    fn parse_public_key(public_key: &str) -> PublicKey {
        PublicKey::decode(commonware_formatting::from_hex(public_key).unwrap()).unwrap()
    }

    fn parse_signature(signature: &str) -> Signature {
        Signature::decode(commonware_formatting::from_hex(signature).unwrap()).unwrap()
    }

    fn vector_1() -> (PrivateKey, PublicKey, Vec<u8>, Signature) {
        (
            // secret key
            parse_private_key(
                "
                9d61b19deffd5a60ba844af492ec2cc4
                4449c5697b326919703bac031cae7f60
                ",
            ),
            // public key
            parse_public_key(
                "
                d75a980182b10ab7d54bfed3c964073a
                0ee172f3daa62325af021a68f707511a
                ",
            ),
            // message
            b"".to_vec(),
            // signature
            parse_signature(
                "
                e5564300c360ac729086e2cc806e828a
                84877f1eb8e5d974d873e06522490155
                5fb8821590a33bacc61e39701cf9b46b
                d25bf5f0595bbe24655141438e7a100b
                ",
            ),
        )
    }

    fn vector_2() -> (PrivateKey, PublicKey, Vec<u8>, Signature) {
        (
            // secret key
            parse_private_key(
                "
                4ccd089b28ff96da9db6c346ec114e0f
                5b8a319f35aba624da8cf6ed4fb8a6fb
                ",
            ),
            // public key
            parse_public_key(
                "
                3d4017c3e843895a92b70aa74d1b7ebc
                9c982ccf2ec4968cc0cd55f12af4660c
                ",
            ),
            // message
            [0x72].to_vec(),
            // signature
            parse_signature(
                "
                92a009a9f0d4cab8720e820b5f642540
                a2b27b5416503f8fb3762223ebdb69da
                085ac1e43e15996e458f3613d0f11d8c
                387b2eaeb4302aeeb00d291612bb0c00
                ",
            ),
        )
    }

    #[test]
    fn test_codec_private_key() {
        let private_key = parse_private_key(
            "
            9d61b19deffd5a60ba844af492ec2cc4
            4449c5697b326919703bac031cae7f60
            ",
        );
        let encoded = private_key.encode();
        assert_eq!(encoded.len(), PRIVATE_KEY_LENGTH);
        let decoded = PrivateKey::decode(encoded).unwrap();
        assert_eq!(private_key, decoded);
    }

    #[test]
    fn test_codec_public_key() {
        let public_key = parse_public_key(
            "
            d75a980182b10ab7d54bfed3c964073a
            0ee172f3daa62325af021a68f707511a
            ",
        );
        let encoded = public_key.encode();
        assert_eq!(encoded.len(), PUBLIC_KEY_LENGTH);
        let decoded = PublicKey::decode(encoded).unwrap();
        assert_eq!(public_key, decoded);
    }

    #[test]
    fn test_codec_signature() {
        let signature = parse_signature(
            "
            e5564300c360ac729086e2cc806e828a
            84877f1eb8e5d974d873e06522490155
            5fb8821590a33bacc61e39701cf9b46b
            d25bf5f0595bbe24655141438e7a100b
            ",
        );
        let encoded = signature.encode();
        assert_eq!(encoded.len(), SIGNATURE_LENGTH);
        let decoded = Signature::decode(encoded).unwrap();
        assert_eq!(signature, decoded);
    }

    #[test]
    fn rfc8032_test_vector_1() {
        let (private_key, public_key, message, signature) = vector_1();
        test_sign_and_verify(private_key, public_key, &message, signature)
    }

    // sanity check the test infra rejects bad signatures
    #[test]
    #[should_panic]
    fn bad_signature() {
        let (private_key, public_key, message, _) = vector_1();
        let private_key_2 = PrivateKey::random(test_rng());
        let bad_signature = private_key_2.sign_inner(None, &message);
        test_sign_and_verify(private_key, public_key, &message, bad_signature);
    }

    // sanity check the test infra rejects non-matching messages
    #[test]
    #[should_panic]
    fn different_message() {
        let (private_key, public_key, _, signature) = vector_1();
        let different_message = b"this is a different message".to_vec();
        test_sign_and_verify(private_key, public_key, &different_message, signature);
    }

    #[test]
    fn rfc8032_test_vector_2() {
        let (private_key, public_key, message, signature) = vector_2();
        test_sign_and_verify(private_key, public_key, &message, signature)
    }

    #[test]
    fn rfc8032_test_vector_3() {
        let private_key = parse_private_key(
            "
            c5aa8df43f9f837bedb7442f31dcb7b1
            66d38535076f094b85ce3a2e0b4458f7
            ",
        );
        let public_key = parse_public_key(
            "
            fc51cd8e6218a1a38da47ed00230f058
            0816ed13ba3303ac5deb911548908025
            ",
        );
        let message = commonware_formatting::hex!("0xaf82");
        let signature = parse_signature(
            "
            6291d657deec24024827e69c3abe01a3
            0ce548a284743a445e3680d7db5ac3ac
            18ff9b538d16f290ae67f760984dc659
            4a7c15e9716ed28dc027beceea1ec40a
            ",
        );
        test_sign_and_verify(private_key, public_key, &message, signature)
    }

    #[test]
    fn rfc8032_test_vector_1024() {
        let private_key = parse_private_key(
            "
            f5e5767cf153319517630f226876b86c
            8160cc583bc013744c6bf255f5cc0ee5
            ",
        );
        let public_key = parse_public_key(
            "
            278117fc144c72340f67d0f2316e8386
            ceffbf2b2428c9c51fef7c597f1d426e
            ",
        );
        let message = commonware_formatting::from_hex(
            "
            08b8b2b733424243760fe426a4b54908
            632110a66c2f6591eabd3345e3e4eb98
            fa6e264bf09efe12ee50f8f54e9f77b1
            e355f6c50544e23fb1433ddf73be84d8
            79de7c0046dc4996d9e773f4bc9efe57
            38829adb26c81b37c93a1b270b20329d
            658675fc6ea534e0810a4432826bf58c
            941efb65d57a338bbd2e26640f89ffbc
            1a858efcb8550ee3a5e1998bd177e93a
            7363c344fe6b199ee5d02e82d522c4fe
            ba15452f80288a821a579116ec6dad2b
            3b310da903401aa62100ab5d1a36553e
            06203b33890cc9b832f79ef80560ccb9
            a39ce767967ed628c6ad573cb116dbef
            efd75499da96bd68a8a97b928a8bbc10
            3b6621fcde2beca1231d206be6cd9ec7
            aff6f6c94fcd7204ed3455c68c83f4a4
            1da4af2b74ef5c53f1d8ac70bdcb7ed1
            85ce81bd84359d44254d95629e9855a9
            4a7c1958d1f8ada5d0532ed8a5aa3fb2
            d17ba70eb6248e594e1a2297acbbb39d
            502f1a8c6eb6f1ce22b3de1a1f40cc24
            554119a831a9aad6079cad88425de6bd
            e1a9187ebb6092cf67bf2b13fd65f270
            88d78b7e883c8759d2c4f5c65adb7553
            878ad575f9fad878e80a0c9ba63bcbcc
            2732e69485bbc9c90bfbd62481d9089b
            eccf80cfe2df16a2cf65bd92dd597b07
            07e0917af48bbb75fed413d238f5555a
            7a569d80c3414a8d0859dc65a46128ba
            b27af87a71314f318c782b23ebfe808b
            82b0ce26401d2e22f04d83d1255dc51a
            ddd3b75a2b1ae0784504df543af8969b
            e3ea7082ff7fc9888c144da2af58429e
            c96031dbcad3dad9af0dcbaaaf268cb8
            fcffead94f3c7ca495e056a9b47acdb7
            51fb73e666c6c655ade8297297d07ad1
            ba5e43f1bca32301651339e22904cc8c
            42f58c30c04aafdb038dda0847dd988d
            cda6f3bfd15c4b4c4525004aa06eeff8
            ca61783aacec57fb3d1f92b0fe2fd1a8
            5f6724517b65e614ad6808d6f6ee34df
            f7310fdc82aebfd904b01e1dc54b2927
            094b2db68d6f903b68401adebf5a7e08
            d78ff4ef5d63653a65040cf9bfd4aca7
            984a74d37145986780fc0b16ac451649
            de6188a7dbdf191f64b5fc5e2ab47b57
            f7f7276cd419c17a3ca8e1b939ae49e4
            88acba6b965610b5480109c8b17b80e1
            b7b750dfc7598d5d5011fd2dcc5600a3
            2ef5b52a1ecc820e308aa342721aac09
            43bf6686b64b2579376504ccc493d97e
            6aed3fb0f9cd71a43dd497f01f17c0e2
            cb3797aa2a2f256656168e6c496afc5f
            b93246f6b1116398a346f1a641f3b041
            e989f7914f90cc2c7fff357876e506b5
            0d334ba77c225bc307ba537152f3f161
            0e4eafe595f6d9d90d11faa933a15ef1
            369546868a7f3a45a96768d40fd9d034
            12c091c6315cf4fde7cb68606937380d
            b2eaaa707b4c4185c32eddcdd306705e
            4dc1ffc872eeee475a64dfac86aba41c
            0618983f8741c5ef68d3a101e8a3b8ca
            c60c905c15fc910840b94c00a0b9d0
            ",
        )
        .unwrap();
        let signature = parse_signature(
            "
            0aab4c900501b3e24d7cdf4663326a3a
            87df5e4843b2cbdb67cbf6e460fec350
            aa5371b1508f9f4528ecea23c436d94b
            5e8fcd4f681e30a6ac00a9704a188a03
            ",
        );
        test_sign_and_verify(private_key, public_key, &message, signature)
    }

    #[test]
    fn rfc8032_test_vector_sha() {
        let private_key = commonware_formatting::from_hex(
            "
            833fe62409237b9d62ec77587520911e
            9a759cec1d19755b7da901b96dca3d42
            ",
        )
        .unwrap();
        let public_key = commonware_formatting::from_hex(
            "
            ec172b93ad5e563bf4932c70e1245034
            c35467ef2efd4d64ebf819683467e2bf
            ",
        )
        .unwrap();
        let message = commonware_formatting::from_hex(
            "
            ddaf35a193617abacc417349ae204131
            12e6fa4e89a97ea20a9eeee64b55d39a
            2192992a274fc1a836ba3c23a3feebbd
            454d4423643ce80e2a9ac94fa54ca49f
            ",
        )
        .unwrap();
        let signature = commonware_formatting::from_hex(
            "
            dc2a4459e7369633a52b1bf277839a00
            201009a3efbf3ecb69bea2186c26b589
            09351fc9ac90b3ecfdfbc7c66431e030
            3dca179c138ac17ad9bef1177331a704
            ",
        )
        .unwrap();
        test_sign_and_verify(
            PrivateKey::decode(private_key).unwrap(),
            PublicKey::decode(public_key).unwrap(),
            &message,
            Signature::decode(signature).unwrap(),
        )
    }

    fn verify_raw_vectors(items: &[(PrivateKey, PublicKey, Vec<u8>, Signature)]) -> bool {
        ed_core::batch::verify_projected(
            &mut test_rng(),
            items,
            |_, (_, public_key, message, signature)| {
                (
                    &public_key.key,
                    ed_core::Signature::from(signature.raw),
                    None,
                    message.as_slice(),
                )
            },
            &Sequential,
        )
        .is_ok()
    }

    #[test]
    fn batch_verify_valid() {
        assert!(verify_raw_vectors(&[vector_1(), vector_2()]));
    }

    #[test]
    fn batch_verify_invalid() {
        let mut v2 = vector_2();
        v2.3.raw[3] = 0xff;
        assert!(!verify_raw_vectors(&[vector_1(), v2]));
    }

    #[test]
    fn batch_verify_empty() {
        let entries: [BatchEntry<'_, PublicKey>; 0] = [];
        assert!(!PublicKey::verify_batch(
            &mut test_rng(),
            &entries,
            |_, entry| *entry,
            &Sequential
        ));
    }

    #[test]
    fn batch_framing_matches_union_unique() {
        // Check streamed framing against raw signatures across namespace-length
        // encoding boundaries.
        let key = PrivateKey::random(test_rng());
        let public_key = key.public_key();
        let message = b"message";
        for len in [0, 1, 127, 128, 255, 16383, 16384] {
            let namespace = vec![42; len];
            let signature = key.sign_inner(None, &union_unique(&namespace, message));
            for supplied_namespace in [namespace.as_slice(), b"other"] {
                let entries = [BatchEntry {
                    namespace: supplied_namespace,
                    message,
                    public_key: &public_key,
                    signature: &signature,
                }];
                assert_eq!(
                    PublicKey::verify_batch(
                        &mut test_rng(),
                        &entries,
                        |_, entry| *entry,
                        &Sequential
                    ),
                    supplied_namespace == namespace,
                );
            }

            // Moving a byte across the namespace boundary must invalidate the signature.
            if !namespace.is_empty() {
                let moved_message = [&namespace[len - 1..], message].concat();
                let entries = [BatchEntry {
                    namespace: &namespace[..len - 1],
                    message: &moved_message,
                    public_key: &public_key,
                    signature: &signature,
                }];
                assert!(!PublicKey::verify_batch(
                    &mut test_rng(),
                    &entries,
                    |_, entry| *entry,
                    &Sequential
                ));
            }
        }
    }

    #[test]
    fn projected_batch_borrows_records() {
        fn verify(
            records: &[(Vec<u8>, Signature, usize)],
            namespace: &[u8],
            publics: &[PublicKey; 2],
            strategy: &impl Strategy,
        ) -> bool {
            PublicKey::verify_batch(
                &mut test_rng(),
                records,
                |index, record| {
                    assert!(core::ptr::eq(record, &records[index]));
                    BatchEntry {
                        namespace,
                        message: &record.0,
                        public_key: &publics[record.2],
                        signature: &record.1,
                    }
                },
                strategy,
            )
        }

        // Mix empty and large messages from repeated signers in an uneven batch.
        let mut rng = test_rng();
        let keys = [PrivateKey::random(&mut rng), PrivateKey::random(&mut rng)];
        let publics = keys.each_ref().map(|key| key.public_key());
        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        let namespace = b"namespace";
        let mut records: Vec<_> = (0..25)
            .map(|i| {
                let message = vec![i as u8; if i % 3 == 0 { 0 } else { 1024 }];
                let signature = keys[i % 2].sign(namespace, &message);
                (message, signature, i % 2)
            })
            .collect();

        // Both strategies must verify the original borrowed records.
        assert!(verify(&records, namespace, &publics, &Sequential));
        assert!(verify(&records, namespace, &publics, &parallel.manual()));

        // Every entry must be checked, including the uneven final shard.
        for index in 0..records.len() {
            records[index].0.push(0);
            assert!(!verify(&records, namespace, &publics, &Sequential));
            assert!(!verify(&records, namespace, &publics, &parallel.manual()));
            records[index].0.pop();
        }

        // A noncanonical scalar in the final record must invalidate the batch.
        let mut invalid = records;
        invalid[24].1.raw[63] |= 0x80;
        assert!(!verify(&invalid, namespace, &publics, &Sequential));
        assert!(!verify(&invalid, namespace, &publics, &parallel.manual()));

        // Empty input must fail verification.
        let empty: [BatchEntry<'_, PublicKey>; 0] = [];
        assert!(!PublicKey::verify_batch(
            &mut rng,
            &empty,
            |_, entry| *entry,
            &Sequential
        ));
    }

    #[test]
    fn projected_batch_indexes_zero_sized_items() {
        fn verify(
            messages: &[Vec<u8>],
            signatures: &[Signature],
            public_keys: &[PublicKey],
            strategy: &impl Strategy,
        ) -> bool {
            let items = vec![(); messages.len()];
            PublicKey::verify_batch(
                &mut test_rng(),
                &items,
                |index, ()| BatchEntry {
                    namespace: b"namespace",
                    message: &messages[index],
                    public_key: &public_keys[index % public_keys.len()],
                    signature: &signatures[index],
                },
                strategy,
            )
        }

        // Use an uneven batch whose unit items identify messages only by their original index.
        let mut rng = test_rng();
        let keys = [PrivateKey::random(&mut rng), PrivateKey::random(&mut rng)];
        let public_keys = keys.each_ref().map(|key| key.public_key());
        let mut messages: Vec<_> = (0..25).map(|i| vec![i as u8; 32]).collect();
        let signatures: Vec<_> = messages
            .iter()
            .enumerate()
            .map(|(i, message)| keys[i % keys.len()].sign(b"namespace", message))
            .collect();
        let rayon = Rayon::new(NZUsize!(4)).unwrap();
        let parallel = rayon.manual();

        // Both strategies must resolve each original index to the matching signed message.
        assert!(verify(&messages, &signatures, &public_keys, &Sequential));
        assert!(verify(&messages, &signatures, &public_keys, &parallel));

        // Changing each indexed message in turn must fail the whole batch.
        for index in 0..messages.len() {
            messages[index][0] ^= 1;
            assert!(!verify(&messages, &signatures, &public_keys, &Sequential));
            assert!(!verify(&messages, &signatures, &public_keys, &parallel));
            messages[index][0] ^= 1;
        }
    }

    #[test]
    fn test_zero_signature_fails() {
        let (_, public_key, message, _) = vector_1();
        let zero_sig = Signature::decode(vec![0u8; Signature::SIZE]).unwrap();
        assert!(!public_key.verify_inner(None, &message, &zero_sig));
    }

    #[test]
    fn test_high_s_fails() {
        let (_, public_key, message, signature) = vector_1();
        let mut bad_signature = signature.to_vec();
        bad_signature[63] |= 0x80; // make S non-canonical
        let bad_signature = Signature::decode(bad_signature).unwrap();
        assert!(!public_key.verify_inner(None, &message, &bad_signature));
    }

    #[test]
    fn test_invalid_r_fails() {
        let (_, public_key, message, signature) = vector_1();
        let mut bad_signature = signature.to_vec();
        for b in bad_signature.iter_mut().take(32) {
            *b = 0xff; // invalid R component
        }
        let bad_signature = Signature::decode(bad_signature).unwrap();
        assert!(!public_key.verify_inner(None, &message, &bad_signature));
    }

    #[test]
    fn test_from_signing_key() {
        let signing_key = ed_core::SigningKey::new(test_rng());
        let expected_public = signing_key.verification_key();
        let private_key = PrivateKey::from(signing_key);
        assert_eq!(private_key.public_key().key, expected_public);
    }

    #[test]
    fn test_private_key_redacted() {
        let private_key = PrivateKey::random(test_rng());
        let debug = format!("{:?}", private_key);
        let display = format!("{}", private_key);
        assert!(debug.contains("REDACTED"));
        assert!(display.contains("REDACTED"));
    }

    #[test]
    fn test_from_private_key_to_public_key() {
        let private_key = PrivateKey::random(test_rng());
        assert_eq!(private_key.public_key(), PublicKey::from(private_key));
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
