use crate::{Array, BatchScheme, Error, Scheme};
use commonware_codec::{Codec, Error as CodecError, Reader, SizedCodec, Writer};
use commonware_utils::{hex, union_unique};
use ed25519_consensus::{self, VerificationKey};
use rand::{CryptoRng, Rng, RngCore};
use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::ops::Deref;

const CURVE_NAME: &str = "ed25519";
const PRIVATE_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// Ed25519 Signer.
#[derive(Clone)]
pub struct Ed25519 {
    signer: ed25519_consensus::SigningKey,
    verifier: ed25519_consensus::VerificationKey,
}

impl Scheme for Ed25519 {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn new<R: CryptoRng + Rng>(r: &mut R) -> Self {
        let signer = ed25519_consensus::SigningKey::new(r);
        let verifier = signer.verification_key();
        Self { signer, verifier }
    }

    fn from(private_key: PrivateKey) -> Option<Self> {
        let signer = private_key.key;
        let verifier = signer.verification_key();
        Some(Self { signer, verifier })
    }

    fn private_key(&self) -> PrivateKey {
        PrivateKey::from(self.signer.clone())
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.verifier)
    }

    fn sign(&mut self, namespace: Option<&[u8]>, message: &[u8]) -> Signature {
        let sig = match namespace {
            Some(namespace) => self.signer.sign(&union_unique(namespace, message)),
            None => self.signer.sign(message),
        };
        Signature::from(sig)
    }

    fn verify(
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> bool {
        match namespace {
            Some(namespace) => {
                let payload = union_unique(namespace, message);
                public_key
                    .key
                    .verify(&signature.signature, &payload)
                    .is_ok()
            }
            None => public_key.key.verify(&signature.signature, message).is_ok(),
        }
    }
}

/// Ed25519 Batch Verifier.
pub struct Ed25519Batch {
    verifier: ed25519_consensus::batch::Verifier,
}

impl BatchScheme for Ed25519Batch {
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn new() -> Self {
        Ed25519Batch {
            verifier: ed25519_consensus::batch::Verifier::new(),
        }
    }

    fn add(
        &mut self,
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> bool {
        let payload = match namespace {
            Some(namespace) => Cow::Owned(union_unique(namespace, message)),
            None => Cow::Borrowed(message),
        };
        let item = ed25519_consensus::batch::Item::from((
            public_key.key.into(),
            signature.signature,
            &payload,
        ));
        self.verifier.queue(item);
        true
    }

    fn verify<R: RngCore + CryptoRng>(self, rng: &mut R) -> bool {
        self.verifier.verify(rng).is_ok()
    }
}

/// Ed25519 Private Key.
#[derive(Clone)]
pub struct PrivateKey {
    raw: [u8; PRIVATE_KEY_LENGTH],
    key: ed25519_consensus::SigningKey,
}

impl Codec for PrivateKey {
    fn write(&self, writer: &mut impl Writer) {
        self.raw.write(writer);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        Self::read_from(reader).map_err(|err| CodecError::Wrapped(CURVE_NAME, err.into()))
    }

    fn len_encoded(&self) -> usize {
        PRIVATE_KEY_LENGTH
    }
}

impl SizedCodec for PrivateKey {
    const LEN_ENCODED: usize = PRIVATE_KEY_LENGTH;
}

impl Array for PrivateKey {
    type Error = Error;
}

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
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
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

impl From<ed25519_consensus::SigningKey> for PrivateKey {
    fn from(key: ed25519_consensus::SigningKey) -> Self {
        let raw = key.to_bytes();
        Self { raw, key }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; PRIVATE_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidPrivateKeyLength)?;
        let key = ed25519_consensus::SigningKey::from(raw);
        Ok(Self { raw, key })
    }
}

impl TryFrom<&Vec<u8>> for PrivateKey {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

/// Ed25519 Public Key.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PublicKey {
    raw: [u8; PUBLIC_KEY_LENGTH],
    key: ed25519_consensus::VerificationKey,
}

impl Codec for PublicKey {
    fn write(&self, writer: &mut impl Writer) {
        self.raw.write(writer);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        Self::read_from(reader).map_err(|err| CodecError::Wrapped(CURVE_NAME, err.into()))
    }

    fn len_encoded(&self) -> usize {
        PUBLIC_KEY_LENGTH
    }
}

impl SizedCodec for PublicKey {
    const LEN_ENCODED: usize = PUBLIC_KEY_LENGTH;
}

impl Array for PublicKey {
    type Error = Error;
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

impl From<VerificationKey> for PublicKey {
    fn from(key: VerificationKey) -> Self {
        let raw = key.to_bytes();
        Self { raw, key }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; PUBLIC_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidPublicKeyLength)?;
        let key = VerificationKey::try_from(value).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { raw, key })
    }
}

impl TryFrom<&Vec<u8>> for PublicKey {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

/// Ed25519 Signature.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; SIGNATURE_LENGTH],
    signature: ed25519_consensus::Signature,
}

impl Codec for Signature {
    fn write(&self, writer: &mut impl Writer) {
        self.raw.write(writer);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        Self::read_from(reader).map_err(|err| CodecError::Wrapped(CURVE_NAME, err.into()))
    }

    fn len_encoded(&self) -> usize {
        SIGNATURE_LENGTH
    }
}

impl SizedCodec for Signature {
    const LEN_ENCODED: usize = SIGNATURE_LENGTH;
}

impl Array for Signature {
    type Error = Error;
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
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

impl From<ed25519_consensus::Signature> for Signature {
    fn from(value: ed25519_consensus::Signature) -> Self {
        let raw = value.to_bytes();
        Self {
            raw,
            signature: value,
        }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; SIGNATURE_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidSignatureLength)?;
        let signature = ed25519_consensus::Signature::from(raw);
        Ok(Self { raw, signature })
    }
}

impl TryFrom<&Vec<u8>> for Signature {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

/// Test vectors sourced from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1.
#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn test_sign_and_verify(
        private_key: PrivateKey,
        public_key: PublicKey,
        message: &[u8],
        signature: Signature,
    ) {
        let mut signer = <Ed25519 as Scheme>::from(private_key).unwrap();
        let computed_signature = signer.sign(None, message);
        assert_eq!(computed_signature, signature);
        assert!(Ed25519::verify(
            None,
            message,
            &PublicKey::try_from(public_key.to_vec()).unwrap(),
            &computed_signature
        ));
    }

    fn parse_private_key(private_key: &str) -> PrivateKey {
        PrivateKey::try_from(commonware_utils::from_hex_formatted(private_key).unwrap()).unwrap()
    }

    fn parse_public_key(public_key: &str) -> PublicKey {
        PublicKey::try_from(commonware_utils::from_hex_formatted(public_key).unwrap()).unwrap()
    }

    fn parse_signature(signature: &str) -> Signature {
        Signature::try_from(commonware_utils::from_hex_formatted(signature).unwrap()).unwrap()
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
        let mut signer = <Ed25519 as Scheme>::new(&mut OsRng);
        let bad_signature = signer.sign(None, message.as_ref());
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
        let message: [u8; 2] = [0xaf, 0x82];
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
        let message = commonware_utils::from_hex_formatted(
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
        let private_key = commonware_utils::from_hex_formatted(
            "
            833fe62409237b9d62ec77587520911e
            9a759cec1d19755b7da901b96dca3d42
            ",
        )
        .unwrap();
        let public_key = commonware_utils::from_hex_formatted(
            "
            ec172b93ad5e563bf4932c70e1245034
            c35467ef2efd4d64ebf819683467e2bf
            ",
        )
        .unwrap();
        let message = commonware_utils::from_hex_formatted(
            "
            ddaf35a193617abacc417349ae204131
            12e6fa4e89a97ea20a9eeee64b55d39a
            2192992a274fc1a836ba3c23a3feebbd
            454d4423643ce80e2a9ac94fa54ca49f
            ",
        )
        .unwrap();
        let signature = commonware_utils::from_hex_formatted(
            "
            dc2a4459e7369633a52b1bf277839a00
            201009a3efbf3ecb69bea2186c26b589
            09351fc9ac90b3ecfdfbc7c66431e030
            3dca179c138ac17ad9bef1177331a704
            ",
        )
        .unwrap();
        test_sign_and_verify(
            PrivateKey::try_from(private_key).unwrap(),
            PublicKey::try_from(public_key).unwrap(),
            &message,
            Signature::try_from(signature).unwrap(),
        )
    }

    #[test]
    fn batch_verify_valid() {
        let v1 = vector_1();
        let v2 = vector_2();
        let mut batch = Ed25519Batch::new();
        assert!(batch.add(None, &v1.2, &v1.1, &v1.3));
        assert!(batch.add(None, &v2.2, &v2.1, &v2.3));
        assert!(batch.verify(&mut rand::thread_rng()));
    }

    #[test]
    fn batch_verify_invalid() {
        let v1 = vector_1();
        let v2 = vector_2();
        let mut bad_signature = v2.3.to_vec();
        bad_signature[3] = 0xff;

        let mut batch = Ed25519Batch::new();
        assert!(batch.add(None, &v1.2, &v1.1, &v1.3));
        assert!(batch.add(
            None,
            &v2.2,
            &v2.1,
            &Signature::try_from(bad_signature).unwrap()
        ));
        assert!(!batch.verify(&mut rand::thread_rng()));
    }
}
