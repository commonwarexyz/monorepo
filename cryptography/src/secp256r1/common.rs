cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::borrow::ToOwned;
    } else {
        use alloc::borrow::ToOwned;
    }
}
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_utils::{hex, Array, Span};
use core::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CURVE_NAME: &str = "secp256r1";
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 33; // Y-Parity || X

/// Internal Secp256r1 Private Key storage.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyInner {
    raw: [u8; PRIVATE_KEY_LENGTH],
    /// `ZeroizeOnDrop` is implemented for `SigningKey` and can't be called directly.
    ///
    /// Reference: <https://github.com/RustCrypto/signatures/blob/a83c494216b6f3dacba5d4e4376785e2ea142044/ecdsa/src/signing.rs#L487-L493>
    #[zeroize(skip)]
    pub key: SigningKey,
}

impl PrivateKeyInner {
    pub fn new(key: SigningKey) -> Self {
        let raw = key.to_bytes().into();
        Self { raw, key }
    }

    pub fn from_rng<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::new(SigningKey::random(rng))
    }
}

impl Write for PrivateKeyInner {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PrivateKeyInner {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; PRIVATE_KEY_LENGTH]>::read(buf)?;
        let result = SigningKey::from_slice(&raw);
        #[cfg(feature = "std")]
        let key = result.map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        #[cfg(not(feature = "std"))]
        let key = result
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, alloc::format!("{:?}", e).into()))?;
        Ok(Self { raw, key })
    }
}

impl FixedSize for PrivateKeyInner {
    const SIZE: usize = PRIVATE_KEY_LENGTH;
}

impl Span for PrivateKeyInner {}

impl Array for PrivateKeyInner {}

impl Hash for PrivateKeyInner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for PrivateKeyInner {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PrivateKeyInner {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for PrivateKeyInner {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PrivateKeyInner {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<SigningKey> for PrivateKeyInner {
    fn from(signer: SigningKey) -> Self {
        Self::new(signer)
    }
}

impl Debug for PrivateKeyInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PrivateKeyInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PrivateKeyInner {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(Self::from_rng(&mut rand))
    }
}

/// Internal Secp256r1 Public Key storage.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicKeyInner {
    raw: [u8; PUBLIC_KEY_LENGTH],
    pub key: VerifyingKey,
}

impl PublicKeyInner {
    pub fn new(key: VerifyingKey) -> Self {
        let encoded = key.to_encoded_point(true);
        let raw: [u8; PUBLIC_KEY_LENGTH] = encoded.as_bytes().try_into().unwrap();
        Self { raw, key }
    }

    pub fn from_private_key(private_key: &PrivateKeyInner) -> Self {
        Self::new(private_key.key.verifying_key().to_owned())
    }
}

impl Write for PublicKeyInner {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PublicKeyInner {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; PUBLIC_KEY_LENGTH]>::read(buf)?;
        let key = VerifyingKey::from_sec1_bytes(&raw)
            .map_err(|_| CodecError::Invalid(CURVE_NAME, "Invalid PublicKey"))?;
        Ok(Self { raw, key })
    }
}

impl FixedSize for PublicKeyInner {
    const SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl Span for PublicKeyInner {}

impl Array for PublicKeyInner {}

impl Hash for PublicKeyInner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl AsRef<[u8]> for PublicKeyInner {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PublicKeyInner {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<VerifyingKey> for PublicKeyInner {
    fn from(verifier: VerifyingKey) -> Self {
        Self::new(verifier)
    }
}

impl Debug for PublicKeyInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PublicKeyInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKeyInner {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKeyInner::from_rng(&mut rand);
        Ok(Self::from_private_key(&private_key))
    }
}

/// Macro to implement newtype wrapper traits for PrivateKey.
macro_rules! impl_private_key_wrapper {
    ($name:ident) => {
        impl crate::PrivateKey for $name {}

        impl crate::PrivateKeyExt for $name {
            fn from_rng<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
                Self(PrivateKeyInner::from_rng(rng))
            }
        }

        impl commonware_codec::Write for $name {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                self.0.write(buf);
            }
        }

        impl commonware_codec::Read for $name {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl bytes::Buf,
                cfg: &(),
            ) -> Result<Self, commonware_codec::Error> {
                PrivateKeyInner::read_cfg(buf, cfg).map(Self)
            }
        }

        impl commonware_codec::FixedSize for $name {
            const SIZE: usize = PRIVATE_KEY_LENGTH;
        }

        impl commonware_utils::Span for $name {}

        impl commonware_utils::Array for $name {}

        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl core::ops::Deref for $name {
            type Target = [u8];
            fn deref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<p256::ecdsa::SigningKey> for $name {
            fn from(signer: p256::ecdsa::SigningKey) -> Self {
                Self(PrivateKeyInner::from(signer))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Debug::fmt(&self.0, f)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

/// Macro to implement newtype wrapper traits for PublicKey.
macro_rules! impl_public_key_wrapper {
    ($name:ident) => {
        impl crate::PublicKey for $name {}

        impl commonware_codec::Write for $name {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                self.0.write(buf);
            }
        }

        impl commonware_codec::Read for $name {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl bytes::Buf,
                cfg: &(),
            ) -> Result<Self, commonware_codec::Error> {
                PublicKeyInner::read_cfg(buf, cfg).map(Self)
            }
        }

        impl commonware_codec::FixedSize for $name {
            const SIZE: usize = PUBLIC_KEY_LENGTH;
        }

        impl commonware_utils::Span for $name {}

        impl commonware_utils::Array for $name {}

        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl core::ops::Deref for $name {
            type Target = [u8];
            fn deref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<p256::ecdsa::VerifyingKey> for $name {
            fn from(verifier: p256::ecdsa::VerifyingKey) -> Self {
                Self(PublicKeyInner::from(verifier))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Debug::fmt(&self.0, f)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

pub(crate) use impl_private_key_wrapper;
pub(crate) use impl_public_key_wrapper;

/// Test vectors sourced from (FIPS 186-4)
/// <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use commonware_codec::DecodeExt;

    pub fn create_private_key() -> PrivateKeyInner {
        const HEX: &str = "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464";
        PrivateKeyInner::decode(commonware_utils::from_hex_formatted(HEX).unwrap().as_ref())
            .unwrap()
    }

    pub fn parse_vector_keypair(
        private_key: &str,
        qx: &str,
        qy: &str,
    ) -> (PrivateKeyInner, PublicKeyInner) {
        let public_key = parse_public_key_as_compressed(qx, qy);
        (
            PrivateKeyInner::decode(
                commonware_utils::from_hex_formatted(private_key)
                    .unwrap()
                    .as_ref(),
            )
            .unwrap(),
            public_key,
        )
    }

    pub fn parse_public_key_as_compressed(qx: &str, qy: &str) -> PublicKeyInner {
        PublicKeyInner::decode(parse_public_key_as_compressed_vector(qx, qy).as_ref()).unwrap()
    }

    pub fn parse_public_key_as_compressed_vector(qx: &str, qy: &str) -> Vec<u8> {
        let qx = commonware_utils::from_hex_formatted(&padding_odd_length_hex(qx)).unwrap();
        let qy = commonware_utils::from_hex_formatted(&padding_odd_length_hex(qy)).unwrap();
        let mut compressed = Vec::with_capacity(qx.len() + 1);
        if qy.last().unwrap().is_multiple_of(2) {
            compressed.push(0x02);
        } else {
            compressed.push(0x03);
        }
        compressed.extend_from_slice(&qx);
        compressed
    }

    pub fn parse_public_key_as_uncompressed_vector(qx: &str, qy: &str) -> Vec<u8> {
        let qx = commonware_utils::from_hex_formatted(qx).unwrap();
        let qy = commonware_utils::from_hex_formatted(qy).unwrap();
        let mut uncompressed_public_key = Vec::with_capacity(65);
        uncompressed_public_key.push(0x04);
        uncompressed_public_key.extend_from_slice(&qx);
        uncompressed_public_key.extend_from_slice(&qy);
        uncompressed_public_key
    }

    pub fn padding_odd_length_hex(value: &str) -> String {
        if !value.len().is_multiple_of(2) {
            return format!("0{value}");
        }
        value.to_string()
    }

    pub fn vector_keypair_1() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357",
            "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f",
            "9681b517b1cda17d0d83d335d9c4a8a9a9b0b1b3c7106d8f3c72bc5093dc275f",
        )
    }

    pub fn vector_keypair_2() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d",
            "f6836a8add91cb182d8d258dda6680690eb724a66dc3bb60d2322565c39e4ab9",
            "1f837aa32864870cb8e8d0ac2ff31f824e7beddc4bb7ad72c173ad974b289dc2",
        )
    }

    pub fn vector_keypair_3() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "78d5d8b7b3e2c16b3e37e7e63becd8ceff61e2ce618757f514620ada8a11f6e4",
            "76711126cbb2af4f6a5fe5665dad4c88d27b6cb018879e03e54f779f203a854e",
            "a26df39960ab5248fd3620fd018398e788bd89a3cea509b352452b69811e6856",
        )
    }

    pub fn vector_keypair_4() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "2a61a0703860585fe17420c244e1de5a6ac8c25146b208ef88ad51ae34c8cb8c",
            "e1aa7196ceeac088aaddeeba037abb18f67e1b55c0a5c4e71ec70ad666fcddc8",
            "d7d35bdce6dedc5de98a7ecb27a9cd066a08f586a733b59f5a2cdb54f971d5c8",
        )
    }

    pub fn vector_keypair_5() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "01b965b45ff386f28c121c077f1d7b2710acc6b0cb58d8662d549391dcf5a883",
            "1f038c5422e88eec9e88b815e8f6b3e50852333fc423134348fc7d79ef8e8a10",
            "43a047cb20e94b4ffb361ef68952b004c0700b2962e0c0635a70269bc789b849",
        )
    }

    pub fn vector_keypair_6() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "fac92c13d374c53a085376fe4101618e1e181b5a63816a84a0648f3bdc24e519",
            "7258f2ab96fc84ef6ccb33e308cd392d8b568ea635730ceb4ebd72fa870583b9",
            "489807ca55bdc29ca5c8fe69b94f227b0345cccdbe89975e75d385cc2f6bb1e2",
        )
    }

    pub fn vector_keypair_7() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "f257a192dde44227b3568008ff73bcf599a5c45b32ab523b5b21ca582fef5a0a",
            "d2e01411817b5512b79bbbe14d606040a4c90deb09e827d25b9f2fc068997872",
            "503f138f8bab1df2c4507ff663a1fdf7f710e7adb8e7841eaa902703e314e793",
        )
    }

    pub fn vector_keypair_8() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "add67e57c42a3d28708f0235eb86885a4ea68e0d8cfd76eb46134c596522abfd",
            "55bed2d9c029b7f230bde934c7124ed52b1330856f13cbac65a746f9175f85d7",
            "32805e311d583b4e007c40668185e85323948e21912b6b0d2cda8557389ae7b0",
        )
    }

    pub fn vector_keypair_9() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "4494860fd2c805c5c0d277e58f802cff6d731f76314eb1554142a637a9bc5538",
            "5190277a0c14d8a3d289292f8a544ce6ea9183200e51aec08440e0c1a463a4e4",
            "ecd98514821bd5aaf3419ab79b71780569470e4fed3da3c1353b28fe137f36eb",
        )
    }

    pub fn vector_keypair_10() -> (PrivateKeyInner, PublicKeyInner) {
        parse_vector_keypair(
            "d40b07b1ea7b86d4709ef9dc634c61229feb71abd63dc7fc85ef46711a87b210",
            "fbcea7c2827e0e8085d7707b23a3728823ea6f4878b24747fb4fd2842d406c73",
            "2393c85f1f710c5afc115a39ba7e18abe03f19c9d4bb3d47d19468b818efa535",
        )
    }

    pub fn vector_public_key_validation_1() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "e0f7449c5588f24492c338f2bc8f7865f755b958d48edb0f2d0056e50c3fd5b7",
                "86d7e9255d0f4b6f44fa2cd6f8ba3c0aa828321d6d8cc430ca6284ce1d5b43a0",
            ),
            true,
        )
    }

    pub fn vector_public_key_validation_3() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "17875397ae87369365656d490e8ce956911bd97607f2aff41b56f6f3a61989826",
                "980a3c4f61b9692633fbba5ef04c9cb546dd05cdec9fa8428b8849670e2fba92",
            ),
            false,
        )
    }

    pub fn vector_public_key_validation_4() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "f2d1c0dc0852c3d8a2a2500a23a44813ccce1ac4e58444175b440469ffc12273",
                "32bfe992831b305d8c37b9672df5d29fcb5c29b4a40534683e3ace23d24647dd",
            ),
            false,
        )
    }

    pub fn vector_public_key_validation_5() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "10b0ca230fff7c04768f4b3d5c75fa9f6c539bea644dffbec5dc796a213061b58",
                "f5edf37c11052b75f771b7f9fa050e353e464221fec916684ed45b6fead38205",
            ),
            false,
        )
    }

    pub fn vector_public_key_validation_6() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "2c1052f25360a15062d204a056274e93cbe8fc4c4e9b9561134ad5c15ce525da",
                "ced9783713a8a2a09eff366987639c625753295d9a85d0f5325e32dedbcada0b",
            ),
            true,
        )
    }

    pub fn vector_public_key_validation_7() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "a40d077a87dae157d93dcccf3fe3aca9c6479a75aa2669509d2ef05c7de6782f",
                "503d86b87d743ba20804fd7e7884aa017414a7b5b5963e0d46e3a9611419ddf3",
            ),
            false,
        )
    }

    pub fn vector_public_key_validation_8() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "2633d398a3807b1895548adbb0ea2495ef4b930f91054891030817df87d4ac0a",
                "d6b2f738e3873cc8364a2d364038ce7d0798bb092e3dd77cbdae7c263ba618d2",
            ),
            true,
        )
    }

    pub fn vector_public_key_validation_9() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "14bf57f76c260b51ec6bbc72dbd49f02a56eaed070b774dc4bad75a54653c3d56",
                "7a231a23bf8b3aa31d9600d888a0678677a30e573decd3dc56b33f365cc11236",
            ),
            false,
        )
    }

    pub fn vector_public_key_validation_10() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "2fa74931ae816b426f484180e517f5050c92decfc8daf756cd91f54d51b302f1",
                "5b994346137988c58c14ae2152ac2f6ad96d97decb33099bd8a0210114cd1141",
            ),
            true,
        )
    }

    pub fn vector_public_key_validation_12() -> (Vec<u8>, bool) {
        (
            parse_public_key_as_compressed_vector(
                "7a81a7e0b015252928d8b36e4ca37e92fdc328eb25c774b4f872693028c4be38",
                "08862f7335147261e7b1c3d055f9a316e4cab7daf99cc09d1c647f5dd6e7d5bb",
            ),
            false,
        )
    }

    pub fn vector_sig_verification_raw(
        qx: &str,
        qy: &str,
        r: &str,
        s: &str,
        m: &str,
    ) -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>) {
        let public_key = parse_public_key_as_compressed(qx, qy);
        let signature = parse_signature(r, s);
        let message = commonware_utils::from_hex_formatted(m).unwrap();
        (public_key, signature, message)
    }

    pub fn parse_signature(r: &str, s: &str) -> p256::ecdsa::Signature {
        let vec_r = commonware_utils::from_hex_formatted(r).unwrap();
        let vec_s = commonware_utils::from_hex_formatted(s).unwrap();
        let f1 = p256::FieldBytes::from_slice(&vec_r);
        let f2 = p256::FieldBytes::from_slice(&vec_s);
        p256::ecdsa::Signature::from_scalars(*f1, *f2).unwrap()
    }

    pub fn vector_sig_verification_1_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555",
            "e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9",
            "d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0",
            "a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6",
            "e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7
            745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce1
            3409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_2_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "5cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2",
            "ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85",
            "dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693",
            "d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c",
            "069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d683877f95ecc6d6c81623
            d8fac4e900ed0019964094e7de91f1481989ae1873004565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8
            ecaadc9bd0e81ad91b2b3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_3_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "2ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb",
            "5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64",
            "9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8",
            "9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc",
            "df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d8d746429a393ba88840d
            661615e07def615a342abedfa4ce912e562af714959896858af817317a840dcff85a057bb91a3c2bf9010550
            0362754a6dd321cdd86128cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_4_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c",
            "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927",
            "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f",
            "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
            "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e928
            40c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064
            a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
        );
        (public_key, sig, message, true)
    }

    pub fn vector_sig_verification_5_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864",
            "7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a",
            "1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407",
            "cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a",
            "73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc46
            61d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc565
            56f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08",
        );
        (public_key, sig, message, true)
    }

    pub fn vector_sig_verification_6_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "a849bef575cac3c6920fbce675c3b787136209f855de19ffe2e8d29b31a5ad86",
            "bf5fe4f7858f9b805bd8dcc05ad5e7fb889de2f822f3d8b41694e6c55c16b471",
            "25acc3aa9d9e84c7abf08f73fa4195acc506491d6fc37cb9074528a7db87b9d6",
            "9b21d5b5259ed3f2ef07dfec6cc90d3a37855d1ce122a85ba6a333f307d31537",
            "666036d9b4a2426ed6585a4e0fd931a8761451d29ab04bd7dc6d0c5b9e38e6c2b263ff6cb837bd04399d
            e3d757c6c7005f6d7a987063cf6d7e8cb38a4bf0d74a282572bd01d0f41e3fd066e3021575f0fa04f27b700d
            5b7ddddf50965993c3f9c7118ed78888da7cb221849b3260592b8e632d7c51e935a0ceae15207bedd548",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_7_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "3dfb6f40f2471b29b77fdccba72d37c21bba019efa40c1c8f91ec405d7dcc5df",
            "f22f953f1e395a52ead7f3ae3fc47451b438117b1e04d613bc8555b7d6e6d1bb",
            "548886278e5ec26bed811dbb72db1e154b6f17be70deb1b210107decb1ec2a5a",
            "e93bfebd2f14f3d827ca32b464be6e69187f5edbd52def4f96599c37d58eee75",
            "7e80436bce57339ce8da1b5660149a20240b146d108deef3ec5da4ae256f8f894edcbbc57b34ce37089c
            0daa17f0c46cd82b5a1599314fd79d2fd2f446bd5a25b8e32fcf05b76d644573a6df4ad1dfea707b479d9723
            7a346f1ec632ea5660efb57e8717a8628d7f82af50a4e84b11f21bdff6839196a880ae20b2a0918d58cd",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_8_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "69b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd0214",
            "d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa2f",
            "288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790",
            "247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979",
            "1669bfb657fdc62c3ddd63269787fc1c969f1850fb04c933dda063ef74a56ce13e3a649700820f0061ef
            abf849a85d474326c8a541d99830eea8131eaea584f22d88c353965dabcdc4bf6b55949fd529507dfb803ab6
            b480cd73ca0ba00ca19c438849e2cea262a1c57d8f81cd257fb58e19dec7904da97d8386e87b84948169",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_9_raw() -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool)
    {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "bf02cbcf6d8cc26e91766d8af0b164fc5968535e84c158eb3bc4e2d79c3cc682",
            "069ba6cb06b49d60812066afa16ecf7b51352f2c03bd93ec220822b1f3dfba03",
            "f5acb06c59c2b4927fb852faa07faf4b1852bbb5d06840935e849c4d293d1bad",
            "049dab79c89cc02f1484c437f523e080a75f134917fda752f2d5ca397addfe5d",
            "3fe60dd9ad6caccf5a6f583b3ae65953563446c4510b70da115ffaa0ba04c076115c7043ab8733403cd6
            9c7d14c212c655c07b43a7c71b9a4cffe22c2684788ec6870dc2013f269172c822256f9e7cc674791bf2d848
            6c0f5684283e1649576efc982ede17c7b74b214754d70402fb4bb45ad086cf2cf76b3d63f7fce39ac970",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_10_raw(
    ) -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool) {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "224a4d65b958f6d6afb2904863efd2a734b31798884801fcab5a590f4d6da9de",
            "178d51fddada62806f097aa615d33b8f2404e6b1479f5fd4859d595734d6d2b9",
            "87b93ee2fecfda54deb8dff8e426f3c72c8864991f8ec2b3205bb3b416de93d2",
            "4044a24df85be0cc76f21a4430b75b8e77b932a87f51e4eccbc45c263ebf8f66",
            "983a71b9994d95e876d84d28946a041f8f0a3f544cfcc055496580f1dfd4e312a2ad418fe69dbc61db23
            0cc0c0ed97e360abab7d6ff4b81ee970a7e97466acfd9644f828ffec538abc383d0e92326d1c88c55e1f46a6
            68a039beaa1be631a89129938c00a81a3ae46d4aecbf9707f764dbaccea3ef7665e4c4307fa0b0a3075c",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_11_raw(
    ) -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool) {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "43691c7795a57ead8c5c68536fe934538d46f12889680a9cb6d055a066228369",
            "f8790110b3c3b281aa1eae037d4f1234aff587d903d93ba3af225c27ddc9ccac",
            "8acd62e8c262fa50dd9840480969f4ef70f218ebf8ef9584f199031132c6b1ce",
            "cfca7ed3d4347fb2a29e526b43c348ae1ce6c60d44f3191b6d8ea3a2d9c92154",
            "4a8c071ac4fd0d52faa407b0fe5dab759f7394a5832127f2a3498f34aac287339e043b4ffa79528faf19
            9dc917f7b066ad65505dab0e11e6948515052ce20cfdb892ffb8aa9bf3f1aa5be30a5bbe85823bddf70b39fd
            7ebd4a93a2f75472c1d4f606247a9821f1a8c45a6cb80545de2e0c6c0174e2392088c754e9c8443eb5af",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_12_raw(
    ) -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool) {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "9157dbfcf8cf385f5bb1568ad5c6e2a8652ba6dfc63bc1753edf5268cb7eb596",
            "972570f4313d47fc96f7c02d5594d77d46f91e949808825b3d31f029e8296405",
            "dfaea6f297fa320b707866125c2a7d5d515b51a503bee817de9faa343cc48eeb",
            "8f780ad713f9c3e5a4f7fa4c519833dfefc6a7432389b1e4af463961f09764f2",
            "0a3a12c3084c865daf1d302c78215d39bfe0b8bf28272b3c0b74beb4b7409db0718239de700785581514
            321c6440a4bbaea4c76fa47401e151e68cb6c29017f0bce4631290af5ea5e2bf3ed742ae110b04ade83a5dbd
            7358f29a85938e23d87ac8233072b79c94670ff0959f9c7f4517862ff829452096c78f5f2e9a7e4e9216",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_13_raw(
    ) -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool) {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "072b10c081a4c1713a294f248aef850e297991aca47fa96a7470abe3b8acfdda",
            "9581145cca04a0fb94cedce752c8f0370861916d2a94e7c647c5373ce6a4c8f5",
            "09f5483eccec80f9d104815a1be9cc1a8e5b12b6eb482a65c6907b7480cf4f19",
            "a4f90e560c5e4eb8696cb276e5165b6a9d486345dedfb094a76e8442d026378d",
            "785d07a3c54f63dca11f5d1a5f496ee2c2f9288e55007e666c78b007d95cc28581dce51f490b30fa73dc
            9e2d45d075d7e3a95fb8a9e1465ad191904124160b7c60fa720ef4ef1c5d2998f40570ae2a870ef3e894c2bc
            617d8a1dc85c3c55774928c38789b4e661349d3f84d2441a3b856a76949b9f1f80bc161648a1cad5588e",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_14_raw(
    ) -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool) {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "09308ea5bfad6e5adf408634b3d5ce9240d35442f7fe116452aaec0d25be8c24",
            "f40c93e023ef494b1c3079b2d10ef67f3170740495ce2cc57f8ee4b0618b8ee5",
            "5cc8aa7c35743ec0c23dde88dabd5e4fcd0192d2116f6926fef788cddb754e73",
            "9c9c045ebaa1b828c32f82ace0d18daebf5e156eb7cbfdc1eff4399a8a900ae7",
            "76f987ec5448dd72219bd30bf6b66b0775c80b394851a43ff1f537f140a6e7229ef8cd72ad58b1d2d202
            98539d6347dd5598812bc65323aceaf05228f738b5ad3e8d9fe4100fd767c2f098c77cb99c2992843ba3eed9
            1d32444f3b6db6cd212dd4e5609548f4bb62812a920f6e2bf1581be1ebeebdd06ec4e971862cc42055ca",
        );
        (public_key, sig, message, false)
    }

    pub fn vector_sig_verification_15_raw(
    ) -> (PublicKeyInner, p256::ecdsa::Signature, Vec<u8>, bool) {
        let (public_key, sig, message) = vector_sig_verification_raw(
            "2d98ea01f754d34bbc3003df5050200abf445ec728556d7ed7d5c54c55552b6d",
            "9b52672742d637a32add056dfd6d8792f2a33c2e69dafabea09b960bc61e230a",
            "06108e525f845d0155bf60193222b3219c98e3d49424c2fb2a0987f825c17959",
            "62b5cdd591e5b507e560167ba8f6f7cda74673eb315680cb89ccbc4eec477dce",
            "60cd64b2cd2be6c33859b94875120361a24085f3765cb8b2bf11e026fa9d8855dbe435acf7882e84f3c7
            857f96e2baab4d9afe4588e4a82e17a78827bfdb5ddbd1c211fbc2e6d884cddd7cb9d90d5bf4a7311b83f352
            508033812c776a0e00c003c7e0d628e50736c7512df0acfa9f2320bd102229f46495ae6d0857cc452a84",
        );
        (public_key, sig, message, true)
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;

        commonware_codec::conformance_tests! {
            PublicKeyInner,
            PrivateKeyInner,
        }
    }
}
