//! BLS12-381 implementation of the [crate::Verifier] and [crate::Signer] traits.
//!
//! This implementation uses the `blst` crate for BLS12-381 operations. This
//! crate implements serialization according to the "ZCash BLS12-381" specification
//! (<https://github.com/supranational/blst/tree/master?tab=readme-ov-file#serialization-format>)
//! and hashes messages according to RFC 9380.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{bls12381, PrivateKey, PublicKey, Signature, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use commonware_utils::test_rng;
//!
//! let mut rng = test_rng();
//!
//! // Generate a new private key
//! let mut signer = bls12381::PrivateKey::random(&mut rng);
//!
//! // Create a message to sign
//! let namespace = b"demo";
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

use super::primitives::{
    group::{self, G1_ELEMENT_BYTE_LENGTH, G1Bytes, G2_ELEMENT_BYTE_LENGTH, G2Bytes, Private},
    ops,
    variant::{MinPk, Variant},
};
use crate::{BatchEntry, BatchVerifier, Encoding, Malformed, Secret, Signer as _};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{
    Buf, Copying, DecodeExt, EncodeFixed, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    ops::Deref,
};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

const CURVE_NAME: &str = "bls12381";

/// BLS12-381 private key.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    raw: Secret<[u8; group::PRIVATE_KEY_LENGTH]>,
    key: Private,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for PrivateKey {}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.expose(|raw| raw.write(buf));
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
        let key = Private::decode(Copying(raw.as_ref()))
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        Ok(Self {
            raw: Secret::new(*raw),
            key,
        })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = group::PRIVATE_KEY_LENGTH;
}

impl From<Private> for PrivateKey {
    fn from(key: Private) -> Self {
        let raw = Zeroizing::new(key.expose(|s| s.encode_fixed()));
        Self {
            raw: Secret::new(*raw),
            key,
        }
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl crate::PrivateKey for PrivateKey {}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        PublicKey::from(ops::compute_public::<MinPk>(&self.key))
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        ops::sign_message::<MinPk>(&self.key, namespace, msg).into()
    }
}

impl Random for PrivateKey {
    fn random(mut rng: impl CryptoRng) -> Self {
        let (private, _) = ops::keypair::<_, MinPk>(&mut rng);
        private.into()
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

impl crate::PublicKey for PublicKey {}

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        ops::verify_message::<MinPk>(&self.key, namespace, msg, &sig.signature).is_ok()
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
        let hms = strategy.map_collect_vec(items.iter().enumerate(), |(index, item)| {
            let entry = project(index, item);
            ops::hash_with_namespace::<MinPk>(MinPk::MESSAGE, entry.namespace, entry.message)
        });
        let (publics, signatures): (Vec<_>, Vec<_>) = items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let entry = project(index, item);
                (entry.public_key.key, entry.signature.signature)
            })
            .unzip();

        MinPk::batch_verify(rng, &publics, &hms, &signatures, strategy).is_ok()
    }
}

/// The encoding of a BLS12-381 public key.
pub type PublicKeyBytes = Encoding<PublicKey, G1_ELEMENT_BYTE_LENGTH>;

/// BLS12-381 public key.
///
/// A key is built from its [PublicKeyBytes], which must encode a point of the prime-order
/// subgroup other than the identity, so a key needs none of the checks [group] requires of
/// untrusted points.
#[derive(Clone, Eq)]
pub struct PublicKey {
    raw: [u8; <MinPk as Variant>::Public::SIZE],
    key: <MinPk as Variant>::Public,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> Self {
        private_key.public_key()
    }
}

impl AsRef<<MinPk as Variant>::Public> for PublicKey {
    fn as_ref(&self) -> &<MinPk as Variant>::Public {
        &self.key
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Malformed;

    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Malformed> {
        let raw = *bytes.as_array();
        let key = <MinPk as Variant>::Public::try_from(G1Bytes::new(raw))?;
        Ok(Self { raw, key })
    }
}

impl From<PublicKey> for PublicKeyBytes {
    fn from(key: PublicKey) -> Self {
        Self::new(key.raw)
    }
}

impl crate::Validated for PublicKey {
    type Bytes = PublicKeyBytes;
}

impl FixedSize for PublicKey {
    const SIZE: usize = <MinPk as Variant>::Public::SIZE;
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
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

impl From<<MinPk as Variant>::Public> for PublicKey {
    fn from(key: <MinPk as Variant>::Public) -> Self {
        let raw = key.encode_fixed();
        Self { raw, key }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        Ok(private_key.public_key())
    }
}

/// The encoding of a BLS12-381 signature.
pub type SignatureBytes = Encoding<Signature, G2_ELEMENT_BYTE_LENGTH>;

/// BLS12-381 signature.
///
/// A signature is built from its [SignatureBytes] with the same subgroup and identity checks as
/// [PublicKey]. Those checks are expensive, so messages carry [SignatureBytes] and convert many
/// signatures together through [crate::Validated::try_from_batch].
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; <MinPk as Variant>::Signature::SIZE],
    signature: <MinPk as Variant>::Signature,
}

impl crate::Signature for Signature {}

impl AsRef<<MinPk as Variant>::Signature> for Signature {
    fn as_ref(&self) -> &<MinPk as Variant>::Signature {
        &self.signature
    }
}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl TryFrom<SignatureBytes> for Signature {
    type Error = Malformed;

    fn try_from(bytes: SignatureBytes) -> Result<Self, Malformed> {
        let raw = *bytes.as_array();
        let signature = <MinPk as Variant>::Signature::try_from(G2Bytes::new(raw))?;
        Ok(Self { raw, signature })
    }
}

impl From<Signature> for SignatureBytes {
    fn from(signature: Signature) -> Self {
        Self::new(signature.raw)
    }
}

impl crate::Validated for Signature {
    type Bytes = SignatureBytes;
}

impl FixedSize for Signature {
    const SIZE: usize = <MinPk as Variant>::Signature::SIZE;
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

impl From<<MinPk as Variant>::Signature> for Signature {
    fn from(signature: <MinPk as Variant>::Signature) -> Self {
        let raw = signature.encode_fixed();
        Self { raw, signature }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(private_key.sign(b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_TEST", &message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Verifier as _, bls12381};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_math::algebra::Random;
    use commonware_parallel::{Sequential, mocks::explore};
    use commonware_utils::test_rng;

    #[test]
    fn test_codec_private_key() {
        let original =
            parse_private_key("0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
                .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), bls12381::PrivateKey::SIZE);
        let decoded = bls12381::PrivateKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_public_key() {
        let original =
            parse_public_key("0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a")
            .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), PublicKey::SIZE);
        let decoded = PublicKeyBytes::decode(encoded).unwrap();
        assert_eq!(decoded, PublicKeyBytes::from(original.clone()));
        assert_eq!(PublicKey::try_from(decoded).unwrap(), original);
    }

    #[test]
    fn test_codec_signature() {
        let original =
            parse_signature("0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb")
            .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), Signature::SIZE);
        let decoded = SignatureBytes::decode(encoded).unwrap();
        assert_eq!(decoded, SignatureBytes::from(original.clone()));
        assert_eq!(Signature::try_from(decoded).unwrap(), original);
    }

    fn parse_private_key(private_key: &str) -> Result<PrivateKey, CodecError> {
        PrivateKey::decode(commonware_formatting::from_hex(private_key).unwrap())
    }

    fn parse_public_key(public_key: &str) -> Option<PublicKey> {
        let bytes = PublicKeyBytes::decode(commonware_formatting::from_hex(public_key).unwrap());
        PublicKey::try_from(bytes.ok()?).ok()
    }

    fn parse_signature(signature: &str) -> Option<Signature> {
        let bytes = SignatureBytes::decode(commonware_formatting::from_hex(signature).unwrap());
        Signature::try_from(bytes.ok()?).ok()
    }

    #[test]
    fn test_from_private() {
        let mut rng = test_rng();
        let private = Private::random(&mut rng);
        let private_key = PrivateKey::from(private);
        // Verify the key works by signing and verifying
        let msg = b"test message";
        let sig = private_key.sign(b"ns", msg);
        assert!(private_key.public_key().verify(b"ns", msg, &sig));
    }

    #[test]
    fn test_private_key_redacted() {
        let mut rng = test_rng();
        let private_key = PrivateKey::random(&mut rng);
        let debug = format!("{:?}", private_key);
        let display = format!("{}", private_key);
        assert!(debug.contains("REDACTED"));
        assert!(display.contains("REDACTED"));
    }

    #[test]
    fn batch_verify_empty() {
        let entries: [BatchEntry<'_, PublicKey>; 0] = [];
        assert!(!PublicKey::verify_batch(
            &mut test_rng(),
            &entries,
            |_, entry| *entry,
            &Sequential,
        ));
    }

    #[test]
    fn batch_verify_invalid_message() {
        // Start with a valid namespaced signature.
        let mut rng = test_rng();
        let private_key = PrivateKey::random(&mut rng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(b"ns", b"message");
        let mut entries = [BatchEntry {
            namespace: b"ns",
            message: b"message",
            public_key: &public_key,
            signature: &signature,
        }];
        assert!(PublicKey::verify_batch(
            &mut rng,
            &entries,
            |_, entry| *entry,
            &Sequential,
        ));

        // Changing the message must invalidate the signature.
        entries[0].message = b"invalid";
        assert!(!PublicKey::verify_batch(
            &mut rng,
            &entries,
            |_, entry| *entry,
            &Sequential,
        ));
    }

    #[test]
    fn projected_batch_indexes_zero_sized_items() {
        struct Batch {
            namespaces: Vec<&'static [u8]>,
            messages: Vec<Vec<u8>>,
            signers: Vec<usize>,
            public_keys: Vec<PublicKey>,
            signatures: Vec<Signature>,
        }

        impl Batch {
            fn verify(&self, strategy: &impl Strategy) -> bool {
                let items = vec![(); self.messages.len()];
                PublicKey::verify_batch(
                    &mut test_rng(),
                    &items,
                    |index, ()| BatchEntry {
                        namespace: self.namespaces[index],
                        message: &self.messages[index],
                        public_key: &self.public_keys[self.signers[index]],
                        signature: &self.signatures[index],
                    },
                    strategy,
                )
            }
        }

        // Build an uneven batch whose unit items identify their namespace, message, signer, and
        // signature only by original index.
        let mut rng = test_rng();
        let keys: Vec<_> = (0..3).map(|_| PrivateKey::random(&mut rng)).collect();
        let namespaces: Vec<&'static [u8]> = (0..9)
            .map(|i| [b"".as_slice(), b"alpha", b"beta"][(i / 3) % 3])
            .collect();
        let messages: Vec<_> = (0..9).map(|i| vec![i as u8; i * 7]).collect();
        let signers: Vec<_> = (0..9).map(|i| i % keys.len()).collect();
        let signatures = (0..9)
            .map(|i| keys[signers[i]].sign(namespaces[i], &messages[i]))
            .collect();
        let mut batch = Batch {
            namespaces,
            messages,
            signers,
            public_keys: keys.iter().map(|key| key.public_key()).collect(),
            signatures,
        };

        // Check each expected verdict across execution shapes.
        let check = |batch: &Batch, expected: bool| {
            assert_eq!(explore(|strategy| batch.verify(strategy)), expected);
        };
        check(&batch, true);

        // Changing the message, namespace, or signer at any index must fail the whole batch.
        for index in 0..batch.messages.len() {
            batch.messages[index].push(0);
            check(&batch, false);
            batch.messages[index].pop();

            let namespace = core::mem::replace(&mut batch.namespaces[index], b"other");
            check(&batch, false);
            batch.namespaces[index] = namespace;

            let signer = batch.signers[index];
            batch.signers[index] = (signer + 1) % keys.len();
            check(&batch, false);
            batch.signers[index] = signer;
        }

        // Restoring every entry must verify again.
        check(&batch, true);
    }

    #[test]
    fn validation_contract() {
        // Keys that must fail to convert: the canonical identity encoding, an encoding whose
        // compression flag is clear, and the curve point `x = 4` outside the prime-order
        // subgroup.
        let mut identity_g1 = [0u8; 48];
        identity_g1[0] = 0xc0;
        let mut outside_g1 = [0u8; 48];
        outside_g1[0] = 0x80;
        outside_g1[47] = 4;

        // Signatures are validated at conversion as well, so the malformed signatures are the
        // same kinds of encoding in G2, with `x = 2` the curve point outside the subgroup.
        let mut identity_g2 = [0u8; 96];
        identity_g2[0] = 0xc0;
        let mut outside_g2 = [0u8; 96];
        outside_g2[0] = 0x80;
        outside_g2[95] = 2;

        // The contract also accepts a malformed signature that converts and then fails to
        // verify, so this asserts that the subgroup check happens at conversion.
        assert!(Signature::try_from(SignatureBytes::new(outside_g2)).is_err());
        crate::assert_validation_contract::<PrivateKey>(
            &[&identity_g1, &[0; 48], &outside_g1],
            |_| vec![identity_g2.to_vec(), vec![0; 96], outside_g2.to_vec()],
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PublicKeyBytes>,
            CodecConformance<PrivateKey>,
            CodecConformance<SignatureBytes>,
        }
    }
}
