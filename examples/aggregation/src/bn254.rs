use ark_bn254::{Fr as Scalar, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use commonware_cryptography::{Array, Error, Hasher as _, Scheme, Sha256};
use commonware_utils::{hex, union_unique, SizedSerialize};
use eigen_crypto_bn254::utils::map_to_curve;
use rand::{CryptoRng, Rng};
use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};

const DIGEST_LENGTH: usize = 32;
const PRIVATE_KEY_LENGTH: usize = 32;
const G1_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = G1_LENGTH;
const G2_LENGTH: usize = 64;
const PUBLIC_KEY_LENGTH: usize = G2_LENGTH;

/// If message provided is exactly 32 bytes, it is assumed to be a hash digest.
#[derive(Clone)]
pub struct Bn254 {
    private: Scalar,
    public: G2Affine,
}

impl Scheme for Bn254 {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn new<R: CryptoRng + Rng>(r: &mut R) -> Self {
        let sk = Scalar::rand(r);
        let pk = G2Projective::generator() * sk;
        Self {
            private: sk,
            public: pk.into_affine(),
        }
    }

    fn from(private_key: PrivateKey) -> Option<Self> {
        let sk = private_key.key;
        let pk = G2Projective::generator() * sk;
        Some(Self {
            private: sk,
            public: pk.into_affine(),
        })
    }

    fn private_key(&self) -> PrivateKey {
        PrivateKey::from(self.private)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public)
    }

    fn sign(&mut self, namespace: Option<&[u8]>, message: &[u8]) -> Signature {
        // Generate payload
        let hash: [u8; DIGEST_LENGTH] = if namespace.is_none() && message.len() == DIGEST_LENGTH {
            message.try_into().unwrap()
        } else {
            let payload = match namespace {
                Some(namespace) => Cow::Owned(union_unique(namespace, message)),
                None => Cow::Borrowed(message),
            };
            let mut hasher = Sha256::new();
            hasher.update(payload.as_ref());
            let hash = hasher.finalize();
            hash.as_ref().try_into().unwrap()
        };

        // Map to curve
        let msg_on_g1 = map_to_curve(&hash);

        // Generate signature
        let sig = msg_on_g1 * self.private;
        let sig = sig.into_affine();

        // Serialize signature
        Signature::from(sig)
    }

    fn verify(
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        // Generate payload
        let hash: [u8; DIGEST_LENGTH] = if namespace.is_none() && message.len() == DIGEST_LENGTH {
            message.try_into().unwrap()
        } else {
            let payload = match namespace {
                Some(namespace) => Cow::Owned(union_unique(namespace, message)),
                None => Cow::Borrowed(message),
            };
            let mut hasher = Sha256::new();
            hasher.update(payload.as_ref());
            let hash = hasher.finalize();
            hash.as_ref().try_into().unwrap()
        };

        // Map to curve
        let msg_on_g1 = map_to_curve(&hash);

        // Pairing check
        let lhs = ark_bn254::Bn254::pairing(msg_on_g1, public_key.key);
        let rhs = ark_bn254::Bn254::pairing(signature.sig, G2Affine::generator());
        lhs == rhs
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKey {
    raw: [u8; PRIVATE_KEY_LENGTH],
    key: Scalar,
}

impl Array for PrivateKey {}

impl SizedSerialize for PrivateKey {
    const SERIALIZED_LEN: usize = PRIVATE_KEY_LENGTH;
}

impl Hash for PrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
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

impl From<Scalar> for PrivateKey {
    fn from(key: Scalar) -> Self {
        let mut raw = [0u8; PRIVATE_KEY_LENGTH];
        key.serialize_compressed(&mut raw[..]).unwrap();
        Self { raw, key }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; PRIVATE_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidPrivateKeyLength)?;
        let key = Scalar::deserialize_compressed(value).map_err(|_| Error::InvalidPrivateKey)?;
        if key == Scalar::ZERO {
            return Err(Error::InvalidPrivateKey);
        }
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

#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey {
    raw: [u8; PUBLIC_KEY_LENGTH],
    key: G2Affine,
}

impl Array for PublicKey {}

impl SizedSerialize for PublicKey {
    const SERIALIZED_LEN: usize = PUBLIC_KEY_LENGTH;
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
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

impl From<G2Affine> for PublicKey {
    fn from(key: G2Affine) -> Self {
        let mut raw = [0u8; PUBLIC_KEY_LENGTH];
        key.serialize_compressed(&mut raw[..]).unwrap();
        Self { raw, key }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; PUBLIC_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidPublicKeyLength)?;
        let key = G2Affine::deserialize_compressed(value).map_err(|_| Error::InvalidPublicKey)?;
        if !key.is_in_correct_subgroup_assuming_on_curve() || !key.is_on_curve() || key.is_zero() {
            return Err(Error::InvalidPublicKey);
        }
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

#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; SIGNATURE_LENGTH],
    sig: G1Affine,
}

impl Array for Signature {}

impl SizedSerialize for Signature {
    const SERIALIZED_LEN: usize = SIGNATURE_LENGTH;
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

impl From<G1Affine> for Signature {
    fn from(sig: G1Affine) -> Self {
        let mut raw = [0u8; SIGNATURE_LENGTH];
        sig.serialize_compressed(&mut raw[..]).unwrap();
        Self { raw, sig }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; SIGNATURE_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidSignatureLength)?;
        let sig = G1Affine::deserialize_compressed(value).map_err(|_| Error::InvalidSignature)?;
        if !sig.is_in_correct_subgroup_assuming_on_curve() || !sig.is_on_curve() || sig.is_zero() {
            return Err(Error::InvalidSignature);
        }
        Ok(Self { raw, sig })
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

// TODO: cleanup handling of G1 vs G2 public keys (+ unify with signature)
#[derive(Clone, Eq, PartialEq)]
pub struct G1PublicKey {
    raw: [u8; G1_LENGTH],
    key: G1Affine,
}

impl Array for G1PublicKey {}

impl SizedSerialize for G1PublicKey {
    const SERIALIZED_LEN: usize = G1_LENGTH;
}

impl Hash for G1PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for G1PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for G1PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for G1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for G1PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<G1Affine> for G1PublicKey {
    fn from(key: G1Affine) -> Self {
        let mut raw = [0u8; G1_LENGTH];
        key.serialize_compressed(&mut raw[..]).unwrap();
        Self { raw, key }
    }
}

impl TryFrom<&[u8]> for G1PublicKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; G1_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidPublicKeyLength)?;
        let key = G1Affine::deserialize_compressed(value).map_err(|_| Error::InvalidPublicKey)?;
        if !key.is_in_correct_subgroup_assuming_on_curve() || !key.is_on_curve() || key.is_zero() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self { raw, key })
    }
}

impl TryFrom<&Vec<u8>> for G1PublicKey {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for G1PublicKey {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl Debug for G1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for G1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Bn254 {
    pub fn public_g1(&self) -> G1PublicKey {
        let pk = G1Projective::generator() * self.private;
        G1PublicKey::from(pk.into_affine())
    }
}

pub fn get_points(
    g1: &[G1PublicKey],
    g2: &[PublicKey],
    signatures: &[Signature],
) -> Option<(G1Affine, G2Affine, G1Affine)> {
    let mut agg_public_g1 = G1Projective::ZERO;
    for public in g1 {
        agg_public_g1 += public.key.into_group();
    }
    let agg_public_g1 = agg_public_g1.into_affine();

    let mut agg_public_g2 = G2Projective::ZERO;
    for public in g2 {
        agg_public_g2 += public.key.into_group();
    }
    let agg_public_g2 = agg_public_g2.into_affine();

    let mut agg_signature = G1Projective::ZERO;
    for signature in signatures {
        agg_signature += signature.sig.into_group();
    }
    let agg_signature = agg_signature.into_affine();
    Some((agg_public_g1, agg_public_g2, agg_signature))
}

pub fn aggregate_signatures(signatures: &[Signature]) -> Option<Signature> {
    let mut agg_signature = G1Projective::ZERO;
    for signature in signatures {
        agg_signature += signature.sig.into_group();
    }
    Some(Signature::from(agg_signature.into_affine()))
}

pub fn aggregate_verify(
    publics: &[PublicKey],
    namespace: Option<&[u8]>,
    message: &[u8],
    signature: &Signature,
) -> bool {
    // Aggregate public keys
    let mut agg_public = G2Projective::ZERO;
    for public in publics {
        agg_public += public.key.into_group();
    }
    let agg_public = agg_public.into_affine();
    let public = PublicKey::from(agg_public);

    // Verify signature
    Bn254::verify(namespace, message, &public, signature)
}
