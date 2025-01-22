use ark_bn254::{Fr as Scalar, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use commonware_cryptography::{Hasher, PrivateKey, PublicKey, Scheme, Sha256, Signature};
use commonware_utils::union_unique;
use eigen_crypto_bn254::utils::map_to_curve;
use rand::{CryptoRng, Rng};
use std::borrow::Cow;

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
    fn new<R: CryptoRng + Rng>(r: &mut R) -> Self {
        let sk = Scalar::rand(r);
        let pk = G2Projective::generator() * sk;
        Self {
            private: sk,
            public: pk.into_affine(),
        }
    }

    fn from(private_key: PrivateKey) -> Option<Self> {
        let private_key: [u8; PRIVATE_KEY_LENGTH] = match private_key.as_ref().try_into() {
            Ok(key) => key,
            Err(_) => return None,
        };
        let sk = Scalar::deserialize_compressed(private_key.as_ref()).ok()?;
        if sk == Scalar::ZERO {
            return None;
        }
        let pk = G2Projective::generator() * sk;
        Some(Self {
            private: sk,
            public: pk.into_affine(),
        })
    }

    fn private_key(&self) -> PrivateKey {
        let mut bytes = Vec::with_capacity(PRIVATE_KEY_LENGTH);
        self.private.serialize_compressed(&mut bytes).unwrap();
        bytes.into()
    }

    fn public_key(&self) -> PublicKey {
        let mut bytes = Vec::with_capacity(PUBLIC_KEY_LENGTH);
        self.public.serialize_compressed(&mut bytes).unwrap();
        bytes.into()
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
        let mut bytes = Vec::with_capacity(SIGNATURE_LENGTH);
        sig.serialize_compressed(&mut bytes).unwrap();
        bytes.into()
    }

    fn validate(public_key: &PublicKey) -> bool {
        let public = G2Affine::deserialize_compressed(public_key.as_ref());
        if public.is_err() {
            return false;
        }
        let public = public.unwrap();
        public.is_in_correct_subgroup_assuming_on_curve()
            && public.is_on_curve()
            && !public.is_zero()
    }

    fn verify(
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        let Ok(public) = G2Affine::deserialize_compressed(public_key.as_ref()) else {
            return false;
        };
        if !public.is_in_correct_subgroup_assuming_on_curve()
            || !public.is_on_curve()
            || public.is_zero()
        {
            return false;
        }
        let Ok(signature) = G1Affine::deserialize_compressed(signature.as_ref()) else {
            return false;
        };
        if !signature.is_in_correct_subgroup_assuming_on_curve()
            || !signature.is_on_curve()
            || signature.is_zero()
        {
            return false;
        }

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
        let lhs = ark_bn254::Bn254::pairing(msg_on_g1, public);
        let rhs = ark_bn254::Bn254::pairing(signature, G2Affine::generator());
        lhs == rhs
    }

    fn len() -> (usize, usize) {
        (PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH)
    }
}

impl Bn254 {
    pub fn public_g1(&self) -> PublicKey {
        let pk = G1Projective::generator() * self.private;
        let mut bytes = Vec::with_capacity(G1_LENGTH);
        pk.into_affine().serialize_compressed(&mut bytes).unwrap();
        bytes.into()
    }
}

pub fn get_points(
    g1: &[PublicKey],
    g2: &[PublicKey],
    signatures: &[Signature],
) -> Option<(G1Affine, G2Affine, G1Affine)> {
    let mut agg_public_g1 = G1Projective::ZERO;
    for public in g1 {
        let Ok(public) = G1Affine::deserialize_compressed(public.as_ref()) else {
            return None;
        };
        if !public.is_in_correct_subgroup_assuming_on_curve()
            || !public.is_on_curve()
            || public.is_zero()
        {
            return None;
        }
        agg_public_g1 += public.into_group();
    }
    let agg_public_g1 = agg_public_g1.into_affine();

    let mut agg_public_g2 = G2Projective::ZERO;
    for public in g2 {
        let Ok(public) = G2Affine::deserialize_compressed(public.as_ref()) else {
            return None;
        };
        if !public.is_in_correct_subgroup_assuming_on_curve()
            || !public.is_on_curve()
            || public.is_zero()
        {
            return None;
        }
        agg_public_g2 += public.into_group();
    }
    let agg_public_g2 = agg_public_g2.into_affine();

    let mut agg_signature = G1Projective::ZERO;
    for signature in signatures {
        let Ok(signature) = G1Affine::deserialize_compressed(signature.as_ref()) else {
            return None;
        };
        if !signature.is_in_correct_subgroup_assuming_on_curve()
            || !signature.is_on_curve()
            || signature.is_zero()
        {
            return None;
        }
        agg_signature += signature.into_group();
    }
    let agg_signature = agg_signature.into_affine();
    Some((agg_public_g1, agg_public_g2, agg_signature))
}

pub fn aggregate_signatures(signatures: &[Signature]) -> Option<Signature> {
    let mut agg_signature = G1Projective::ZERO;
    for signature in signatures {
        let Ok(signature) = G1Affine::deserialize_compressed(signature.as_ref()) else {
            return None;
        };
        if !signature.is_in_correct_subgroup_assuming_on_curve()
            || !signature.is_on_curve()
            || signature.is_zero()
        {
            return None;
        }
        agg_signature += signature.into_group();
    }
    let mut bytes = Vec::with_capacity(SIGNATURE_LENGTH);
    agg_signature.serialize_compressed(&mut bytes).unwrap();
    Some(bytes.into())
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
        let Ok(public) = G2Affine::deserialize_compressed(public.as_ref()) else {
            return false;
        };
        if !public.is_in_correct_subgroup_assuming_on_curve()
            || !public.is_on_curve()
            || public.is_zero()
        {
            return false;
        }
        agg_public += public.into_group();
    }
    let mut public = Vec::with_capacity(PUBLIC_KEY_LENGTH);
    agg_public.serialize_compressed(&mut public).unwrap();

    // Verify signature
    Bn254::verify(namespace, message, &public.into(), signature)
}
