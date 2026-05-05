use crate::{
    bls12381::primitives::group::{Scalar, G1},
    ed25519::{self, core as ed_core},
    transcript::{Summary, Transcript},
    Secret,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_utils::{ordered::Map, union_unique, Array, Span, TryCollect};
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed_core::VerificationKey;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};
use std::num::NonZeroU32;
use zeroize::Zeroizing;

const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone, Debug)]
pub struct PrivateKey {
    inner: Secret<ed_core::SigningKey>,
}

impl Random for PrivateKey {
    fn random(rng: impl CryptoRngCore) -> Self {
        Self {
            inner: Secret::new(ed_core::SigningKey::new(rng)),
        }
    }
}

impl crate::Signer for PrivateKey {
    type Signature = ed25519::Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.inner.expose(|key| PublicKey {
            inner: key.verification_key(),
        })
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        let payload = union_unique(namespace, msg);
        self.inner.expose(|key| {
            let sig = key.sign(&payload);
            ed25519::Signature::read(&mut &sig.to_bytes()[..]).expect("valid 64-byte signature")
        })
    }
}

impl PrivateKey {
    /// Get the [`PublicKey`] associated with this private key.
    pub fn public(&self) -> PublicKey {
        crate::Signer::public_key(self)
    }

    fn diffie_hellman(&self, public: &PublicKey, transcript: &mut Transcript) {
        // Convert our ed25519 seed to an x25519 static secret.
        // Ed25519 derives the scalar via SHA-512(seed)[0..32]; x25519 StaticSecret
        // applies its own clamping on top of these bytes.
        let x25519_secret = self.inner.expose(|key| {
            let hash = Sha512::digest(key.as_bytes());
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes.copy_from_slice(&hash[..32]);
            x25519_dalek::StaticSecret::from(scalar_bytes)
        });

        // Convert the ed25519 public key (compressed Edwards Y) to an x25519
        // public key (Montgomery U-coordinate).
        let edwards =
            CompressedEdwardsY::from_slice(public.as_ref()).expect("public key is 32 bytes");
        let montgomery = edwards
            .decompress()
            .expect("valid ed25519 public key decompresses")
            .to_montgomery();
        let x25519_public = x25519_dalek::PublicKey::from(montgomery.to_bytes());

        let shared = x25519_secret.diffie_hellman(&x25519_public);
        transcript.commit(shared.as_bytes().as_slice());
    }

    /// Compute the VRF output between ourselves and the receiver, for a given message.
    ///
    /// If our receiver calls this method using their [`PrivateKey`] and our [`PublicKey`],
    /// then the result will be the same.
    ///
    /// Changing the message in any way will produce a completely different output.
    ///
    /// Without knowing either [`PrivateKey`], the output is indistinguishable from
    /// a random value.
    pub(super) fn vrf(&self, msg: &Summary, receiver: &PublicKey) -> Scalar {
        let mut transcript = Transcript::resume(*msg);
        self.diffie_hellman(receiver, &mut transcript);
        Scalar::random(&mut transcript.noise(b"vrf"))
    }

    /// Compute several [`Self::vrf`] outputs, along with commitments to these outputs.
    ///
    /// We take in several receivers now, and associate each of them with their output.
    ///
    /// We also produce [`VrfCommitments`], which contain commitments.
    ///
    /// # Panics
    ///
    /// Panics if `receivers` contains duplicate public keys.
    pub(super) fn vrf_batch_checked(
        &self,
        msg: &Summary,
        receivers: impl IntoIterator<Item = PublicKey>,
    ) -> (Map<PublicKey, Scalar>, VrfCommitments) {
        let scalars: Map<PublicKey, Scalar> = receivers
            .into_iter()
            .map(|receiver| {
                let s = self.vrf(msg, &receiver);
                (receiver, s)
            })
            .try_collect()
            .expect("receivers must be unique");
        let commitments: Map<PublicKey, G1> = scalars
            .iter_pairs()
            .map(|(pk, s)| (pk.clone(), G1::generator() * s))
            .try_collect()
            .expect("keys are unique");
        (
            scalars,
            VrfCommitments {
                proof: Proof { key: self.clone() },
                commitments,
            },
        )
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.expose(|key| key.as_bytes().write(buf));
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
        let key = ed_core::SigningKey::from(*raw);
        Ok(Self {
            inner: Secret::new(key),
        })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = PUBLIC_KEY_LENGTH;
}

/// A public key, which we can use to create and check VRF outputs with.
///
/// This can be created using [`PrivateKey::public`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PublicKey {
    inner: VerificationKey,
}

impl crate::Verifier for PublicKey {
    type Signature = ed25519::Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        let payload = union_unique(namespace, msg);
        self.inner
            .verify(
                &ed_core::Signature::from(<[u8; 64]>::try_from(sig.as_ref()).unwrap()),
                &payload,
            )
            .is_ok()
    }
}

impl crate::PublicKey for PublicKey {}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.as_bytes().write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; PUBLIC_KEY_LENGTH]>::read_cfg(buf, &())?;
        let inner = VerificationKey::try_from(raw)
            .map_err(|e: ed_core::Error| CodecError::Wrapped("evrf", e.into()))?;
        Ok(Self { inner })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl Deref for PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&**self))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&**self))
    }
}

/// An insecure "proof" that simply contains the sender's private key.
///
/// This is NOT a real zero-knowledge proof. It reveals the private key,
/// completely breaking the VRF's secrecy property. We use this placeholder
/// so that commitment checking works while the real ZK proof is being developed.
#[derive(Clone)]
struct Proof {
    key: PrivateKey,
}

impl Proof {
    /// Check that each commitment matches the VRF output for the corresponding receiver.
    fn check(&self, msg: &Summary, sender: &PublicKey, commitments: &Map<PublicKey, G1>) -> bool {
        if self.key.public() != *sender {
            return false;
        }
        commitments.iter_pairs().all(|(receiver, commitment)| {
            let expected = G1::generator() * &self.key.vrf(msg, receiver);
            *commitment == expected
        })
    }
}

impl Write for Proof {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.inner.expose(|key| key.as_bytes().write(buf));
    }
}

impl Read for Proof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            key: PrivateKey::read(buf)?,
        })
    }
}

impl FixedSize for Proof {
    const SIZE: usize = PrivateKey::SIZE;
}

impl Write for VrfCommitments {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.commitments.write(buf);
    }
}

impl EncodeSize for VrfCommitments {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.commitments.encode_size()
    }
}

impl Read for VrfCommitments {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, max_players: &Self::Cfg) -> Result<Self, CodecError> {
        let proof: Proof = ReadExt::read(buf)?;
        let range = commonware_codec::RangeCfg::new(0..=max_players.get() as usize);
        let commitments = Read::read_cfg(buf, &(range, (), ()))?;
        Ok(Self { proof, commitments })
    }
}

/// Commitments to the output of [`PrivateKey::vrf`] for several receivers.
///
/// These commitments bind the output value for each receiver, without revealing
/// what it is.
#[derive(Clone)]
pub struct VrfCommitments {
    proof: Proof,
    commitments: Map<PublicKey, G1>,
}

impl VrfCommitments {
    /// Shift the commitment for `receiver` by `delta`.
    ///
    /// This exists to allow tests to simulate an adversary who provides
    /// fake mask commitments (exploiting the empty proof).
    pub(super) fn perturb(&mut self, receiver: &PublicKey, delta: &G1) {
        if let Some(c) = self.commitments.get_value_mut(receiver) {
            *c += delta;
        }
    }

    /// Extract the VRF output commitments, after checking their integrity.
    ///
    /// For a given message and sender, we can check that the commitments contain
    /// what [`PrivateKey::vrf`] would produce for that receiver.
    pub fn check(self, msg: &Summary, sender: &PublicKey) -> Option<Map<PublicKey, G1>> {
        if !self.proof.check(msg, sender, &self.commitments) {
            return None;
        }
        Some(self.commitments)
    }

    /// Compute [`Self::check`] for an entire batch.
    ///
    /// `rng` is needed to allow to optimize this check, making it potentially
    /// faster than checking each value in isolation.
    ///
    /// A sender will only appear in the output if their output is correct.
    ///
    /// # Panics
    ///
    /// Panics if `outputs` contains duplicate sender public keys.
    pub fn check_batch(
        _rng: &mut impl CryptoRngCore,
        outputs: impl IntoIterator<Item = (PublicKey, Bytes, Self)>,
    ) -> Map<PublicKey, Map<PublicKey, G1>> {
        outputs
            .into_iter()
            .filter_map(|(sender, mut msg, commitments)| {
                let summary: Summary = ReadExt::read(&mut msg).ok()?;
                let checked = commitments.check(&summary, &sender)?;
                Some((sender, checked))
            })
            .try_collect()
            .expect("senders must be unique")
    }
}
