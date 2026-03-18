use crate::{
    bls12381::primitives::group::{Scalar, G1},
    ed25519, Secret,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, Write};
use commonware_math::algebra::Random;
use commonware_utils::{hex, ordered::Map, union_unique, Array, Span};
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use ed25519_consensus::VerificationKey;
use rand_core::CryptoRngCore;

const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone, Debug)]
pub struct PrivateKey {
    inner: Secret<ed25519_consensus::SigningKey>,
}

impl Random for PrivateKey {
    fn random(rng: impl CryptoRngCore) -> Self {
        Self {
            inner: Secret::new(ed25519_consensus::SigningKey::new(rng)),
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
        self.inner
            .expose(|key| ed25519::Signature::from(key.sign(&payload)))
    }
}

impl PrivateKey {
    /// Get the [`PublicKey`] associated with this private key.
    pub fn public(&self) -> PublicKey {
        crate::Signer::public_key(self)
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
    pub(super) fn vrf(&self, _msg: &[u8], _receiver: &PublicKey) -> Scalar {
        todo!()
    }

    /// Compute several [`Self::vrf`] outputs, along with commitments to these outputs.
    ///
    /// We take in several receivers now, and associate each of them with their output.
    ///
    /// We also produce [`VrfCommitments`], which contain commitments
    pub(super) fn vrf_batch_checked(
        &self,
        _msg: &[u8],
        _receivers: impl IntoIterator<Item = PublicKey>,
    ) -> (Map<PublicKey, Scalar>, VrfCommitments) {
        todo!()
    }
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
                &ed25519_consensus::Signature::from(<[u8; 64]>::try_from(sig.as_ref()).unwrap()),
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
            .map_err(|e: ed25519_consensus::Error| CodecError::Wrapped("evrf", e.into()))?;
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
        write!(f, "{}", hex(self))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(self))
    }
}

struct Proof {}

impl Write for Proof {
    fn write(&self, _buf: &mut impl BufMut) {}
}

impl EncodeSize for Proof {
    fn encode_size(&self) -> usize {
        0
    }
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

/// Commitments to the output of [`PrivateKey::vrf`] for several receivers.
///
/// These commitments bind the output value for each receiver, without revealing
/// what it is.
pub struct VrfCommitments {
    proof: Proof,
    commitments: Map<PublicKey, G1>,
}

impl VrfCommitments {
    /// Extract the VRF output commitments, after checking their integrity.
    ///
    /// For a given message and sender, we can check that the commitments contain
    /// what [`PrivateKey::vrf`] would produce for that receiver.
    pub fn check(self, _msg: &[u8], _sender: &PublicKey) -> Option<Map<PublicKey, G1>> {
        todo!()
    }

    /// Compute [`Self::check`] for an entire batch.
    ///
    /// `rng` is needed to allow to optimize this check, making it potentially
    /// faster than checking each value in isolation.
    ///
    /// A sender will only appear in the output if their output is correct.
    pub fn check_batch(
        _rng: &mut impl CryptoRngCore,
        _outputs: impl IntoIterator<Item = (PublicKey, Bytes, Self)>,
    ) -> Map<PublicKey, Map<PublicKey, G1>> {
        todo!()
    }
}
