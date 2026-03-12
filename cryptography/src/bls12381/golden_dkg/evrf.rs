use crate::bls12381::primitives::group::{Scalar, G1};
use bytes::Bytes;
use commonware_utils::ordered::Map;
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

pub struct PrivateKey {}

impl PrivateKey {
    /// Get the [`PublicKey`] associated with this private key.
    pub fn public(&self) -> PublicKey {
        todo!()
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
    pub fn vrf(&self, _msg: &[u8], _receiver: &PublicKey) -> Scalar {
        todo!()
    }

    /// Compute several [`Self::vrf`] outputs, along with commitments to these outputs.
    ///
    /// We take in several receivers now, and associate each of them with their output.
    ///
    /// We also produce [`VrfCommitments`], which contain commitments
    pub fn vrf_batch_checked(
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey {}

struct Proof {}

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
        _outputs: BTreeMap<PublicKey, (Bytes, Self)>,
    ) -> Map<PublicKey, Map<PublicKey, G1>> {
        todo!()
    }
}
