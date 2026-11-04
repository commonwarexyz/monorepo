//! Deterministic key material and epoch configuration for test committees.
//!
//! Everything derives from a seed with no attempt to protect key material.

use crate::{
    multimmit::{
        config::{Parameters, Protocol},
        scheme::{Available, Generic, Scheme, bls12381, bls12381_sas, ed25519 as ed25519_suite},
        types::{BlockRef, CertificateId, ChainId, EpochGenesis, PathLimits},
    },
    types::{Epoch, Height},
};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _, bls12381::primitives::variant::Variant, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_utils::{Participant, TestRng, ordered::Set};
use std::sync::Arc;

/// The BLS12-381 multisig suite over Ed25519 identities.
pub type Bls<V, Q = Available> = bls12381::Scheme<ed25519::PublicKey, V, Q>;

/// The synchronized aggregate suite over Ed25519 identities.
pub type Sas<V, Q = Available> = bls12381_sas::Scheme<ed25519::PublicKey, V, Q>;

/// The Ed25519 suite.
pub type Ed25519<Q = Available> = ed25519_suite::Scheme<Q>;

/// A suite whose committees the mocks can deal.
pub trait Fixture: Scheme<PublicKey = ed25519::PublicKey> {
    /// Deals one signer per network key and a verifier, all in identity order.
    ///
    /// `network_keys` must be sorted by public key.
    fn committee(
        rng: &mut TestRng,
        parameters: &Arc<Parameters>,
        network_keys: &[ed25519::PrivateKey],
    ) -> (Vec<Generic<Self>>, Generic<Self>);
}

fn identities(network_keys: &[ed25519::PrivateKey]) -> Set<ed25519::PublicKey> {
    Set::try_from(
        network_keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>(),
    )
    .expect("identities are unique")
}

impl<V: Variant, Q: bls12381::Quorum> Fixture for Bls<V, Q> {
    fn committee(
        rng: &mut TestRng,
        parameters: &Arc<Parameters>,
        network_keys: &[ed25519::PrivateKey],
    ) -> (Vec<Generic<Self>>, Generic<Self>) {
        let dealt = Self::deal(rng, parameters, &identities(network_keys))
            .expect("mock committee material is consistent");
        (dealt.signers, dealt.verifier)
    }
}

impl<V: Variant, Q: bls12381::Quorum> Fixture for Sas<V, Q> {
    fn committee(
        rng: &mut TestRng,
        parameters: &Arc<Parameters>,
        network_keys: &[ed25519::PrivateKey],
    ) -> (Vec<Generic<Self>>, Generic<Self>) {
        let dealt = Self::deal(rng, parameters, &identities(network_keys))
            .expect("mock committee material is consistent");
        (dealt.signers, dealt.verifier)
    }
}

impl<Q: ed25519_suite::Quorum> Fixture for Ed25519<Q> {
    fn committee(
        _: &mut TestRng,
        parameters: &Arc<Parameters>,
        network_keys: &[ed25519::PrivateKey],
    ) -> (Vec<Generic<Self>>, Generic<Self>) {
        let participants = identities(network_keys);
        let signers = network_keys
            .iter()
            .map(|key| {
                Self::signer(parameters, participants.clone(), key.clone())
                    .expect("mock committee material is consistent")
            })
            .collect();
        let verifier = Self::verifier(parameters, participants)
            .expect("mock committee material is consistent");
        (signers, verifier)
    }
}

/// Returns a digest of `label` and `marker`.
pub fn digest(label: &[u8], marker: u64) -> Sha256Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

/// Builds an epoch configuration whose epoch and genesis digests derive from `seed`, with one
/// producer chain per entry of `producers`.
pub fn test_config(
    seed: u64,
    namespace: &[u8],
    participants: u32,
    producers: Vec<Participant>,
    limits: PathLimits,
) -> Protocol<Sha256Digest> {
    let epoch = Epoch::new(seed);
    let chains = u32::try_from(producers.len()).expect("producer count is representable");
    let tips = (0..chains)
        .map(|chain| {
            BlockRef::new(
                ChainId::new(chain),
                Height::zero(),
                digest(b"mock genesis", seed + u64::from(chain)),
            )
        })
        .collect();
    let genesis = EpochGenesis::new(
        epoch,
        digest(b"mock leader genesis", seed),
        CertificateId::new(digest(b"mock vqc genesis", seed)),
        CertificateId::new(digest(b"mock lqc genesis", seed)),
        tips,
    )
    .expect("mock genesis is valid");
    Protocol::new(namespace, participants as usize, producers, limits, genesis)
        .expect("mock configuration is valid")
}
