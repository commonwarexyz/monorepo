//! Deterministic key material and epoch configuration for test committees.
//!
//! Everything derives from a seed with no attempt to protect key material.

pub use crate::multimmit::scheme::bls12381_threshold::dealer::DealtSharing;
use crate::{
    multimmit::{
        config::Protocol,
        scheme::bls12381_threshold::{Dealt, deal, dealer::deal_sharing},
        types::{BlockRef, CertificateId, ChainId, EpochGenesis, PathLimits},
    },
    types::{Epoch, Height},
};
use commonware_cryptography::{
    Hasher, Sha256, bls12381::primitives::variant::Variant, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_utils::{Participant, TestRng, ordered::Set};

/// Deterministic key material for one committee.
pub type Keys<V> = Dealt<ed25519::PublicKey, V>;

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

/// Constructs deterministic key material for `config` and ordered `identities`.
///
/// Randomness is consumed for ordinary keys, then the DA sharing, then the nullification
/// sharing.
pub fn keys<V: Variant>(
    rng: &mut TestRng,
    config: &Protocol<Sha256Digest>,
    identities: &Set<ed25519::PublicKey>,
) -> Keys<V> {
    deal(rng, config.parameters(), identities).expect("mock committee material is consistent")
}

/// Deals a `required`-of-`total` threshold sharing from `rng`.
pub fn sharing<V: Variant>(rng: &mut TestRng, total: u32, required: u32) -> DealtSharing<V> {
    deal_sharing(rng, total, required)
}
