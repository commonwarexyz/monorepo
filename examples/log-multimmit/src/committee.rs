//! Committee material every node derives from the participant list.

use crate::config::RunConfig;
use commonware_consensus::{
    multimmit::{
        config::{Protocol, Tuning},
        mocks::keys::keys,
        scheme::bls12381::Scheme,
        types::{CodecConfig, EpochGenesis, Window},
    },
    types::{Epoch, Participant, ViewDelta},
};
use commonware_cryptography::{
    Sha256, Signer as _, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest,
};
use commonware_utils::{TestRng, ordered::Set};

/// Signature namespace for this example's consensus deployment.
const CONSENSUS_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_CONSENSUS";

/// Seed every node uses to derive the same committee material.
const COMMITTEE_SEED: u64 = 42;

/// Views kept below the current view.
///
/// The committee is fixed and the engine runs indefinitely, so this window is what bounds memory.
const VIEW_RETENTION: u64 = 64;

/// The committee every node derives from one shared seed.
///
/// Every node knows every key, which is only acceptable because this is an example: a real
/// deployment gives each validator its own keys from a key ceremony.
pub struct Committee {
    /// The validated immutable epoch configuration.
    pub config: Protocol<Digest>,
    /// Network identities in participant order.
    pub identities: Vec<ed25519::PublicKey>,
    /// Network private keys in participant order.
    pub network_keys: Vec<ed25519::PrivateKey>,
    /// One signing scheme per participant, in participant order.
    pub signers: Vec<Scheme<ed25519::PublicKey, MinPk>>,
    /// A keyless verification scheme.
    pub verifier: Scheme<ed25519::PublicKey, MinPk>,
}

impl Committee {
    /// Builds a committee of `participants` from `seed`, with one producer chain per entry of
    /// `producers`.
    fn new(seed: u64, participants: u32, producers: Vec<Participant>, window: Window) -> Self {
        let mut network_keys = (0..participants)
            .map(|index| ed25519::PrivateKey::from_seed(seed ^ (u64::from(index) + 1)))
            .collect::<Vec<_>>();
        network_keys.sort_by_key(|key| key.public_key());
        let identities = network_keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>();
        let genesis = EpochGenesis::new::<Sha256>(Epoch::zero(), producers.len())
            .expect("the committee has at least one producer");
        let config = Protocol::new(
            CONSENSUS_NAMESPACE,
            participants as usize,
            producers,
            window,
            genesis,
        )
        .expect("validated committee configuration");
        // A deterministic generator is what lets every node derive the same keys from the seed.
        let keys = keys::<MinPk>(
            &mut TestRng::new(seed),
            config.parameters(),
            &Set::try_from(identities.clone()).expect("identities are unique"),
        );
        Self {
            config,
            identities,
            network_keys,
            signers: keys.signers,
            verifier: keys.verifier,
        }
    }

    /// Returns the bounded codec configuration of the epoch.
    pub const fn codec(&self) -> CodecConfig {
        self.config.codec_config()
    }
}

/// Returns each producer's committee position, in chain order.
///
/// Every producer must be a participant.
fn producer_participants(participants: &[u64], producers: &[u64]) -> Vec<Participant> {
    producers
        .iter()
        .map(|producer| {
            let index = participants
                .iter()
                .position(|participant| participant == producer)
                .expect("every producer is a participant");
            Participant::from_usize(index)
        })
        .collect()
}

/// Derives the committee every node shares from a validated configuration.
pub fn derive(config: &RunConfig) -> Committee {
    let seed = config
        .benchmark
        .as_ref()
        .map_or(COMMITTEE_SEED, |benchmark| benchmark.committee_seed);
    let participants = &config.network.participants;
    Committee::new(
        seed,
        u32::try_from(participants.len()).expect("too many participants"),
        producer_participants(participants, &config.network.producers),
        config.tuning.window().expect("validated window"),
    )
}

/// Returns the tuning of every node.
///
/// The artifact byte limit is left to the engine, which takes the committee's largest artifact,
/// and at least 1 MiB: the largest artifact grows with participants, chains, and the window.
pub const fn tuning() -> Tuning {
    Tuning {
        view_retention: ViewDelta::new(VIEW_RETENTION),
        ..Tuning::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WINDOW_CAP;
    use commonware_consensus::{
        Epochable as _,
        multimmit::types::{ChainId, TransactionBlockHeader},
        types::Height,
    };
    use commonware_cryptography::Hasher as _;

    fn window() -> Window {
        Window::new(WINDOW_CAP).expect("the default window is valid")
    }

    #[test]
    fn tuning_is_valid_for_the_shipped_committee() {
        // The engine cross-checks the tuning against the committee, so an over-tight bound only
        // shows up at startup. Check it here so the example cannot ship a manifest it rejects.
        for participants in [6u32, 7, 11] {
            let committee = Committee::new(
                COMMITTEE_SEED,
                participants,
                vec![Participant::new(1), Participant::new(participants - 1)],
                window(),
            );
            assert!(
                tuning()
                    .validate::<Sha256, MinPk>(&committee.config)
                    .is_ok()
            );
        }

        // The deployment scale: fifty validators, every one producing.
        let committee = Committee::new(
            COMMITTEE_SEED,
            50,
            (0..50).map(Participant::new).collect(),
            window(),
        );
        assert!(
            tuning()
                .validate::<Sha256, MinPk>(&committee.config)
                .is_ok()
        );
    }

    #[test]
    fn nodes_derive_the_same_committee() {
        let producers = vec![Participant::new(0), Participant::new(3)];
        let first = Committee::new(COMMITTEE_SEED, 7, producers.clone(), window());
        let second = Committee::new(COMMITTEE_SEED, 7, producers, window());
        assert_eq!(first.identities, second.identities);
        assert_eq!(first.config, second.config);
        assert_eq!(first.config.genesis().tips().len(), 2);
        for (index, signer) in first.signers.iter().enumerate() {
            assert_eq!(signer.me(), Some(Participant::from_usize(index)));
        }

        // A header one node's producer signs verifies under the verifier another node derived.
        let header = TransactionBlockHeader::new(
            first.config.epoch(),
            ChainId::new(0),
            Height::new(1),
            first.config.genesis().tips()[0].digest(),
            Sha256::hash(&[b"body"]),
        )
        .expect("header is valid");
        let signed = first.signers[0]
            .sign_transaction_block(header)
            .expect("participant 0 produces chain 0");
        assert!(second.verifier.verify_transaction_block(&signed));
    }

    #[test]
    fn producer_keys_define_chain_order() {
        assert_eq!(
            producer_participants(&[10, 20, 30, 40], &[40, 20]),
            [Participant::new(3), Participant::new(1)]
        );
        assert_eq!(
            producer_participants(&[10, 20], &[10, 20]),
            [Participant::new(0), Participant::new(1)]
        );
    }
}
