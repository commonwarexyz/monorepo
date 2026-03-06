pub mod bounds;
pub mod minimmit;
pub mod simplex;
pub mod utils;

use crate::{simplex::strategy::StrategyChoice, utils::Partition};
use arbitrary::Arbitrary;
use commonware_cryptography::ed25519::PublicKey as Ed25519PublicKey;
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{deterministic, Clock};
use commonware_utils::{NZUsize, NZU16};
pub use minimmit::{
    fuzz::fuzz as minimmit_fuzz, MinimmitBls12381MinPk, MinimmitBls12381MinSig,
    MinimmitBls12381MultisigMinPk, MinimmitBls12381MultisigMinSig, MinimmitEd25519,
    MinimmitSecp256r1,
};
pub use simplex::{
    fuzz::fuzz, SimplexBls12381MinPk, SimplexBls12381MinSig, SimplexBls12381MultisigMinPk,
    SimplexBls12381MultisigMinSig, SimplexEd25519, SimplexSecp256r1,
};
use std::{
    num::{NonZeroU16, NonZeroUsize},
    time::Duration,
};

pub const EPOCH: u64 = 333;

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const FAULT_INJECTION_RATIO: u64 = 5;
const MIN_NUMBER_OF_FAULTS: u64 = 2;
const MIN_REQUIRED_CONTAINERS: u64 = 5;
const MAX_REQUIRED_CONTAINERS: u64 = 50;
const MAX_SLEEP_DURATION: Duration = Duration::from_secs(10);
const NAMESPACE: &[u8] = b"consensus_fuzz";
const MAX_RAW_BYTES: usize = 32_768;

/// Network configuration for fuzz testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Configuration {
    /// Total number of nodes.
    pub n: u32,
    /// Number of faulty (Byzantine) nodes.
    pub faults: u32,
    /// Number of correct (honest) nodes.
    pub correct: u32,
}

impl Configuration {
    pub const fn new(n: u32, faults: u32, correct: u32) -> Self {
        Self { n, faults, correct }
    }

    /// Returns true if this configuration can make progress (liveness).
    pub fn can_finalize(&self) -> bool {
        self.faults <= bounds::max_faults(self.n)
    }
}

/// 4 nodes, 1 faulty, 3 correct (standard BFT config)
pub const N4F1C3: Configuration = Configuration::new(4, 1, 3);
/// 4 nodes, 3 faulty, 1 correct (adversarial majority, no liveness)
pub const N4F3C1: Configuration = Configuration::new(4, 3, 1);
/// 6 nodes, 1 faulty, 5 correct (standard Minimmit 5f+1 config)
pub const N6F1C5: Configuration = Configuration::new(6, 1, 5);
/// 6 nodes, 5 faulty, 1 correct (adversarial majority, no liveness for Minimmit)
pub const N6F5C1: Configuration = Configuration::new(6, 5, 1);

pub async fn setup_degraded_network<E: Clock>(
    oracle: &mut Oracle<Ed25519PublicKey, E>,
    participants: &[Ed25519PublicKey],
) {
    let Some(victim) = participants.last() else {
        return;
    };
    let victim_idx = participants.len() - 1;
    let degraded = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::from_millis(50),
        success_rate: 0.6,
    };
    for (peer_idx, peer) in participants.iter().enumerate() {
        if peer_idx == victim_idx {
            continue;
        }
        oracle.remove_link(victim.clone(), peer.clone()).await.ok();
        oracle.remove_link(peer.clone(), victim.clone()).await.ok();
        oracle
            .add_link(victim.clone(), peer.clone(), degraded.clone())
            .await
            .unwrap();
        oracle
            .add_link(peer.clone(), victim.clone(), degraded.clone())
            .await
            .unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub raw_bytes: Vec<u8>,
    pub required_containers: u64,
    pub degraded_network: bool,
    pub configuration: Configuration,
    pub partition: Partition,
    pub strategy: StrategyChoice,
}

#[derive(Debug, Clone)]
pub struct MinimmitFuzzInput(FuzzInput);

impl From<MinimmitFuzzInput> for FuzzInput {
    fn from(value: MinimmitFuzzInput) -> Self {
        value.0
    }
}

fn choose_configuration(
    u: &mut arbitrary::Unstructured<'_>,
    dominant: Configuration,
    minority: Configuration,
) -> arbitrary::Result<Configuration> {
    Ok(match u.int_in_range(1..=100)? {
        1..=95 => dominant,
        _ => minority,
    })
}

fn arbitrary_input_with_configuration(
    u: &mut arbitrary::Unstructured<'_>,
    configuration: Configuration,
    degraded_configuration: Configuration,
) -> arbitrary::Result<FuzzInput> {
    // Bias towards Connected partition
    let partition = match u.int_in_range(0..=99)? {
        0..=79 => Partition::Connected,                    // 80%
        80..=84 => Partition::Isolated,                    // 5%
        85..=89 => Partition::TwoPartitionsWithByzantine,  // 5%
        90..=94 => Partition::ManyPartitionsWithByzantine, // 5%
        _ => Partition::Ring,                              // 5%
    };

    // Bias degraded networking - 1%
    let degraded_network = partition == Partition::Connected
        && configuration == degraded_configuration
        && u.int_in_range(0..=99)? == 1;

    let required_containers = u.int_in_range(MIN_REQUIRED_CONTAINERS..=MAX_REQUIRED_CONTAINERS)?;

    // SmallScope mutations with round-based injections - 80%,
    // AnyScope mutations - 10%,
    // FutureScope mutations with round-based injections - 10%
    let fault_rounds_bound = u.int_in_range(1..=required_containers)?;
    let max_faults = fault_rounds_bound / FAULT_INJECTION_RATIO;
    let min_faults = MIN_NUMBER_OF_FAULTS.min(fault_rounds_bound);
    let fault_rounds = u.int_in_range(0..=max_faults)?.max(min_faults);
    let strategy = match u.int_in_range(0..=9)? {
        0 => StrategyChoice::AnyScope,
        1 => StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        },
        _ => StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        },
    };

    // Collect bytes for RNG
    let remaining = u.len().min(MAX_RAW_BYTES);
    let raw_bytes = u.bytes(remaining)?.to_vec();

    Ok(FuzzInput {
        raw_bytes,
        partition,
        configuration,
        degraded_network,
        required_containers,
        strategy,
    })
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let configuration = choose_configuration(u, N4F1C3, N4F3C1)?;
        arbitrary_input_with_configuration(u, configuration, N4F1C3)
    }
}

impl Arbitrary<'_> for MinimmitFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let configuration = choose_configuration(u, N6F1C5, N6F5C1)?;
        let inner = arbitrary_input_with_configuration(u, configuration, N6F1C5)?;
        Ok(Self(inner))
    }
}

pub(crate) type NetworkChannels = (
    (
        commonware_p2p::simulated::Sender<Ed25519PublicKey, deterministic::Context>,
        commonware_p2p::simulated::Receiver<Ed25519PublicKey>,
    ),
    (
        commonware_p2p::simulated::Sender<Ed25519PublicKey, deterministic::Context>,
        commonware_p2p::simulated::Receiver<Ed25519PublicKey>,
    ),
    (
        commonware_p2p::simulated::Sender<Ed25519PublicKey, deterministic::Context>,
        commonware_p2p::simulated::Receiver<Ed25519PublicKey>,
    ),
);

pub trait FuzzMode {
    const TWIN: bool;
}

pub struct Standard;

impl FuzzMode for Standard {
    const TWIN: bool = false;
}

pub struct Twinable;

impl FuzzMode for Twinable {
    const TWIN: bool = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bytes(seed: u64) -> [u8; 512] {
        let mut bytes = [0u8; 512];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u64) as u8;
        }
        bytes
    }

    #[test]
    fn minimmit_fuzz_input_uses_only_5f_plus_1_configurations() {
        for seed in 0..512u64 {
            let bytes = sample_bytes(seed);
            let mut u = arbitrary::Unstructured::new(&bytes);
            let input =
                MinimmitFuzzInput::arbitrary(&mut u).expect("must generate minimmit fuzz input");
            let input: FuzzInput = input.into();
            assert!(
                input.configuration == N6F1C5 || input.configuration == N6F5C1,
                "unexpected minimmit configuration: {:?}",
                input.configuration
            );
        }
    }
}
