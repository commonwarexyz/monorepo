pub mod disrupter;
pub mod fuzz;
pub mod invariants;
pub mod strategy;

use commonware_codec::Read;
use commonware_consensus::{
    elector::{Config as ElectorConfig, RoundRobin},
    minimmit::scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::{self, mocks::Fixture},
    ed25519::PublicKey as Ed25519PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_runtime::deterministic;

pub trait Minimmit: 'static
where
    <<Self::Scheme as certificate::Scheme>::Certificate as Read>::Cfg: Default,
{
    type Scheme: Scheme<Sha256Digest, PublicKey = Ed25519PublicKey>;
    type Elector: ElectorConfig<Self::Scheme> + Default;
    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme>;
}

pub struct MinimmitEd25519;

impl Minimmit for MinimmitEd25519 {
    type Scheme = ed25519::Scheme;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        ed25519::fixture(context, namespace, n)
    }
}

pub struct MinimmitBls12381MultisigMinPk;

impl Minimmit for MinimmitBls12381MultisigMinPk {
    type Scheme = bls12381_multisig::Scheme<Ed25519PublicKey, MinPk>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_multisig::fixture::<MinPk, _>(context, namespace, n)
    }
}

pub struct MinimmitBls12381MultisigMinSig;

impl Minimmit for MinimmitBls12381MultisigMinSig {
    type Scheme = bls12381_multisig::Scheme<Ed25519PublicKey, MinSig>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_multisig::fixture::<MinSig, _>(context, namespace, n)
    }
}

pub struct MinimmitBls12381MinPk;

impl Minimmit for MinimmitBls12381MinPk {
    type Scheme = bls12381_threshold::Scheme<Ed25519PublicKey, MinPk>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_threshold::fixture::<MinPk, _>(context, namespace, n)
    }
}

pub struct MinimmitBls12381MinSig;

impl Minimmit for MinimmitBls12381MinSig {
    type Scheme = bls12381_threshold::Scheme<Ed25519PublicKey, MinSig>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_threshold::fixture::<MinSig, _>(context, namespace, n)
    }
}

pub struct MinimmitSecp256r1;

impl Minimmit for MinimmitSecp256r1 {
    type Scheme = secp256r1::Scheme<Ed25519PublicKey>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        secp256r1::fixture(context, namespace, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{simplex::strategy::StrategyChoice, utils::Partition, FuzzInput, Standard, N6F1C5};
    use commonware_macros::{test_group, test_traced};
    use proptest::prelude::*;

    const TEST_CONTAINERS: u64 = 1000;
    const PROPERTY_TEST_CONTAINERS: u64 = 30;
    const SEED: u64 = 0;

    fn test_input(seed: u64, containers: u64) -> FuzzInput {
        FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            partition: Partition::Connected,
            configuration: N6F1C5,
            required_containers: containers,
            degraded_network: false,
            strategy: StrategyChoice::AnyScope,
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_connected() {
        fuzz::fuzz::<MinimmitEd25519, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_secp256r1_connected() {
        fuzz::fuzz::<MinimmitSecp256r1, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minpk_connected() {
        fuzz::fuzz::<MinimmitBls12381MultisigMinPk, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minsig_connected() {
        fuzz::fuzz::<MinimmitBls12381MultisigMinSig, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minpk_connected() {
        fuzz::fuzz::<MinimmitBls12381MinPk, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minsig_connected() {
        fuzz::fuzz::<MinimmitBls12381MinSig, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    fn property_test_strategy() -> impl Strategy<Value = FuzzInput> {
        any::<u64>().prop_map(move |seed| test_input(seed, PROPERTY_TEST_CONTAINERS))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test_group("slow")]
        #[test]
        fn property_test_ed25519_connected(input in property_test_strategy()) {
            fuzz::fuzz::<MinimmitEd25519, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_secp256r1_connected(input in property_test_strategy()) {
            fuzz::fuzz::<MinimmitSecp256r1, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minpk_connected(input in property_test_strategy()) {
            fuzz::fuzz::<MinimmitBls12381MultisigMinPk, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minsig_connected(input in property_test_strategy()) {
            fuzz::fuzz::<MinimmitBls12381MultisigMinSig, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minpk_connected(input in property_test_strategy()) {
            fuzz::fuzz::<MinimmitBls12381MinPk, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minsig_connected(input in property_test_strategy()) {
            fuzz::fuzz::<MinimmitBls12381MinSig, Standard>(input);
        }
    }
}
