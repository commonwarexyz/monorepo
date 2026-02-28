use commonware_codec::Read;
use commonware_consensus::{
    elector::{Config as ElectorConfig, RoundRobin},
    simplex::scheme::{
        bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519, secp256r1,
        Scheme,
    },
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::{self, mocks::Fixture},
    ed25519::PublicKey as Ed25519PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_runtime::deterministic;

pub trait Simplex: 'static
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

pub struct SimplexEd25519;

impl Simplex for SimplexEd25519 {
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

pub struct SimplexBls12381MultisigMinPk;

impl Simplex for SimplexBls12381MultisigMinPk {
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

pub struct SimplexBls12381MultisigMinSig;

impl Simplex for SimplexBls12381MultisigMinSig {
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

pub struct SimplexBls12381MinPk;

impl Simplex for SimplexBls12381MinPk {
    type Scheme = bls12381_threshold_vrf::Scheme<Ed25519PublicKey, MinPk>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_threshold_vrf::fixture::<MinPk, _>(context, namespace, n)
    }
}

pub struct SimplexBls12381MinSig;

impl Simplex for SimplexBls12381MinSig {
    type Scheme = bls12381_threshold_vrf::Scheme<Ed25519PublicKey, MinSig>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_threshold_vrf::fixture::<MinSig, _>(context, namespace, n)
    }
}

pub struct SimplexSecp256r1;

impl Simplex for SimplexSecp256r1 {
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
    use crate::{fuzz, strategy::StrategyChoice, utils::Partition, FuzzInput, Standard, N4F1C3};
    use commonware_macros::{test_group, test_traced};
    use proptest::prelude::*;

    const TEST_CONTAINERS: u64 = 1000;
    const PROPERTY_TEST_CONTAINERS: u64 = 30;
    const SEED: u64 = 0;

    fn test_input(seed: u64, containers: u64) -> FuzzInput {
        FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            partition: Partition::Connected,
            configuration: N4F1C3,
            required_containers: containers,
            degraded_network: false,
            strategy: StrategyChoice::AnyScope,
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_connected() {
        fuzz::<SimplexEd25519, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_secp256r1_connected() {
        fuzz::<SimplexSecp256r1, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minpk_connected() {
        fuzz::<SimplexBls12381MultisigMinPk, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minsig_connected() {
        fuzz::<SimplexBls12381MultisigMinSig, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minpk_connected() {
        fuzz::<SimplexBls12381MinPk, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minsig_connected() {
        fuzz::<SimplexBls12381MinSig, Standard>(test_input(SEED, TEST_CONTAINERS));
    }

    fn property_test_strategy() -> impl Strategy<Value = FuzzInput> {
        any::<u64>().prop_map(move |seed| test_input(seed, PROPERTY_TEST_CONTAINERS))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test_group("slow")]
        #[test]
        fn property_test_ed25519_connected(input in property_test_strategy()) {
            fuzz::<SimplexEd25519, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_secp256r1_connected(input in property_test_strategy()) {
            fuzz::<SimplexSecp256r1, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minpk_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MultisigMinPk, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minsig_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MultisigMinSig, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minpk_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MinPk, Standard>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minsig_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MinSig, Standard>(input);
        }
    }
}
