use commonware_codec::Read;
use commonware_consensus::simplex::{
    elector::{Config as ElectorConfig, RoundRobin},
    scheme::{
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
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::cell::RefCell;

    const TEST_CONTAINERS: u64 = 1000;
    const DEFAULT_SEED: u64 = 0;

    fn test_input(containers: u64) -> FuzzInput {
        use std::env;

        // Use deterministic seed by default, allow override via environment variable
        let seed = env::var("FUZZ_SEED")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_SEED);

        // Get pseudo-random bytes
        let mut seeded_rng = StdRng::seed_from_u64(seed);
        let mut raw_bytes = vec![0u8; 1024];
        seeded_rng.fill_bytes(&mut raw_bytes);

        FuzzInput {
            seed,
            partition: Partition::Connected,
            configuration: N4F1C3,
            raw_bytes,
            offset: RefCell::new(0),
            rng: RefCell::new(StdRng::seed_from_u64(seed)),
            required_containers: containers,
            degraded_network: false,
            strategy: StrategyChoice::AnyScope,
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_connected() {
        fuzz::<SimplexEd25519, Standard>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_secp256r1_connected() {
        fuzz::<SimplexSecp256r1, Standard>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minpk_connected() {
        fuzz::<SimplexBls12381MultisigMinPk, Standard>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minsig_connected() {
        fuzz::<SimplexBls12381MultisigMinSig, Standard>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minpk_connected() {
        fuzz::<SimplexBls12381MinPk, Standard>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minsig_connected() {
        fuzz::<SimplexBls12381MinSig, Standard>(test_input(TEST_CONTAINERS));
    }
}
