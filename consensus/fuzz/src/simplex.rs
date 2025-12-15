use commonware_codec::Read;
use commonware_consensus::simplex::{
    mocks::fixtures::{bls12381_multisig, bls12381_threshold, ed25519, Fixture},
    signing_scheme::{
        bls12381_multisig as multisig_scheme, bls12381_threshold as threshold_scheme,
        ed25519 as ed25519_scheme, Scheme as SimplexScheme,
    },
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_runtime::deterministic;

pub trait Simplex: 'static
where
    <<Self::Scheme as SimplexScheme>::Certificate as Read>::Cfg: Default,
{
    type Scheme: SimplexScheme<PublicKey = Ed25519PublicKey>;
    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme>;
}

pub struct SimplexEd25519;

impl Simplex for SimplexEd25519 {
    type Scheme = ed25519_scheme::Scheme;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        ed25519(context, n)
    }
}

pub struct SimplexBls12381MultisigMinPk;

impl Simplex for SimplexBls12381MultisigMinPk {
    type Scheme = multisig_scheme::Scheme<Ed25519PublicKey, MinPk>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls12381_multisig::<MinPk, _>(context, n)
    }
}

pub struct SimplexBls12381MultisigMinSig;

impl Simplex for SimplexBls12381MultisigMinSig {
    type Scheme = multisig_scheme::Scheme<Ed25519PublicKey, MinSig>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls12381_multisig::<MinSig, _>(context, n)
    }
}

pub struct SimplexBls12381MinPk;

impl Simplex for SimplexBls12381MinPk {
    type Scheme = threshold_scheme::Scheme<Ed25519PublicKey, MinPk>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls12381_threshold::<MinPk, _>(context, n)
    }
}

pub struct SimplexBls12381MinSig;

impl Simplex for SimplexBls12381MinSig {
    type Scheme = threshold_scheme::Scheme<Ed25519PublicKey, MinSig>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls12381_threshold::<MinSig, _>(context, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fuzz, utils::Partition, FuzzInput, N4C3F1};
    use commonware_macros::{test_group, test_traced};
    use proptest::prelude::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::cell::RefCell;

    const TEST_CONTAINERS: u64 = 1000;
    const PROPERTY_TEST_CONTAINERS: u64 = 30;

    fn test_input(containers: u64) -> FuzzInput {
        use rand::thread_rng;
        use std::env;

        // Check for seed from environment variable, otherwise use random
        let seed = env::var("FUZZ_SEED")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| thread_rng().next_u64());

        // Get pseudo-random bytes
        let mut seeded_rng = StdRng::seed_from_u64(seed);
        let mut raw_bytes = vec![0u8; 1024];
        seeded_rng.fill_bytes(&mut raw_bytes);

        FuzzInput {
            seed,
            partition: Partition::Connected,
            configuration: N4C3F1,
            raw_bytes,
            offset: RefCell::new(0),
            rng: RefCell::new(StdRng::seed_from_u64(seed)),
            required_containers: containers,
            degraded_network_node: false,
        }
    }

    fn property_test_strategy() -> impl Strategy<Value = FuzzInput> {
        any::<u64>().prop_map(move |seed| {
            let mut seeded_rng = StdRng::seed_from_u64(seed);
            let mut raw_bytes = vec![0u8; 1024];
            seeded_rng.fill_bytes(&mut raw_bytes);

            FuzzInput {
                seed,
                partition: Partition::Connected,
                configuration: N4C3F1,
                raw_bytes,
                offset: RefCell::new(0),
                rng: RefCell::new(StdRng::seed_from_u64(seed)),
                required_containers: PROPERTY_TEST_CONTAINERS,
                degraded_network_node: false,
            }
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_connected() {
        fuzz::<SimplexEd25519>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minpk_connected() {
        fuzz::<SimplexBls12381MultisigMinPk>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minsig_connected() {
        fuzz::<SimplexBls12381MultisigMinSig>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minpk_connected() {
        fuzz::<SimplexBls12381MinPk>(test_input(TEST_CONTAINERS));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minsig_connected() {
        fuzz::<SimplexBls12381MinSig>(test_input(TEST_CONTAINERS));
    }

    // Property-based test variants using proptest

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test_group("slow")]
        #[test]
        fn property_test_ed25519_connected(input in property_test_strategy()) {
            fuzz::<SimplexEd25519>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minpk_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MultisigMinPk>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minsig_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MultisigMinSig>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minpk_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MinPk>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minsig_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MinSig>(input);
        }
    }
}
