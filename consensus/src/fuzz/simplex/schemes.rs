use crate::{
    simplex::{
        elector::{self, RoundRobin},
        scheme::{
            Scheme, bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519,
            secp256r1,
        },
    },
    types::{TermLength, ViewDelta},
};
use commonware_codec::Read;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::{self, mocks::Fixture},
    ed25519::PublicKey as Ed25519PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_runtime::deterministic;
use std::time::Duration;

/// Returns a round-robin elector config for the fuzzed term length and
/// optimistic lookahead (ignored for single-view terms, where it is a no-op).
fn round_robin(term_length: TermLength, optimistic_views: ViewDelta) -> RoundRobin {
    if term_length.get() == 1 {
        RoundRobin::default()
    } else {
        RoundRobin::default().with_term(term_length, Duration::from_secs(12), optimistic_views)
    }
}

pub trait Simplex: 'static
where
    <<Self::Scheme as certificate::Verifier>::Certificate as Read>::Cfg: Default,
{
    type Scheme: Scheme<Sha256Digest, PublicKey = Ed25519PublicKey>;
    type Elector: elector::Config<Self::Scheme>;
    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector;
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

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

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

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

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

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

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

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

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

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

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

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

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
    use super::super::{
        FuzzInput, HANDOFF_DECISIONS, Mode, Scheme,
        connected::{ConnectedPlan, TERM_LENGTH_BOUNDARIES, connected_input},
    };
    use crate::{
        Handoff,
        fuzz::Plan,
        types::{TermLength, ViewDelta},
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_macros::{test_group, test_traced};
    use commonware_utils::NZU32;

    const TEST_CONTAINERS: u64 = 1000;
    const SEED: u64 = 0;

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_connected() {
        Scheme::Ed25519.run(
            connected_input(SEED, TEST_CONTAINERS, TermLength::ONE),
            Mode::Standard,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_stable_leader_connected() {
        // Multi-view terms with a small optimistic-view budget exercise the
        // stable-leader path, unlike the TermLength::ONE tests above.
        let input = FuzzInput {
            optimistic_views: ViewDelta::new(2),
            ..connected_input(SEED, TEST_CONTAINERS, TermLength::new(NZU32!(5)))
        };
        Scheme::Ed25519.run(input, Mode::Standard);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_secp256r1_connected() {
        Scheme::Secp256r1.run(
            connected_input(SEED, TEST_CONTAINERS, TermLength::ONE),
            Mode::Standard,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minpk_connected() {
        Scheme::MultisigMinPk.run(
            connected_input(SEED, TEST_CONTAINERS, TermLength::ONE),
            Mode::Standard,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minsig_connected() {
        Scheme::MultisigMinSig.run(
            connected_input(SEED, TEST_CONTAINERS, TermLength::ONE),
            Mode::Standard,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minpk_connected() {
        Scheme::ThresholdMinPk.run(
            connected_input(SEED, TEST_CONTAINERS, TermLength::ONE),
            Mode::Standard,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minsig_connected() {
        Scheme::ThresholdMinSig.run(
            connected_input(SEED, TEST_CONTAINERS, TermLength::ONE),
            Mode::Standard,
        );
    }

    #[test_group("slow")]
    #[test]
    fn test_connected_boundaries() {
        let run_all = |plan: ConnectedPlan| {
            for scheme in Scheme::ALL {
                Plan::connected(scheme, plan)
                    .run(&mut Unstructured::new(&[]))
                    .unwrap();
            }
        };

        // Replay the historical failure at both single-view and multi-view term lengths.
        for term_length in TERM_LENGTH_BOUNDARIES {
            run_all(ConnectedPlan {
                seed: 11_990_182_099_415_019_554,
                term_length,
                handoff: Handoff::Wait,
            });
        }

        // The regression shrank to eight zero bytes. Exercise every term
        // length and handoff on that seed, including its original single-view case.
        for term_length in TERM_LENGTH_BOUNDARIES {
            for handoff in HANDOFF_DECISIONS {
                run_all(ConnectedPlan {
                    seed: SEED,
                    term_length,
                    handoff,
                });
            }
        }
    }

    fn minifuzz_connected(scheme: Scheme) {
        minifuzz::Builder::default()
            .with_search_limit(100)
            .test(|u| Plan::connected(scheme, u.arbitrary()?).run(u));
    }

    #[test_group("slow")]
    #[test]
    fn minifuzz_ed25519_connected() {
        minifuzz_connected(Scheme::Ed25519);
    }

    #[test_group("slow")]
    #[test]
    fn minifuzz_secp256r1_connected() {
        minifuzz_connected(Scheme::Secp256r1);
    }

    #[test_group("slow")]
    #[test]
    fn minifuzz_bls12381_multisig_minpk_connected() {
        minifuzz_connected(Scheme::MultisigMinPk);
    }

    #[test_group("slow")]
    #[test]
    fn minifuzz_bls12381_multisig_minsig_connected() {
        minifuzz_connected(Scheme::MultisigMinSig);
    }

    #[test_group("slow")]
    #[test]
    fn minifuzz_bls12381_threshold_minpk_connected() {
        minifuzz_connected(Scheme::ThresholdMinPk);
    }

    #[test_group("slow")]
    #[test]
    fn minifuzz_bls12381_threshold_minsig_connected() {
        minifuzz_connected(Scheme::ThresholdMinSig);
    }
}
