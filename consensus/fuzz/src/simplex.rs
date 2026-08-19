#[cfg(feature = "mocks")]
use crate::simplex_certificate_mock as cert_mock;
use crate::{BYZANTINE_IDX, Configuration, N4F1C3, id_mock};
use commonware_codec::Read;
use commonware_consensus::{
    simplex::{
        elector::{Config as ElectorConfig, Elector, Random, RoundRobin, Terms},
        scheme::{
            Scheme, bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519,
            secp256r1,
        },
    },
    types::{Participant, Round, TermLength, View, ViewDelta},
};
use commonware_cryptography::{
    PublicKey, Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    certificate,
    ed25519::PublicKey as Ed25519PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_runtime::deterministic;
use std::time::Duration;

/// Returns a round-robin elector config for the fuzzed term length and
/// optimistic lookahead (ignored for single-view terms, where it is a no-op).
pub(crate) fn round_robin(term_length: TermLength, optimistic_views: ViewDelta) -> RoundRobin {
    if term_length.get() == 1 {
        RoundRobin::default()
    } else {
        RoundRobin::default().with_term(term_length, Duration::from_secs(12), optimistic_views)
    }
}

#[derive(Clone)]
pub struct ByzantineFirstLeaderRoundRobin {
    term_length: TermLength,
    optimistic_views: ViewDelta,
}

impl Default for ByzantineFirstLeaderRoundRobin {
    fn default() -> Self {
        Self {
            term_length: TermLength::ONE,
            optimistic_views: ViewDelta::zero(),
        }
    }
}

#[derive(Clone)]
pub struct ByzantineFirstLeaderElector<S: Scheme<Sha256Digest>> {
    fallback: <RoundRobin<Sha256> as ElectorConfig<S>>::Elector,
}

impl<S: Scheme<Sha256Digest>> ElectorConfig<S> for ByzantineFirstLeaderRoundRobin {
    type Elector = ByzantineFirstLeaderElector<S>;

    fn build(self, participants: &commonware_utils::ordered::Set<S::PublicKey>) -> Self::Elector {
        Self::Elector {
            fallback: round_robin(self.term_length, self.optimistic_views).build(participants),
        }
    }
}

impl<S: Scheme<Sha256Digest>> Elector<S> for ByzantineFirstLeaderElector<S> {
    fn terms(&self) -> Terms {
        self.fallback.terms()
    }

    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> Participant {
        if round.view().term_index(self.terms().length()) == 1 {
            return Participant::from_usize(BYZANTINE_IDX);
        }
        self.fallback.elect(round, certificate)
    }
}

#[derive(Clone)]
pub struct CustomRoundRobinShuffled {
    term_length: TermLength,
    optimistic_views: ViewDelta,
}

impl Default for CustomRoundRobinShuffled {
    fn default() -> Self {
        Self {
            term_length: TermLength::ONE,
            optimistic_views: ViewDelta::zero(),
        }
    }
}

impl<S: Scheme<Sha256Digest>> ElectorConfig<S> for CustomRoundRobinShuffled {
    type Elector = <RoundRobin<Sha256> as ElectorConfig<S>>::Elector;

    fn build(self, participants: &commonware_utils::ordered::Set<S::PublicKey>) -> Self::Elector {
        let seed = b"fuzz_shuffled_seed_round_robin";
        let config = RoundRobin::<Sha256>::shuffled(seed);
        let config = if self.term_length.get() == 1 {
            config
        } else {
            config.with_term(
                self.term_length,
                Duration::from_secs(12),
                self.optimistic_views,
            )
        };
        config.build(participants)
    }
}

#[derive(Clone)]
pub struct CustomRandomSelected;

impl Default for CustomRandomSelected {
    fn default() -> Self {
        Self
    }
}

impl<P: PublicKey, V: Variant> ElectorConfig<bls12381_threshold_vrf::Scheme<P, V>>
    for CustomRandomSelected
{
    type Elector = <Random as ElectorConfig<bls12381_threshold_vrf::Scheme<P, V>>>::Elector;

    fn build(self, participants: &commonware_utils::ordered::Set<P>) -> Self::Elector {
        Random.build(participants)
    }
}

pub trait Simplex: 'static
where
    <<Self::Scheme as certificate::Verifier>::Certificate as Read>::Cfg: Default,
{
    type Scheme: Scheme<Sha256Digest>;
    type Elector: ElectorConfig<Self::Scheme>;
    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector;

    /// Term length actually enforced by [`Self::elector`].
    ///
    /// Electors without stable-leader support (e.g. VRF-random selection)
    /// always rotate, so they report [`TermLength::ONE`] regardless of the
    /// fuzzed input; term-window invariants must use this value.
    fn effective_term_length(term_length: TermLength) -> TermLength {
        term_length
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    );

    /// A view whose leader is the configured Byzantine participant in the
    /// dedicated audit harness, if this instantiation has a statically known
    /// leader schedule. Returning `None` disables rejected-certification
    /// sampling for that instantiation.
    fn audit_rejection_view(_configuration: Configuration) -> Option<View> {
        None
    }
}

pub struct SimplexEd25519;

impl Simplex for SimplexEd25519 {
    type Scheme = ed25519::Scheme;
    type Elector = RoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = ed25519::fixture(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

pub struct SimplexId;

impl Simplex for SimplexId {
    type Scheme = id_mock::Scheme;

    type Elector = RoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        id_mock::fixture(context, namespace, n)
    }

    fn audit_rejection_view(configuration: Configuration) -> Option<View> {
        (configuration == N4F1C3).then(|| View::new(3))
    }
}

#[cfg(feature = "mocks")]
pub struct SimplexCertificateMock;

#[cfg(feature = "mocks")]
impl Simplex for SimplexCertificateMock {
    type Scheme = cert_mock::Scheme<Ed25519PublicKey, false>;

    type Elector = RoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = cert_mock::fixture_with::<false, true, true, _>(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }

    fn audit_rejection_view(configuration: Configuration) -> Option<View> {
        (configuration == N4F1C3).then(|| View::new(3))
    }
}

#[cfg(feature = "mocks")]
pub struct SimplexCertificateMockByzantineFirstLeader;

#[cfg(feature = "mocks")]
impl Simplex for SimplexCertificateMockByzantineFirstLeader {
    type Scheme = cert_mock::Scheme<Ed25519PublicKey, false>;

    type Elector = ByzantineFirstLeaderRoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        ByzantineFirstLeaderRoundRobin {
            term_length,
            optimistic_views,
        }
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = cert_mock::fixture_with::<false, true, true, _>(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }

    fn audit_rejection_view(configuration: Configuration) -> Option<View> {
        (configuration == N4F1C3).then(|| View::new(1))
    }
}

pub struct SimplexEd25519CustomRoundRobin;

impl Simplex for SimplexEd25519CustomRoundRobin {
    type Scheme = ed25519::Scheme;
    type Elector = CustomRoundRobinShuffled;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        CustomRoundRobinShuffled {
            term_length,
            optimistic_views,
        }
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = ed25519::fixture(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

pub struct SimplexBls12381MultisigMinPk;

impl Simplex for SimplexBls12381MultisigMinPk {
    type Scheme = bls12381_multisig::Scheme<Ed25519PublicKey, MinPk>;
    type Elector = RoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = bls12381_multisig::fixture::<MinPk, _>(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

pub struct SimplexBls12381MultisigMinSig;

impl Simplex for SimplexBls12381MultisigMinSig {
    type Scheme = bls12381_multisig::Scheme<Ed25519PublicKey, MinSig>;
    type Elector = RoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = bls12381_multisig::fixture::<MinSig, _>(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

pub struct SimplexBls12381MinPk;

impl Simplex for SimplexBls12381MinPk {
    type Scheme = bls12381_threshold_vrf::Scheme<Ed25519PublicKey, MinPk>;
    type Elector = RoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = bls12381_threshold_vrf::fixture::<MinPk, _>(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

pub struct SimplexBls12381MinPkCustomRandom;

impl Simplex for SimplexBls12381MinPkCustomRandom {
    type Scheme = bls12381_threshold_vrf::Scheme<Ed25519PublicKey, MinPk>;
    type Elector = CustomRandomSelected;

    fn elector(_term_length: TermLength, _optimistic_views: ViewDelta) -> Self::Elector {
        CustomRandomSelected
    }

    fn effective_term_length(_term_length: TermLength) -> TermLength {
        TermLength::ONE
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = bls12381_threshold_vrf::fixture::<MinPk, _>(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

pub struct SimplexBls12381MinSig;

impl Simplex for SimplexBls12381MinSig {
    type Scheme = bls12381_threshold_vrf::Scheme<Ed25519PublicKey, MinSig>;
    type Elector = Random;

    fn elector(_term_length: TermLength, _optimistic_views: ViewDelta) -> Self::Elector {
        Random
    }

    fn effective_term_length(_term_length: TermLength) -> TermLength {
        TermLength::ONE
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = bls12381_threshold_vrf::fixture::<MinSig, _>(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

pub struct SimplexSecp256r1;

impl Simplex for SimplexSecp256r1 {
    type Scheme = secp256r1::Scheme<Ed25519PublicKey>;
    type Elector = RoundRobin;

    fn elector(term_length: TermLength, optimistic_views: ViewDelta) -> Self::Elector {
        round_robin(term_length, optimistic_views)
    }

    fn setup(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> (
        Vec<<Self::Scheme as certificate::Verifier>::PublicKey>,
        Vec<Self::Scheme>,
    ) {
        let fixture = secp256r1::fixture(context, namespace, n);
        (fixture.participants, fixture.schemes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BYZANTINE_IDX, BlockFilterChoice, CertifyChoice, CodeCoverage, FaultyMessaging, FuzzInput,
        N4F1C3, ReporterWiring, Standard, TwinsMutator, fuzz, strategy::StrategyChoice,
        utils::Partition,
    };
    use commonware_consensus::{
        simplex::{ForwardingPolicy, mocks::application::Certifier},
        types::{Epoch, Round, TermLength, ViewDelta},
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_utils::{NZU32, TryCollect, ordered::Set};
    use proptest::prelude::*;

    const TEST_CONTAINERS: u64 = 1000;
    const PROPERTY_TEST_CONTAINERS: u64 = 30;
    const TERM_LENGTH_BOUNDARIES: [TermLength; 2] = [TermLength::ONE, TermLength::new(NZU32!(5))];
    const SEED: u64 = 0;

    #[test]
    fn certify_choice_single_cancel_targets_only_idx() {
        let c0 = CertifyChoice::SingleCancel { target_idx: 1 }.into_certifier(1);
        assert!(matches!(c0, Certifier::Cancel));
        let c1 = CertifyChoice::SingleCancel { target_idx: 1 }.into_certifier(0);
        assert!(matches!(c1, Certifier::Always));
    }

    #[test]
    fn certify_choice_single_pending_targets_only_idx() {
        let c0 = CertifyChoice::SinglePending { target_idx: 2 }.into_certifier(2);
        assert!(matches!(c0, Certifier::Pending));
        let c1 = CertifyChoice::SinglePending { target_idx: 2 }.into_certifier(3);
        assert!(matches!(c1, Certifier::Always));
    }

    #[test]
    fn certify_choice_reject_view_is_consistent_across_validators() {
        let choice = CertifyChoice::RejectView {
            view: commonware_consensus::types::View::new(5),
        };
        for validator_idx in [0, 3] {
            let Certifier::Custom(certify) = choice.into_certifier(validator_idx) else {
                panic!("RejectView must construct a custom certifier");
            };
            let result = |view| {
                certify(
                    commonware_consensus::types::Round::new(
                        commonware_consensus::types::Epoch::new(crate::EPOCH),
                        commonware_consensus::types::View::new(view),
                    ),
                    Sha256Digest([0; 32]),
                )
            };
            assert!(!result(5));
            assert!(result(6));
        }
    }

    #[test]
    fn byzantine_first_leader_round_robin_pins_first_stable_term() {
        let participants = (0..4)
            .map(id_mock::PublicKey::from_index)
            .try_collect::<Set<_>>()
            .expect("public keys are unique");
        let term_length = TermLength::new(NZU32!(2));
        let elector: ByzantineFirstLeaderElector<id_mock::Scheme> =
            ByzantineFirstLeaderRoundRobin {
                term_length,
                optimistic_views: ViewDelta::zero(),
            }
            .build(&participants);

        assert_eq!(
            elector
                .elect(Round::new(Epoch::new(crate::EPOCH), View::new(1)), None)
                .get() as usize,
            BYZANTINE_IDX
        );
        assert_eq!(
            elector
                .elect(Round::new(Epoch::new(crate::EPOCH), View::new(2)), None)
                .get() as usize,
            BYZANTINE_IDX
        );
        assert_ne!(
            elector
                .elect(Round::new(Epoch::new(crate::EPOCH), View::new(3)), None)
                .get() as usize,
            BYZANTINE_IDX
        );
    }

    fn test_input(seed: u64, containers: u64, term_length: TermLength) -> FuzzInput {
        FuzzInput {
            raw_bytes: seed.to_be_bytes().to_vec(),
            partition: Partition::Connected,
            configuration: N4F1C3,
            required_containers: containers,
            term_length,
            optimistic_views: ViewDelta::new(term_length.get()),
            heterogeneous_optimism: true,
            degraded_network: false,
            strategy: StrategyChoice::AnyScope,
            messaging_faults: Vec::new(),
            mailbox_size: crate::DEFAULT_MAILBOX_SIZE,
            forwarding: ForwardingPolicy::Disabled,
            certify: CertifyChoice::Always,
            block_filter: BlockFilterChoice::None,
            reporting: ReporterWiring::Solo,
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_connected() {
        fuzz::<SimplexEd25519, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_faulty_messaging_connected() {
        fuzz::<SimplexEd25519, FaultyMessaging, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_twin_connected() {
        fuzz::<SimplexEd25519, TwinsMutator, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_shuffled_connected() {
        fuzz::<SimplexEd25519CustomRoundRobin, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_ed25519_stable_leader_connected() {
        // Multi-view terms exercise the stable-leader path, unlike the
        // TermLength::ONE tests above.
        fuzz::<SimplexEd25519, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::new(NZU32!(5)),
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_secp256r1_connected() {
        fuzz::<SimplexSecp256r1, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minpk_connected() {
        fuzz::<SimplexBls12381MultisigMinPk, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_multisig_minsig_connected() {
        fuzz::<SimplexBls12381MultisigMinSig, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minpk_connected() {
        fuzz::<SimplexBls12381MinPk, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_selected_minpk_connected() {
        fuzz::<SimplexBls12381MinPkCustomRandom, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_bls12381_threshold_minsig_connected() {
        fuzz::<SimplexBls12381MinSig, Standard, CodeCoverage>(test_input(
            SEED,
            TEST_CONTAINERS,
            TermLength::ONE,
        ));
    }

    fn property_test_strategy() -> impl Strategy<Value = FuzzInput> {
        (
            any::<u64>(),
            prop::sample::select(TERM_LENGTH_BOUNDARIES.as_slice()),
        )
            .prop_map(move |(seed, term_length)| {
                test_input(seed, PROPERTY_TEST_CONTAINERS, term_length)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test_group("slow")]
        #[test]
        fn property_test_ed25519_connected(input in property_test_strategy()) {
            fuzz::<SimplexEd25519, Standard, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_ed25519_faulty_messaging_connected(input in property_test_strategy()) {
            fuzz::<SimplexEd25519, FaultyMessaging, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_ed25519_twins_mutator_connected(input in property_test_strategy()) {
            fuzz::<SimplexEd25519, TwinsMutator, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_ed25519_shuffled_twins_mutator_connected(input in property_test_strategy()) {
            fuzz::<SimplexEd25519CustomRoundRobin, TwinsMutator, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_secp256r1_connected(input in property_test_strategy()) {
            fuzz::<SimplexSecp256r1, Standard, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minpk_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MultisigMinPk, Standard, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_multisig_minsig_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MultisigMinSig, Standard, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minpk_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MinPk, Standard, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_selected_minpk_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MinPkCustomRandom, Standard, CodeCoverage>(input);
        }

        #[test_group("slow")]
        #[test]
        fn property_test_bls12381_threshold_minsig_connected(input in property_test_strategy()) {
            fuzz::<SimplexBls12381MinSig, Standard, CodeCoverage>(input);
        }
    }
}
