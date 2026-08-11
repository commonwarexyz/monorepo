//! End-to-end Simplex Twins mutators over standard and coding marshal.
//!
//! The compromised identity runs one full Simplex engine plus a Byzantine
//! secondary with the same signing key. Their vote, certificate, and resolver
//! channels are split by the shared Twins helpers. Every correct engine and the
//! compromised primary use a real marshal/application data path. Standard
//! selects an Inline or Deferred wrapper and uses the general Disrupter;
//! coding uses Marshaled directly and a Commitment-typed double-voter.

mod coding;
mod layout;
mod observer;
pub(crate) mod stack;

use super::{
    app::{
        AlwaysAcceptBlockBuilderApp, ApplicationChoice, BlockContextRegistry, DeliveryReporter,
        FaultyConfig, SelectedBlockBuilderApp,
    },
    input::MarshalTwinsInput,
    invariants::{self, CertificationAgreementInvariant, HeaderMismatchInvariant},
};
use crate::{
    NAMESPACE, NetworkChannels, SimplexCertificateMock, SimplexId, TwinsBackend, TwinsCase,
    TwinsDisrupter, TwinsSetup, TwinsTopology, run_twins_with_backend, simplex::Simplex,
    strategy::StrategyChoice,
};
pub use coding::fuzz_marshal_coding_twins;
use commonware_consensus::{
    marshal::mocks::{
        application::Application, block::Block as MockBlock, harness::NUM_VALIDATORS,
    },
    simplex::{mocks::twins, types::Context as SimplexContext},
    types::{Epoch, TermLength, View},
};
use commonware_cryptography::{
    Digestible, certificate::ConstantProvider, sha256::Digest as Sha256Digest,
};
use commonware_p2p::{Receiver, Sender, simulated::Oracle};
use commonware_runtime::{Runner, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize, sync::Mutex};
use layout::{AttackLayout, attack_layout};
pub(crate) use observer::ObservedMarshal;
use stack::{
    ATTACK_SLOW_VERIFY_DELAY, ATTACK_VICTIM_VERIFY_DELAY, DEFAULT_MAX_PENDING_ACKS,
    DeferredMarshal, InlineMarshal, MarshalChoice, SelectedMarshal, TwinsBlockBuilder,
    TwinsMarshal, Validator, genesis_block, register_engine_networks, setup_network,
    setup_network_links, setup_validator, start_engine, wait_for_liveness,
};
use std::{
    collections::HashMap,
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Opt-in ground-truth probe for header-context mismatches.
static VERIFY_PROBE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("MARSHAL_TWINS_PROBE").is_ok());
static SKIPPED_CASES: AtomicUsize = AtomicUsize::new(0);
static EXECUTED_CASES: AtomicUsize = AtomicUsize::new(0);

const MAX_CASES: usize = 64;
const ATTACK_MAX_CASES: usize = 2048;
const CASE_REPORT_INTERVAL: usize = 1024;
const DEEP_PENDING_ACKS: NonZeroUsize = NZUsize!(8);

fn pending_ack_invariant_limit(max_pending_acks: NonZeroUsize) -> Option<NonZeroUsize> {
    (max_pending_acks <= DEEP_PENDING_ACKS).then_some(max_pending_acks)
}

fn record_case_outcome(was_executed: bool, stack: &str) {
    let counter = if was_executed {
        &EXECUTED_CASES
    } else {
        &SKIPPED_CASES
    };
    counter.fetch_add(1, Ordering::Relaxed);
    let executed = EXECUTED_CASES.load(Ordering::Relaxed);
    let skipped = SKIPPED_CASES.load(Ordering::Relaxed);
    let total = executed.saturating_add(skipped);
    if (was_executed || skipped != 1) && !total.is_multiple_of(CASE_REPORT_INTERVAL) {
        return;
    }
    eprintln!(
        "[marshal-twins] case coverage: executed={executed} skipped={skipped} \
         skip_ratio={:.2}% stack={stack}",
        (skipped as f64 / total.max(1) as f64) * 100.0,
    );
}

struct MarshalTwinsInputDebug<'a>(&'a MarshalTwinsInput);

impl fmt::Debug for MarshalTwinsInputDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let input = self.0;
        f.debug_struct("MarshalTwinsInput")
            .field("raw_bytes_len", &input.raw_bytes.len())
            .field("rounds", &input.rounds)
            .field("case_selector", &input.case_selector)
            .field("sustained", &input.sustained)
            .field("strategy", &input.strategy)
            .field("trailing_blocks", &input.trailing_blocks)
            .field("forwarding", &input.forwarding)
            .finish()
    }
}

pub(crate) type SchemeOf<P> = <P as Simplex>::Scheme;
pub(crate) type PublicKeyOf<P> =
    <<P as Simplex>::Scheme as commonware_cryptography::certificate::Verifier>::PublicKey;
pub(crate) type Ctx<P> = SimplexContext<Sha256Digest, PublicKeyOf<P>>;
pub(crate) type B<P> = MockBlock<Sha256Digest, Ctx<P>>;
type PrimaryApp<P> = AlwaysAcceptBlockBuilderApp<Ctx<P>, SchemeOf<P>>;
type BackendMarker<P, A, M> = std::marker::PhantomData<fn() -> (P, A, M)>;

#[derive(Clone, Copy)]
enum CasePolicy {
    General,
    AttackLayout,
}

#[derive(Clone, Copy)]
struct StackSelection {
    application: ApplicationChoice,
    marshal: MarshalChoice,
    max_pending_acks: NonZeroUsize,
}

struct MarshalTwinsBackend<P: Simplex, A: TwinsBlockBuilder<P>, M> {
    input: MarshalTwinsInput,
    probe_input: Arc<str>,
    app_config: FaultyConfig,
    application_choice: ApplicationChoice,
    marshal_choice: MarshalChoice,
    stack_label: Arc<str>,
    case_policy: CasePolicy,
    max_pending_acks: NonZeroUsize,
    _marker: BackendMarker<P, A, M>,
}

struct MarshalTwinsState<P: Simplex> {
    validators: Vec<Validator<P>>,
    honest: Vec<(usize, Application<B<P>>)>,
    primaries: Vec<(usize, Application<B<P>>)>,
    certification_agreement: CertificationAgreementInvariant,
    block_contexts: BlockContextRegistry<Ctx<P>>,
    genesis: Sha256Digest,
}

impl<P: Simplex, A: TwinsBlockBuilder<P>, M> MarshalTwinsBackend<P, A, M> {
    fn new(
        input: MarshalTwinsInput,
        probe_input: Arc<str>,
        case_policy: CasePolicy,
        selection: StackSelection,
        stack_label: Arc<str>,
        entropy: Vec<u8>,
    ) -> Self {
        let fault_injection_rounds = if matches!(case_policy, CasePolicy::AttackLayout) {
            input.rounds.max(4)
        } else {
            input.rounds
        };
        let mut rng = FuzzRng::new(entropy);
        let app_config = FaultyConfig::new(&mut rng, View::new(fault_injection_rounds.into()));
        Self {
            input,
            probe_input,
            app_config,
            application_choice: selection.application,
            marshal_choice: selection.marshal,
            stack_label,
            case_policy,
            max_pending_acks: selection.max_pending_acks,
            _marker: std::marker::PhantomData,
        }
    }

    fn uses_attack_layout(&self) -> bool {
        matches!(self.case_policy, CasePolicy::AttackLayout)
    }

    fn pending_ack_invariant_limit(&self) -> Option<NonZeroUsize> {
        pending_ack_invariant_limit(self.max_pending_acks)
    }

    fn report_empty_case(&self, reason: &str) {
        record_case_outcome(false, &self.stack_label);
        if *VERIFY_PROBE {
            panic!(
                "marshal Twins generated no eligible case: reason={reason} policy={} \
                 strategy={:?} stack={} input={}",
                if self.uses_attack_layout() {
                    "attack-layout"
                } else {
                    "general"
                },
                self.input.strategy,
                self.stack_label,
                self.probe_input,
            );
        }
    }
}

impl<P, A, M> TwinsBackend<P> for MarshalTwinsBackend<P, A, M>
where
    P: Simplex,
    A: TwinsBlockBuilder<P>,
    M: TwinsMarshal<P, A> + TwinsMarshal<P, PrimaryApp<P>>,
{
    type State = MarshalTwinsState<P>;
    type Case = Option<AttackLayout>;
    type Digest = Sha256Digest;

    async fn setup(&mut self, context: &mut deterministic::Context) -> TwinsSetup<P, Self::State> {
        let (participants, schemes) = P::setup(context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
        setup_network_links::<P>(&mut oracle, &participants).await;
        let genesis_block = genesis_block::<P>(participants[0].clone());
        let genesis = genesis_block.digest();
        let block_contexts = BlockContextRegistry::default();
        block_contexts.record(genesis, genesis_block.context.clone());
        let mut validators = Vec::with_capacity(participants.len());
        let mut registrations = HashMap::with_capacity(participants.len());
        for (idx, validator) in participants.iter().enumerate() {
            let setup = setup_validator::<P>(
                context
                    .child("validator")
                    .with_attribute("index", idx)
                    .child("marshal"),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[idx].clone()),
                genesis_block.clone(),
                self.max_pending_acks,
                None,
            )
            .await;
            let networks = register_engine_networks::<P>(&oracle, validator.clone()).await;
            validators.push(setup);
            registrations.insert(validator.clone(), networks);
        }
        TwinsSetup {
            oracle,
            participants,
            schemes,
            registrations,
            state: MarshalTwinsState {
                validators,
                honest: Vec::with_capacity(NUM_VALIDATORS as usize - 1),
                primaries: Vec::new(),
                certification_agreement: CertificationAgreementInvariant::new(
                    self.stack_label.clone(),
                    self.marshal_choice,
                ),
                block_contexts,
                genesis,
            },
        }
    }

    fn term_length(&self) -> TermLength {
        TermLength::ONE
    }

    fn framework(&mut self, _rng: &mut FuzzRng, participants: usize) -> twins::Framework {
        let uses_attack_layout = self.uses_attack_layout();
        twins::Framework {
            participants,
            faults: 1,
            rounds: if uses_attack_layout {
                self.input.rounds.max(4).into()
            } else {
                self.input.rounds.into()
            },
            mode: if uses_attack_layout || !self.input.sustained {
                twins::Mode::Sampled
            } else {
                twins::Mode::Sustained
            },
            max_cases: if uses_attack_layout {
                ATTACK_MAX_CASES
            } else {
                MAX_CASES
            },
        }
    }

    fn select_case(
        &mut self,
        rng: &mut FuzzRng,
        participants: &[PublicKeyOf<P>],
        cases: Vec<twins::Case>,
    ) -> Option<TwinsCase<Self::Case>> {
        let (case, attack) = if self.uses_attack_layout() {
            let eligible = |cases: Vec<twins::Case>| {
                cases
                    .into_iter()
                    .filter_map(|case| {
                        let byzantine = *case.compromised.first()?;
                        attack_layout::<P>(&case.scenario, participants, byzantine)
                            .map(|layout| (case, layout))
                    })
                    .collect::<Vec<_>>()
            };
            let mut attack_cases = eligible(cases);
            if attack_cases.is_empty() {
                let framework = self.framework(rng, participants.len());
                attack_cases = eligible(twins::cases(rng, framework));
            }
            let count = attack_cases.len();
            if count == 0 {
                self.report_empty_case(
                    "neither generated scenario sample contains an AttackLayout",
                );
                return None;
            }
            let (case, layout) = attack_cases
                .into_iter()
                .nth(usize::from(self.input.case_selector) % count)
                .expect("selected AttackLayout case must exist");
            (case, Some(layout))
        } else {
            if cases.is_empty() {
                self.report_empty_case("no generated Twins case");
                return None;
            }
            let count = cases.len();
            let case = cases
                .into_iter()
                .nth(usize::from(self.input.case_selector) % count)
                .expect("selected general case must exist");
            (case, None)
        };
        record_case_outcome(true, &self.stack_label);
        if *VERIFY_PROBE && let Some(layout) = attack {
            eprintln!(
                "[marshal-twins] attack layout: precursor={} attack={} victim={} slow={} fast={} \
                 slow_delay_ms={} victim_delay_ms={} stack={}",
                layout.precursor_view,
                layout.attack_view,
                layout.victim,
                layout.slow,
                layout.fast,
                ATTACK_SLOW_VERIFY_DELAY.as_millis(),
                ATTACK_VICTIM_VERIFY_DELAY.as_millis(),
                self.stack_label,
            );
        }
        Some(TwinsCase {
            scenario: case.scenario,
            compromised: case.compromised,
            data: attack,
        })
    }

    fn spawn_primary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        _participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        vote: (
            impl Sender<PublicKey = PublicKeyOf<P>>,
            impl Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl Sender<PublicKey = PublicKeyOf<P>>,
            impl Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKeyOf<P>>,
            impl Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) {
        let primary_builder = <M as TwinsMarshal<P, PrimaryApp<P>>>::create(
            self.marshal_choice,
            &context,
            AlwaysAcceptBlockBuilderApp::<Ctx<P>, SchemeOf<P>>::default()
                .with_block_contexts(state.block_contexts.clone())
                .with_reporter(DeliveryReporter::new(
                    idx,
                    state.validators[idx].application.clone(),
                    self.pending_ack_invariant_limit(),
                    self.stack_label.clone(),
                )),
            state.validators[idx].mailbox.clone(),
        );
        state.validators[idx].start(primary_builder.clone());
        state
            .primaries
            .push((idx, state.validators[idx].application.clone()));
        start_engine::<P, _, _, _>(
            context,
            oracle,
            validator,
            scheme,
            topology.elector.clone(),
            primary_builder.clone(),
            primary_builder,
            state.validators[idx].mailbox.clone(),
            state.genesis,
            "marshal-twins-primary".into(),
            self.input.forwarding,
            vote,
            certificate,
            resolver,
        );
    }

    fn disrupter(&self) -> Option<TwinsDisrupter> {
        Some(TwinsDisrupter {
            strategy: self.input.strategy,
            required_containers: self.input.rounds.into(),
            epoch: Epoch::zero(),
        })
    }

    fn spawn_honest(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        _participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        channels: NetworkChannels<PublicKeyOf<P>>,
    ) {
        let verification_delay = match topology.data {
            Some(layout) if layout.slow == idx => {
                Some((layout.precursor_view, ATTACK_SLOW_VERIFY_DELAY))
            }
            Some(layout) if layout.victim == idx => {
                Some((layout.precursor_view, ATTACK_VICTIM_VERIFY_DELAY))
            }
            _ => None,
        };
        let application = A::create(
            self.application_choice,
            self.app_config,
            verification_delay,
            state.block_contexts.clone(),
            DeliveryReporter::new(
                idx,
                state.validators[idx].application.clone(),
                self.pending_ack_invariant_limit(),
                self.stack_label.clone(),
            ),
        );
        let builder = <M as TwinsMarshal<P, A>>::create(
            self.marshal_choice,
            &context,
            application,
            state.validators[idx].mailbox.clone(),
        );
        state.validators[idx].start(builder.clone());
        state
            .honest
            .push((idx, state.validators[idx].application.clone()));
        let observed: ObservedMarshal<P, <M as TwinsMarshal<P, A>>::Wrapper> = ObservedMarshal {
            validator: idx,
            probe_input: self.probe_input.clone(),
            context: Arc::new(Mutex::new(context.child("automaton_invariants"))),
            inner: builder.clone(),
            certification_agreement: state.certification_agreement.clone(),
            header_mismatch: HeaderMismatchInvariant::new(
                self.application_choice,
                self.app_config,
                A::rejects,
                state.block_contexts.clone(),
                self.marshal_choice,
                self.stack_label.clone(),
            ),
        };
        start_engine::<P, _, _, _>(
            context.child("honest"),
            oracle,
            validator,
            scheme,
            topology.elector.clone(),
            observed,
            builder,
            state.validators[idx].mailbox.clone(),
            state.genesis,
            format!("marshal-twins-honest-{idx}"),
            self.input.forwarding,
            channels.0,
            channels.1,
            channels.2,
        );
    }

    async fn observe_liveness(
        &mut self,
        context: &deterministic::Context,
        state: &mut Self::State,
        prefix_end: View,
    ) {
        wait_for_liveness(
            context,
            &state.honest,
            prefix_end,
            self.input.trailing_blocks.into(),
            self.stack_label.clone(),
        )
        .await;
    }

    fn check_invariants(
        &mut self,
        _context: &deterministic::Context,
        state: &mut Self::State,
        _topology: &TwinsTopology<P, Self::Case>,
    ) {
        for (idx, application) in &state.primaries {
            invariants::check_local_blocks(*idx, application, state.genesis, &self.stack_label);
        }
        invariants::check_all_blocks(&state.honest, state.genesis, Some(&self.stack_label));
    }
}

/// Crypto: `SimplexCertificateMock`. Marshal: standard, wrapper from fuzz
/// input. Cluster: `N4F1C3` Twins, general campaign. Liveness: checked.
/// App: from fuzz input (always-accept or faulty).
pub fn fuzz_marshal_standard_twins(input: MarshalTwinsInput) {
    let (selection, entropy) = select_general_stack(&input.raw_bytes);
    fuzz_marshal_twins_with::<
        SimplexCertificateMock,
        SelectedBlockBuilderApp<Ctx<SimplexCertificateMock>, SchemeOf<SimplexCertificateMock>>,
        SelectedMarshal,
    >(input, CasePolicy::General, selection, entropy);
}

/// Crypto: `SimplexId`. Marshal: standard, deferred. Cluster: `N4F1C3` Twins,
/// `SplitHeader` strategy. Liveness: checked. App: fixed always-accept.
pub fn fuzz_marshal_standard_deferred_id_twins_split_header(mut input: MarshalTwinsInput) {
    input.strategy = StrategyChoice::SplitHeader {
        fault_rounds: input.rounds.into(),
        fault_rounds_bound: input.rounds.into(),
    };
    fuzz_marshal_twins_with::<
        SimplexId,
        AlwaysAcceptBlockBuilderApp<Ctx<SimplexId>, SchemeOf<SimplexId>>,
        DeferredMarshal,
    >(
        input.clone(),
        CasePolicy::AttackLayout,
        StackSelection {
            application: ApplicationChoice::AlwaysAccept,
            marshal: MarshalChoice::Deferred,
            max_pending_acks: NZUsize!(2),
        },
        input.raw_bytes,
    );
}

/// Crypto: `SimplexId`. Marshal: standard, inline. Cluster: `N4F1C3` Twins,
/// `SplitHeader` strategy. Liveness: checked. App: fixed always-accept.
/// Inline certification structurally returns true, so this target covers the
/// verify-side split-header invariant, not certification poisoning.
pub fn fuzz_marshal_standard_inline_id_twins_split_header(mut input: MarshalTwinsInput) {
    input.strategy = StrategyChoice::SplitHeader {
        fault_rounds: input.rounds.into(),
        fault_rounds_bound: input.rounds.into(),
    };
    fuzz_marshal_twins_with::<
        SimplexId,
        AlwaysAcceptBlockBuilderApp<Ctx<SimplexId>, SchemeOf<SimplexId>>,
        InlineMarshal,
    >(
        input.clone(),
        CasePolicy::AttackLayout,
        StackSelection {
            application: ApplicationChoice::AlwaysAccept,
            marshal: MarshalChoice::Inline,
            max_pending_acks: NZUsize!(2),
        },
        input.raw_bytes,
    );
}

fn select_general_stack(raw_bytes: &[u8]) -> (StackSelection, Vec<u8>) {
    let Some((&selector, entropy)) = raw_bytes.split_last() else {
        return (
            StackSelection {
                application: ApplicationChoice::AlwaysAccept,
                marshal: MarshalChoice::Deferred,
                max_pending_acks: NZUsize!(2),
            },
            vec![0],
        );
    };
    // Keep application, wrapper, and acknowledgement depth independent while
    // preserving the remaining bytes as identical scenario/runtime entropy.
    let application = ApplicationChoice::from_selector(selector);
    let wrapper = if selector & 0b10 == 0 {
        MarshalChoice::Deferred
    } else {
        MarshalChoice::Inline
    };
    let max_pending_acks = match (selector >> 2) & 0b11 {
        0 => NZUsize!(1),
        1 => NZUsize!(2),
        2 => DEEP_PENDING_ACKS,
        _ => DEFAULT_MAX_PENDING_ACKS,
    };
    let entropy = if entropy.is_empty() {
        vec![0]
    } else {
        entropy.to_vec()
    };
    (
        StackSelection {
            application,
            marshal: wrapper,
            max_pending_acks,
        },
        entropy,
    )
}

fn fuzz_marshal_twins_with<P, A, M>(
    input: MarshalTwinsInput,
    case_policy: CasePolicy,
    selection: StackSelection,
    entropy: Vec<u8>,
) where
    P: Simplex,
    A: TwinsBlockBuilder<P>,
    M: TwinsMarshal<P, A> + TwinsMarshal<P, PrimaryApp<P>>,
{
    let stack_label: Arc<str> = format!(
        "application={} wrapper={} max_pending_acks={}",
        selection.application, selection.marshal, selection.max_pending_acks
    )
    .into();
    if *VERIFY_PROBE {
        eprintln!("[marshal-twins] selected stack: {stack_label}");
    }
    let probe_input: Arc<str> = format!("{:?}", MarshalTwinsInputDebug(&input)).into();
    let rng = FuzzRng::new(entropy.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let scenario_entropy = entropy.clone();
        let mut backend = MarshalTwinsBackend::<P, A, M>::new(
            input,
            probe_input,
            case_policy,
            selection,
            stack_label,
            entropy,
        );
        run_twins_with_backend::<P, _>(&mut context, &mut backend, scenario_entropy).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_stack_samples_tight_and_deep_ack_windows() {
        assert_eq!(select_general_stack(&[0]).0.max_pending_acks, NZUsize!(1));
        assert_eq!(
            select_general_stack(&[0b100]).0.max_pending_acks,
            NZUsize!(2),
        );
        assert_eq!(
            select_general_stack(&[0b1000]).0.max_pending_acks,
            NZUsize!(8),
        );
        assert_eq!(
            select_general_stack(&[0b1100]).0.max_pending_acks,
            DEFAULT_MAX_PENDING_ACKS,
        );
    }

    #[test]
    fn pending_ack_oracle_is_armed_only_for_reachable_windows() {
        assert_eq!(
            pending_ack_invariant_limit(DEEP_PENDING_ACKS),
            Some(DEEP_PENDING_ACKS)
        );
        assert_eq!(pending_ack_invariant_limit(DEFAULT_MAX_PENDING_ACKS), None);
    }

    #[test]
    fn probe_input_elides_raw_entropy() {
        let input = MarshalTwinsInput {
            raw_bytes: vec![0xAB; 1024],
            rounds: 1,
            case_selector: 0,
            sustained: false,
            strategy: StrategyChoice::AnyScope,
            trailing_blocks: 1,
            forwarding: commonware_consensus::simplex::ForwardingPolicy::Disabled,
        };

        let rendered = format!("{:?}", MarshalTwinsInputDebug(&input));
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171, 171"));
    }
}
