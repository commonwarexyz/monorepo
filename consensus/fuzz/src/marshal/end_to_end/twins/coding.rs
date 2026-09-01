//! End-to-end Simplex Twins mutator over coding marshal.
//!
//! Coding uses [`Marshaled`](commonware_consensus::marshal::coding::Marshaled)
//! directly; the standard marshal's Deferred and Inline wrappers do not
//! participate in this target.

use super::{
    super::{
        app::{
            AlwaysAcceptBlockBuilderApp, ApplicationChoice, BlockContextRegistry, FaultyConfig,
            SelectedBlockBuilderApp,
        },
        coding_disrupter,
        coding_stack::{
            CodingB, CodingCtx, CodingValidator, CommitmentOf, coding_genesis, coding_marshaled,
            setup_validator_coding, start_engine_coding_with_networks,
        },
        input::MarshalTwinsInput,
        invariants::{self, CertificationAgreementInvariant, HeaderMismatchInvariant},
    },
    DEEP_PENDING_ACKS, MAX_CASES, MarshalTwinsInputDebug, ObservedMarshal, PublicKeyOf, SchemeOf,
    VERIFY_PROBE, record_case_outcome,
    stack::{
        DEFAULT_MAX_PENDING_ACKS, register_engine_networks, setup_network, setup_network_links,
        wait_for_liveness,
    },
};
use crate::{
    NAMESPACE, NetworkChannels, TwinsBackend, TwinsCase, TwinsDisrupter, TwinsSetup, TwinsTopology,
    run_twins_with_backend, simplex::Simplex,
};
use commonware_consensus::{
    CertifiableBlock as _,
    marshal::mocks::{application::Application, harness::NUM_VALIDATORS},
    simplex::{mocks::twins, scheme::Scheme as SimplexScheme},
    types::{TermLength, View},
};
use commonware_cryptography::{Committable as _, Digestible as _, certificate::ConstantProvider};
use commonware_p2p::{Receiver, Sender, simulated::Oracle};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize};
use std::{collections::HashMap, marker::PhantomData, num::NonZeroUsize, sync::Arc};

type PrimaryApp<P> = AlwaysAcceptBlockBuilderApp<CodingCtx<P>, SchemeOf<P>, CodingB<P>>;
type HonestApp<P> = SelectedBlockBuilderApp<CodingCtx<P>, SchemeOf<P>, CodingB<P>>;

struct CodingTwinsBackend<P: Simplex> {
    input: MarshalTwinsInput,
    app_config: FaultyConfig,
    application_choice: ApplicationChoice,
    max_pending_acks: NonZeroUsize,
    probe_input: Arc<str>,
    stack_label: Arc<str>,
    _marker: PhantomData<fn() -> P>,
}

struct CodingTwinsState<P: Simplex> {
    validators: Vec<CodingValidator<P>>,
    honest: Vec<(usize, Application<CodingB<P>>)>,
    primaries: Vec<(usize, Application<CodingB<P>>)>,
    certification_agreement: CertificationAgreementInvariant<CommitmentOf<P>>,
    block_contexts: BlockContextRegistry<CodingCtx<P>>,
    genesis_digest: commonware_cryptography::sha256::Digest,
    genesis_commitment: CommitmentOf<P>,
}

impl<P: Simplex> CodingTwinsBackend<P> {
    fn new(
        input: MarshalTwinsInput,
        application_choice: ApplicationChoice,
        max_pending_acks: NonZeroUsize,
        probe_input: Arc<str>,
        stack_label: Arc<str>,
        entropy: Vec<u8>,
    ) -> Self {
        let mut rng = FuzzRng::new(entropy);
        let app_config = FaultyConfig::new(&mut rng, View::new(input.rounds.into()));
        Self {
            input,
            app_config,
            application_choice,
            max_pending_acks,
            probe_input,
            stack_label,
            _marker: PhantomData,
        }
    }

    fn report_empty_case(&self) {
        record_case_outcome(false, &self.stack_label);
        if *VERIFY_PROBE {
            panic!(
                "marshal coding Twins generated no case: strategy={:?} stack={} input={}",
                self.input.strategy, self.stack_label, self.probe_input,
            );
        }
    }
}

impl<P> TwinsBackend<P> for CodingTwinsBackend<P>
where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    type State = CodingTwinsState<P>;
    type Case = ();
    type Digest = CommitmentOf<P>;

    async fn setup(&mut self, context: &mut deterministic::Context) -> TwinsSetup<P, Self::State> {
        let (participants, schemes) = P::setup(context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
        setup_network_links::<P>(&mut oracle, &participants).await;

        let genesis = coding_genesis::<P>(participants[0].clone());
        let genesis_digest = genesis.inner().digest();
        let genesis_commitment = genesis.commitment();
        let block_contexts = BlockContextRegistry::default();
        block_contexts.record(genesis_digest, genesis.inner().context());
        let mut validators = Vec::with_capacity(participants.len());
        let mut registrations = HashMap::with_capacity(participants.len());
        for (idx, validator) in participants.iter().enumerate() {
            let setup = setup_validator_coding::<P>(
                context
                    .child("validator")
                    .with_attribute("index", idx)
                    .child("marshal"),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[idx].clone()),
                genesis.clone(),
                self.max_pending_acks,
                (self.max_pending_acks.get() <= DEEP_PENDING_ACKS.get())
                    .then_some(self.max_pending_acks),
                idx,
                self.stack_label.clone(),
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
            state: CodingTwinsState {
                validators,
                honest: Vec::with_capacity(NUM_VALIDATORS as usize - 1),
                primaries: Vec::new(),
                certification_agreement: CertificationAgreementInvariant::coding(
                    self.stack_label.clone(),
                ),
                block_contexts,
                genesis_digest,
                genesis_commitment,
            },
        }
    }

    fn term_length(&self) -> TermLength {
        TermLength::ONE
    }

    fn framework(&mut self, _rng: &mut FuzzRng, participants: usize) -> twins::Framework {
        twins::Framework {
            participants,
            faults: 1,
            rounds: self.input.rounds.into(),
            mode: if self.input.sustained {
                twins::Mode::Sustained
            } else {
                twins::Mode::Sampled
            },
            max_cases: MAX_CASES,
        }
    }

    fn select_case(
        &mut self,
        _rng: &mut FuzzRng,
        _participants: &[PublicKeyOf<P>],
        cases: Vec<twins::Case>,
    ) -> Option<TwinsCase<Self::Case>> {
        if cases.is_empty() {
            self.report_empty_case();
            return None;
        }
        let count = cases.len();
        let case = cases
            .into_iter()
            .nth(usize::from(self.input.case_selector) % count)
            .expect("selected coding Twins case must exist");
        record_case_outcome(true, &self.stack_label);
        Some(TwinsCase {
            scenario: case.scenario,
            compromised: case.compromised,
            data: (),
        })
    }

    fn spawn_primary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        _participants: &Arc<[PublicKeyOf<P>]>,
        scheme: SchemeOf<P>,
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
        let node = &state.validators[idx];
        let marshaled = coding_marshaled::<P, _>(
            &context,
            ConstantProvider::new(scheme.clone()),
            PrimaryApp::<P>::default().with_block_contexts(state.block_contexts.clone()),
            node.mailbox.clone(),
            node.shards.clone(),
        );
        start_engine_coding_with_networks::<P, _, _, _>(
            context,
            oracle,
            validator,
            scheme,
            topology.elector.clone(),
            marshaled.clone(),
            marshaled,
            node.mailbox.clone(),
            state.genesis_commitment,
            self.input.forwarding,
            vote,
            certificate,
            resolver,
        );
        state.primaries.push((idx, node.application.clone()));
    }

    fn disrupter(&self) -> Option<TwinsDisrupter> {
        None
    }

    fn spawn_secondary(
        &mut self,
        context: deterministic::Context,
        _state: &mut Self::State,
        _oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        _participants: &Arc<[PublicKeyOf<P>]>,
        scheme: SchemeOf<P>,
        _validator: PublicKeyOf<P>,
        _idx: usize,
        _topology: &TwinsTopology<P, Self::Case>,
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
        coding_disrupter::start::<P>(
            context,
            scheme,
            self.input.strategy,
            self.input.rounds.into(),
            vote,
            certificate,
            resolver,
        );
    }

    fn spawn_honest(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        _participants: &Arc<[PublicKeyOf<P>]>,
        scheme: SchemeOf<P>,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        channels: NetworkChannels<PublicKeyOf<P>>,
    ) {
        let node = &state.validators[idx];
        let application = HonestApp::<P>::new(self.application_choice, self.app_config, None)
            .with_block_contexts(state.block_contexts.clone());
        let marshaled = coding_marshaled::<P, _>(
            &context,
            ConstantProvider::new(scheme.clone()),
            application,
            node.mailbox.clone(),
            node.shards.clone(),
        );
        let observed = ObservedMarshal {
            validator: idx,
            probe_input: self.probe_input.clone(),
            context: Arc::new(commonware_utils::sync::Mutex::new(
                context.child("automaton_invariants"),
            )),
            inner: marshaled.clone(),
            certification_agreement: state.certification_agreement.clone(),
            header_mismatch: HeaderMismatchInvariant::<P, FaultyConfig, CommitmentOf<P>>::coding(
                self.application_choice,
                self.app_config,
                HonestApp::<P>::rejects,
                state.block_contexts.clone(),
                self.stack_label.clone(),
            ),
        };
        start_engine_coding_with_networks::<P, _, _, _>(
            context,
            oracle,
            validator,
            scheme,
            topology.elector.clone(),
            observed,
            marshaled,
            node.mailbox.clone(),
            state.genesis_commitment,
            self.input.forwarding,
            channels.0,
            channels.1,
            channels.2,
        );
        state.honest.push((idx, node.application.clone()));
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
            invariants::check_local_blocks(
                *idx,
                application,
                state.genesis_digest,
                commonware_consensus::types::Height::zero(),
                &self.stack_label,
            );
        }
        invariants::check_all_blocks(
            &state.honest,
            state.genesis_digest,
            commonware_consensus::types::Height::zero(),
            Some(&self.stack_label),
        );
    }
}

fn select_coding_stack(raw_bytes: &[u8]) -> (ApplicationChoice, NonZeroUsize, Vec<u8>) {
    let Some((&selector, entropy)) = raw_bytes.split_last() else {
        return (ApplicationChoice::AlwaysAccept, NZUsize!(2), vec![0]);
    };
    let max_pending_acks = match (selector >> 1) & 0b11 {
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
        ApplicationChoice::from_selector(selector),
        max_pending_acks,
        entropy,
    )
}

/// Crypto: `P`. Marshal: coding. Cluster: `N4F1C3` Twins, general campaign.
/// Liveness: checked. App: selected by fuzz input.
///
/// Coding's consensus payload is a [`CommitmentOf`]. The secondary signs both an
/// observed proposal and a conflicting coding commitment with the compromised
/// identity's key, producing real double votes across the Twins partition.
pub fn fuzz_marshal_coding_twins<P>(input: MarshalTwinsInput)
where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let (application_choice, max_pending_acks, entropy) = select_coding_stack(&input.raw_bytes);
    let stack_label: Arc<str> = format!(
        "application={application_choice} marshal=coding max_pending_acks={max_pending_acks}"
    )
    .into();
    let probe_input: Arc<str> = format!("{:?}", MarshalTwinsInputDebug(&input)).into();
    let rng = FuzzRng::new(entropy.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let scenario_entropy = entropy.clone();
        let mut backend = CodingTwinsBackend::<P>::new(
            input,
            application_choice,
            max_pending_acks,
            probe_input,
            stack_label,
            entropy,
        );
        run_twins_with_backend::<P, _>(&mut context, &mut backend, scenario_entropy).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::StrategyChoice;
    use commonware_consensus::simplex::ForwardPolicy;

    #[test]
    fn coding_stack_selects_application_ack_depth_and_preserves_entropy() {
        let (choice, max_pending_acks, entropy) = select_coding_stack(&[1, 2, 5]);
        assert_eq!(choice, ApplicationChoice::Faulty);
        assert_eq!(max_pending_acks, DEEP_PENDING_ACKS);
        assert_eq!(entropy, vec![1, 2]);

        let (choice, max_pending_acks, entropy) = select_coding_stack(&[]);
        assert_eq!(choice, ApplicationChoice::AlwaysAccept);
        assert_eq!(max_pending_acks, NZUsize!(2));
        assert_eq!(entropy, vec![0]);
    }

    #[test]
    fn coding_twins_makes_post_prefix_progress() {
        fuzz_marshal_coding_twins::<crate::SimplexCertificateMock>(MarshalTwinsInput {
            raw_bytes: vec![0],
            rounds: 1,
            case_selector: 0,
            sustained: false,
            strategy: StrategyChoice::SmallScope {
                fault_rounds: 1,
                fault_rounds_bound: 1,
            },
            trailing_blocks: 1,
            forwarding: ForwardPolicy::Disabled,
        });
    }
}
