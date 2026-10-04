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
        coding_disrupter::{self, CodingFaults},
        coding_stack::{
            CodingB, CodingCtx, CodingValidator, CommitmentOf, DigestLookups, FaultyProposer,
            ProposalFault, coding_genesis, coding_marshaled, sample_shards_mailbox_size,
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
use commonware_consensus::{
    CertifiableBlock as _,
    marshal::mocks::{application::Application, harness::NUM_VALIDATORS},
    simplex::{mocks::twins, scheme::Scheme as SimplexScheme},
    types::{TermLength, View},
};
use commonware_consensus_fuzz_core::{
    NAMESPACE, NetworkChannels, TwinsBackend, TwinsCase, TwinsDisrupter, TwinsSetup, TwinsTopology,
    run_twins_with_backend, simplex::Simplex,
};
use commonware_cryptography::{Committable as _, Digestible as _, certificate::ConstantProvider};
use commonware_p2p::{Receiver, Sender, simulated::Oracle};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize};
use std::{collections::HashMap, marker::PhantomData, num::NonZeroUsize, sync::Arc};

type PrimaryApp<P> = AlwaysAcceptBlockBuilderApp<CodingCtx<P>, SchemeOf<P>, CodingB<P>>;
type HonestApp<P> = SelectedBlockBuilderApp<CodingCtx<P>, SchemeOf<P>, CodingB<P>>;

/// Stack axes decoded from the reserved selector byte of the coding Twins tape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CodingStackSelection {
    application: ApplicationChoice,
    max_pending_acks: NonZeroUsize,
    /// Ancestors the honest applications walk past the parent.
    ancestry_depth: u8,
    /// Whether honest applications issue digest-keyed marshal lookups.
    digest_lookups: bool,
    /// Header fault of the compromised identity's proposals.
    proposal_fault: Option<ProposalFault>,
}

struct CodingTwinsBackend<P: Simplex> {
    input: MarshalTwinsInput,
    app_config: FaultyConfig,
    selection: CodingStackSelection,
    shards_mailbox_size: NonZeroUsize,
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
        selection: CodingStackSelection,
        probe_input: Arc<str>,
        stack_label: Arc<str>,
        entropy: Vec<u8>,
    ) -> Self {
        let mut rng = FuzzRng::new(entropy);
        let app_config = FaultyConfig::new(&mut rng, View::new(input.rounds.into()));
        let shards_mailbox_size = sample_shards_mailbox_size(&mut rng);
        Self {
            input,
            app_config,
            selection,
            shards_mailbox_size,
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
                self.selection.max_pending_acks,
                (self.selection.max_pending_acks.get() <= DEEP_PENDING_ACKS.get())
                    .then_some(self.selection.max_pending_acks),
                idx,
                self.stack_label.clone(),
                self.shards_mailbox_size,
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
        // The compromised identity's proposals may carry a header fault; the
        // honest applications never wrap.
        let application = FaultyProposer::<P, _>::new(
            PrimaryApp::<P>::default().with_block_contexts(state.block_contexts.clone()),
            self.selection.proposal_fault,
            state.block_contexts.clone(),
        );
        let marshaled = coding_marshaled::<P, _>(
            &context,
            ConstantProvider::new(scheme.clone()),
            application,
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
            CodingFaults::none(),
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
        let application = DigestLookups::<P, _>::new(
            HonestApp::<P>::new(self.selection.application, self.app_config, None)
                .with_ancestry_depth(self.selection.ancestry_depth)
                .with_block_contexts(state.block_contexts.clone()),
            self.selection.digest_lookups.then(|| node.mailbox.clone()),
        );
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
                self.selection.application,
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

/// Decodes the stack selector byte: bit 0 application, bits 1-2 acknowledgement
/// depth, bits 3-4 ancestry depth, bit 5 digest lookups, bits 6-7 the
/// compromised proposer's fault. The remaining bytes stay scenario/runtime
/// entropy.
fn select_coding_stack(raw_bytes: &[u8]) -> (CodingStackSelection, Vec<u8>) {
    let Some((&selector, entropy)) = raw_bytes.split_last() else {
        return (
            CodingStackSelection {
                application: ApplicationChoice::AlwaysAccept,
                max_pending_acks: NZUsize!(2),
                ancestry_depth: 0,
                digest_lookups: false,
                proposal_fault: None,
            },
            vec![0],
        );
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
        CodingStackSelection {
            application: ApplicationChoice::from_selector(selector),
            max_pending_acks,
            ancestry_depth: (selector >> 3) & 0b11,
            digest_lookups: (selector >> 5) & 1 == 1,
            proposal_fault: ProposalFault::from_selector(selector),
        },
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
    let (selection, entropy) = select_coding_stack(&input.raw_bytes);
    let stack_label: Arc<str> = format!(
        "application={} marshal=coding max_pending_acks={}",
        selection.application, selection.max_pending_acks
    )
    .into();
    let probe_input: Arc<str> = format!(
        "{:?} selection={selection:?}",
        MarshalTwinsInputDebug(&input)
    )
    .into();
    let rng = FuzzRng::new(entropy.clone());
    let cfg = deterministic::Config::new().with_rng(rng);
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let scenario_entropy = entropy.clone();
        let mut backend =
            CodingTwinsBackend::<P>::new(input, selection, probe_input, stack_label, entropy);
        run_twins_with_backend::<P, _>(&mut context, &mut backend, scenario_entropy).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::simplex::ForwardPolicy;
    use commonware_consensus_fuzz_core::strategy::StrategyChoice;

    #[test]
    fn coding_stack_selects_application_ack_depth_and_preserves_entropy() {
        let (selection, entropy) = select_coding_stack(&[1, 2, 5]);
        assert_eq!(selection.application, ApplicationChoice::Faulty);
        assert_eq!(selection.max_pending_acks, DEEP_PENDING_ACKS);
        assert_eq!(selection.ancestry_depth, 0);
        assert!(!selection.digest_lookups);
        assert_eq!(selection.proposal_fault, None);
        assert_eq!(entropy, vec![1, 2]);

        let (selection, entropy) = select_coding_stack(&[]);
        assert_eq!(selection.application, ApplicationChoice::AlwaysAccept);
        assert_eq!(selection.max_pending_acks, NZUsize!(2));
        assert_eq!(entropy, vec![0]);

        let (selection, _) = select_coding_stack(&[0, 0b1011_1000]);
        assert_eq!(selection.ancestry_depth, 3);
        assert!(selection.digest_lookups);
        assert_eq!(selection.proposal_fault, Some(ProposalFault::WrongParent));
    }

    #[test]
    fn coding_twins_makes_post_prefix_progress() {
        fuzz_marshal_coding_twins::<commonware_consensus_fuzz_core::SimplexCertificateMock>(
            MarshalTwinsInput {
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
                floor: None,
            },
        );
    }

    /// Deep ancestry walks, digest lookups, and each proposer fault of the
    /// compromised identity keep the honest nodes live.
    #[test]
    fn coding_twins_runs_with_lookups_and_proposer_faults() {
        for selector in [0b0111_1000, 0b1011_1000, 0b1111_1001] {
            fuzz_marshal_coding_twins::<commonware_consensus_fuzz_core::SimplexCertificateMock>(
                MarshalTwinsInput {
                    raw_bytes: vec![3, 1, 4, selector],
                    rounds: 3,
                    case_selector: 1,
                    sustained: false,
                    strategy: StrategyChoice::AnyScope,
                    trailing_blocks: 2,
                    forwarding: ForwardPolicy::Disabled,
                    floor: None,
                },
            );
        }
    }
}
