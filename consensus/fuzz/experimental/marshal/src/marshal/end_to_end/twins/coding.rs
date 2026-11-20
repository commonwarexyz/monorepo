//! End-to-end Simplex Twins mutator over coding marshal.
//!
//! Coding uses [`Marshaled`](commonware_consensus::marshal::coding::Marshaled)
//! directly; the standard marshal's Deferred and Inline wrappers do not
//! participate in this target.

use super::{
    super::{
        app::{
            AlwaysAcceptBlockBuilderApp, ApplicationChoice, BlockContextRegistry, FaultTable,
            FaultyConfig, NodeRole, SelectedBlockBuilderApp,
        },
        coding_disrupter::{self, CodingFaults},
        coding_stack::{
            CodingB, CodingCtx, CodingValidator, CommitmentOf, DigestLookups, FaultyProposer,
            ProposalFault, coding_genesis, coding_marshaled, sample_shards_mailbox_size,
            setup_validator_coding, start_engine_coding_with_networks,
        },
        input::MarshalTwinsInput,
        invariants::{self, CertificationAgreementInvariant, HeaderMismatchInvariant, Liveness},
        trusted::CodingReads,
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
    marshal::mocks::{
        application::Application,
        harness::{LINK, NUM_VALIDATORS},
    },
    simplex::{mocks::twins, scheme::Scheme as SimplexScheme},
    types::{Epoch, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    NAMESPACE, NetworkChannels, TwinsBackend, TwinsCase, TwinsDisrupter, TwinsSetup, TwinsTopology,
    continuation::{Channel, Hook, ReplicaTap, Role, gate, tap_elector, tap_finalized},
    run_twins_with_backend_and_hook,
    simplex::Simplex,
};
use commonware_cryptography::{Committable as _, Digestible as _, certificate::ConstantProvider};
use commonware_p2p::{
    Receiver, Sender,
    simulated::{Link, Oracle},
};
use commonware_runtime::{Clock as _, Handle, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize, SystemTimeExt as _};
use std::{
    collections::HashMap, marker::PhantomData, num::NonZeroUsize, sync::Arc, time::Duration,
};

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
    /// Views the secondary's sampled faulty views move by: past a trusted
    /// continuation's release, 0 without one.
    view_offset: u64,
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
    /// A trusted continuation's taps, by participant; empty without one.
    taps: Vec<Option<Arc<ReplicaTap<P>>>>,
    /// The twin pair's tasks, by role, kept only under a continuation.
    actors: Vec<(Role, Handle<()>)>,
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
        // The sampled table is drawn either way, so the shard mailbox keeps its sample.
        let sampled = FaultyConfig::new(&mut rng, input.rounds, input.term_length);
        let app_config = match input.fault_table {
            FaultTable::Sampled => sampled,
            FaultTable::RejectTermEnds => {
                FaultyConfig::rejecting_term_ends(input.rounds, input.term_length)
            }
        };
        let shards_mailbox_size = sample_shards_mailbox_size(&mut rng);
        Self {
            input,
            app_config,
            selection,
            shards_mailbox_size,
            probe_input,
            stack_label,
            view_offset: 0,
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
            state: CodingTwinsState {
                validators,
                honest: Vec::with_capacity(NUM_VALIDATORS as usize - 1),
                primaries: Vec::new(),
                certification_agreement: CertificationAgreementInvariant::coding(
                    self.stack_label.clone(),
                    self.input.term_length,
                ),
                block_contexts,
                genesis_digest,
                genesis_commitment,
                taps: Vec::new(),
                actors: Vec::new(),
            },
        }
    }

    fn term_length(&self) -> TermLength {
        self.input.term_length
    }

    fn optimistic_views(&self) -> ViewDelta {
        self.input.optimistic_views
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
            PrimaryApp::<P>::new(NodeRole::Compromised, self.input.handoff, None)
                .with_block_contexts(state.block_contexts.clone()),
            self.selection.proposal_fault,
            self.input.fault_scope,
            self.input.term_length,
            state.block_contexts.clone(),
        );
        let marshaled = coding_marshaled::<P, _>(
            &context,
            ConstantProvider::new(scheme.clone()),
            application,
            node.mailbox.clone(),
            node.shards.clone(),
        );
        let engine = start_engine_coding_with_networks::<P, _, _, _, _>(
            context,
            oracle.control(validator.clone()),
            validator,
            scheme,
            topology.elector.clone(),
            marshaled.clone(),
            marshaled.clone(),
            marshaled,
            state.genesis_commitment,
            self.input.forwarding,
            vote,
            certificate,
            resolver,
        );
        if !state.taps.is_empty() {
            state.actors.push((Role::Primary, engine));
        }
        state.primaries.push((idx, node.application.clone()));
    }

    fn disrupter(&self) -> Option<TwinsDisrupter> {
        None
    }

    fn spawn_secondary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
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
        // The core marks the vote receiver it hands the secondary.
        let voter = coding_disrupter::start::<P>(
            context,
            scheme,
            self.input.strategy,
            self.input.rounds.into(),
            vote,
            certificate,
            resolver,
            CodingFaults::none(),
            self.view_offset,
            None,
        );
        if !state.taps.is_empty() {
            state.actors.push((Role::Secondary, voter));
        }
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
        let tap = state.taps.get(idx).cloned().flatten();
        let tap = tap.as_ref();
        let node = &state.validators[idx];
        if let Some(tap) = tap {
            tap.set_reads(Arc::new(CodingReads::<P>::new(node.mailbox.clone())));
        }
        let application = DigestLookups::<P, _>::new(
            HonestApp::<P>::new(
                NodeRole::Honest,
                self.selection.application,
                self.app_config,
                None,
                self.input.handoff,
            )
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
        let ((vote_sender, vote_receiver), (certificate_sender, certificate_receiver), resolver) =
            channels;
        let (resolver_sender, resolver_receiver) = resolver;
        drop(start_engine_coding_with_networks::<P, _, _, _, _>(
            context,
            oracle.control(validator.clone()),
            validator,
            scheme,
            tap_elector(tap, topology.elector.clone()),
            observed,
            marshaled.clone(),
            tap_finalized(tap, marshaled),
            state.genesis_commitment,
            self.input.forwarding,
            (vote_sender, gate(tap, vote_receiver, Channel::Vote)),
            (
                certificate_sender,
                gate(tap, certificate_receiver, Channel::Certificate),
            ),
            (
                resolver_sender,
                gate(tap, resolver_receiver, Channel::Resolver),
            ),
        ));
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
            Liveness::sampled(
                self.input.handoff,
                self.input.optimistic_views,
                self.input.term_length,
            ),
        )
        .await;
    }

    fn check_invariants(
        &mut self,
        _context: &deterministic::Context,
        state: &mut Self::State,
        _topology: &TwinsTopology<P, Self::Case>,
    ) {
        // The compromised primary's application accepts everything.
        for (idx, application) in &state.primaries {
            invariants::check_local_blocks(
                *idx,
                application,
                state.genesis_digest,
                commonware_consensus::types::Height::zero(),
                &|_| false,
                &self.stack_label,
            );
        }
        invariants::check_all_blocks(
            &state.honest,
            state.genesis_digest,
            commonware_consensus::types::Height::zero(),
            &|context| {
                HonestApp::<P>::rejects(self.selection.application, self.app_config, context)
            },
            Some(&self.stack_label),
        );
    }

    fn install_taps(
        &mut self,
        state: &mut Self::State,
        taps: Vec<Option<Arc<ReplicaTap<P>>>>,
    ) -> bool {
        state.taps = taps;
        true
    }

    fn take_actors(&mut self, state: &mut Self::State) -> Vec<(Role, Handle<()>)> {
        std::mem::take(&mut state.actors)
    }

    fn link(&self) -> Link {
        LINK
    }

    fn epoch(&self) -> Epoch {
        Epoch::zero()
    }

    fn set_view_offset(&mut self, offset: u64) {
        self.view_offset = offset;
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
/// Liveness: checked under the pinned extensions, else safety only. App:
/// selected by fuzz input.
///
/// Coding's consensus payload is a [`CommitmentOf`]. The secondary signs both an
/// observed proposal and a conflicting coding commitment with the compromised
/// identity's key, producing real double votes across the Twins partition.
pub fn fuzz_marshal_coding_twins<P>(input: MarshalTwinsInput)
where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let _ = run_coding_twins::<P>(input, None);
}

/// Runs one coding Twins case, as a trusted continuation with `hook` (see
/// [run_twins_with_backend_and_hook]); returns the runtime's auditor state and the
/// simulated time at its end.
pub(crate) fn run_coding_twins<P>(
    input: MarshalTwinsInput,
    hook: Option<Hook<P>>,
) -> (String, Duration)
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
        run_twins_with_backend_and_hook::<P, _>(&mut context, &mut backend, scenario_entropy, hook)
            .await;
        (context.auditor().state(), context.current().epoch())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assert_adversary_acted, assert_reached,
        marshal::end_to_end::{coding_stack::FaultScope, invariants::CORRUPTED_PARENT_VOTE},
        prepare_event,
    };
    use commonware_consensus::{Handoff, simplex::ForwardPolicy};
    use commonware_consensus_fuzz_core::{
        HANDOFF_DECISIONS, byzantine::TWIN_SECONDARY, strategy::StrategyChoice,
    };
    use commonware_utils::NZU32;

    /// The pinned extensions: single-view terms, no lookahead, `Wait`.
    fn pinned() -> MarshalTwinsInput {
        MarshalTwinsInput {
            raw_bytes: Vec::new(),
            rounds: 1,
            case_selector: 0,
            sustained: false,
            strategy: StrategyChoice::AnyScope,
            trailing_blocks: 1,
            forwarding: ForwardPolicy::Disabled,
            floor: None,
            term_length: TermLength::ONE,
            optimistic_views: ViewDelta::zero(),
            handoff: Handoff::Wait,
            fault_table: FaultTable::Sampled,
            fault_scope: FaultScope::Term,
        }
    }

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
        assert_adversary_acted(&[TWIN_SECONDARY], || {
            fuzz_marshal_coding_twins::<commonware_consensus_fuzz_core::SimplexCertificateMock>(
                MarshalTwinsInput {
                    raw_bytes: vec![0],
                    strategy: StrategyChoice::SmallScope {
                        fault_rounds: 1,
                        fault_rounds_bound: 1,
                    },
                    ..pinned()
                },
            );
        });
    }

    /// The extensions: three-view terms, a lookahead of two and `handoff`, on
    /// the stack `selector` picks.
    fn extended_input(selector: u8, handoff: Handoff<()>) -> MarshalTwinsInput {
        MarshalTwinsInput {
            raw_bytes: vec![3, 1, 4, selector],
            rounds: 3,
            trailing_blocks: 2,
            term_length: TermLength::new(NZU32!(3)),
            optimistic_views: ViewDelta::new(2),
            handoff,
            ..pinned()
        }
    }

    /// Every handoff decision reaches an honest node's prepare on stable terms
    /// with a lookahead under both applications (selector bit 0 picks the
    /// faulty one, whose own prepare answers), while the secondary twin acts.
    #[test]
    fn coding_twins_prepare_under_every_decision() {
        for handoff in HANDOFF_DECISIONS {
            for selector in [0, 1] {
                assert_reached(&[prepare_event(handoff)], || {
                    assert_adversary_acted(&[TWIN_SECONDARY], || {
                        fuzz_marshal_coding_twins::<
                            commonware_consensus_fuzz_core::SimplexCertificateMock,
                        >(extended_input(selector, handoff));
                    });
                });
            }
        }
    }

    /// The compromised proposer's skipped height scoped to its term end, under a
    /// pipelined vote on terms of two and three views: the earlier views of its
    /// term certify, and an honest incoming leader votes early over the
    /// forged-height block that ends it. Seeds run until one run reaches it.
    #[test]
    fn coding_twins_vote_over_a_term_end_skipped_height() {
        for term in [2u32, 3] {
            assert_reached(&[CORRUPTED_PARENT_VOTE], || {
                for seed in 0..32u8 {
                    commonware_consensus_fuzz_core::reach::reset();
                    fuzz_marshal_coding_twins::<
                        commonware_consensus_fuzz_core::SimplexCertificateMock,
                    >(MarshalTwinsInput {
                        raw_bytes: vec![seed, 1, 4, 0b1100_0000],
                        rounds: 5,
                        term_length: TermLength::new(NZU32!(term)),
                        fault_scope: FaultScope::TermEnd,
                        ..extended_input(0b1100_0000, Handoff::Vote(()))
                    });
                    if commonware_consensus_fuzz_core::reach::count(CORRUPTED_PARENT_VOTE) > 0 {
                        eprintln!("corrupted term end at term length {term}: seed {seed}");
                        break;
                    }
                }
            });
        }
    }

    /// The compromised proposer's skipped height on every block of its term,
    /// under a pipelined vote: an honest incoming leader votes early over its
    /// forged-height block as the uncertified parent. A handoff parent ends a
    /// term without a nullification, so a whole-term fault offers one reliably
    /// only under a single-view term. Seeds run until one run reaches it.
    #[test]
    fn coding_twins_vote_over_a_skipped_height_proposer() {
        assert_reached(&[CORRUPTED_PARENT_VOTE], || {
            for seed in 0..16u8 {
                commonware_consensus_fuzz_core::reach::reset();
                fuzz_marshal_coding_twins::<commonware_consensus_fuzz_core::SimplexCertificateMock>(
                    MarshalTwinsInput {
                        raw_bytes: vec![seed, 1, 4, 0b1100_0000],
                        rounds: 5,
                        term_length: TermLength::ONE,
                        ..extended_input(0b1100_0000, Handoff::Vote(()))
                    },
                );
                if commonware_consensus_fuzz_core::reach::count(CORRUPTED_PARENT_VOTE) > 0 {
                    break;
                }
            }
        });
    }

    /// Deep ancestry walks, digest lookups, and each proposer fault of the
    /// compromised identity keep the honest nodes live.
    #[test]
    fn coding_twins_runs_with_lookups_and_proposer_faults() {
        for selector in [0b0111_1000, 0b1011_1000, 0b1111_1001] {
            assert_adversary_acted(&[TWIN_SECONDARY], || {
                fuzz_marshal_coding_twins::<commonware_consensus_fuzz_core::SimplexCertificateMock>(
                    MarshalTwinsInput {
                        raw_bytes: vec![3, 1, 4, selector],
                        rounds: 3,
                        case_selector: 1,
                        trailing_blocks: 2,
                        ..pinned()
                    },
                );
            });
        }
    }
}
