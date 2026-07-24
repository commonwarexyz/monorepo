//! End-to-end Simplex Twins mutator over standard marshal.
//!
//! The compromised identity runs one full Simplex engine plus the existing
//! [`crate::disrupter::Disrupter`] with one signing key. Their vote, certificate,
//! and resolver channels are split by the shared Twins helpers. Every correct
//! engine and the compromised primary use a real
//! `Deferred -> Marshal -> Application` data path. The secondary mutator can
//! preserve an observed payload while changing its proposal header. In addition
//! to delivery and liveness checks, the target asserts that a header-scoped
//! verification rejection is never reused during certification.

use super::{
    ENGINE_CERTIFICATE, ENGINE_RESOLVER, ENGINE_VOTE, app::BlockBuilderApp,
    input::MarshalTwinsInput, invariant,
};
use crate::{
    BYZANTINE_IDX, NAMESPACE, POST_GST_WINDOW, SimplexCertificateMock, SimplexId, simplex::Simplex,
    start_disrupter_with_epoch, strategy::StrategyChoice, twins_network,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, CertifiableBlock,
    marshal::{
        Config, Start,
        core::{Actor, Mailbox},
        mocks::{
            application::Application,
            block::Block as MockBlock,
            harness::{
                BLOCKS_PER_EPOCH, LINK, NUM_VALIDATORS, PAGE_CACHE_SIZE, PAGE_SIZE, TEST_QUOTA,
            },
        },
        resolver::p2p as resolver,
        standard::{Deferred, Standard},
    },
    simplex::{
        Engine, Floor, config, elector::RoundRobin, mocks::twins, types::Context as SimplexContext,
    },
    types::{Delta, Epoch, FixedEpocher, Height, Round, TermLength, View, ViewDelta},
};
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256,
    certificate::{ConstantProvider, Verifier as _},
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    Receiver, Sender,
    simulated::{
        Config as NetworkConfig, Network as SimulatedNetwork, Oracle,
        Receiver as SimulatedReceiver, Sender as SimulatedSender,
    },
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Runner, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::archive::immutable;
use commonware_utils::{
    FuzzRng, NZU64, NZUsize,
    channel::{fallible::OneshotExt as _, oneshot},
    sync::Mutex,
};
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
    time::Duration,
};

/// Opt-in ground-truth probe. Set `MARSHAL_TWINS_PROBE=1` to log whenever the
/// `Deferred` context-mismatch branch actually rejects a block (the exact
/// branch that poisons the gate). Off by default so normal fuzzing keeps the
/// unperturbed timing — the probe only observes `inner.verify`'s verdict after
/// it is forwarded, but the extra task hop still shifts the schedule slightly.
static VERIFY_PROBE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("MARSHAL_TWINS_PROBE").is_ok());

const MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(64);
const POLL: Duration = Duration::from_millis(50);
const MAX_CASES: usize = 64;
const ATTACK_MAX_CASES: usize = 2048;
const ATTACK_VERIFY_DELAY: Duration = Duration::from_secs(3);

type SchemeOf<P> = <P as Simplex>::Scheme;
type PublicKeyOf<P> =
    <<P as Simplex>::Scheme as commonware_cryptography::certificate::Verifier>::PublicKey;
type Ctx<P> = SimplexContext<Sha256Digest, PublicKeyOf<P>>;
type B<P> = MockBlock<Sha256Digest, Ctx<P>>;
type Builder<P> = Deferred<
    deterministic::Context,
    SchemeOf<P>,
    BlockBuilderApp<Ctx<P>, SchemeOf<P>>,
    B<P>,
    FixedEpocher,
>;
type TwinElector = twins::Elector<RoundRobin<Sha256>>;
type VerifiedContexts<P> = HashMap<(Round, Sha256Digest), Vec<Ctx<P>>>;
type Network<P> = (
    SimulatedSender<PublicKeyOf<P>, deterministic::Context>,
    SimulatedReceiver<PublicKeyOf<P>>,
);

#[derive(Clone, Copy)]
struct AttackLayout {
    precursor_view: View,
    attack_view: View,
    victim: usize,
    slow: usize,
    fast: usize,
    delayed_validators: [usize; 2],
}

fn contains<K: PartialEq>(partition: &[K], participant: &K) -> bool {
    partition.iter().any(|candidate| candidate == participant)
}

/// Find adjacent views that can carry the complete split-header schedule.
///
/// At `W`, two secondary-only validators are delayed during application
/// verification. Together with the secondary twin they can form a
/// nullification, while the primary twin and the remaining fast validator
/// cannot finalize. At `W+1`, the fast validator overlaps both halves and
/// carries the primary proposal to the secondary before the delayed validator
/// completes the good notarization quorum. The victim remains secondary-only
/// and receives the parent-mutated leader header first.
fn attack_layout<P: Simplex>(
    scenario: &twins::Scenario,
    participants: &[PublicKeyOf<P>],
) -> Option<AttackLayout> {
    let rounds = scenario.rounds();
    let honest = (0..participants.len())
        .filter(|idx| *idx != BYZANTINE_IDX)
        .collect::<Vec<_>>();

    for attack_idx in 1..rounds.len() {
        if rounds[attack_idx].leader() != BYZANTINE_IDX {
            continue;
        }

        let precursor_number =
            u64::try_from(attack_idx).expect("Twins round index must fit in u64");
        let precursor_view = View::new(precursor_number);
        let attack_view = View::new(precursor_number + 1);
        let (precursor_primary, precursor_secondary) =
            scenario.partitions(precursor_view, TermLength::ONE, participants);
        let (attack_primary, attack_secondary) =
            scenario.partitions(attack_view, TermLength::ONE, participants);

        for &victim in &honest {
            if contains(&precursor_primary, &participants[victim])
                || !contains(&precursor_secondary, &participants[victim])
                || contains(&attack_primary, &participants[victim])
                || !contains(&attack_secondary, &participants[victim])
            {
                continue;
            }

            for &slow in &honest {
                if slow == victim
                    || contains(&precursor_primary, &participants[slow])
                    || !contains(&precursor_secondary, &participants[slow])
                    || !contains(&attack_primary, &participants[slow])
                    || contains(&attack_secondary, &participants[slow])
                {
                    continue;
                }

                let fast = honest
                    .iter()
                    .copied()
                    .find(|idx| *idx != victim && *idx != slow)?;
                if !contains(&precursor_primary, &participants[fast])
                    || contains(&precursor_secondary, &participants[fast])
                    || !contains(&attack_primary, &participants[fast])
                    || !contains(&attack_secondary, &participants[fast])
                {
                    continue;
                }

                let precursor_leader = rounds[attack_idx - 1].leader();
                if precursor_leader != fast {
                    continue;
                }

                return Some(AttackLayout {
                    precursor_view,
                    attack_view,
                    victim,
                    slow,
                    fast,
                    delayed_validators: [slow, victim],
                });
            }
        }
    }
    None
}

struct ConsensusNetworks<P: Simplex> {
    vote: Network<P>,
    certificate: Network<P>,
    resolver: Network<P>,
}

struct Validator<P: Simplex> {
    mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    application: Application<B<P>>,
}

fn genesis_block<P: Simplex>(leader: PublicKeyOf<P>) -> B<P> {
    let parent = Sha256::hash(&[b""]);
    let context = Ctx::<P> {
        round: Round::new(Epoch::zero(), View::zero()),
        leader,
        parent: (View::zero(), parent),
    };
    MockBlock::new::<Sha256>(context, parent, Height::zero(), 0)
}

async fn setup_network<P: Simplex>(
    context: deterministic::Context,
    participants: Vec<PublicKeyOf<P>>,
) -> Oracle<PublicKeyOf<P>, deterministic::Context> {
    let (network, oracle) = SimulatedNetwork::new_with_peers(
        context,
        NetworkConfig {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
        participants,
    )
    .await;
    network.start();
    oracle
}

async fn setup_network_links<P: Simplex>(
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
) {
    for sender in participants {
        for receiver in participants {
            if sender == receiver {
                continue;
            }
            let _ = oracle
                .add_link(sender.clone(), receiver.clone(), LINK.clone())
                .await;
        }
    }
}

async fn setup_validator<P: Simplex>(
    context: deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    provider: ConstantProvider<SchemeOf<P>, Epoch>,
    genesis: B<P>,
) -> Validator<P> {
    let application = Application::<B<P>>::default();
    let config = Config {
        provider,
        epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        start: Start::Genesis(genesis),
        mailbox_size: NZUsize!(100),
        view_retention: ViewDelta::new(10),
        max_repair: NZUsize!(10),
        max_pending_acks: MAX_PENDING_ACKS,
        block_codec_config: (),
        partition_prefix: format!("validator-{validator}"),
        prunable_items_per_section: NZU64!(10),
        replay_buffer: NZUsize!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
    };
    let control = oracle.control(validator.clone());
    let backfill = control.register(1, TEST_QUOTA).await.unwrap();
    let resolver = resolver::init(
        context.child("resolver"),
        resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill,
    );

    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    let network = control.register(2, TEST_QUOTA).await.unwrap();
    broadcast_engine.start(network);

    let finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
        immutable::Config {
            metadata_partition: format!(
                "{}-finalizations-by-height-metadata",
                config.partition_prefix
            ),
            freezer_table_partition: format!(
                "{}-finalizations-by-height-freezer-table",
                config.partition_prefix
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{}-finalizations-by-height-freezer-key",
                config.partition_prefix
            ),
            freezer_key_page_cache: config.page_cache.clone(),
            freezer_value_partition: format!(
                "{}-finalizations-by-height-freezer-value",
                config.partition_prefix
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!(
                "{}-finalizations-by-height-ordinal",
                config.partition_prefix
            ),
            items_per_section: NZU64!(10),
            codec_config: SchemeOf::<P>::certificate_codec_config_unbounded(),
            replay_buffer: config.replay_buffer,
            freezer_key_write_buffer: config.key_write_buffer,
            freezer_value_write_buffer: config.value_write_buffer,
            ordinal_write_buffer: config.key_write_buffer,
        },
    )
    .await
    .expect("failed to initialize finalizations by height archive");
    let finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        immutable::Config {
            metadata_partition: format!("{}-finalized-blocks-metadata", config.partition_prefix),
            freezer_table_partition: format!(
                "{}-finalized-blocks-freezer-table",
                config.partition_prefix
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{}-finalized-blocks-freezer-key",
                config.partition_prefix
            ),
            freezer_key_page_cache: config.page_cache.clone(),
            freezer_value_partition: format!(
                "{}-finalized-blocks-freezer-value",
                config.partition_prefix
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{}-finalized-blocks-ordinal", config.partition_prefix),
            items_per_section: NZU64!(10),
            codec_config: config.block_codec_config,
            replay_buffer: config.replay_buffer,
            freezer_key_write_buffer: config.key_write_buffer,
            freezer_value_write_buffer: config.value_write_buffer,
            ordinal_write_buffer: config.key_write_buffer,
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive");

    let (actor, mailbox, _) = Actor::init(
        context.child("actor"),
        finalizations_by_height,
        finalized_blocks,
        config,
    )
    .await;
    actor.start(application.clone(), buffer, resolver);
    Validator {
        mailbox,
        application,
    }
}

struct HeaderMismatchInvariant<P: Simplex> {
    verified_contexts: Arc<Mutex<VerifiedContexts<P>>>,
}

impl<P: Simplex> Clone for HeaderMismatchInvariant<P> {
    fn clone(&self) -> Self {
        Self {
            verified_contexts: self.verified_contexts.clone(),
        }
    }
}

impl<P: Simplex> Default for HeaderMismatchInvariant<P> {
    fn default() -> Self {
        Self {
            verified_contexts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<P: Simplex> HeaderMismatchInvariant<P> {
    fn record_verify(&self, context: Ctx<P>, digest: Sha256Digest) {
        self.verified_contexts
            .lock()
            .entry((context.round, digest))
            .or_default()
            .push(context);
    }

    async fn observed_mismatch(
        &self,
        mailbox: &Mailbox<SchemeOf<P>, Standard<B<P>>>,
        round: Round,
        digest: Sha256Digest,
    ) -> bool {
        let Some(block) = mailbox.get_block(&digest).await else {
            return false;
        };
        self.verified_contexts
            .lock()
            .get(&(round, digest))
            .is_some_and(|contexts| contexts.iter().any(|context| context != &block.context()))
    }
}

/// Passively observes the real [`Deferred`] automaton calls made by Simplex.
///
/// The mock application accepts every well-formed block, so a failed certification
/// after the same `(round, digest)` was verified under a context that differs from
/// the block's embedded context means a header-scoped rejection leaked into the
/// matching-header certification.
struct ObservedDeferred<P: Simplex> {
    validator: usize,
    probe_input: Arc<str>,
    context: Arc<Mutex<deterministic::Context>>,
    inner: Builder<P>,
    mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    invariant: HeaderMismatchInvariant<P>,
}

impl<P: Simplex> Clone for ObservedDeferred<P> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator,
            probe_input: self.probe_input.clone(),
            context: self.context.clone(),
            inner: self.inner.clone(),
            mailbox: self.mailbox.clone(),
            invariant: self.invariant.clone(),
        }
    }
}

impl<P: Simplex> Automaton for ObservedDeferred<P> {
    type Context = Ctx<P>;
    type Digest = Sha256Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        self.inner.propose(context).await
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        self.invariant.record_verify(context.clone(), digest);
        if !*VERIFY_PROBE {
            return self.inner.verify(context, digest).await;
        }
        // Ground-truth probe: forward the real verdict unchanged, then off the
        // critical path check whether this call is `Deferred`'s context-mismatch
        // rejection — a `false` verdict whose consensus context disagrees with
        // the stored block's embedded context. That is exactly the branch that
        // writes `false` into the `(round, digest)` gate. The forward happens
        // before the diagnostic `get_block`, so certification timing is not
        // delayed by the lookup.
        let inner_rx = self.inner.verify(context.clone(), digest).await;
        let (tx, rx) = oneshot::channel();
        let mailbox = self.mailbox.clone();
        let probe_context = self.context.lock().child("verify_probe");
        let validator = self.validator;
        let probe_input = self.probe_input.clone();
        probe_context.spawn(move |_| async move {
            let Ok(value) = inner_rx.await else {
                return;
            };
            tx.send_lossy(value);
            if !value
                && let Some(block) = mailbox.get_block(&digest).await
                && block.context() != context
            {
                eprintln!(
                    "[marshal-twins] mismatch-branch rejection: validator={} round={} \
                     digest={digest} input={}",
                    validator, context.round, probe_input
                );
            }
        });
        rx
    }
}

impl<P: Simplex> CertifiableAutomaton for ObservedDeferred<P> {
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        let result = self.inner.certify(round, digest).await;
        let (tx, rx) = oneshot::channel();
        let invariant = self.invariant.clone();
        let mailbox = self.mailbox.clone();
        let context = self.context.lock().child("certify");
        context.spawn(move |_| async move {
            match result.await {
                Ok(value) => {
                    let mismatch = invariant.observed_mismatch(&mailbox, round, digest).await;
                    assert!(
                        value || !mismatch,
                        "marshal Twins invariant violated: certification reused a \
                         header-scoped verification rejection"
                    );
                    tx.send_lossy(value);
                }
                Err(_) => {
                    assert!(
                        !invariant.observed_mismatch(&mailbox, round, digest).await,
                        "marshal Twins invariant violated: certification closed after a \
                         header-scoped verification rejection"
                    );
                }
            }
        });
        rx
    }
}

async fn register_engine_networks<P: Simplex>(
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
) -> ConsensusNetworks<P> {
    let control = oracle.control(validator);
    let vote = control.register(ENGINE_VOTE, TEST_QUOTA).await.unwrap();
    let certificate = control
        .register(ENGINE_CERTIFICATE, TEST_QUOTA)
        .await
        .unwrap();
    let resolver = control.register(ENGINE_RESOLVER, TEST_QUOTA).await.unwrap();
    ConsensusNetworks {
        vote,
        certificate,
        resolver,
    }
}

#[allow(clippy::too_many_arguments)]
fn start_engine<P: Simplex, A>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    elector: TwinElector,
    automaton: A,
    relay: Builder<P>,
    mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    genesis: Sha256Digest,
    partition: String,
    forwarding: commonware_consensus::simplex::ForwardingPolicy,
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
) where
    A: CertifiableAutomaton<Context = Ctx<P>, Digest = Sha256Digest>,
{
    let engine = Engine::new(
        context.child("engine"),
        config::Config {
            blocker: oracle.control(validator),
            scheme,
            elector,
            automaton,
            relay,
            reporter: mailbox,
            partition,
            mailbox_size: NZUsize!(1024),
            epoch: Epoch::zero(),
            floor: Floor::Genesis(genesis),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            view_retention: Delta::new(10),
            skip_timeout: Duration::from_secs(11),
            fetch_concurrent: NZUsize!(1),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
            forwarding,
        },
    );
    engine.start(vote, certificate, resolver);
}

fn trailing_blocks<P: Simplex>(application: &Application<B<P>>, prefix_end: View) -> usize {
    application
        .blocks()
        .values()
        .filter(|block| block.context.round.view() > prefix_end)
        .count()
}

async fn wait_for_liveness<P: Simplex>(
    context: &deterministic::Context,
    honest: &[(usize, Application<B<P>>)],
    prefix_end: View,
    required: usize,
) {
    select! {
        _ = context.sleep(POST_GST_WINDOW) => {
            let progress = honest
                .iter()
                .map(|(idx, application)| {
                    (*idx, trailing_blocks::<P>(application, prefix_end))
                })
                .collect::<Vec<_>>();
            panic!(
                "marshal Twins mutator made no post-prefix progress: \
                 required={required} observed={progress:?}"
            );
        },
        _ = async {
            loop {
                if honest
                    .iter()
                    .all(|(_, application)| {
                        trailing_blocks::<P>(application, prefix_end) >= required
                    })
                {
                    return;
                }
                context.sleep(POLL).await;
            }
        } => {},
    }
}

/// Run one sampled end-to-end standard-marshal Twins mutator.
pub fn fuzz_marshal_twins(input: MarshalTwinsInput) {
    fuzz_marshal_twins_with::<SimplexCertificateMock>(input);
}

/// Run the standard-marshal Twins mutator with ID crypto and the focused
/// split-header strategy.
pub fn fuzz_marshal_twins_id_split_header(mut input: MarshalTwinsInput) {
    input.strategy = StrategyChoice::SplitHeader {
        fault_rounds: input.rounds.into(),
        fault_rounds_bound: input.rounds.into(),
    };
    fuzz_marshal_twins_with::<SimplexId>(input);
}

fn fuzz_marshal_twins_with<P: Simplex>(input: MarshalTwinsInput) {
    let probe_input: Arc<str> = if *VERIFY_PROBE {
        format!("{input:?}").into()
    } else {
        "".into()
    };
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (participants, schemes) = P::setup(&mut context, NAMESPACE, NUM_VALIDATORS);
        let participants: Arc<[PublicKeyOf<P>]> = participants.into();
        let header_attack = matches!(
            &input.strategy,
            StrategyChoice::HeaderScope { .. } | StrategyChoice::SplitHeader { .. }
        );
        // A sustained canonical scenario never elects the fixed
        // `BYZANTINE_IDX` identity. Header-attack inputs therefore sample
        // multiple adjacent rounds and retain only cases with the complete W/W+1
        // topology. Other strategies keep the original scenario selection.
        let mode = if header_attack {
            twins::Mode::Sampled
        } else if input.sustained {
            twins::Mode::Sustained
        } else {
            twins::Mode::Sampled
        };
        let rounds = if header_attack {
            input.rounds.max(4)
        } else {
            input.rounds
        };
        let cases = twins::cases(
            &mut context,
            twins::Framework {
                participants: participants.len(),
                faults: 1,
                rounds: rounds.into(),
                mode,
                max_cases: if header_attack {
                    ATTACK_MAX_CASES
                } else {
                    MAX_CASES
                },
            },
        );
        let fixed_cases = cases
            .into_iter()
            .filter(|case| case.compromised.as_slice() == [BYZANTINE_IDX])
            .collect::<Vec<_>>();
        let (scenario, attack) = if header_attack {
            let attack_cases = fixed_cases
                .into_iter()
                .filter_map(|case| {
                    attack_layout::<P>(&case.scenario, participants.as_ref())
                        .map(|layout| (case.scenario, layout))
                })
                .collect::<Vec<_>>();
            let attack_case_count = attack_cases.len();
            let Some((scenario, layout)) = attack_cases
                .into_iter()
                .nth(input.case_selector as usize % attack_case_count.max(1))
            else {
                return;
            };
            (scenario, Some(layout))
        } else {
            let Some(case) =
                fixed_cases.get(input.case_selector as usize % fixed_cases.len().max(1))
            else {
                return;
            };
            (case.scenario.clone(), None)
        };
        if *VERIFY_PROBE && let Some(layout) = attack {
            eprintln!(
                "[marshal-twins] attack layout: precursor={} attack={} victim={} slow={} fast={}",
                layout.precursor_view, layout.attack_view, layout.victim, layout.slow, layout.fast
            );
        }
        let term_length = TermLength::ONE;
        let elector = twins::Elector::new(
            RoundRobin::<Sha256>::default(),
            &scenario,
            participants.len(),
        );

        let mut oracle = setup_network::<P>(context.child("network"), participants.to_vec()).await;
        setup_network_links::<P>(&mut oracle, participants.as_ref()).await;
        let genesis_block = genesis_block::<P>(participants[0].clone());

        let mut validators = Vec::with_capacity(participants.len());
        let mut networks = Vec::with_capacity(participants.len());
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
            )
            .await;
            validators.push(setup);
            networks.push(Some(
                register_engine_networks::<P>(&oracle, validator.clone()).await,
            ));
        }

        let genesis = genesis_block.digest();
        let mut honest = Vec::with_capacity(participants.len() - 1);
        for idx in 0..participants.len() {
            let validator = participants[idx].clone();
            let validator_context = context.child("validator").with_attribute("index", idx);
            let validator_networks = networks[idx]
                .take()
                .expect("validator networks must be registered once");

            if idx != BYZANTINE_IDX {
                let application = match attack {
                    Some(layout) if layout.delayed_validators.contains(&idx) => {
                        BlockBuilderApp::<Ctx<P>, SchemeOf<P>>::with_verification_delay(
                            layout.precursor_view,
                            ATTACK_VERIFY_DELAY,
                        )
                    }
                    _ => BlockBuilderApp::<Ctx<P>, SchemeOf<P>>::default(),
                };
                let builder = Deferred::new(
                    validator_context.child("deferred"),
                    application,
                    validators[idx].mailbox.clone(),
                    FixedEpocher::new(BLOCKS_PER_EPOCH),
                );
                honest.push((idx, validators[idx].application.clone()));
                let observed: ObservedDeferred<P> = ObservedDeferred {
                    validator: idx,
                    probe_input: probe_input.clone(),
                    context: Arc::new(Mutex::new(
                        validator_context.child("header_mismatch_invariant"),
                    )),
                    inner: builder.clone(),
                    mailbox: validators[idx].mailbox.clone(),
                    invariant: HeaderMismatchInvariant::default(),
                };
                start_engine::<P, _>(
                    validator_context.child("honest"),
                    &oracle,
                    validator,
                    schemes[idx].clone(),
                    elector.clone(),
                    observed,
                    builder,
                    validators[idx].mailbox.clone(),
                    genesis,
                    format!("marshal-twins-honest-{idx}"),
                    input.forwarding,
                    validator_networks.vote,
                    validator_networks.certificate,
                    validator_networks.resolver,
                );
                continue;
            }

            let primary_builder = Deferred::new(
                validator_context.child("deferred_primary"),
                BlockBuilderApp::<Ctx<P>, SchemeOf<P>>::default(),
                validators[idx].mailbox.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );
            let (vote_sender, vote_receiver) = validator_networks.vote;
            let (certificate_sender, certificate_receiver) = validator_networks.certificate;
            let (resolver_sender, resolver_receiver) = validator_networks.resolver;
            let (vote_sender_primary, vote_sender_secondary) =
                vote_sender.split_with(twins_network::vote_forwarder::<P>(
                    participants.clone(),
                    scenario.clone(),
                    term_length,
                ));
            let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
                validator_context.child("vote_split"),
                twins_network::vote_router::<P>(
                    participants.clone(),
                    scenario.clone(),
                    term_length,
                ),
            );
            let (certificate_sender_primary, certificate_sender_secondary) = certificate_sender
                .split_with(twins_network::certificate_forwarder::<P>(
                    participants.clone(),
                    scenario.clone(),
                    term_length,
                    schemes[idx].clone(),
                ));
            let (certificate_receiver_primary, certificate_receiver_secondary) =
                certificate_receiver.split_with(
                    validator_context.child("certificate_split"),
                    twins_network::certificate_router::<P>(
                        participants.clone(),
                        scenario.clone(),
                        term_length,
                        schemes[idx].clone(),
                    ),
                );
            let (resolver_sender_primary, resolver_sender_secondary) =
                resolver_sender.split_with(twins_network::resolver_forwarder::<P>(
                    participants.clone(),
                    scenario.clone(),
                    term_length,
                    schemes[idx].clone(),
                ));
            let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                .split_with(
                    validator_context.child("resolver_split"),
                    twins_network::resolver_router::<P>(
                        participants.clone(),
                        scenario.clone(),
                        term_length,
                        schemes[idx].clone(),
                    ),
                );

            start_engine::<P, _>(
                validator_context.child("primary"),
                &oracle,
                validator.clone(),
                schemes[idx].clone(),
                elector.clone(),
                primary_builder.clone(),
                primary_builder,
                validators[idx].mailbox.clone(),
                genesis,
                "marshal-twins-primary".into(),
                input.forwarding,
                (vote_sender_primary, vote_receiver_primary),
                (certificate_sender_primary, certificate_receiver_primary),
                (resolver_sender_primary, resolver_receiver_primary),
            );
            start_disrupter_with_epoch::<P>(
                validator_context.child("secondary"),
                schemes[idx].clone(),
                &input.strategy,
                input.rounds.into(),
                Epoch::zero(),
                (vote_sender_secondary, vote_receiver_secondary),
                (certificate_sender_secondary, certificate_receiver_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
            );
        }

        let prefix_end = View::new(scenario.rounds().len() as u64);
        wait_for_liveness::<P>(&context, &honest, prefix_end, input.trailing_blocks.into()).await;
        invariant::check_all_blocks(input.trailing_blocks.into(), &honest);
    });
}
