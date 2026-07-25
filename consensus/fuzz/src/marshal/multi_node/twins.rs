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
    ENGINE_CERTIFICATE, ENGINE_RESOLVER, ENGINE_VOTE,
    app::{BlockBuilderApp, RandomizedBlockBuilderApp, RandomizedConfig},
    input::MarshalTwinsInput,
    invariant::{self, HeaderMismatchInvariant},
};
use crate::{
    BYZANTINE_IDX, NAMESPACE, NetworkChannels, POST_GST_WINDOW, SimplexCertificateMock, SimplexId,
    TwinsBackend, TwinsCase, TwinsDisrupter, TwinsSetup, TwinsTopology, run_twins_with_backend,
    simplex::Simplex, strategy::StrategyChoice,
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
    simplex::{Engine, Floor, config, mocks::twins, types::Context as SimplexContext},
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
    simulated::{Config as NetworkConfig, Network as SimulatedNetwork, Oracle},
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
use rand::RngExt as _;
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
type Builder<P, A> = Deferred<deterministic::Context, SchemeOf<P>, A, B<P>, FixedEpocher>;

trait TwinsBlockBuilder<P: Simplex>:
    commonware_consensus::Application<
        deterministic::Context,
        SigningScheme = SchemeOf<P>,
        Context = Ctx<P>,
        Block = B<P>,
        Input = (),
    > + Clone
{
    fn create(config: RandomizedConfig, verification_delay: Option<(View, Duration)>) -> Self;

    fn rejects(config: RandomizedConfig, context: &Ctx<P>) -> bool;
}

impl<P: Simplex> TwinsBlockBuilder<P> for BlockBuilderApp<Ctx<P>, SchemeOf<P>> {
    fn create(_config: RandomizedConfig, verification_delay: Option<(View, Duration)>) -> Self {
        match verification_delay {
            Some((view, delay)) => Self::with_verification_delay(view, delay),
            None => Self::default(),
        }
    }

    fn rejects(_config: RandomizedConfig, _context: &Ctx<P>) -> bool {
        false
    }
}

impl<P: Simplex> TwinsBlockBuilder<P> for RandomizedBlockBuilderApp<Ctx<P>, SchemeOf<P>> {
    fn create(config: RandomizedConfig, verification_delay: Option<(View, Duration)>) -> Self {
        Self::new(config, verification_delay)
    }

    fn rejects(config: RandomizedConfig, context: &Ctx<P>) -> bool {
        config.rejects(context)
    }
}

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

/// Passively observes the real [`Deferred`] automaton calls made by Simplex.
///
/// A failed certification after the same `(round, digest)` was verified under
/// a context that differs from the block's embedded context means a
/// header-scoped rejection leaked into matching-header certification, unless
/// the selected application deliberately rejects the embedded context.
struct ObservedDeferred<P: Simplex, A: TwinsBlockBuilder<P>> {
    validator: usize,
    probe_input: Arc<str>,
    context: Arc<Mutex<deterministic::Context>>,
    inner: Builder<P, A>,
    mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    invariant: HeaderMismatchInvariant<P, RandomizedConfig>,
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> Clone for ObservedDeferred<P, A> {
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

impl<P: Simplex, A: TwinsBlockBuilder<P>> Automaton for ObservedDeferred<P, A> {
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

impl<P: Simplex, A: TwinsBlockBuilder<P>> CertifiableAutomaton for ObservedDeferred<P, A> {
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        let result = self.inner.certify(round, digest).await;
        let (tx, rx) = oneshot::channel();
        let invariant = self.invariant.clone();
        let mailbox = self.mailbox.clone();
        let context = self.context.lock().child("certify");
        context.spawn(move |_| async move {
            match result.await {
                Ok(value) => {
                    invariant
                        .check_certification(&mailbox, round, digest, Some(value))
                        .await;
                    tx.send_lossy(value);
                }
                Err(_) => {
                    invariant
                        .check_certification(&mailbox, round, digest, None)
                        .await;
                }
            }
        });
        rx
    }
}

async fn register_engine_networks<P: Simplex>(
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
) -> NetworkChannels<PublicKeyOf<P>> {
    let control = oracle.control(validator);
    let vote = control.register(ENGINE_VOTE, TEST_QUOTA).await.unwrap();
    let certificate = control
        .register(ENGINE_CERTIFICATE, TEST_QUOTA)
        .await
        .unwrap();
    let resolver = control.register(ENGINE_RESOLVER, TEST_QUOTA).await.unwrap();
    (vote, certificate, resolver)
}

#[allow(clippy::too_many_arguments)]
fn start_engine<P: Simplex, A, App: TwinsBlockBuilder<P>>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    elector: crate::TwinsElector<P>,
    automaton: A,
    relay: Builder<P, App>,
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

struct MarshalTwinsBackend<P: Simplex, A: TwinsBlockBuilder<P>> {
    input: MarshalTwinsInput,
    probe_input: Arc<str>,
    app_config: RandomizedConfig,
    _marker: std::marker::PhantomData<fn() -> (P, A)>,
}

struct MarshalTwinsState<P: Simplex> {
    validators: Vec<Validator<P>>,
    honest: Vec<(usize, Application<B<P>>)>,
    genesis: Sha256Digest,
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> MarshalTwinsBackend<P, A> {
    fn new(input: MarshalTwinsInput, probe_input: Arc<str>) -> Self {
        let header_attack = matches!(
            input.strategy,
            StrategyChoice::HeaderScope { .. } | StrategyChoice::SplitHeader { .. }
        );
        let randomized_rounds = if header_attack {
            input.rounds.max(4)
        } else {
            input.rounds
        };
        let mut rng = FuzzRng::new(input.raw_bytes.clone());
        let app_config = RandomizedConfig::new(rng.random(), View::new(randomized_rounds.into()));
        Self {
            input,
            probe_input,
            app_config,
            _marker: std::marker::PhantomData,
        }
    }

    fn header_attack(&self) -> bool {
        matches!(
            self.input.strategy,
            StrategyChoice::HeaderScope { .. } | StrategyChoice::SplitHeader { .. }
        )
    }
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> TwinsBackend<P> for MarshalTwinsBackend<P, A> {
    type State = MarshalTwinsState<P>;
    type Case = Option<AttackLayout>;

    async fn setup(&mut self, context: &mut deterministic::Context) -> TwinsSetup<P, Self::State> {
        let (participants, schemes) = P::setup(context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
        setup_network_links::<P>(&mut oracle, &participants).await;
        let genesis_block = genesis_block::<P>(participants[0].clone());
        let genesis = genesis_block.digest();
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
                genesis,
            },
        }
    }

    fn term_length(&self) -> TermLength {
        TermLength::ONE
    }

    fn framework(
        &mut self,
        _context: &mut deterministic::Context,
        participants: usize,
    ) -> twins::Framework {
        let header_attack = self.header_attack();
        twins::Framework {
            participants,
            faults: 1,
            rounds: if header_attack {
                self.input.rounds.max(4).into()
            } else {
                self.input.rounds.into()
            },
            mode: if header_attack || !self.input.sustained {
                twins::Mode::Sampled
            } else {
                twins::Mode::Sustained
            },
            max_cases: if header_attack {
                ATTACK_MAX_CASES
            } else {
                MAX_CASES
            },
        }
    }

    fn select_case(
        &mut self,
        _context: &mut deterministic::Context,
        participants: &[PublicKeyOf<P>],
        cases: Vec<twins::Case>,
    ) -> Option<TwinsCase<Self::Case>> {
        let fixed_cases = cases
            .into_iter()
            .filter(|case| case.compromised.as_slice() == [BYZANTINE_IDX])
            .collect::<Vec<_>>();
        let (case, attack) = if self.header_attack() {
            let attack_cases = fixed_cases
                .into_iter()
                .filter_map(|case| {
                    attack_layout::<P>(&case.scenario, participants).map(|layout| (case, layout))
                })
                .collect::<Vec<_>>();
            let count = attack_cases.len();
            let (case, layout) = attack_cases
                .into_iter()
                .nth(self.input.case_selector as usize % count.max(1))?;
            (case, Some(layout))
        } else {
            let count = fixed_cases.len();
            let case = fixed_cases
                .into_iter()
                .nth(self.input.case_selector as usize % count.max(1))?;
            (case, None)
        };
        if *VERIFY_PROBE && let Some(layout) = attack {
            eprintln!(
                "[marshal-twins] attack layout: precursor={} attack={} victim={} slow={} fast={}",
                layout.precursor_view, layout.attack_view, layout.victim, layout.slow, layout.fast
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
        // The compromised primary may propose a block that the randomized
        // honest application rejects; honest proposers never reject their own.
        let primary_builder = Deferred::new(
            context.child("deferred"),
            BlockBuilderApp::<Ctx<P>, SchemeOf<P>>::default(),
            state.validators[idx].mailbox.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );
        start_engine::<P, _, _>(
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
            Some(layout) if layout.delayed_validators.contains(&idx) => {
                Some((layout.precursor_view, ATTACK_VERIFY_DELAY))
            }
            _ => None,
        };
        let application = A::create(self.app_config, verification_delay);
        let builder = Deferred::new(
            context.child("deferred"),
            application,
            state.validators[idx].mailbox.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );
        state
            .honest
            .push((idx, state.validators[idx].application.clone()));
        let observed: ObservedDeferred<P, A> = ObservedDeferred {
            validator: idx,
            probe_input: self.probe_input.clone(),
            context: Arc::new(Mutex::new(context.child("header_mismatch_invariant"))),
            inner: builder.clone(),
            mailbox: state.validators[idx].mailbox.clone(),
            invariant: HeaderMismatchInvariant::new(self.app_config, A::rejects),
        };
        start_engine::<P, _, _>(
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
        wait_for_liveness::<P>(
            context,
            &state.honest,
            prefix_end,
            self.input.trailing_blocks.into(),
        )
        .await;
    }

    fn check_invariants(
        &mut self,
        _context: &deterministic::Context,
        state: &mut Self::State,
        _topology: &TwinsTopology<P, Self::Case>,
    ) {
        invariant::check_all_blocks(self.input.trailing_blocks.into(), &state.honest);
    }
}

/// Run one sampled end-to-end standard-marshal Twins mutator.
pub fn fuzz_marshal_twins(input: MarshalTwinsInput) {
    fuzz_marshal_twins_with::<
        SimplexCertificateMock,
        BlockBuilderApp<Ctx<SimplexCertificateMock>, SchemeOf<SimplexCertificateMock>>,
    >(input);
}

/// Run standard-marshal Twins with input-derived application behavior.
pub fn fuzz_marshal_twins_randomized_app(input: MarshalTwinsInput) {
    fuzz_marshal_twins_with::<
        SimplexCertificateMock,
        RandomizedBlockBuilderApp<Ctx<SimplexCertificateMock>, SchemeOf<SimplexCertificateMock>>,
    >(input);
}

/// Run the standard-marshal Twins mutator with ID crypto and the focused
/// split-header strategy.
pub fn fuzz_marshal_twins_id_split_header(mut input: MarshalTwinsInput) {
    input.strategy = StrategyChoice::SplitHeader {
        fault_rounds: input.rounds.into(),
        fault_rounds_bound: input.rounds.into(),
    };
    fuzz_marshal_twins_with::<SimplexId, BlockBuilderApp<Ctx<SimplexId>, SchemeOf<SimplexId>>>(
        input,
    );
}

fn fuzz_marshal_twins_with<P: Simplex, A: TwinsBlockBuilder<P>>(input: MarshalTwinsInput) {
    let probe_input: Arc<str> = if *VERIFY_PROBE {
        format!("{input:?}").into()
    } else {
        "".into()
    };
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let mut backend = MarshalTwinsBackend::<P, A>::new(input, probe_input);
        run_twins_with_backend::<P, _>(&mut context, &mut backend).await;
    });
}
