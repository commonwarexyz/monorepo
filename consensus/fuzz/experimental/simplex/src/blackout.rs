//! Blackout: every live validator of a committee restarts inside one view, and
//! the cluster must still move.
//!
//! A voter journals its own votes and certificates, but the batcher keeps peer
//! votes only in memory, and journal replay does not re-seed the batcher with the
//! node's own votes (`consensus/src/simplex/actors/voter/actor.rs`, the replay
//! comment "If this is not the case (cluster-wide shutdown), we will recover when
//! timing out"). Recovery after a cluster-wide shutdown therefore rests on the
//! timeout retry of each replayed vote reaching every batcher, the node's own
//! included.
//!
//! The scenario is a script with fuzzer-chosen timing on the deterministic
//! runtime: four participants on the certificate mock scheme, participant 0
//! absent when `absent` is on (it never runs an engine, so the three live
//! validators are exactly a quorum), lossless links between live validators, and
//! up to [`MAX_BLACKOUTS`] blackouts in sequence on the same cluster. A blackout
//! runs connected, removes every link between live validators, records whether
//! every validator of the crash set has reported its own nullify for its current
//! view, crashes the crash set at one instant, waits, restores the links and
//! restarts the crashed validators on their storage.
//!
//! After the last blackout is healed (time `T`) every live validator must report
//! a finalization above the highest finalization any live validator reported up
//! to `T`, within [`LIVENESS_WINDOW`] (`blackout-liveness`). The run then settles and applies
//! the crash-fault runner's safety checks to every live validator (`blackout-safety`).
//!
//! Not asserted: a recovery time, liveness during or between blackouts, Byzantine
//! validators, storage loss, other schemes, and the layers above the engine.

use crate::{
    chaos::{
        runner::{
            CHAOS_FINISH_SETTLE, ChaosReporter, ChaosValidator, check_safety, restart_durable,
        },
        watch::Checker,
    },
    evidence,
    mallory::runner::{FinalizationClock, StepBoundary, liveness_target, wait_for_step_boundary},
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    Handoff, IndexSubscription, Monitor as _,
    simplex::{ForwardPolicy, mocks::relay},
    types::{TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BlockFilterChoice, CertifyChoice, N4F0C4, ReporterWiring, build_validator_with_reporter,
    setup_network,
    simplex::{Simplex, SimplexCertificateMock},
    state_bounds,
    strategy::StrategyChoice,
    utils::Partition,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{Clock, Metrics as _, Runner, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize, channel::ring, probability};
use futures::future::join_all;
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Most input bytes kept as the runtime's entropy.
pub const MAX_RAW_BYTES: usize = commonware_consensus_fuzz_core::MAX_RAW_BYTES;
/// `absent` is decoded from `0..=ABSENT_DRAW_MAX`; only the top value turns it off.
pub const ABSENT_DRAW_MAX: u8 = 7;
/// Link latency bounds, in milliseconds.
pub const MIN_LATENCY_MS: u64 = 1;
pub const MAX_LATENCY_MS: u64 = 50;
/// Upper bound of the link jitter, in milliseconds.
pub const MAX_JITTER_MS: u64 = 50;
/// Bounds of the number of blackouts in one run.
pub const MIN_BLACKOUTS: usize = 1;
pub const MAX_BLACKOUTS: usize = 3;
/// Upper bound of the connected run before a blackout, in milliseconds.
pub const MAX_START_MS: u64 = 3_000;
/// Upper bound of the isolation before the crash, in milliseconds. Decoded in
/// reverse, so a short input gets the longest isolation.
pub const MAX_ISOLATE_MS: u64 = 5_000;
/// Crash masks are decoded from `0..=MAX_CRASH_MASK`.
pub const MAX_CRASH_MASK: u8 = 0b111;
/// Upper bound of the time every crashed validator stays down, in milliseconds.
pub const MAX_DOWN_MS: u64 = 3_000;
/// Upper bound of the time between two restart starts, in milliseconds.
pub const MAX_STAGGER_MS: u64 = 2_000;

/// Participants in the committee.
pub const PARTICIPANTS: usize = 4;
/// The participant that never runs an engine when `absent` is on.
pub const ABSENT_PARTICIPANT: usize = 0;
/// Engine leader timeout; the same value the crash-fault runner's restart uses.
pub const LEADER_TIMEOUT: Duration = Duration::from_secs(1);
/// Engine certification timeout; the same value the crash-fault runner's
/// restart uses.
pub const CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounded wait, from `T`, for a fresh finalization at every live validator.
pub const LIVENESS_WINDOW: Duration = Duration::from_secs(120);
/// Absolute finalization floor of the liveness target; the fresh frontier above
/// the baseline always dominates it.
const REQUIRED_CONTAINERS: u64 = 1;

/// One blackout of the script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blackout {
    /// Connected run before the links are removed.
    pub start_ms: u64,
    /// Isolation before the crash.
    pub isolate_ms: u64,
    /// Bit `i` selects live validator `i + 1`; zero, or a mask that selects no
    /// live validator, selects every live validator.
    pub crash_mask: u8,
    /// Time every crashed validator stays down before the first restart.
    pub down_ms: u64,
    /// Time from the start of one restart to the start of the next.
    pub stagger_ms: u64,
    /// Restore the links before the first restart instead of after the last.
    pub relink_first: bool,
}

impl Blackout {
    /// The participant indices this blackout crashes, in index order.
    pub fn crash_set(&self, absent: bool) -> Vec<usize> {
        let live = live_validators(absent);
        let selected: Vec<usize> = (0..MAX_CRASH_MASK.count_ones() as usize)
            .filter(|bit| self.crash_mask & (1 << bit) != 0)
            .map(|bit| bit + 1)
            .filter(|validator| live.contains(validator))
            .collect();
        if selected.is_empty() { live } else { selected }
    }
}

/// The scenario's input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzInput {
    /// The runtime's entropy: a copy of the whole input, at most
    /// [`MAX_RAW_BYTES`].
    pub raw_bytes: Vec<u8>,
    /// Participant 0 never runs an engine.
    pub absent: bool,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    /// At least [`MIN_BLACKOUTS`], at most [`MAX_BLACKOUTS`].
    pub blackouts: Vec<Blackout>,
}

impl<'a> Arbitrary<'a> for Blackout {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            start_ms: u.int_in_range(0..=MAX_START_MS)?,
            isolate_ms: MAX_ISOLATE_MS - u.int_in_range(0..=MAX_ISOLATE_MS)?,
            crash_mask: u.int_in_range(0..=MAX_CRASH_MASK)?,
            down_ms: u.int_in_range(0..=MAX_DOWN_MS)?,
            stagger_ms: u.int_in_range(0..=MAX_STAGGER_MS)?,
            relink_first: u.int_in_range(0..=1u8)? == 0,
        })
    }
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_bytes = u
            .peek_bytes(u.len().min(MAX_RAW_BYTES))
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let absent = u.int_in_range(0..=ABSENT_DRAW_MAX)? != ABSENT_DRAW_MAX;
        let latency_ms = u.int_in_range(MIN_LATENCY_MS..=MAX_LATENCY_MS)?;
        let jitter_ms = u.int_in_range(0..=MAX_JITTER_MS)?;
        let count = u.int_in_range(MIN_BLACKOUTS..=MAX_BLACKOUTS)?;
        let blackouts = (0..count)
            .map(|_| Blackout::arbitrary(u))
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            raw_bytes,
            absent,
            latency_ms,
            jitter_ms,
            blackouts,
        })
    }
}

/// What the cut of one blackout read for one validator of its crash set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutValue {
    pub validator: usize,
    /// The engine's `current_view` gauge.
    pub current_view: u64,
    /// The validator's retained reporter holds its own nullify at
    /// `current_view`.
    pub own_nullify: bool,
}

/// The result of one blackout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlackoutReport {
    pub crash_set: Vec<usize>,
    /// Every validator of the crash set had reported its own nullify for its
    /// current view at the cut.
    pub all_nullified: bool,
    /// The values the cut read, one per validator of the crash set.
    pub cut: Vec<CutValue>,
}

/// The result of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub blackouts: Vec<BlackoutReport>,
    /// The highest finalized view any live validator reported up to `T`.
    pub max_baseline: u64,
    /// Simulated time from `T` to the last live validator's fresh finalization.
    pub recovery: Duration,
    /// The run had the shape a cluster-wide restart after a nullify needs:
    /// participant 0 absent, every live validator crashed, and `all_nullified`
    /// in some blackout.
    pub full_restart_after_nullify: bool,
}

/// A fault planted at the observation boundary of an invariant, for negative
/// controls. [`fuzz`] and [`run`] plant nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    None,
    /// From `T` on, no finalization of `validator` reaches the liveness check.
    SilenceFinalizations {
        validator: usize,
    },
    /// Before the end checks, `validator`'s reporter gets a finalize vote for a
    /// second payload at the highest view it finalize-voted for.
    ConflictingFinalization {
        validator: usize,
    },
}

/// One step of a run, for tests that check the script's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    /// An engine was built for `validator` at setup.
    Started {
        validator: usize,
        generation: u32,
        partition: String,
    },
    Linked {
        from: usize,
        to: usize,
        latency_ms: u64,
        jitter_ms: u64,
        /// Every message on the link is delivered.
        lossless: bool,
    },
    Unlinked {
        from: usize,
        to: usize,
    },
    /// Blackout `index` begins its connected run.
    BlackoutStarted {
        index: usize,
    },
    /// Every link between live validators is gone.
    Isolated,
    /// The cut of step 3 was read.
    Cut,
    /// Both task handles of `validator` were aborted; every validator of the
    /// crash set is aborted at one instant, before any handle is awaited.
    Aborted {
        validator: usize,
    },
    /// Both task handles of `validator` finished.
    Stopped {
        validator: usize,
    },
    /// Every link between live validators is back.
    Relinked,
    /// The restart of `validator` begins; restarts of one blackout begin
    /// `stagger_ms` apart, in index order.
    Restarting {
        validator: usize,
    },
    /// `validator` was rebuilt on its partition.
    Restarted {
        validator: usize,
        generation: u32,
        partition: String,
        same_reporter: bool,
    },
    /// `T`: the last blackout is healed.
    Healed {
        max_baseline: u64,
        target: u64,
    },
    /// `validator` first reported a finalization at or above the target.
    Crossed {
        validator: usize,
        view: u64,
    },
    /// The settle window after the liveness check ended.
    Settled,
    /// The crash-fault runner's safety checks passed over every live validator.
    SafetyChecked {
        validators: Vec<usize>,
    },
}

/// An [`Observation`] with its simulated time since the run started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub at: Duration,
    pub what: Observation,
}

/// The participant indices that run an engine.
pub fn live_validators(absent: bool) -> Vec<usize> {
    (0..PARTICIPANTS)
        .filter(|index| !absent || *index != ABSENT_PARTICIPANT)
        .collect()
}

/// Whether `nullifies` (a reporter's map from view to nullify signers) holds
/// `me` at `current_view`. A gauge of 0 never matches.
pub fn own_nullify_at<K: Eq + std::hash::Hash>(
    nullifies: &HashMap<View, HashSet<K>>,
    me: &K,
    current_view: u64,
) -> bool {
    current_view > 0
        && nullifies
            .get(&View::new(current_view))
            .is_some_and(|signers| signers.contains(me))
}

/// The `all_nullified` flag of a cut: every validator was past view 0 and held
/// its own nullify at its current view.
pub fn all_nullified(cut: &[CutValue]) -> bool {
    cut.iter()
        .all(|value| value.current_view > 0 && value.own_nullify)
}

/// The fuzz entry.
pub fn fuzz(input: FuzzInput) {
    run(input);
}

/// Run one scenario and return its report.
pub fn run(input: FuzzInput) -> Report {
    run_inner(input, Plant::None, false).0
}

/// [`run`] with a planted fault, also returning every [`Observation`].
pub fn run_observed(input: FuzzInput, plant: Plant) -> (Report, Vec<Observed>) {
    run_inner(input, plant, true)
}

/// The shared constructors' input for this scenario: four participants, connected,
/// every engine certifying, single-view terms, no lookahead.
fn base_input(raw_bytes: Vec<u8>) -> commonware_consensus_fuzz_core::FuzzInput {
    commonware_consensus_fuzz_core::FuzzInput {
        raw_bytes,
        required_containers: REQUIRED_CONTAINERS,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        heterogeneous_optimism: false,
        handoff: Handoff::Wait,
        degraded_network: false,
        configuration: N4F0C4,
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
        mailbox_size: commonware_consensus_fuzz_core::DEFAULT_MAILBOX_SIZE,
        forwarding: ForwardPolicy::Disabled,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    }
}

struct Recorder {
    enabled: bool,
    start: SystemTime,
    events: Vec<Observed>,
}

impl Recorder {
    fn push(&mut self, context: &deterministic::Context, what: Observation) {
        self.push_at(context.current(), what);
    }

    fn push_at(&mut self, at: SystemTime, what: Observation) {
        if self.enabled {
            let at = at
                .duration_since(self.start)
                .expect("simulated time never runs backwards");
            self.events.push(Observed { at, what });
        }
    }
}

struct Links<K: commonware_cryptography::PublicKey> {
    oracle: Oracle<K, deterministic::Context>,
    participants: Vec<K>,
    live: Vec<usize>,
    link: Link,
}

impl<K: commonware_cryptography::PublicKey> Links<K> {
    async fn remove(
        &self,
        from: usize,
        to: usize,
        recorder: &mut Recorder,
        context: &deterministic::Context,
    ) {
        self.oracle
            .remove_link(
                self.participants[from].clone(),
                self.participants[to].clone(),
            )
            .await
            .unwrap_or_else(|error| {
                panic!("blackout harness: remove_link failed for {from}->{to}: {error}")
            });
        recorder.push(context, Observation::Unlinked { from, to });
    }

    async fn add(
        &self,
        from: usize,
        to: usize,
        recorder: &mut Recorder,
        context: &deterministic::Context,
    ) {
        self.oracle
            .add_link(
                self.participants[from].clone(),
                self.participants[to].clone(),
                self.link.clone(),
            )
            .await
            .unwrap_or_else(|error| {
                panic!("blackout harness: add_link failed for {from}->{to}: {error}")
            });
        recorder.push(
            context,
            Observation::Linked {
                from,
                to,
                latency_ms: self.link.latency.as_millis() as u64,
                jitter_ms: self.link.jitter.as_millis() as u64,
                lossless: self.link.success_rate == probability!(1.0),
            },
        );
    }

    fn live_pairs(&self) -> Vec<(usize, usize)> {
        let mut pairs = Vec::new();
        for &from in &self.live {
            for &to in &self.live {
                if from != to {
                    pairs.push((from, to));
                }
            }
        }
        pairs
    }

    async fn isolate(&self, recorder: &mut Recorder, context: &deterministic::Context) {
        for (from, to) in self.live_pairs() {
            self.remove(from, to, recorder, context).await;
        }
        recorder.push(context, Observation::Isolated);
    }

    async fn relink(&self, recorder: &mut Recorder, context: &deterministic::Context) {
        for (from, to) in self.live_pairs() {
            self.add(from, to, recorder, context).await;
        }
        recorder.push(context, Observation::Relinked);
    }
}

fn run_inner(input: FuzzInput, plant: Plant, observe: bool) -> (Report, Vec<Observed>) {
    type P = SimplexCertificateMock;

    let base = base_input(input.raw_bytes.clone());
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let executor = deterministic::Runner::new(deterministic::Config::new().with_rng(rng));
    executor.start(|mut context| async move {
        let mut recorder = Recorder {
            enabled: observe,
            start: context.current(),
            events: Vec::new(),
        };
        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &base).await;
        let live = live_validators(input.absent);
        let term_length = P::effective_term_length(base.term_length);
        let relay = Arc::new(relay::Relay::new());

        // Replace the default mesh of `setup_network`: links only between live validators,
        // with the input's latency and jitter.
        let links = Links {
            oracle: oracle.clone(),
            participants: participants.clone(),
            live: live.clone(),
            link: Link {
                latency: Duration::from_millis(input.latency_ms),
                jitter: Duration::from_millis(input.jitter_ms),
                success_rate: probability!(1.0),
            },
        };
        for from in 0..PARTICIPANTS {
            for to in 0..PARTICIPANTS {
                if from != to {
                    links.remove(from, to, &mut recorder, &context).await;
                }
            }
        }
        links.relink(&mut recorder, &context).await;

        let mut managed: HashMap<usize, ChaosValidator<P>> = HashMap::new();
        for &i in &live {
            let validator = participants[i].clone();
            let (pending, recovered, resolver) = registrations
                .remove(&validator)
                .expect("blackout harness: participant was not registered");
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let partition = validator.to_string();
            let mv = build_validator_with_reporter::<P, _, _, _, _, _, _, _, _>(
                None,
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator,
                P::elector(term_length, base.optimistic_views),
                relay.clone(),
                LEADER_TIMEOUT,
                CERTIFICATION_TIMEOUT,
                base.mailbox_size,
                base.forwarding,
                partition,
                pending,
                recovered,
                resolver,
                base.certify,
                base.handoff,
                base.reporting,
            );
            recorder.push(
                &context,
                Observation::Started {
                    validator: i,
                    generation: mv.generation(),
                    partition: mv.partition().to_string(),
                },
            );
            managed.insert(i, mv);
        }
        let reporters: HashMap<usize, ChaosReporter<P>> =
            managed.iter().map(|(i, mv)| (*i, mv.reporter())).collect();

        // Subscribe once per live reporter; a restart keeps the reporter, so its
        // monitor keeps delivering.
        let mut clock = FinalizationClock {
            latest: vec![0u64; PARTICIPANTS],
            monitors: Vec::with_capacity(live.len()),
        };
        for &i in &live {
            let (latest, monitor): (View, IndexSubscription<View>) =
                reporters[&i].clone().subscribe().await;
            clock.latest[i] = latest.get();
            clock.monitors.push((i, monitor));
        }

        let mut blackout_reports = Vec::with_capacity(input.blackouts.len());
        for (index, blackout) in input.blackouts.iter().enumerate() {
            recorder.push(&context, Observation::BlackoutStarted { index });
            context
                .sleep(Duration::from_millis(blackout.start_ms))
                .await;
            links.isolate(&mut recorder, &context).await;
            context
                .sleep(Duration::from_millis(blackout.isolate_ms))
                .await;

            // The cut: one metrics snapshot and one reporter read per validator,
            // with no await in between, so every value is from one instant.
            let crash_set = blackout.crash_set(input.absent);
            let metrics = context.encode();
            let cut: Vec<CutValue> = crash_set
                .iter()
                .map(|&i| {
                    let me = &participants[i];
                    let current_view =
                        evidence::current_view(&metrics, &state_bounds::Node::public_key(me));
                    let own_nullify =
                        own_nullify_at(&reporters[&i].inner().nullifies.lock(), me, current_view);
                    CutValue {
                        validator: i,
                        current_view,
                        own_nullify,
                    }
                })
                .collect();
            recorder.push(&context, Observation::Cut);
            blackout_reports.push(BlackoutReport {
                crash_set: crash_set.clone(),
                all_nullified: all_nullified(&cut),
                cut,
            });

            // Crash the whole set at one instant: abort every handle before
            // awaiting any of them.
            let mut handles = Vec::with_capacity(crash_set.len() * 2);
            for &i in &crash_set {
                let mv = managed
                    .get_mut(&i)
                    .expect("crash set holds live validators");
                for handle in [mv.take_engine_handle(), mv.take_app_handle()]
                    .into_iter()
                    .flatten()
                {
                    handle.abort();
                    handles.push(handle);
                }
                recorder.push(&context, Observation::Aborted { validator: i });
            }
            for handle in handles {
                let _ = handle.await;
            }
            for &i in &crash_set {
                managed
                    .get_mut(&i)
                    .expect("crash set holds live validators")
                    .mark_crashed();
                recorder.push(&context, Observation::Stopped { validator: i });
            }

            context.sleep(Duration::from_millis(blackout.down_ms)).await;
            if blackout.relink_first {
                links.relink(&mut recorder, &context).await;
            }
            // Restart `k` of the crash set starts `k * stagger_ms` after the
            // first one, so the restarts run concurrently and a zero stagger
            // starts every restart at one instant.
            let participants_ref = &participants;
            let relay_ref = &relay;
            let base_ref = &base;
            let context_ref = &context;
            let restarts: Vec<_> = crash_set
                .iter()
                .enumerate()
                .map(|(position, &i)| {
                    let mut mv = managed.remove(&i).expect("crash set holds live validators");
                    let mut oracle = oracle.clone();
                    let offset = Duration::from_millis(blackout.stagger_ms * position as u64);
                    async move {
                        if !offset.is_zero() {
                            context_ref.sleep(offset).await;
                        }
                        let started = context_ref.current();
                        restart_durable::<P>(
                            &mut mv,
                            context_ref,
                            &mut oracle,
                            participants_ref,
                            relay_ref,
                            base_ref,
                            Duration::ZERO,
                        )
                        .await;
                        (i, mv, started, context_ref.current())
                    }
                })
                .collect();
            let mut steps = Vec::with_capacity(crash_set.len() * 2);
            for (i, mv, started, finished) in join_all(restarts).await {
                let same_reporter = Arc::ptr_eq(
                    &mv.reporter().inner().finalizes,
                    &reporters[&i].inner().finalizes,
                );
                steps.push((started, Observation::Restarting { validator: i }));
                steps.push((
                    finished,
                    Observation::Restarted {
                        validator: i,
                        generation: mv.generation(),
                        partition: mv.partition().to_string(),
                        same_reporter,
                    },
                ));
                managed.insert(i, mv);
            }
            steps.sort_by_key(|(at, _)| *at);
            for (at, what) in steps {
                recorder.push_at(at, what);
            }
            if !blackout.relink_first {
                links.relink(&mut recorder, &context).await;
            }
        }

        // `T`. A planted silence replaces the validator's monitor with one whose
        // sender is held and never used.
        let mut _silenced = None;
        if let Plant::SilenceFinalizations { validator } = plant {
            let (sender, receiver) = ring::channel::<View>(NZUsize!(1));
            let entry = clock
                .monitors
                .iter_mut()
                .find(|(node, _)| *node == validator)
                .expect("plant names a live validator");
            entry.1 = receiver;
            _silenced = Some(sender);
        }
        let live_set: HashSet<usize> = live.iter().copied().collect();
        clock.drain();
        let max_baseline = clock.baseline(&live_set);
        let target = liveness_target(REQUIRED_CONTAINERS, max_baseline);
        let healed = context.current();
        let deadline = healed + LIVENESS_WINDOW;
        recorder.push(
            &context,
            Observation::Healed {
                max_baseline,
                target,
            },
        );

        let mut crossed: HashMap<usize, SystemTime> = HashMap::new();
        loop {
            clock.drain();
            for &i in &live {
                if clock.latest[i] >= target && !crossed.contains_key(&i) {
                    crossed.insert(i, context.current());
                    recorder.push(
                        &context,
                        Observation::Crossed {
                            validator: i,
                            view: clock.latest[i],
                        },
                    );
                }
            }
            if crossed.len() == live.len() {
                break;
            }
            let lagging: HashSet<usize> = live
                .iter()
                .copied()
                .filter(|i| !crossed.contains_key(i))
                .collect();
            if matches!(
                wait_for_step_boundary(
                    &mut context,
                    &mut clock,
                    &lagging,
                    target.saturating_sub(1),
                    deadline,
                )
                .await,
                StepBoundary::Timeout
            ) {
                clock.drain();
                let mut diag = String::new();
                for &i in &live {
                    if clock.latest[i] >= target {
                        continue;
                    }
                    let reporter = reporters[&i].inner();
                    let notarization = reporter
                        .notarizations
                        .lock()
                        .keys()
                        .copied()
                        .max()
                        .unwrap_or_else(View::zero);
                    let nullification = reporter
                        .nullifications
                        .lock()
                        .keys()
                        .copied()
                        .max()
                        .unwrap_or_else(View::zero);
                    let _ = write!(
                        diag,
                        " validator{i}={{finalization={} notarization={notarization} \
                         nullification={nullification}}}",
                        clock.latest[i],
                    );
                }
                panic!(
                    "blackout-liveness: no fresh finalization from every live validator within \
                     {LIVENESS_WINDOW:?} of the last heal (target={target} \
                     max_baseline={max_baseline}); lagging:{diag}"
                );
            }
        }
        let last = crossed
            .values()
            .copied()
            .max()
            .expect("every live validator crossed");
        let recovery = last
            .duration_since(healed)
            .expect("a crossing never precedes the heal");

        context.sleep(CHAOS_FINISH_SETTLE).await;
        clock.drain();
        recorder.push(&context, Observation::Settled);

        if let Plant::ConflictingFinalization { validator } = plant {
            let reporter = reporters[&validator].inner();
            let mut finalizes = reporter.finalizes.lock();
            let view = *finalizes
                .keys()
                .max()
                .expect("plant needs a finalize vote at the validator");
            finalizes
                .entry(view)
                .or_default()
                .entry(Sha256Digest::from([0xb7; 32]))
                .or_default()
                .insert(participants[validator].clone());
        }

        let live_reporters: Vec<ChaosReporter<P>> =
            live.iter().map(|i| reporters[i].clone()).collect();
        let mut checker = Checker::new();
        check_safety::<P>(
            &mut checker,
            &live_reporters,
            term_length,
            base.optimistic_views,
            base.handoff,
        );
        recorder.push(
            &context,
            Observation::SafetyChecked {
                validators: live.clone(),
            },
        );

        let full_restart_after_nullify = input.absent
            && blackout_reports
                .iter()
                .any(|report| report.all_nullified && report.crash_set == live);
        let report = Report {
            blackouts: blackout_reports,
            max_baseline,
            recovery,
            full_restart_after_nullify,
        };
        (report, recorder.events)
    })
}
