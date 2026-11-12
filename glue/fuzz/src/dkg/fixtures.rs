//! What the tests of the DKG modules share: fixed tapes and controls, the
//! identity sets and epoch descriptions a test builds records over, and what
//! the tests of the restart drivers sample, watch, and search runs with.

use super::{
    Cut, CutScope, EnvironmentControls, Info, LinkControls, MockGroup, Outcome, PublicKey,
    RESHARE_IDENTITIES, Rotation,
    environment::{Event, Program, Stack},
    pacing::PacedCounts,
    public_keys,
    reshare_input::ROTATIONS,
    signers,
};
use crate::stateful::runner::Panic;
use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::deal,
    primitives::{group::Share, sharing::Mode},
};
use commonware_glue::dkg::types::EpochOutcome;
use commonware_runtime::{Handle, Storage as _, deterministic};
use commonware_utils::{N3f1, TestRng, ordered::Set, sequence::Unit, sync::Mutex};
use std::{future::Future, sync::Arc, thread};

/// What a half of the compromised identity says when it stops on the dealing
/// it stored being contradicted by the one the ceremony selected.
const CONTRADICTED: &str = "InvalidPersistedDealing";

/// Whether a half of the run `panics` were raised in stopped on a
/// contradicted dealing. The oracle never reads what a panic says; a test
/// recognises the run it is about by it.
pub(super) fn contradicted(panics: &[Panic]) -> bool {
    panics
        .iter()
        .any(|panic| panic.message.contains(CONTRADICTED))
}

/// The engine each of `panics` is attributed to and the last line of what it
/// said, in the order they were raised.
pub(super) fn raised(panics: Vec<Panic>) -> Vec<(Option<usize>, String)> {
    panics
        .into_iter()
        .map(|Panic { engine, message }| {
            let said = message.lines().last().unwrap_or_default().to_string();
            (engine, said)
        })
        .collect()
}

/// The tape of a fixed input.
pub(super) fn tape(seed: u16) -> Vec<u8> {
    (0..96u16)
        .map(|byte| (byte.wrapping_mul(31).wrapping_add(seed) ^ (seed >> 8)) as u8)
        .collect()
}

/// The input `bytes` decode to, the way libFuzzer's are decoded.
pub(super) fn decode<I: for<'a> Arbitrary<'a>>(bytes: &[u8]) -> I {
    I::arbitrary(&mut Unstructured::new(bytes)).expect("every input decodes")
}

/// Links that only delay.
pub(super) const CLEAN: LinkControls = LinkControls {
    latency_ms: 10,
    jitter_ms: 1,
    delivery_percent: 100,
};

/// Slow, jittery, lossy links.
pub(super) const LOSSY: LinkControls = LinkControls {
    latency_ms: 40,
    jitter_ms: 30,
    delivery_percent: 85,
};

/// The cut of `scope` around `identity` that starts `delay` steps after the
/// cut before it has ended and lasts `duration` steps.
pub(super) const fn cut(delay: u8, duration: u8, identity: u8, scope: CutScope) -> Cut {
    Cut {
        delay,
        duration,
        identity,
        scope,
    }
}

/// The links, the cut, and the seed of the tape of an input on which a
/// ceremony fails under one restart. The schedule crashes the first identity
/// before any ack reaches it and keeps it down past the midpoint, so it posts
/// no dealer log, and the cut of the link between two others leaves each of
/// them with two players unacknowledged, more than a log may reveal. One
/// usable log remains where a quorum of them is needed.
pub(super) fn failing() -> (LinkControls, Vec<Cut>, u16) {
    let links = LinkControls {
        latency_ms: 50,
        jitter_ms: 0,
        delivery_percent: 100,
    };
    (links, vec![cut(0, 64, 1, CutScope::To(2))], 2136)
}

/// The schedule the tape of [`failing`] draws: the crash of the first
/// identity and its restart, in milliseconds from the start of the run.
pub(super) fn failing_schedule() -> Vec<(u128, Event)> {
    vec![(50, Event::Crash(0)), (32_050, Event::Restart(0))]
}

/// The committee never changes.
pub(super) const STAY: [Rotation; ROTATIONS] = [Rotation::Stay; ROTATIONS];

/// The outside identity joins before every ceremony.
pub(super) const ROTATE: [Rotation; ROTATIONS] = [
    Rotation::Replace(0),
    Rotation::Replace(1),
    Rotation::Replace(2),
    Rotation::Replace(3),
    Rotation::Replace(0),
];

/// The identity outside the first committee of every fixed reshare input.
pub(super) const OUTSIDER: u8 = 4;

/// The identities of a bootstrap run, which are its committee, in identity
/// order.
pub(super) fn committee() -> Vec<PublicKey> {
    public_keys(&super::identities())
}

/// The identities of a reshare run, in identity order.
pub(super) fn identities() -> Vec<PublicKey> {
    public_keys(&signers(RESHARE_IDENTITIES))
}

/// The description of `epoch` among the identities of [`committee`], with
/// the output a trusted dealer deals them under `seed`, and each member's
/// share of that output in identity order.
pub(super) fn described(seed: u64, epoch: Epoch) -> (Info, Vec<Share>) {
    let players = Set::from_iter_dedup(committee());
    let (output, shares) =
        deal::<MockGroup, _, N3f1>(TestRng::new(seed), Mode::NonZeroCounter, players.clone())
            .expect("a trusted deal must succeed");
    let info = Info {
        outcome: EpochOutcome::Success,
        epoch,
        output,
        players: players.clone(),
        next_players: players,
        directory: Unit,
    };
    (info, shares.values().to_vec())
}

/// The restart schedule a run among `identities` identities draws from
/// `tape` under `environment`, in milliseconds from the start of the run.
pub(super) fn schedule(
    environment: &EnvironmentControls,
    tape: &[u8],
    identities: usize,
) -> Vec<(u128, Event)> {
    let mut environment = environment.clone();
    environment.cuts.clear();
    Program::new(&environment, tape.to_vec(), identities)
        .events()
        .iter()
        .map(|(at, event)| (at.as_millis(), event.clone()))
        .collect()
}

/// The inputs a restart driver's tests sample.
pub(super) mod sample {
    use commonware_utils::{TestRng, sync::Mutex};
    use rand::RngExt as _;
    use std::{
        env, fs,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
    };

    /// Names a directory of input files to sample instead of drawn inputs.
    const DIRECTORY: &str = "DKG_SAMPLE_DIR";

    /// The stack of a thread that runs sampled inputs. An unoptimized engine
    /// nests its futures deeply.
    const STACK: usize = 16 << 20;

    /// Run `run` on each of `count` inputs, on every core, and return what
    /// it returned in the order of the inputs.
    ///
    /// The inputs are eight bytes each, drawn from a fixed seed: an input
    /// type stretches them into a whole session. If the environment names a
    /// directory, the first `count` files of it in name order are the inputs
    /// instead, so that two builds can be measured on one set of inputs.
    pub(in crate::dkg) fn each<T: Send>(count: usize, run: impl Fn(&[u8]) -> T + Sync) -> Vec<T> {
        let inputs: Vec<Vec<u8>> = match env::var_os(DIRECTORY) {
            Some(directory) => {
                let mut files: Vec<_> = fs::read_dir(directory)
                    .expect("the sample directory is listed")
                    .map(|entry| entry.expect("the sample directory is listed").path())
                    .collect();
                files.sort();
                files
                    .iter()
                    .take(count)
                    .map(|file| fs::read(file).expect("a sampled input is read"))
                    .collect()
            }
            None => (0..count as u64)
                .map(|seed| {
                    let mut bytes = [0u8; 8];
                    TestRng::new(seed).fill(&mut bytes[..]);
                    bytes.to_vec()
                })
                .collect(),
        };
        assert_eq!(inputs.len(), count, "the sample is short");
        over(&inputs, |input| run(input))
    }

    /// Run `run` on each of `inputs`, on every core, and return what it
    /// returned in the order of the inputs.
    pub(in crate::dkg) fn over<I: Sync, T: Send>(
        inputs: &[I],
        run: impl Fn(&I) -> T + Sync,
    ) -> Vec<T> {
        let workers = thread::available_parallelism().map_or(1, |workers| workers.get());
        let next = AtomicUsize::new(0);
        let results = Mutex::new(Vec::with_capacity(inputs.len()));
        thread::scope(|scope| {
            for _ in 0..workers {
                thread::Builder::new()
                    .stack_size(STACK)
                    .spawn_scoped(scope, || {
                        loop {
                            let index = next.fetch_add(1, Ordering::Relaxed);
                            let Some(input) = inputs.get(index) else {
                                break;
                            };
                            let result = run(input);
                            results.lock().push((index, result));
                        }
                    })
                    .expect("a sampling thread starts");
            }
        });
        let mut results = results.into_inner();
        results.sort_by_key(|(index, _)| *index);
        results.into_iter().map(|(_, result)| result).collect()
    }
}

/// What one run of a sample came to.
pub(super) struct Sampled {
    pub(super) outcome: Outcome,
    /// Whether a ceremony of the run failed.
    pub(super) failed: bool,
    pub(super) crashes: usize,
    pub(super) paced: PacedCounts,
    /// Pairs of spans in which two identities were impaired at once.
    pub(super) overlaps: usize,
}

/// What a sample of decoded inputs came to, summed over its runs. A run is
/// named by its position in the sample.
#[derive(Debug, Default)]
pub(super) struct Sample {
    pub(super) runs: usize,
    pub(super) completed: usize,
    pub(super) timeouts: usize,
    /// The runs in which a ceremony failed.
    pub(super) failed: Vec<usize>,
    pub(super) crashes: usize,
    pub(super) paced: PacedCounts,
    /// The runs in which two identities were impaired at once.
    pub(super) overlapping: Vec<usize>,
}

impl Sample {
    /// Sum what `runs` came to, in the order of the sample.
    pub(super) fn of(runs: impl IntoIterator<Item = Sampled>) -> Self {
        let mut sample = Self::default();
        for (run, sampled) in runs.into_iter().enumerate() {
            sample.runs += 1;
            sample.completed += usize::from(sampled.outcome == Outcome::Completed);
            sample.timeouts += usize::from(sampled.outcome == Outcome::Timeout);
            if sampled.failed {
                sample.failed.push(run);
            }
            sample.crashes += sampled.crashes;
            sample.paced += sampled.paced;
            if sampled.overlaps > 0 {
                sample.overlapping.push(run);
            }
        }
        println!("{sample:?}");
        sample
    }
}

/// The first of `candidates`, in order, on which `run` shows a scenario, with
/// what `run` made of it.
///
/// Where a crash finds its engine, where a restart finds its peers, and where
/// a floor falls depend on the timing of the engines, so a test does not name
/// the input its scenario plays out under. It looks for the scenario among a
/// range of candidates, asserts what it is named for on the first run that
/// shows it, and fails only if none does. The candidates are run `abreast` at
/// a time, each on its own thread, and every run made on the way is checked
/// by the oracle like any other.
pub(super) fn first<I: Send, T: Send>(
    candidates: impl IntoIterator<Item = I>,
    abreast: usize,
    run: impl Fn(I) -> Option<T> + Sync,
) -> T {
    let mut candidates = candidates.into_iter();
    loop {
        let tried: Vec<I> = candidates.by_ref().take(abreast).collect();
        assert!(!tried.is_empty(), "no candidate shows the scenario");
        let shown = thread::scope(|scope| {
            let run = &run;
            let runs: Vec<_> = tried
                .into_iter()
                .map(|candidate| scope.spawn(move || run(candidate)))
                .collect();

            // The first candidate in order, not the first to finish.
            let runs: Vec<_> = runs
                .into_iter()
                .map(|run| run.join().expect("a run of the range failed"))
                .collect();
            runs.into_iter().flatten().next()
        });
        if let Some(shown) = shown {
            return shown;
        }
    }
}

/// A stack that can tell what an identity whose engine is down has retained.
pub(super) trait Retaining: Stack {
    /// What an identity has retained.
    type Retained: Send;

    /// What the identity at `index`, whose engine is down, has retained.
    fn retained(&mut self, index: usize) -> impl Future<Output = Self::Retained> + Send;
}

/// A stack with what each restart finds put on record before the engine is
/// started.
pub(super) struct Watched<S: Retaining> {
    stack: S,
    /// The starts of each identity's engine so far.
    starts: Vec<usize>,
    retained: Arc<Mutex<Vec<S::Retained>>>,
}

impl<S: Retaining> Watched<S> {
    /// Watch `stack`, recording what each restart finds into `retained`, in
    /// the order of the restarts.
    pub(super) const fn new(stack: S, retained: Arc<Mutex<Vec<S::Retained>>>) -> Self {
        Self {
            stack,
            starts: Vec::new(),
            retained,
        }
    }
}

impl<S: Retaining + Send> Stack for Watched<S> {
    async fn start(&mut self, index: usize) -> Handle<()> {
        if self.starts.len() <= index {
            self.starts.resize(index + 1, 0);
        }
        if self.starts[index] > 0 {
            let retained = self.stack.retained(index).await;
            self.retained.lock().push(retained);
        }
        self.starts[index] += 1;
        self.stack.start(index).await
    }

    fn crashing(&mut self, index: usize) {
        self.stack.crashing(index);
    }

    async fn settled(&mut self, absent: &[bool]) {
        self.stack.settled(absent).await;
    }

    async fn joined(&mut self) {
        self.stack.joined().await;
    }

    fn follows(&self) -> bool {
        self.stack.follows()
    }
}

/// The durable length of the reshare actor's journal of the identity at
/// `index`, whose engine is down and whose storage is `storage`.
pub(super) async fn journal(storage: &deterministic::Context, index: usize) -> u64 {
    stored(storage, &format!("engine-{index}-reshare_events")).await
}

/// The durable length of the journal the Simplex engine of `epoch` keeps for
/// the reshare engine of the identity at `index`, whose engine is down and
/// whose storage is `storage`. The engine's own votes of the epoch are in
/// it.
pub(super) async fn votes(storage: &deterministic::Context, index: usize, epoch: Epoch) -> u64 {
    stored(
        storage,
        &format!("engine-{index}-orchestrator_consensus_{epoch}"),
    )
    .await
}

/// The durable length of the blobs of `partition` in `storage`, none of
/// which a running engine holds open.
async fn stored(storage: &deterministic::Context, partition: &str) -> u64 {
    // The crashed engine's blobs are closed, and these are closed again
    // before the engine opens them.
    let mut stored = 0;
    for name in storage.scan(partition).await.unwrap_or_default() {
        let (_, len) = storage
            .open(partition, &name)
            .await
            .expect("a blob of the partition opens");
        stored += len;
    }
    stored
}
