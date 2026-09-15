//! The database-set driver: one-time state sync, pruning, and rewind over a
//! [`DatabaseSet`] with no consensus above it.
//!
//! A serving set applies a tape-driven history and stands in for the peers
//! a syncing node would fetch from: a [`Shared`] database is itself a
//! [`Source`]. A fresh set of the same shape then runs
//! [`StateSyncSet::sync`] against it through a [`Peer`] wrapper that
//! interleaves honest answers with delayed ones and with answers served from
//! a divergent set that applied a different workload over the same history.
//! While the sync runs, the serving set keeps advancing and the driver
//! forwards tip updates, so the coordinator has to chase a moving target.
//!
//! Once the sync converges the driver checks that the synced set landed on an
//! anchor the serving set actually reached, with that anchor's exact targets
//! and roots, and then keeps using it: it prunes to the anchor, re-executes
//! the serving set's later history on top and requires every height to
//! reproduce the serving set's targets, rewinds back to the anchor, and
//! re-executes forward again. That is the sequence a late joiner's database
//! set goes through once the stateful actor hands it over.
//!
//! The set shapes cover the single-database implementation for every adapter
//! class and the tuple implementation, whose generation coordinator regroups
//! databases that reach their targets at different times.

use super::{
    Digest, PAGE_CACHE_SIZE, PAGE_SIZE, PEER_DELAY, PEER_SCHEDULE_LEN, SYNC_RUN_TIMEOUT,
    TIP_UPDATE_DELAY,
    backend::{
        Any, Backend, Current, ImmutableCompact, ImmutableStandard, KeylessCompact,
        KeylessStandard, Transition, u64_to_digest,
    },
    input::{DatabaseKind, SetShape, StatefulDbSyncFuzzInput},
    runner::{self, Reportable},
};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_glue::stateful::db::{
    Anchor, DatabaseSet, Shared, StateSyncDb, StateSyncSet, SyncEngineConfig, TipUpdate,
};
use commonware_macros::select;
use commonware_runtime::{
    Clock, Runner as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::qmdb::sync::{FeedbackTx, Request, Response, Source};
use commonware_utils::{
    FuzzRng, NZUsize,
    channel::{oneshot, ring},
    sync::Mutex,
};
use rand::RngExt as _;
use std::{
    fmt,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Label this driver reports under.
const TARGET: &str = "glue-stateful-db-sync";

/// The runtime every set runs under.
type Runtime = deterministic::Context;

/// The state transition the serving set applies.
const SERVED_BUMP: u64 = 1;

/// The state transition the divergent set applies instead.
const DIVERGENT_BUMP: u64 = 2;

/// What one peer answer does with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    /// Answer from the serving set.
    Honest,
    /// Answer from the serving set after a delay.
    Delayed,
    /// Answer from the divergent set, which shares the serving set's history
    /// only where the workloads coincide.
    Divergent,
}

/// One answer a peer gave, with the verdict the sync engine sent back for it.
struct Answer {
    behaviour: Behaviour,
    verdict: oneshot::Receiver<bool>,
}

/// The tape-driven answer policy every peer in a set follows.
#[derive(Clone)]
struct Policy {
    schedule: Arc<[Behaviour]>,
    answers: Arc<Mutex<Vec<Answer>>>,
    failures: Arc<AtomicUsize>,
}

impl Policy {
    /// Draw a schedule from the tape at the input's divergence and delay
    /// densities. The schedule always ends with an honest answer, so a
    /// request retried past the divergent answers is eventually served.
    fn new(rng: &mut FuzzRng, divergent: u8, delayed: u8) -> Self {
        let mut samples = [0u8; PEER_SCHEDULE_LEN];
        rng.fill(&mut samples[..]);
        let mut schedule: Vec<Behaviour> = samples
            .iter()
            .map(|sample| {
                let roll = sample % 8;
                if roll < divergent {
                    Behaviour::Divergent
                } else if roll < divergent + delayed {
                    Behaviour::Delayed
                } else {
                    Behaviour::Honest
                }
            })
            .collect();
        schedule[PEER_SCHEDULE_LEN - 1] = Behaviour::Honest;
        Self {
            schedule: schedule.into(),
            answers: Arc::new(Mutex::new(Vec::new())),
            failures: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Record a database that could not serve a request.
    fn failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn behaviour(&self, call: usize) -> Behaviour {
        self.schedule[call % self.schedule.len()]
    }

    /// Register an answer and return the feedback channel the engine reports
    /// its verdict through.
    fn answered(&self, behaviour: Behaviour) -> FeedbackTx {
        let (sender, verdict) = oneshot::channel();
        self.answers.lock().push(Answer { behaviour, verdict });
        Some(sender)
    }

    /// What the engine made of every answer: the number of answers, the
    /// number of divergent answers it rejected, and whether it ever rejected
    /// an honest one.
    fn verdicts(&self) -> (usize, usize, bool) {
        let mut answers = self.answers.lock();
        let mut rejected_divergent = 0;
        let mut rejected_honest = false;
        for answer in answers.iter_mut() {
            let Ok(false) = answer.verdict.try_recv() else {
                continue;
            };
            match answer.behaviour {
                Behaviour::Divergent => rejected_divergent += 1,
                Behaviour::Honest | Behaviour::Delayed => rejected_honest = true,
            }
        }
        (answers.len(), rejected_divergent, rejected_honest)
    }
}

/// A peer serving one database of the set: the serving database behind a
/// tape-driven policy, with the divergent database as the other answer.
///
/// The peer stands in for the p2p resolver, which never surfaces a peer's
/// failure to the sync engine: it retries until some peer answers. A database
/// that cannot serve a request, which a compact database cannot once it has
/// advanced past the requested size, is retried after a delay under the next
/// scheduled behaviour, until the engine either gets an answer or abandons the
/// request because its target moved.
struct Peer<S> {
    context: Runtime,
    honest: S,
    divergent: S,
    policy: Policy,
    calls: AtomicUsize,
}

impl<S> Peer<S> {
    fn new(context: Runtime, honest: S, divergent: S, policy: Policy) -> Self {
        Self {
            context,
            honest,
            divergent,
            policy,
            calls: AtomicUsize::new(0),
        }
    }
}

impl<S: Source<Op: Send>> Source for Peer<S> {
    type Family = S::Family;
    type Digest = S::Digest;
    type Op = S::Op;
    type Error = S::Error;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error> {
        loop {
            let behaviour = self
                .policy
                .behaviour(self.calls.fetch_add(1, Ordering::Relaxed));
            let result = match behaviour {
                Behaviour::Honest => self.honest.serve(request).await,
                Behaviour::Delayed => {
                    self.context.sleep(PEER_DELAY).await;
                    self.honest.serve(request).await
                }
                Behaviour::Divergent => self.divergent.serve(request).await,
            };
            match result {
                Ok((response, _)) => return Ok((response, self.policy.answered(behaviour))),
                Err(_) => self.policy.failed(),
            }
            self.context.sleep(PEER_DELAY).await;
        }
    }
}

/// One shape of database set the driver can run.
trait Shape: 'static {
    /// Label this shape reports under.
    const NAME: &'static str;

    /// The set.
    type Set: DatabaseSet<Runtime> + StateSyncSet<Runtime, Self::Sources, Digest>;

    /// The peers the set syncs from, one per database.
    type Sources: Send + 'static;

    /// The set's configuration over partitions named by `prefix`.
    fn config(prefix: &str, page_cache: CacheRef) -> <Self::Set as DatabaseSet<Runtime>>::Config;

    /// Execute one transition against every database's batch.
    fn execute(
        transition: &Transition,
        bump: u64,
        batches: <Self::Set as DatabaseSet<Runtime>>::Unmerkleized,
    ) -> impl Future<Output = <Self::Set as DatabaseSet<Runtime>>::Merkleized> + Send;

    /// The sync targets merkleized batches produce.
    fn targets(
        merkleized: &<Self::Set as DatabaseSet<Runtime>>::Merkleized,
    ) -> <Self::Set as DatabaseSet<Runtime>>::SyncTargets;

    /// Every database's canonical root.
    fn roots(set: &Self::Set) -> impl Future<Output = Vec<Digest>> + Send;

    /// Peers over the serving and divergent sets.
    fn peers(
        context: &Runtime,
        serving: &Self::Set,
        divergent: &Self::Set,
        policy: &Policy,
    ) -> Self::Sources;
}

/// A single database of backend `B`.
struct Single<B>(PhantomData<B>);

impl<B> Shape for Single<B>
where
    B: Backend,
    B::Db: StateSyncDb<Runtime, Peer<Shared<B::Db>>>,
{
    const NAME: &'static str = B::NAME;
    type Set = Shared<B::Db>;
    type Sources = Peer<Shared<B::Db>>;

    fn config(prefix: &str, page_cache: CacheRef) -> <Self::Set as DatabaseSet<Runtime>>::Config {
        B::config(prefix, page_cache)
    }

    async fn execute(
        transition: &Transition,
        bump: u64,
        batches: <Self::Set as DatabaseSet<Runtime>>::Unmerkleized,
    ) -> <Self::Set as DatabaseSet<Runtime>>::Merkleized {
        B::execute(transition.with_bump(bump), batches).await
    }

    fn targets(
        merkleized: &<Self::Set as DatabaseSet<Runtime>>::Merkleized,
    ) -> <Self::Set as DatabaseSet<Runtime>>::SyncTargets {
        B::sync_target(&B::commitment(merkleized))
    }

    async fn roots(set: &Self::Set) -> Vec<Digest> {
        vec![B::canonical_root(&*set.read().await)]
    }

    fn peers(
        context: &Runtime,
        serving: &Self::Set,
        divergent: &Self::Set,
        policy: &Policy,
    ) -> Self::Sources {
        Peer::new(
            context.child("peer"),
            serving.clone(),
            divergent.clone(),
            policy.clone(),
        )
    }
}

/// A tuple of databases, one per listed backend.
macro_rules! tuple_shape {
    ($name:ident, $label:literal, $($B:ident : $idx:tt),+) => {
        struct $name;

        impl Shape for $name {
            const NAME: &'static str = $label;
            type Set = ($(Shared<<$B as Backend>::Db>,)+);
            type Sources = ($(Peer<Shared<<$B as Backend>::Db>>,)+);

            fn config(
                prefix: &str,
                page_cache: CacheRef,
            ) -> <Self::Set as DatabaseSet<Runtime>>::Config {
                ($($B::config(&format!("{prefix}-{}", $idx), page_cache.clone()),)+)
            }

            async fn execute(
                transition: &Transition,
                bump: u64,
                batches: <Self::Set as DatabaseSet<Runtime>>::Unmerkleized,
            ) -> <Self::Set as DatabaseSet<Runtime>>::Merkleized {
                ($($B::execute(transition.with_bump(bump), batches.$idx).await,)+)
            }

            fn targets(
                merkleized: &<Self::Set as DatabaseSet<Runtime>>::Merkleized,
            ) -> <Self::Set as DatabaseSet<Runtime>>::SyncTargets {
                ($($B::sync_target(&$B::commitment(&merkleized.$idx)),)+)
            }

            async fn roots(set: &Self::Set) -> Vec<Digest> {
                vec![$($B::canonical_root(&*set.$idx.read().await),)+]
            }

            fn peers(
                context: &Runtime,
                serving: &Self::Set,
                divergent: &Self::Set,
                policy: &Policy,
            ) -> Self::Sources {
                ($(Peer::new(
                    context.child(concat!("peer_", stringify!($idx))),
                    serving.$idx.clone(),
                    divergent.$idx.clone(),
                    policy.clone(),
                ),)+)
            }
        }
    };
}

tuple_shape!(Pair, "pair(any,immutable-compact)", Any: 0, ImmutableCompact: 1);
tuple_shape!(
    Triple,
    "triple(current,keyless-standard,keyless-compact)",
    Current: 0,
    KeylessStandard: 1,
    KeylessCompact: 2
);

/// One height of the serving set's history.
struct Served<S: Shape> {
    anchor: Anchor<Digest>,
    transition: Transition,
    targets: <S::Set as DatabaseSet<Runtime>>::SyncTargets,
    roots: Vec<Digest>,
}

/// The serving set, the divergent set, and the history both applied.
struct History<S: Shape> {
    serving: S::Set,
    divergent: S::Set,
    heights: Vec<Served<S>>,
}

impl<S: Shape> History<S> {
    /// The transition producing height `height`.
    fn transition(height: u64) -> Transition {
        Transition {
            view: View::new(height),
            parent: u64_to_digest(height - 1),
            height: Height::new(height),
            bump: SERVED_BUMP,
        }
    }

    /// Apply the next height to both sets, make it durable on the serving
    /// set, and record what the serving set reached.
    async fn advance(&mut self) {
        let height = self.heights.len() as u64 + 1;
        let transition = Self::transition(height);

        let batches = self.divergent.new_batches().await;
        let merkleized = S::execute(&transition, DIVERGENT_BUMP, batches).await;
        self.divergent.apply(merkleized).await;
        assert!(
            self.divergent.finalize().await.durable().await,
            "divergent set must be durable"
        );

        let batches = self.serving.new_batches().await;
        let merkleized = S::execute(&transition, SERVED_BUMP, batches).await;
        let targets = S::targets(&merkleized);
        self.serving.apply(merkleized).await;
        assert!(
            self.serving.finalize().await.durable().await,
            "serving set must be durable"
        );
        assert!(
            self.serving.committed_targets().await == targets,
            "applied targets must be the committed targets"
        );

        self.heights.push(Served {
            anchor: Anchor {
                height: Height::new(height),
                round: Round::new(Epoch::zero(), View::new(height)),
                digest: u64_to_digest(height),
            },
            transition,
            targets,
            roots: S::roots(&self.serving).await,
        });
    }

    fn at(&self, height: Height) -> &Served<S> {
        &self.heights[height.get() as usize - 1]
    }

    fn tip(&self) -> &Served<S> {
        self.heights.last().expect("history is never empty")
    }
}

/// Why a run stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The sync converged and the synced set was used through the rest of
    /// the history.
    Converged,
}

impl fmt::Display for SyncOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Converged => f.write_str("converged"),
        }
    }
}

/// What one run observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DbSyncReport {
    /// The driver that produced this run.
    pub target: &'static str,
    /// The set shape the run synced.
    pub shape: &'static str,
    /// Why the run stopped.
    pub outcome: SyncOutcome,
    /// Heights the serving set applied before the sync started.
    pub served: usize,
    /// Heights the serving set applied while the sync ran.
    pub extra: usize,
    /// Tip updates forwarded to the coordinator.
    pub tip_updates: usize,
    /// The height the sync converged on.
    pub converged: u64,
    /// Requests the peers answered.
    pub answers: usize,
    /// Requests a database could not serve, which the peer retried.
    pub peer_failures: usize,
    /// Divergent answers the engine rejected.
    pub rejected_divergent: usize,
    /// Heights re-executed on the synced set that reproduced the serving
    /// set's targets, over both passes.
    pub reproduced: usize,
}

impl DbSyncReport {
    /// Whether the run synced something and used the result.
    pub const fn measured(&self) -> bool {
        self.answers > 0 && self.converged > 0
    }
}

impl fmt::Display for DbSyncReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] shape={} outcome={} served={} extra={} tip_updates={} converged={} answers={} \
             peer_failures={} rejected_divergent={} reproduced={}{}",
            self.target,
            self.shape,
            self.outcome,
            self.served,
            self.extra,
            self.tip_updates,
            self.converged,
            self.answers,
            self.peer_failures,
            self.rejected_divergent,
            self.reproduced,
            if self.measured() {
                ""
            } else {
                " UNMEASURED (nothing was synced)"
            },
        )
    }
}

impl Reportable for DbSyncReport {
    fn measured(&self) -> bool {
        Self::measured(self)
    }
}

/// libFuzzer entry point.
pub fn fuzz_stateful_db_sync(input: StatefulDbSyncFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_db_sync(input));
}

/// Run one sync over the selected set shape and return what it measured.
///
/// A run is fully determined by its input bytes.
pub fn run_stateful_db_sync(input: StatefulDbSyncFuzzInput) -> DbSyncReport {
    match input.shape {
        SetShape::Single(DatabaseKind::Any) => execute::<Single<Any>>(input),
        SetShape::Single(DatabaseKind::Current) => execute::<Single<Current>>(input),
        SetShape::Single(DatabaseKind::ImmutableStandard) => {
            execute::<Single<ImmutableStandard>>(input)
        }
        SetShape::Single(DatabaseKind::ImmutableCompact) => {
            execute::<Single<ImmutableCompact>>(input)
        }
        SetShape::Single(DatabaseKind::KeylessStandard) => {
            execute::<Single<KeylessStandard>>(input)
        }
        SetShape::Single(DatabaseKind::KeylessCompact) => execute::<Single<KeylessCompact>>(input),
        SetShape::Pair => execute::<Pair>(input),
        SetShape::Triple => execute::<Triple>(input),
    }
}

fn execute<S: Shape>(input: StatefulDbSyncFuzzInput) -> DbSyncReport {
    let entropy = input.raw_bytes.clone();
    let config = deterministic::Config::new().with_rng(FuzzRng::new(entropy.clone()));
    deterministic::Runner::new(config).start(|context| run::<S>(context, input, entropy))
}

async fn run<S: Shape>(
    context: deterministic::Context,
    input: StatefulDbSyncFuzzInput,
    entropy: Vec<u8>,
) -> DbSyncReport {
    let mut rng = FuzzRng::new(entropy);
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let sync_config = SyncEngineConfig {
        fetch_batch_size: input.sync.fetch_batch_size,
        apply_batch_size: input.sync.apply_batch_size,
        max_outstanding_requests: usize::from(input.sync.max_outstanding_requests),
        update_channel_size: NZUsize!(usize::from(input.sync.update_channel_size)),
        max_retained_roots: usize::from(input.sync.max_retained_roots),
    };

    // The serving set and its divergent twin apply the pre-sync history.
    let mut history = History::<S> {
        serving: S::Set::init(
            context.child("serving"),
            S::config("serving", page_cache.clone()),
        )
        .await,
        divergent: S::Set::init(
            context.child("divergent"),
            S::config("divergent", page_cache.clone()),
        )
        .await,
        heights: Vec::new(),
    };
    for _ in 0..input.served_heights {
        history.advance().await;
    }
    let served = history.heights.len();
    let start = history.tip();
    let start_anchor = start.anchor;
    let start_targets = start.targets.clone();

    // The sync chases the serving set from the pre-sync tip. The first height
    // served during the sync is announced before the sync starts, so every
    // run with a moving tip retargets at least once; the rest arrive live.
    let policy = Policy::new(&mut rng, input.peer.divergent, input.peer.delayed);
    let sources = S::peers(&context, &history.serving, &history.divergent, &policy);
    let (tip_tx, tip_rx) = ring::channel(NZUsize!(usize::from(input.sync.update_channel_size)));
    let mut tip_updates = 0;
    let mut extra = input.extra_heights;
    if extra > 0 {
        extra -= 1;
        history.advance().await;
        let tip = history.tip();
        assert!(tip_tx.send_lossy(TipUpdate::new(tip.anchor, tip.targets.clone())));
        tip_updates += 1;
    }
    let sync = context.child("syncing").spawn({
        let config = S::config("syncing", page_cache);
        move |context| async move {
            S::Set::sync(
                context,
                config,
                sources,
                start_anchor,
                start_targets,
                tip_rx,
                sync_config,
            )
            .await
        }
    });

    // Meanwhile the serving set keeps advancing and the driver forwards tip
    // updates: some heights are announced, some announced twice, some not at
    // all, and a stale announcement is repeated for the coordinator to ignore.
    // The last height served is always announced, and nothing is sent after
    // it: a compact database serves only its current size, so a coordinator
    // left chasing an older target than the serving set holds would wait
    // forever on modeled unavailability rather than on a defect.
    for remaining in (0..extra).rev() {
        let mut sample = [0u8; 2];
        rng.fill(&mut sample[..]);
        history.advance().await;
        let tip = history.tip();
        if sample[1] % 8 == 3 && history.heights.len() > 1 {
            let stale = history.at(Height::new(history.heights.len() as u64 - 1));
            tip_tx.send_lossy(TipUpdate::new(stale.anchor, stale.targets.clone()));
        }
        let announcements = match sample[1] % 8 {
            0 if remaining > 0 => 0,
            1 | 2 => 2,
            _ => 1,
        };
        for _ in 0..announcements {
            if tip_tx.send_lossy(TipUpdate::new(tip.anchor, tip.targets.clone())) {
                tip_updates += 1;
            }
        }
        context
            .sleep(TIP_UPDATE_DELAY * u32::from(sample[0] % 4))
            .await;
    }
    // A closed channel and an idle one must both let the coordinator finish.
    let mut close = [0u8; 1];
    rng.fill(&mut close[..]);
    let _tip_tx = (close[0] % 2 == 0).then_some(tip_tx);

    // The coordinator must converge: every schedule answers honestly
    // eventually, the history is finite, and the timeout dwarfs the delays.
    let (synced, anchor) = select! {
        result = sync => {
            result
                .expect("sync task must not panic or be aborted")
                .unwrap_or_else(|err| panic!("state sync failed against honest-eventually peers: {err:?}"))
        },
        _ = context.sleep(SYNC_RUN_TIMEOUT) => {
            panic!("state sync did not converge within {SYNC_RUN_TIMEOUT:?} of simulated time");
        },
    };

    // The converged anchor is one the serving set reached, and the synced set
    // holds exactly that height's state.
    assert!(
        anchor.height >= start_anchor.height
            && anchor.height.get() as usize <= history.heights.len(),
        "sync converged on height {} outside the served history {}..={}",
        anchor.height.get(),
        start_anchor.height.get(),
        history.heights.len(),
    );
    let reached = history.at(anchor.height);
    assert_eq!(
        anchor, reached.anchor,
        "sync converged on an anchor the serving set never produced"
    );
    assert!(
        synced.committed_targets().await == reached.targets,
        "synced set committed targets differ from the serving set's at height {}",
        anchor.height.get(),
    );
    assert_eq!(
        S::roots(&synced).await,
        reached.roots,
        "synced set roots differ from the serving set's at height {}",
        anchor.height.get(),
    );
    let (answers, rejected_divergent, rejected_honest) = policy.verdicts();
    assert!(
        !rejected_honest,
        "the sync engine rejected an answer served from the serving set"
    );

    // Pruning to the anchor keeps the anchor's state.
    assert!(synced.finalize().await.durable().await);
    synced.prune(&reached.targets).await;
    let reached = history.at(anchor.height);
    assert!(
        synced.committed_targets().await == reached.targets,
        "pruning to the converged anchor changed the committed targets"
    );
    assert_eq!(S::roots(&synced).await, reached.roots);

    // The serving set moves on after the sync, and the synced set reproduces
    // the serving set's later history, rewinds to the anchor, and reproduces
    // it again.
    for _ in 0..input.post_heights {
        history.advance().await;
    }
    let reached = history.at(anchor.height);
    let mut reproduced = 0;
    reproduced += replay::<S>(&synced, &history, anchor.height).await;
    synced.rewind_to_targets(reached.targets.clone()).await;
    assert!(
        synced.committed_targets().await == reached.targets,
        "rewinding to the converged anchor did not restore its targets"
    );
    assert_eq!(
        S::roots(&synced).await,
        reached.roots,
        "rewinding to the converged anchor did not restore its roots"
    );
    reproduced += replay::<S>(&synced, &history, anchor.height).await;

    DbSyncReport {
        target: TARGET,
        shape: S::NAME,
        outcome: SyncOutcome::Converged,
        served,
        extra: history.heights.len() - served - usize::from(input.post_heights),
        tip_updates,
        converged: anchor.height.get(),
        answers,
        peer_failures: policy.failures.load(Ordering::Relaxed),
        rejected_divergent,
        reproduced,
    }
}

/// Re-execute the serving set's history above `from` on `set`, requiring every
/// height to reproduce the serving set's targets and roots.
async fn replay<S: Shape>(set: &S::Set, history: &History<S>, from: Height) -> usize {
    let mut reproduced = 0;
    for served in &history.heights[from.get() as usize..] {
        let batches = set.new_batches().await;
        let merkleized = S::execute(&served.transition, SERVED_BUMP, batches).await;
        assert!(
            S::targets(&merkleized) == served.targets,
            "re-executing height {} on the synced set produced targets the serving set did not",
            served.transition.height.get(),
        );
        set.apply(merkleized).await;
        assert!(set.finalize().await.durable().await);
        assert_eq!(
            S::roots(set).await,
            served.roots,
            "re-executing height {} on the synced set produced roots the serving set did not",
            served.transition.height.get(),
        );
        reproduced += 1;
    }
    reproduced
}

/// Thousands of delayed answers and every tape-driven pause between served
/// heights together stay far below the timeout, so a run that times out did
/// not converge rather than merely ran slowly.
const _: () = assert!(
    PEER_DELAY.as_millis() * 4096 + TIP_UPDATE_DELAY.as_millis() * 4 * 64
        < SYNC_RUN_TIMEOUT.as_millis()
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::input::{PeerControls, SyncControls};
    use commonware_utils::NZU64;

    fn tape(seed: u8) -> Vec<u8> {
        (0..96u8)
            .map(|byte| byte.wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn input(
        shape: SetShape,
        served_heights: u8,
        extra_heights: u8,
        batch: u64,
        divergent: u8,
        delayed: u8,
        seed: u8,
    ) -> StatefulDbSyncFuzzInput {
        StatefulDbSyncFuzzInput {
            shape,
            served_heights,
            extra_heights,
            post_heights: 2,
            sync: SyncControls {
                fetch_batch_size: NZU64!(batch),
                apply_batch_size: NZU64!(batch),
                max_outstanding_requests: 2,
                update_channel_size: 2,
                max_retained_roots: 4,
            },
            peer: PeerControls { divergent, delayed },
            raw_bytes: tape(seed),
        }
    }

    /// Runs one fixed input and asserts the checks were not vacuous.
    fn measured(input: StatefulDbSyncFuzzInput) -> DbSyncReport {
        let report = run_stateful_db_sync(input);
        println!("{report}");
        assert!(
            report.measured(),
            "run synced nothing and must not be counted as passing: {report}"
        );
        report
    }

    /// Every shape syncs a static history from honest peers.
    #[test]
    fn every_shape_syncs_a_static_history() {
        for shape in SetShape::ALL {
            measured(input(shape, 4, 0, 4, 0, 0, 1));
        }
    }

    /// Every shape chases a moving tip in the smallest batches, with half
    /// the answers delayed so the tip moves while requests are in flight.
    #[test]
    fn every_shape_chases_a_moving_tip() {
        for shape in SetShape::ALL {
            let report = measured(input(shape, 2, 4, 1, 0, 4, 2));
            assert!(report.tip_updates > 0, "{report}");
            assert!(
                report.converged > report.served as u64,
                "{shape:?}: the sync never retargeted: {report}"
            );
        }
    }

    /// With almost every answer served from the divergent set, every shape
    /// rejects divergent answers and still converges on the serving set's
    /// state.
    #[test]
    fn divergent_answers_are_rejected() {
        for shape in SetShape::ALL {
            let report = measured(input(shape, 4, 2, 1, 7, 0, 3));
            assert!(
                report.rejected_divergent > 0,
                "{shape:?}: no divergent answer was rejected: {report}"
            );
        }
    }

    /// A compact source serves only its current size, so a served height that
    /// is never announced leaves the coordinator waiting on a target no peer
    /// can answer. The driver therefore always announces the last height it
    /// serves during the sync. This input, once a 12-byte fuzzer finding, ends
    /// its live heights with an unannounced one under the old rule.
    #[test]
    fn terminal_tip_is_announced() {
        let report = measured(StatefulDbSyncFuzzInput {
            shape: SetShape::Pair,
            served_heights: 6,
            extra_heights: 5,
            post_heights: 0,
            sync: SyncControls {
                fetch_batch_size: NZU64!(1),
                apply_batch_size: NZU64!(1),
                max_outstanding_requests: 1,
                update_channel_size: 1,
                max_retained_roots: 1,
            },
            peer: PeerControls {
                divergent: 0,
                delayed: 4,
            },
            raw_bytes: vec![0x27],
        });
        assert_eq!(report.converged, 11, "{report}");
    }

    /// I6: a replayed input fails, or passes, identically.
    #[test]
    fn replay_is_reproducible() {
        let first = run_stateful_db_sync(input(SetShape::Triple, 3, 3, 2, 3, 3, 5));
        let second = run_stateful_db_sync(input(SetShape::Triple, 3, 3, 2, 3, 3, 5));
        assert_eq!(first, second, "replaying an input changed what it measured");
    }

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input(SetShape::Pair, 1, 1, 1, 0, 0, 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}
