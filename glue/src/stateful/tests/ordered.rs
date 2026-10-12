//! Ordered mode over an executor and a QMDB database.

use super::{
    common::{PAGE_CACHE_SIZE, PAGE_SIZE, digest_to_u64, u64_to_digest},
    single_db_app::{Qmdb, SingleDatabaseSet, qmdb_config},
};
use crate::{
    executor::{self, Checkpoints, Context, Executed, Executor, Halt, Inbox, StoreConfig},
    stateful::{
        PruneConfig,
        db::{
            AttachableResolver, DatabaseSet, Merkleized as _, Shared, SyncEngineConfig,
            Unmerkleized as _,
        },
        ordered::{Application, Config, Execution, Mailbox, Stateful},
    },
};
use bytes::BufMut;
use commonware_actor::Feedback;
use commonware_codec::{
    Buf, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Block, Heightable, Reporter,
    aggregation::{
        scheme::ed25519,
        types::{Ack, Activity, Certificate, Item},
    },
    ancestry::Ancestry,
    marshal::{Finalized, Ledger, Linear},
    types::{Epoch, Height, OutputIndex},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher as _, Sha256, certificate::mocks::Fixture, sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    mmr::Location,
    qmdb::sync::{Request, Source, Target, source},
    translator::TwoCap,
};
use commonware_utils::{
    Acknowledgement as _, NZU64, NZUsize,
    acknowledgement::{Exact, ExactWaiter},
    channel::oneshot,
    non_empty, non_empty_range,
    range::NonEmptyRange,
    sync::Mutex,
};
use futures::{FutureExt as _, StreamExt as _};
use std::{convert::Infallible, future, num::NonZeroUsize, sync::Arc, time::Duration};

type Databases = SingleDatabaseSet<deterministic::Context>;

/// Key of the counter every changed block adds its input's amount to.
fn counter_key() -> Digest {
    Sha256::hash(&[b"counter"])
}

/// A finalized input: an amount to add to the counter. Zero is invalid in every context.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    height: Height,
    amount: u64,
}

impl Write for Input {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.amount.write(buf);
    }
}

impl EncodeSize for Input {
    fn encode_size(&self) -> usize {
        self.height.encode_size() + self.amount.encode_size()
    }
}

impl Read for Input {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::read(buf)?,
            amount: u64::read(buf)?,
        })
    }
}

impl Digestible for Input {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[b"input", &self.encode()])
    }
}

impl Heightable for Input {
    fn height(&self) -> Height {
        self.height
    }
}

impl Block for Input {
    fn parent(&self) -> Digest {
        Digest::EMPTY
    }
}

/// An executed block, which commits to the database state after its input.
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    height: Height,
    parent: Digest,
    input: Option<Digest>,
    root: Digest,
    range: NonEmptyRange<Location>,
}

impl Write for State {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.parent.write(buf);
        self.input.write(buf);
        self.root.write(buf);
        self.range.write(buf);
    }
}

impl EncodeSize for State {
    fn encode_size(&self) -> usize {
        self.height.encode_size()
            + self.parent.encode_size()
            + self.input.encode_size()
            + self.root.encode_size()
            + self.range.encode_size()
    }
}

impl Read for State {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::read(buf)?,
            parent: Digest::read(buf)?,
            input: Option::<Digest>::read(buf)?,
            root: Digest::read(buf)?,
            range: NonEmptyRange::read(buf)?,
        })
    }
}

impl Digestible for State {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[b"state", &self.encode()])
    }
}

impl Heightable for State {
    fn height(&self) -> Height {
        self.height
    }
}

impl Block for State {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl Executed<Digest> for State {
    fn input(&self) -> Option<Digest> {
        self.input
    }
}

/// A height whose block the application holds, and the signal that releases it.
type Gate = Arc<Mutex<Option<(u64, oneshot::Receiver<()>)>>>;

/// Adds each input's amount to a counter in the database.
#[derive(Clone, Default)]
struct Counter {
    /// Heights of every execution, in order.
    executed: Arc<Mutex<Vec<u64>>>,
    /// Height, and the counter before and after, of every applied block, in order.
    applied: Arc<Mutex<Vec<(u64, u64, u64)>>>,
    /// Holds [`Application::capture`] for the block at a height until released.
    gate: Gate,
    /// Commits changed blocks to a root other than their batches'.
    lie: bool,
}

impl Counter {
    /// Holds the block at `height` in [`Application::capture`], before its batches are applied,
    /// until the returned sender fires.
    fn gate(&self, height: u64) -> oneshot::Sender<()> {
        let (release, released) = oneshot::channel();
        *self.gate.lock() = Some((height, released));
        release
    }
}

/// Reads the counter from applied state.
async fn read_counter(databases: &Databases) -> u64 {
    databases
        .read()
        .await
        .get(&counter_key())
        .await
        .expect("counter is readable")
        .map_or(0, |value| digest_to_u64(&value))
}

impl Application<deterministic::Context> for Counter {
    type Input = Input;
    type Block = State;
    type Databases = Databases;
    type Captured = u64;

    fn sync_targets(
        block: &State,
    ) -> <Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
        Target::new(block.root, block.range.clone())
    }

    async fn genesis(&mut self) -> State {
        let target = <Databases as DatabaseSet<deterministic::Context>>::initial_sync_targets();
        State {
            height: Height::zero(),
            parent: Digest::EMPTY,
            input: None,
            root: target.root,
            range: target.range,
        }
    }

    async fn execute(
        &mut self,
        (_, context): (deterministic::Context, Context<Digest>),
        ancestry: impl Ancestry<State>,
        input: Arc<Input>,
        mut batches: <Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> Execution<Self, deterministic::Context> {
        self.executed.lock().push(context.height.get());
        let parent = Box::pin(ancestry)
            .next()
            .await
            .expect("ancestry starts at the parent");
        if input.amount == 0 {
            return Execution::Unchanged {
                block: State {
                    height: context.height,
                    parent: parent.digest(),
                    input: Some(context.input),
                    root: parent.root,
                    range: parent.range.clone(),
                },
            };
        }
        let counter = batches
            .get(&counter_key())
            .await
            .expect("counter is readable")
            .map_or(0, |value| digest_to_u64(&value));
        batches = batches.write(counter_key(), Some(u64_to_digest(counter + input.amount)));
        let merkleized = batches.merkleize().await.expect("batches merkleize");
        let bounds = merkleized.bounds();
        let root = if self.lie {
            Digest::EMPTY
        } else {
            merkleized.root()
        };
        Execution::Changed {
            block: State {
                height: context.height,
                parent: parent.digest(),
                input: Some(context.input),
                root,
                range: non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            },
            merkleized,
        }
    }

    async fn capture(
        &mut self,
        _: deterministic::Context,
        block: &State,
        _: &<Databases as DatabaseSet<deterministic::Context>>::Merkleized,
        readers: <Databases as DatabaseSet<deterministic::Context>>::Readers,
    ) -> u64 {
        let gate = self
            .gate
            .lock()
            .take_if(|(height, _)| *height == block.height.get());
        if let Some((_, released)) = gate {
            let _ = released.await;
        }
        readers
            .read()
            .await
            .get(&counter_key())
            .await
            .expect("counter is readable")
            .map_or(0, |value| digest_to_u64(&value))
    }

    async fn finalized(
        &mut self,
        _: deterministic::Context,
        block: &State,
        before: u64,
        readers: <Databases as DatabaseSet<deterministic::Context>>::Readers,
    ) {
        let after = readers
            .read()
            .await
            .get(&counter_key())
            .await
            .expect("counter is readable")
            .map_or(0, |value| digest_to_u64(&value));
        self.applied
            .lock()
            .push((block.height.get(), before, after));
    }
}

/// The engine's marshal, which ignores prunes.
#[derive(Clone)]
struct Marshal;

impl Ledger for Marshal {
    type Block = Input;
    type Error = Infallible;

    async fn prune(&self, _: OutputIndex) -> Result<(), Infallible> {
        Ok(())
    }

    fn ack_window(&self) -> NonZeroUsize {
        NZUsize!(4)
    }
}

type TestMailbox = Mailbox<deterministic::Context, Counter>;
type Chain = executor::Mailbox<State>;

/// The executed chain as stateful sees it, recording the prunes stateful requests.
#[derive(Clone)]
struct Recorded {
    chain: Chain,
    pruned: Arc<Mutex<Vec<u64>>>,
}

impl Ledger for Recorded {
    type Block = State;
    type Error = executor::Stopped;

    async fn prune(&self, below: OutputIndex) -> Result<(), executor::Stopped> {
        self.pruned.lock().push(below.get());
        self.chain.prune(below).await
    }

    fn ack_window(&self) -> NonZeroUsize {
        self.chain.ack_window()
    }
}

impl Linear for Recorded {}

/// A running node: stateful, its executor, and their mailboxes.
struct Running {
    stateful: Handle<()>,
    executor: Handle<Result<(), Halt>>,
    inbox: Inbox<Finalized<Input>>,
    mailbox: TestMailbox,
    chain: Chain,
}

impl Running {
    /// Stops the node as a crash would.
    async fn crash(self) {
        self.executor.abort();
        self.stateful.abort();
        let _ = self.executor.await;
        let _ = self.stateful.await;
    }

    /// Reports finalized inputs as `(index, amount)` and returns marshal's acknowledgement
    /// waiters.
    fn report(&mut self, inputs: &[(u64, u64)]) -> Vec<ExactWaiter> {
        inputs
            .iter()
            .map(|&(index, amount)| {
                let (acknowledgement, waiter) = Exact::handle();
                let _ = self.inbox.report(Finalized {
                    index: OutputIndex::new(index),
                    block: Arc::new(Input {
                        height: Height::new(index),
                        amount,
                    }),
                    acknowledgement,
                });
                waiter
            })
            .collect()
    }

    /// Returns the applied counter.
    async fn counter(&self) -> u64 {
        let databases = self
            .mailbox
            .subscribe_databases()
            .await
            .expect("stateful is running");
        read_counter(&databases).await
    }
}

/// Serves a node's databases to peers, and fetches state sync operations from a peer's.
#[derive(Clone, Default)]
struct Resolver {
    /// The node's own databases, once stateful attaches them.
    own: Arc<Mutex<Option<Databases>>>,
    /// The databases state sync fetches from. Requests wait while there are none.
    peer: Arc<Mutex<Option<Databases>>>,
}

impl Source for Resolver {
    type Family = <Databases as Source>::Family;
    type Digest = <Databases as Source>::Digest;
    type Op = <Databases as Source>::Op;
    type Error = <Databases as Source>::Error;

    fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> impl Future<Output = source::Result<Self>> + Send {
        let peer = self.peer.lock().clone();
        async move {
            match peer {
                Some(peer) => peer.serve(request).await,
                None => future::pending().await,
            }
        }
    }
}

impl AttachableResolver<Qmdb<deterministic::Context>> for Resolver {
    async fn attach_database(&self, database: Shared<Qmdb<deterministic::Context>>) {
        *self.own.lock() = Some(database);
    }
}

/// A node's collaborators, kept across restarts.
#[derive(Clone)]
struct Node {
    /// Prefix of the node's storage partitions.
    name: &'static str,
    counter: Counter,
    resolver: Resolver,
    /// Starts an empty chain from a checkpoint instead of genesis.
    checkpoint: bool,
    prune_config: Option<PruneConfig>,
    /// Every prune stateful requested of the executed chain.
    pruned: Arc<Mutex<Vec<u64>>>,
}

impl Default for Node {
    fn default() -> Self {
        Self::named("ordered")
    }
}

impl Node {
    fn named(name: &'static str) -> Self {
        Self {
            name,
            counter: Counter::default(),
            resolver: Resolver::default(),
            checkpoint: false,
            prune_config: None,
            pruned: Arc::default(),
        }
    }

    /// Returns a node that starts from a checkpoint, state-syncing from `source`.
    fn joining(name: &'static str, source: &Self) -> Self {
        Self {
            resolver: Resolver {
                peer: Arc::clone(&source.resolver.own),
                ..Resolver::default()
            },
            checkpoint: true,
            ..Self::named(name)
        }
    }

    async fn start(&self, context: &deterministic::Context) -> Running {
        self.start_with(context, |mailbox| mailbox).await
    }

    /// Starts the node with `consumer` wrapping stateful as the executor's consumer.
    async fn start_with<R>(
        &self,
        context: &deterministic::Context,
        consumer: impl FnOnce(TestMailbox) -> R,
    ) -> Running
    where
        R: Reporter<Activity = Finalized<State>>,
    {
        // A crashed run's databases close before the restarted run opens them again.
        self.resolver.own.lock().take();
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let (stateful, mailbox) = Stateful::init(
            context.child("stateful"),
            Config {
                application: self.counter.clone(),
                db_config: qmdb_config(self.name, page_cache.clone()),
                resolvers: self.resolver.clone(),
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(8),
                    apply_batch_size: NZU64!(16),
                    max_outstanding_requests: NZUsize!(4),
                    update_channel_size: NZUsize!(4),
                },
                mailbox_size: NZUsize!(16),
                prune_config: self.prune_config,
            },
        );
        let (executor, inbox, chain) =
            Executor::<_, _, _, _, TwoCap, Exact>::init::<Finalized<Input>>(
                context.child("executor"),
                executor::Config {
                    execute: mailbox.clone(),
                    consumer: consumer(mailbox.clone()),
                    ack_window: Marshal.ack_window(),
                    epoch: Epoch::zero(),
                    start: if self.checkpoint {
                        executor::Start::Checkpoint
                    } else {
                        executor::Start::Genesis
                    },
                    store: StoreConfig {
                        partition_prefix: self.name.into(),
                        translator: TwoCap,
                        page_cache,
                        items_per_section: NZU64!(4),
                        write_buffer: NZUsize!(1024),
                        replay_buffer: NZUsize!(1024),
                        codec_config: (),
                    },
                    mailbox_size: NZUsize!(16),
                },
            )
            .await;
        let recorded = Recorded {
            chain: chain.clone(),
            pruned: Arc::clone(&self.pruned),
        };
        Running {
            stateful: stateful.start(recorded),
            executor: executor.start(Marshal),
            inbox,
            mailbox,
            chain,
        }
    }
}

/// Forwards blocks from `from` up with acknowledgements the executor never receives, as if the
/// executor crashed before recording that stateful applied them.
#[derive(Clone)]
struct Withhold {
    inner: TestMailbox,
    from: u64,
    /// The executor's acknowledgements, never released.
    withheld: Arc<Mutex<Vec<Exact>>>,
    /// Resolve once stateful durably applied each withheld block.
    applied: Arc<Mutex<Vec<ExactWaiter>>>,
}

impl Reporter for Withhold {
    type Activity = Finalized<State>;

    fn report(&mut self, finalized: Finalized<State>) -> Feedback {
        if finalized.index.get() < self.from {
            return self.inner.report(finalized);
        }
        let (acknowledgement, waiter) = Exact::handle();
        self.withheld.lock().push(finalized.acknowledgement);
        self.applied.lock().push(waiter);
        self.inner.report(Finalized {
            acknowledgement,
            ..finalized
        })
    }
}

async fn acknowledged(waiters: Vec<ExactWaiter>) {
    for waiter in waiters {
        waiter.await.expect("input was acknowledged");
    }
}

#[test]
fn applies_each_block_and_acknowledges_it_once_durable() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let node = Node::default();
        let mut running = node.start(&context).await;
        let waiters = running.report(&[(1, 5), (2, 7), (3, 3)]);
        acknowledged(waiters).await;

        assert_eq!(running.counter().await, 15);
        assert_eq!(
            *node.counter.applied.lock(),
            vec![(1, 0, 5), (2, 5, 12), (3, 12, 15)]
        );
    });
}

#[test]
fn unchanged_blocks_apply_nothing_and_are_acknowledged() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let node = Node::default();
        let mut running = node.start(&context).await;
        let waiters = running.report(&[(1, 5), (2, 0), (3, 2)]);
        acknowledged(waiters).await;

        // The rejected input's block commits to its parent's state and is never applied.
        let parent = running.chain.block_at(Height::new(1)).await.unwrap();
        let rejected = running.chain.block_at(Height::new(2)).await.unwrap();
        assert_eq!(
            Counter::sync_targets(&rejected),
            Counter::sync_targets(&parent)
        );
        assert_eq!(running.counter().await, 7);
        assert_eq!(*node.counter.applied.lock(), vec![(1, 0, 5), (3, 5, 7)]);
    });
}

#[test]
fn an_unchanged_block_after_durable_state_is_acknowledged_at_once() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let node = Node::default();
        let mut running = node.start(&context).await;
        acknowledged(running.report(&[(1, 5)])).await;

        // The state before the rejected input is durable and nothing else is pending, so it is
        // acknowledged without waiting for a barrier that would never start.
        acknowledged(running.report(&[(2, 0)])).await;
        assert_eq!(running.counter().await, 5);
    });
}

#[test]
fn execution_forks_from_blocks_not_yet_applied() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let node = Node::default();
        let release = node.counter.gate(1);
        let mut running = node.start(&context).await;
        let mut waiters = running.report(&[(1, 5), (2, 7), (3, 3)]);

        // Later inputs execute on block 1's pending state before any of it is applied.
        while node.counter.executed.lock().len() < 3 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(running.counter().await, 0);
        assert!(node.counter.applied.lock().is_empty());
        assert!((&mut waiters[0]).now_or_never().is_none());

        release.send(()).expect("block 1 is held");
        acknowledged(waiters).await;
        assert_eq!(running.counter().await, 15);
        assert_eq!(
            *node.counter.applied.lock(),
            vec![(1, 0, 5), (2, 5, 12), (3, 12, 15)]
        );
    });
}

#[test]
fn restart_discards_state_the_executor_did_not_record_as_applied() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let node = Node::default();
        let withheld = Arc::new(Mutex::new(Vec::new()));
        let applied = Arc::new(Mutex::new(Vec::new()));
        let mut running = node
            .start_with(&context, |inner| Withhold {
                inner,
                from: 3,
                withheld: Arc::clone(&withheld),
                applied: Arc::clone(&applied),
            })
            .await;
        let mut waiters = running.report(&[(1, 5), (2, 7), (3, 3)]);
        let unrecorded = waiters.pop().unwrap();
        acknowledged(waiters).await;

        // Stateful made block 3 durable, but the executor never learned of it.
        let durable = loop {
            if let Some(durable) = applied.lock().pop() {
                break durable;
            }
            context.sleep(Duration::from_millis(1)).await;
        };
        durable.await.expect("stateful applied block 3");
        assert_eq!(running.counter().await, 15);
        running.crash().await;
        drop(unrecorded);

        // The databases reopen at block 2, and block 3 is applied again on top of it.
        let restarted_context = context.child("restarted");
        let mut running = node.start(&restarted_context).await;
        acknowledged(running.report(&[(3, 3)])).await;
        assert_eq!(running.counter().await, 15);
        assert_eq!(
            *node.counter.applied.lock(),
            vec![(1, 0, 5), (2, 5, 12), (3, 12, 15), (3, 12, 15)]
        );
    });
}

#[test]
fn pruning_keeps_what_a_restart_needs() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
        let node = Node {
            prune_config: Some(PruneConfig {
                maintenance_interval: NZUsize!(1),
                retained_marshal_blocks: 0,
                retained_qmdb_blocks: 0,
            }),
            ..Node::default()
        };
        let mut running = node.start(&context).await;
        let inputs: Vec<_> = (1..=20).map(|index| (index, 1)).collect();
        acknowledged(running.report(&inputs)).await;

        // Stateful keeps the acknowledgement window plus one blocks behind the applied tip: from
        // block 5 on, each applied block lets the chain drop the block the window left behind.
        // The databases keep everything until a checkpoint is certified.
        while node.pruned.lock().len() < 16 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(*node.pruned.lock(), (1..=16).collect::<Vec<_>>());
        assert_eq!(oldest_retained(&running).await, Location::new(0));

        // Once block 19 is certified, the next applied block prunes the databases too.
        let certified = running.chain.block_at(Height::new(19)).await.unwrap();
        Checkpoints::<ed25519::Scheme, State>::new(running.chain.clone(), NZU64!(20)).report(
            Activity::Certified(certificate(&mut context, certified.digest())),
        );
        acknowledged(running.report(&[(21, 1)])).await;
        while node.pruned.lock().len() < 17 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert!(oldest_retained(&running).await > Location::new(0));
        running.crash().await;

        let restarted_context = context.child("restarted");

        let mut running = node.start(&restarted_context).await;
        acknowledged(running.report(&[(22, 1)])).await;
        assert_eq!(running.counter().await, 22);
    });
}

#[test]
#[should_panic(expected = "executed block does not commit to the batches it produced")]
fn blocks_that_misstate_their_batches_halt() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let node = Node {
            counter: Counter {
                lie: true,
                ..Counter::default()
            },
            ..Node::default()
        };
        let mut running = node.start(&context).await;
        let _waiters = running.report(&[(1, 5)]);
        let _ = running.stateful.await;
    });
}

#[test]
fn a_joining_node_syncs_to_a_checkpoint_and_executes_after_it() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let source = Node::named("source");
        let source_context = context.child("source");
        let mut serving = source.start(&source_context).await;
        let inputs: Vec<_> = (1..=6).map(|index| (index, index)).collect();
        acknowledged(serving.report(&inputs)).await;

        // The joiner syncs to the checkpointed blocks it is offered while marshal holds inputs
        // from a floor below them.
        let joiner = Node::joining("joiner", &source);
        let joiner_context = context.child("joiner");
        let mut joining = joiner.start(&joiner_context).await;
        let waiters = joining.report(&[(3, 3), (4, 4), (5, 5), (6, 6), (7, 7)]);
        for height in [4, 6] {
            let block = serving.chain.block_at(Height::new(height)).await.unwrap();
            joining.chain.sync_to(block).await;
        }
        acknowledged(waiters).await;
        acknowledged(serving.report(&[(7, 7)])).await;

        // Both reach the same block and state, and the joiner applied only what it executed.
        let executed = joining.chain.block_at(Height::new(7)).await.unwrap();
        assert_eq!(
            executed,
            serving.chain.block_at(Height::new(7)).await.unwrap()
        );
        assert_eq!(joining.counter().await, 28);
        let applied = joiner.counter.applied.lock().clone();
        assert!(applied.iter().all(|&(height, _, _)| height > 4));
        assert_eq!(applied.last(), Some(&(7, 21, 28)));
    });
}

#[test]
fn an_interrupted_sync_resumes_toward_its_recorded_target() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let source = Node::named("source");
        let source_context = context.child("source");
        let mut serving = source.start(&source_context).await;
        let inputs: Vec<_> = (1..=6).map(|index| (index, index)).collect();
        acknowledged(serving.report(&inputs)).await;

        // No peer serves the first attempt, which a crash interrupts.
        let stalled = Node {
            checkpoint: true,
            ..Node::named("joiner")
        };
        let stalled_context = context.child("stalled");
        let joining = stalled.start(&stalled_context).await;
        joining
            .chain
            .sync_to(serving.chain.block_at(Height::new(4)).await.unwrap())
            .await;
        context.sleep(Duration::from_millis(50)).await;
        joining.crash().await;

        // Restarted with a peer, the node syncs to the target it persisted without a new offer.
        let joiner = Node::joining("joiner", &source);
        let joiner_context = context.child("joiner");
        let mut joining = joiner.start(&joiner_context).await;
        acknowledged(joining.report(&[(4, 4), (5, 5)])).await;
        assert_eq!(
            joining.chain.block_at(Height::new(5)).await.unwrap(),
            serving.chain.block_at(Height::new(5)).await.unwrap()
        );
        assert_eq!(joining.counter().await, 15);
    });
}

#[test]
fn a_running_sync_acknowledges_the_inputs_its_recorded_targets_cover() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let source = Node::named("source");
        let source_context = context.child("source");
        let mut serving = source.start(&source_context).await;
        let inputs: Vec<_> = (1..=6).map(|index| (index, index)).collect();
        acknowledged(serving.report(&inputs)).await;

        // No peer serves the sync, so it never finishes.
        let stalled = Node {
            checkpoint: true,
            ..Node::named("joiner")
        };
        let stalled_context = context.child("stalled");
        let mut joining = stalled.start(&stalled_context).await;
        let first = serving.chain.block_at(Height::new(4)).await.unwrap();
        joining.chain.sync_to(first).await;
        acknowledged(joining.report(&[(3, 3), (4, 4)])).await;

        // Inputs above the target are held until the sync engines record a newer one.
        let mut held = joining.report(&[(5, 5), (6, 6)]);
        context.sleep(Duration::from_millis(50)).await;
        assert!((&mut held[0]).now_or_never().is_none());
        let newer = serving.chain.block_at(Height::new(6)).await.unwrap();
        joining.chain.sync_to(newer).await;
        acknowledged(held).await;
    });
}

/// Returns a certificate of `digest` as checkpoint zero, signed by a quorum of four.
fn certificate(
    context: &mut deterministic::Context,
    digest: Digest,
) -> Certificate<ed25519::Scheme, Digest> {
    let Fixture { schemes, .. } = ed25519::fixture(context, b"ordered-checkpoints", 4);
    let item = Item {
        height: Height::zero(),
        digest,
    };
    let acks = schemes[..3]
        .iter()
        .map(|scheme| Ack::sign(scheme, Epoch::zero(), item.clone()).unwrap())
        .collect::<Vec<_>>();
    Certificate::from_acks(&schemes[0], non_empty![@acks.iter()], &Sequential).unwrap()
}

/// Returns the oldest operation a node's databases retain.
async fn oldest_retained(running: &Running) -> Location {
    let databases = running.mailbox.subscribe_databases().await.unwrap();
    databases.read().await.bounds().start
}

#[test]
fn pruning_keeps_what_peers_sync_to() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
        let prune_config = Some(PruneConfig {
            maintenance_interval: NZUsize!(1),
            retained_marshal_blocks: 0,
            retained_qmdb_blocks: 0,
        });
        let certified = Node {
            prune_config,
            ..Node::named("certified")
        };
        let uncertified = Node {
            prune_config,
            ..Node::named("uncertified")
        };
        let certified_context = context.child("certified");
        let mut with = certified.start(&certified_context).await;
        let uncertified_context = context.child("uncertified");
        let mut without = uncertified.start(&uncertified_context).await;
        let first: Vec<_> = (1..=11).map(|index| (index, 1)).collect();
        acknowledged(with.report(&first)).await;
        acknowledged(without.report(&first)).await;

        // Checkpoint zero certifies block eleven on one of two otherwise identical nodes.
        let checkpoint = with.chain.block_at(Height::new(11)).await.unwrap();
        let mut checkpoints =
            Checkpoints::<ed25519::Scheme, State>::new(with.chain.clone(), NZU64!(12));
        checkpoints.report(Activity::Certified(certificate(
            &mut context,
            checkpoint.digest(),
        )));
        let rest: Vec<_> = (12..=30).map(|index| (index, 1)).collect();
        acknowledged(with.report(&rest)).await;
        acknowledged(without.report(&rest)).await;
        while certified.pruned.lock().len() < 26 || uncertified.pruned.lock().len() < 26 {
            context.sleep(Duration::from_millis(1)).await;
        }

        // The certified node prunes only up to the operations a peer syncing to block eleven
        // fetches, and the other prunes nothing.
        let oldest = oldest_retained(&with).await;
        assert!(oldest > Location::new(0));
        assert!(oldest <= checkpoint.range.start());
        assert_eq!(oldest_retained(&without).await, Location::new(0));
    });
}
