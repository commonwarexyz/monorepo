//! Executor tests.

use super::*;
use bytes::BufMut;
use commonware_actor::Feedback;
use commonware_codec::{
    Buf, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Automaton as _, Heightable, Monitor as _, Reporter,
    aggregation::{
        scheme::ed25519,
        types::{Ack, Activity, Certificate, Item},
    },
    marshal::{Finalized, Ledger},
    types::{Epoch, OutputIndex},
};
use commonware_cryptography::{
    Digest as _, Hasher as _, Sha256, certificate::mocks::Fixture, sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Handle, Runner as _, Storage as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{
    Acknowledgement as _, NZU16, NZU64, NZUsize,
    acknowledgement::{Exact, ExactWaiter},
    channel::{mpsc::error::TryRecvError, ring},
    non_empty,
    sync::Mutex,
};
use futures::{FutureExt as _, StreamExt as _};
use std::{convert::Infallible, future, num::NonZeroUsize, time::Duration};

/// A finalized input: an amount to add.
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
        Sha256::hash(&[
            b"input",
            &self.height.get().to_be_bytes(),
            &self.amount.to_be_bytes(),
        ])
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

/// An executed block: the running total after its input.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Total {
    height: Height,
    parent: Digest,
    input: Option<Digest>,
    total: u64,
}

impl Write for Total {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.parent.write(buf);
        self.input.write(buf);
        self.total.write(buf);
    }
}

impl EncodeSize for Total {
    fn encode_size(&self) -> usize {
        self.height.encode_size()
            + self.parent.encode_size()
            + self.input.encode_size()
            + self.total.encode_size()
    }
}

impl Read for Total {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::read(buf)?,
            parent: Digest::read(buf)?,
            input: Option::<Digest>::read(buf)?,
            total: u64::read(buf)?,
        })
    }
}

impl Digestible for Total {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[b"total", &self.encode()])
    }
}

impl Heightable for Total {
    fn height(&self) -> Height {
        self.height
    }
}

impl Block for Total {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl Executed<Digest> for Total {
    fn input(&self) -> Option<Digest> {
        self.input
    }
}

/// Adds each input's amount to the running total.
#[derive(Clone, Default)]
struct Adder {
    /// Added to every total, so two adders with different biases disagree.
    bias: u64,
    /// The heights of each execution's whole ancestry, newest first.
    ancestries: Arc<Mutex<Vec<Vec<u64>>>>,
    /// The height of each block execution resumed from.
    resumed: Arc<Mutex<Vec<u64>>>,
    /// The height of each target a state sync started from.
    synced: Arc<Mutex<Vec<u64>>>,
    /// The height of each block reported as certified.
    certified: Arc<Mutex<Vec<u64>>>,
    /// Which block a state sync reaches.
    reach: Reach,
}

/// Which block [`Adder`]'s state sync reaches.
#[derive(Clone, Copy, Default)]
enum Reach {
    /// The target it started from, at once.
    #[default]
    Target,
    /// The first newer target.
    Update,
    /// The target it started from, once a newer one arrives.
    Stale,
    /// The first update at or above this height, recording every update as it arrives.
    Record(u64),
}

impl Execute<deterministic::Context> for Adder {
    type Input = Input;
    type Block = Total;

    async fn genesis(&mut self) -> Total {
        Total {
            height: Height::zero(),
            parent: Digest::EMPTY,
            input: None,
            total: 0,
        }
    }

    fn resume(&mut self, tip: Arc<Total>) {
        self.resumed.lock().push(tip.height.get());
    }

    fn certified(&mut self, block: Arc<Total>) {
        self.certified.lock().push(block.height.get());
    }

    async fn sync(
        &mut self,
        target: Arc<Total>,
        mut updates: ring::Receiver<Update<Total>>,
    ) -> Arc<Total> {
        self.synced.lock().push(target.height.get());
        if matches!(self.reach, Reach::Target) {
            return target;
        }
        loop {
            let Some(Update { block, recorded }) = updates.recv().await else {
                return future::pending().await;
            };
            match self.reach {
                Reach::Update => return block,
                Reach::Target | Reach::Stale => return target,
                Reach::Record(height) => {
                    let _ = recorded.send(());
                    if block.height.get() >= height {
                        return block;
                    }
                }
            }
        }
    }

    async fn execute(
        self,
        (_, context): (deterministic::Context, Context<Digest>),
        ancestry: impl Ancestry<Total>,
        input: Arc<Input>,
    ) -> Total {
        let ancestry = ancestry.collect::<Vec<_>>().await;
        self.ancestries
            .lock()
            .push(ancestry.iter().map(|block| block.height.get()).collect());
        let parent = ancestry.first().expect("ancestry starts at the parent");
        Total {
            height: context.height,
            parent: parent.digest(),
            input: Some(context.input),
            total: parent.total + input.amount + self.bias,
        }
    }
}

/// The engine's marshal, which only records prunes.
#[derive(Clone, Default)]
struct Marshal {
    pruned: Arc<Mutex<Vec<OutputIndex>>>,
}

impl Ledger for Marshal {
    type Block = Input;
    type Error = Infallible;

    async fn prune(&self, below: OutputIndex) -> Result<(), Infallible> {
        self.pruned.lock().push(below);
        Ok(())
    }

    fn ack_window(&self) -> NonZeroUsize {
        NZUsize!(16)
    }
}

/// A block delivered to the consumer, with the acknowledgement it has not released yet.
struct Delivery {
    height: u64,
    block: Arc<Total>,
    acknowledgement: Option<Exact>,
}

/// A consumer that applies blocks only when told to.
#[derive(Clone, Default)]
struct Consumer {
    delivered: Arc<Mutex<Vec<Delivery>>>,
    /// Whether the consumer stopped accepting blocks.
    closed: Arc<Mutex<bool>>,
}

impl Consumer {
    fn heights(&self) -> Vec<u64> {
        self.delivered
            .lock()
            .iter()
            .map(|delivery| delivery.height)
            .collect()
    }

    fn totals(&self) -> Vec<u64> {
        self.delivered
            .lock()
            .iter()
            .map(|delivery| delivery.block.total)
            .collect()
    }

    fn block(&self, height: u64) -> Arc<Total> {
        let delivered = self.delivered.lock();
        let delivery = delivered
            .iter()
            .rev()
            .find(|delivery| delivery.height == height)
            .expect("block was delivered");
        Arc::clone(&delivery.block)
    }

    /// Takes the acknowledgement of the newest delivery of the block at `height`.
    fn take(&self, height: u64) -> Exact {
        let mut delivered = self.delivered.lock();
        let delivery = delivered
            .iter_mut()
            .rev()
            .find(|delivery| delivery.height == height)
            .expect("block was delivered");
        delivery
            .acknowledgement
            .take()
            .expect("block is not applied yet")
    }

    /// Applies the newest delivery of the block at `height`.
    fn apply(&self, height: u64) {
        self.take(height).acknowledge();
    }
}

impl Reporter for Consumer {
    type Activity = Finalized<Total>;

    fn report(&mut self, finalized: Finalized<Total>) -> Feedback {
        if *self.closed.lock() {
            return Feedback::Closed;
        }
        assert_eq!(finalized.index.get(), finalized.block.height.get());
        self.delivered.lock().push(Delivery {
            height: finalized.index.get(),
            block: finalized.block,
            acknowledgement: Some(finalized.acknowledgement),
        });
        Feedback::Ok
    }
}

type TestExecutor = Executor<deterministic::Context, Adder, Marshal, Consumer, TwoCap, Exact>;
type TestInbox = Inbox<Finalized<Input>>;
type TestMailbox = Mailbox<Total>;

/// The executor's collaborators, kept across restarts.
#[derive(Clone, Default)]
struct Parts {
    adder: Adder,
    marshal: Marshal,
    consumer: Consumer,
    /// Starts an empty chain from a checkpoint instead of genesis.
    checkpoint: bool,
}

impl Parts {
    async fn start(
        &self,
        context: &deterministic::Context,
    ) -> (Handle<Result<(), Halt>>, TestInbox, TestMailbox) {
        let config = Config {
            execute: self.adder.clone(),
            consumer: self.consumer.clone(),
            ack_window: NZUsize!(16),
            epoch: Epoch::zero(),
            start: if self.checkpoint {
                Start::Checkpoint
            } else {
                Start::Genesis
            },
            store: StoreConfig {
                partition_prefix: "executor".into(),
                translator: TwoCap,
                page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                items_per_section: NZU64!(1),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config: (),
            },
            mailbox_size: NZUsize!(16),
        };
        let (executor, inbox, mailbox) =
            TestExecutor::init::<Finalized<Input>>(context.child("executor"), config).await;
        (executor.start(self.marshal.clone()), inbox, mailbox)
    }
}

/// Returns the input at `index` and the waiter marshal holds for its acknowledgement.
fn input(index: u64, amount: u64) -> (Finalized<Input>, ExactWaiter) {
    let (acknowledgement, waiter) = Exact::handle();
    let finalized = Finalized {
        index: OutputIndex::new(index),
        block: Arc::new(Input {
            height: Height::new(index),
            amount,
        }),
        acknowledgement,
    };
    (finalized, waiter)
}

/// Returns a block at `height` that executed the input `(height, amount)`, as a checkpoint might
/// certify.
fn certified(height: u64, amount: u64, total: u64) -> Arc<Total> {
    Arc::new(Total {
        height: Height::new(height),
        parent: Sha256::hash(&[b"parent", &height.to_be_bytes()]),
        input: Some(input(height, amount).0.block.digest()),
        total,
    })
}

/// Returns the block [`Adder`] executes on top of `parent` for an input of `amount`.
fn child(parent: &Total, amount: u64) -> Arc<Total> {
    let height = parent.height.next();
    Arc::new(Total {
        height,
        parent: parent.digest(),
        input: Some(input(height.get(), amount).0.block.digest()),
        total: parent.total + amount,
    })
}

/// Returns the chain an unbiased [`Adder`] executes from `inputs`, starting at genesis.
fn expected_chain(inputs: &[(u64, u64)]) -> Vec<Total> {
    let mut chain = vec![Total {
        height: Height::zero(),
        parent: Digest::EMPTY,
        input: None,
        total: 0,
    }];
    for &(index, amount) in inputs {
        let parent = chain.last().unwrap();
        let block = Total {
            height: Height::new(index),
            parent: parent.digest(),
            input: Some(
                Input {
                    height: Height::new(index),
                    amount,
                }
                .digest(),
            ),
            total: parent.total + amount,
        };
        chain.push(block);
    }
    chain
}

/// Waits until `condition` holds.
async fn until(context: &deterministic::Context, condition: impl Fn() -> bool) {
    for _ in 0..1_000 {
        if condition() {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    panic!("condition never held");
}

/// Returns whether marshal's acknowledgement resolved. Polls a pending waiter only.
fn acknowledged(waiter: &mut ExactWaiter) -> bool {
    matches!(waiter.now_or_never(), Some(Ok(())))
}

/// Waits until marshal's acknowledgement resolves.
async fn until_acknowledged(context: &deterministic::Context, waiter: &mut ExactWaiter) {
    for _ in 0..1_000 {
        if acknowledged(waiter) {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    panic!("input was never acknowledged");
}

/// Reports the inputs `(index, amount)` and returns marshal's waiters for them.
fn report(inbox: &mut TestInbox, inputs: &[(u64, u64)]) -> Vec<ExactWaiter> {
    inputs
        .iter()
        .map(|&(index, amount)| {
            let (input, waiter) = input(index, amount);
            assert_eq!(inbox.report(input), Feedback::Ok);
            waiter
        })
        .collect()
}

#[test]
fn executes_each_input_and_acknowledges_it_once_applied() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (_executor, mut inbox, _) = parts.start(&context).await;
        let inputs = [(1, 5), (2, 7), (3, 3)];
        let mut waiters = report(&mut inbox, &inputs);
        until(&context, || parts.consumer.heights().len() == 3).await;
        assert_eq!(parts.consumer.heights(), vec![1, 2, 3]);
        assert_eq!(parts.consumer.totals(), vec![5, 12, 15]);
        for (index, amount) in inputs {
            let block = parts.consumer.block(index);
            assert_eq!(block.input, Some(input(index, amount).0.block.digest()));
            if index > 1 {
                assert_eq!(block.parent, parts.consumer.block(index - 1).digest());
            }
        }

        // Marshal's acknowledgement follows the consumer's, in delivery order.
        context.sleep(Duration::from_millis(10)).await;
        assert!(!acknowledged(&mut waiters[0]));
        parts.consumer.apply(1);
        until_acknowledged(&context, &mut waiters[0]).await;
        parts.consumer.apply(3);
        context.sleep(Duration::from_millis(10)).await;
        assert!(!acknowledged(&mut waiters[2]));
        parts.consumer.apply(2);
        until_acknowledged(&context, &mut waiters[1]).await;
        until_acknowledged(&context, &mut waiters[2]).await;
    });
}

#[test]
fn genesis_input_is_acknowledged_without_execution() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (_executor, mut inbox, _) = parts.start(&context).await;
        let mut waiters = report(&mut inbox, &[(0, 9), (1, 1)]);
        until_acknowledged(&context, &mut waiters[0]).await;
        until(&context, || parts.consumer.heights() == vec![1]).await;
        assert_eq!(parts.consumer.totals(), vec![1]);
    });
}

#[test]
fn execution_sees_the_executed_chain_newest_first() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (_executor, mut inbox, _) = parts.start(&context).await;
        report(&mut inbox, &[(1, 1), (2, 1), (3, 1)]);
        until(&context, || parts.consumer.heights().len() == 3).await;
        assert_eq!(
            *parts.adder.ancestries.lock(),
            vec![vec![0], vec![1, 0], vec![2, 1, 0]]
        );
    });
}

#[test]
fn a_crash_before_recording_genesis_resumes_from_it() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, _inbox, _) = parts.start(&context).await;
        executor.abort();
        let _ = executor.await;

        // Without its applied cursor, the chain holds only genesis, as a crash between archiving
        // genesis and recording the cursor leaves it.
        context.remove("executor_applied", None).await.unwrap();
        let restarted_context = context.child("restarted");
        let (_executor, mut inbox, _) = parts.start(&restarted_context).await;
        assert_eq!(*parts.adder.resumed.lock(), vec![0, 0]);
        let mut waiters = report(&mut inbox, &[(1, 5)]);
        until(&context, || parts.consumer.heights() == vec![1]).await;
        parts.consumer.apply(1);
        until_acknowledged(&context, &mut waiters[0]).await;
    });
}

#[test]
fn a_crash_before_recording_genesis_resumes_from_it_even_with_a_checkpoint_start() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, _inbox, _) = parts.start(&context).await;
        executor.abort();
        let _ = executor.await;

        // A chain holding only genesis started from it, so a checkpoint start does not sync.
        context.remove("executor_applied", None).await.unwrap();
        let parts = Parts {
            checkpoint: true,
            ..parts
        };
        let restarted_context = context.child("restarted");
        let (_executor, mut inbox, _) = parts.start(&restarted_context).await;
        assert_eq!(*parts.adder.resumed.lock(), vec![0, 0]);
        report(&mut inbox, &[(1, 5)]);
        until(&context, || parts.consumer.heights() == vec![1]).await;
        assert!(parts.adder.synced.lock().is_empty());
    });
}

#[test]
fn restart_redelivers_unapplied_blocks_and_acknowledges_applied_inputs() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, _) = parts.start(&context).await;
        report(&mut inbox, &[(1, 5), (2, 7), (3, 3)]);
        until(&context, || parts.consumer.heights().len() == 3).await;
        parts.consumer.apply(1);
        context.sleep(Duration::from_millis(10)).await;
        executor.abort();
        let _ = executor.await;

        // Execution resumes from the applied block, and marshal redelivers every input it did not
        // see acknowledged.
        let restarted_context = context.child("restarted");
        let (_executor, mut inbox, _) = parts.start(&restarted_context).await;
        assert_eq!(*parts.adder.resumed.lock(), vec![0, 1]);
        let mut waiters = report(&mut inbox, &[(1, 5), (2, 7), (3, 3)]);
        until_acknowledged(&context, &mut waiters[0]).await;
        until(&context, || parts.consumer.heights() == vec![1, 2, 3, 2, 3]).await;
        assert_eq!(parts.consumer.totals(), vec![5, 12, 15, 12, 15]);
        assert!(!acknowledged(&mut waiters[1]));
        parts.consumer.apply(2);
        parts.consumer.apply(3);
        until_acknowledged(&context, &mut waiters[1]).await;
        until_acknowledged(&context, &mut waiters[2]).await;
    });
}

#[test]
#[should_panic(expected = "execution is not deterministic")]
fn nondeterministic_execution_halts() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, _) = parts.start(&context).await;
        report(&mut inbox, &[(1, 5), (2, 7)]);
        until(&context, || parts.consumer.heights().len() == 2).await;
        // Applying the first block makes the second, already executed, durable too.
        parts.consumer.apply(1);
        context.sleep(Duration::from_millis(10)).await;
        executor.abort();
        let _ = executor.await;

        let parts = Parts {
            adder: Adder {
                bias: 1,
                ..Adder::default()
            },
            ..parts
        };
        let restarted_context = context.child("restarted");
        let (executor, mut inbox, _) = parts.start(&restarted_context).await;
        report(&mut inbox, &[(2, 7)]);
        let _ = executor.await;
    });
}

#[test]
#[should_panic(expected = "marshal redelivered an input other than the one executed")]
fn a_redelivered_input_below_applied_must_match_the_archive() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, _) = parts.start(&context).await;
        let mut waiters = report(&mut inbox, &[(1, 5)]);
        until(&context, || parts.consumer.heights() == vec![1]).await;
        parts.consumer.apply(1);
        until_acknowledged(&context, &mut waiters[0]).await;
        executor.abort();
        let _ = executor.await;

        // After a restart, marshal redelivers an applied input with a different payload.
        let restarted_context = context.child("restarted");
        let (executor, mut inbox, _) = parts.start(&restarted_context).await;
        report(&mut inbox, &[(1, 6)]);
        let _ = executor.await;
    });
}

#[test]
fn a_closed_consumer_halts_the_executor() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, _) = parts.start(&context).await;
        *parts.consumer.closed.lock() = true;
        report(&mut inbox, &[(1, 5)]);
        assert_eq!(executor.await.unwrap(), Err(Halt::ConsumerClosed));
    });
}

#[test]
fn a_dropped_acknowledgement_halts_the_executor() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, _) = parts.start(&context).await;
        let mut waiters = report(&mut inbox, &[(1, 5)]);
        until(&context, || parts.consumer.heights() == vec![1]).await;
        drop(parts.consumer.take(1));
        assert_eq!(executor.await.unwrap(), Err(Halt::Unacknowledged));
        assert!(!acknowledged(&mut waiters[0]));
    });
}

#[test]
fn ledger_reads_the_executed_chain_and_prunes_behind_applied() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;
        let mut waiters = report(&mut inbox, &[(1, 1), (2, 2), (3, 3), (4, 4)]);
        until(&context, || parts.consumer.heights().len() == 4).await;
        for height in 1..=3 {
            parts.consumer.apply(height);
        }
        until_acknowledged(&context, &mut waiters[2]).await;
        assert_eq!(Ledger::ack_window(&mailbox), NZUsize!(16));
        for height in 0..=4 {
            let block = mailbox.block_at(Height::new(height)).await.unwrap();
            assert_eq!(block.height.get(), height);
        }
        assert!(mailbox.block_at(Height::new(5)).await.is_none());

        // Nothing is pruned before a checkpoint is certified.
        Ledger::prune(&mailbox, OutputIndex::new(9)).await.unwrap();
        context.sleep(Duration::from_millis(10)).await;
        assert!(parts.marshal.pruned.lock().is_empty());

        // Pruning never passes the applied block, and prunes marshal alike.
        let certified = mailbox.block_at(Height::new(4)).await.unwrap();
        mailbox.certified(Height::new(4), certified.digest());
        Ledger::prune(&mailbox, OutputIndex::new(9)).await.unwrap();
        until(&context, || !parts.marshal.pruned.lock().is_empty()).await;
        assert_eq!(*parts.marshal.pruned.lock(), vec![OutputIndex::new(3)]);
        assert!(mailbox.block_at(Height::new(2)).await.is_none());
        for height in 3..=4 {
            assert!(mailbox.block_at(Height::new(height)).await.is_some());
        }
    });
}

#[test]
fn a_replayed_checkpoint_below_the_pruned_chain_is_ignored_after_restart() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, mailbox) = parts.start(&context).await;
        let mut waiters = report(&mut inbox, &[(1, 1), (2, 2), (3, 3), (4, 4)]);
        until(&context, || parts.consumer.heights().len() == 4).await;
        for height in 1..=4 {
            parts.consumer.apply(height);
        }
        until_acknowledged(&context, &mut waiters[3]).await;
        let older = parts.consumer.block(1).digest();
        let newer = parts.consumer.block(3).digest();
        mailbox.certified(Height::new(1), older);
        mailbox.certified(Height::new(3), newer);
        Ledger::prune(&mailbox, OutputIndex::new(4)).await.unwrap();
        until(&context, || !parts.marshal.pruned.lock().is_empty()).await;
        assert!(mailbox.block_at(Height::new(1)).await.is_none());
        executor.abort();
        let _ = executor.await;

        // Aggregation replays its journal oldest first: the pruned checkpoint is covered by the
        // newer one, which is retained and verified again.
        let restarted_context = context.child("restarted");
        let (executor, _inbox, mailbox) = parts.start(&restarted_context).await;
        mailbox.certified(Height::new(1), older);
        mailbox.certified(Height::new(3), newer);
        Ledger::prune(&mailbox, OutputIndex::new(4)).await.unwrap();
        until(&context, || parts.marshal.pruned.lock().len() == 2).await;
        assert!(mailbox.block_at(Height::new(3)).await.is_some());
        assert!(executor.now_or_never().is_none());
    });
}

#[test]
fn a_checkpoint_ahead_of_execution_that_diverges_halts_the_executor() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, mailbox) = parts.start(&context).await;

        // The certified digest is checked once the block at its height executes, which is then
        // never delivered.
        mailbox.certified(Height::new(2), Sha256::hash(&[b"another block"]));
        report(&mut inbox, &[(1, 5), (2, 7)]);
        assert_eq!(executor.await.unwrap(), Err(Halt::Diverged(Height::new(2))));
        assert_eq!(parts.consumer.heights(), vec![1]);
    });
}

#[test]
fn a_checkpoint_of_an_executed_block_that_diverges_halts_the_executor() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, mut inbox, mailbox) = parts.start(&context).await;
        report(&mut inbox, &[(1, 5)]);
        until(&context, || parts.consumer.heights() == vec![1]).await;

        mailbox.certified(Height::new(1), Sha256::hash(&[b"another block"]));
        assert_eq!(executor.await.unwrap(), Err(Halt::Diverged(Height::new(1))));
    });
}

type TestCheckpoints = Checkpoints<ed25519::Scheme, Total>;

/// Returns a certificate of `digest` as checkpoint `checkpoint`, signed by a quorum of four.
fn certificate(
    context: &mut deterministic::Context,
    checkpoint: u64,
    digest: Digest,
) -> Certificate<ed25519::Scheme, Digest> {
    let Fixture { schemes, .. } = ed25519::fixture(context, b"executor-checkpoints", 4);
    let item = Item {
        height: Height::new(checkpoint),
        digest,
    };
    let acks = schemes[..3]
        .iter()
        .map(|scheme| Ack::sign(scheme, Epoch::zero(), item.clone()).unwrap())
        .collect::<Vec<_>>();
    Certificate::from_acks(&schemes[0], non_empty![@acks.iter()], &Sequential).unwrap()
}

#[test]
fn checkpoints_certify_the_last_block_of_each_interval() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (_executor, _, mailbox) = parts.start(&context).await;
        let checkpoints = TestCheckpoints::new(mailbox, NZU64!(4));
        assert_eq!(checkpoints.height(Height::zero()), Some(Height::new(3)));
        assert_eq!(checkpoints.height(Height::new(1)), Some(Height::new(7)));
        assert_eq!(checkpoints.height(Height::new(u64::MAX)), None);
    });
}

#[test]
fn checkpoints_answer_once_the_block_is_executed() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;
        let mut checkpoints = TestCheckpoints::new(mailbox, NZU64!(2));

        // Checkpoint zero certifies height one, which is not executed yet.
        let mut digest = checkpoints.propose(Height::zero()).await;
        context.sleep(Duration::from_millis(10)).await;
        assert!((&mut digest).now_or_never().is_none());
        report(&mut inbox, &[(1, 5)]);
        let digest = digest.await.unwrap();
        until(&context, || parts.consumer.heights() == vec![1]).await;
        assert_eq!(digest, parts.consumer.block(1).digest());

        // An executed block answers at once, and verification compares digests.
        assert_eq!(
            checkpoints.propose(Height::zero()).await.await.unwrap(),
            digest
        );
        assert!(
            checkpoints
                .verify(Height::zero(), digest)
                .await
                .await
                .unwrap()
        );
        let other = Sha256::hash(&[b"other"]);
        assert!(
            !checkpoints
                .verify(Height::zero(), other)
                .await
                .await
                .unwrap()
        );
    });
}

#[test]
fn certified_checkpoints_are_retained() {
    deterministic::Runner::default().start(|mut context| async move {
        let parts = Parts::default();
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;
        let mut checkpoints = TestCheckpoints::new(mailbox.clone(), NZU64!(2));
        let mut waiters = report(&mut inbox, &[(1, 1), (2, 1), (3, 1), (4, 1)]);
        until(&context, || parts.consumer.heights().len() == 4).await;
        for height in 1..=4 {
            parts.consumer.apply(height);
        }
        until_acknowledged(&context, &mut waiters[3]).await;

        // Checkpoint zero certifies height one.
        let newest = certificate(&mut context, 0, parts.consumer.block(1).digest());
        assert!(checkpoints.latest().is_none());
        assert_eq!(
            checkpoints.report(Activity::Certified(newest.clone())),
            Feedback::Ok
        );
        let latest = checkpoints.latest().unwrap();
        assert_eq!(latest.item, newest.item);
        assert_eq!(latest.certificate, newest.certificate);

        // Pruning stops at the certified block and the inputs after it.
        Ledger::prune(&mailbox, OutputIndex::new(4)).await.unwrap();
        until(&context, || !parts.marshal.pruned.lock().is_empty()).await;
        assert_eq!(*parts.marshal.pruned.lock(), vec![OutputIndex::new(1)]);
        assert!(mailbox.block_at(Height::new(0)).await.is_none());
        assert!(mailbox.block_at(Height::new(1)).await.is_some());
    });
}

#[test]
fn checkpoints_monitor_the_executors_epoch() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (_executor, _, mailbox) = parts.start(&context).await;
        let mut checkpoints = TestCheckpoints::new(mailbox, NZU64!(2));

        // The epoch never changes, and the subscription stays open.
        let (epoch, mut updates) = checkpoints.subscribe().await;
        assert_eq!(epoch, Epoch::zero());
        context.sleep(Duration::from_millis(10)).await;
        assert!(matches!(updates.try_recv(), Err(TryRecvError::Empty)));
    });
}

#[test]
fn divergence_halts_the_executor() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts::default();
        let (executor, _, mailbox) = parts.start(&context).await;
        let mut checkpoints = TestCheckpoints::new(mailbox, NZU64!(2));
        let item = Item {
            height: Height::zero(),
            digest: Sha256::hash(&[b"ours"]),
        };
        assert_eq!(checkpoints.report(Activity::Diverged(item)), Feedback::Ok);
        assert_eq!(executor.await.unwrap(), Err(Halt::Diverged(Height::new(1))));
    });
}

#[test]
fn checkpoint_start_executes_after_the_synced_block() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            checkpoint: true,
            ..Parts::default()
        };
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;
        let mut checkpoints = TestCheckpoints::new(mailbox.clone(), NZU64!(2));
        let below = checkpoints.propose(Height::zero()).await;
        let at = checkpoints.propose(Height::new(1)).await;

        // Inputs from marshal's floor are held until the chain has a base.
        let mut waiters = report(&mut inbox, &[(2, 1), (3, 2), (4, 3), (5, 4)]);
        context.sleep(Duration::from_millis(10)).await;
        assert!(!acknowledged(&mut waiters[0]));
        assert!(parts.consumer.heights().is_empty());
        assert!(mailbox.block_at(Height::zero()).await.is_none());

        // Inputs at or below the synced block are acknowledged without executing them.
        let base = certified(3, 2, 100);
        mailbox.sync_to(Arc::clone(&base)).await;
        until_acknowledged(&context, &mut waiters[1]).await;
        assert!(acknowledged(&mut waiters[0]));
        assert_eq!(*parts.adder.synced.lock(), vec![3]);
        assert_eq!(*parts.adder.resumed.lock(), vec![3]);
        assert_eq!(*parts.adder.certified.lock(), vec![3]);
        assert_eq!(
            mailbox.block_at(Height::new(3)).await,
            Some(Arc::clone(&base))
        );
        until(&context, || parts.consumer.heights() == vec![4, 5]).await;
        assert_eq!(parts.consumer.totals(), vec![103, 107]);

        // A checkpoint below the base can no longer be answered, and the base answers its own.
        assert!(below.await.is_err());
        assert_eq!(at.await.unwrap(), base.digest());
    });
}

#[test]
fn sync_follows_newer_targets_and_resumes_after_a_crash() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            adder: Adder {
                reach: Reach::Update,
                ..Adder::default()
            },
            checkpoint: true,
            ..Parts::default()
        };
        let (executor, _, mailbox) = parts.start(&context).await;
        mailbox.sync_to(certified(3, 2, 100)).await;
        until(&context, || parts.adder.synced.lock().len() == 1).await;
        executor.abort();
        let _ = executor.await;

        // The persisted target restarts the sync, and only newer targets reach it.
        let restarted_context = context.child("restarted");
        let (_executor, mut inbox, mailbox) = parts.start(&restarted_context).await;
        until(&context, || *parts.adder.synced.lock() == vec![3, 3]).await;
        assert!(mailbox.sync_to(certified(2, 1, 50)).await);
        assert!(mailbox.sync_to(certified(3, 2, 100)).await);
        let base = certified(6, 3, 200);
        assert!(mailbox.sync_to(Arc::clone(&base)).await);
        until(&context, || *parts.adder.resumed.lock() == vec![6]).await;
        assert_eq!(mailbox.block_at(Height::new(6)).await, Some(base));

        // Offers no longer matter once the chain has a base.
        assert!(!mailbox.sync_to(certified(9, 4, 300)).await);

        let mut waiters = report(&mut inbox, &[(6, 3), (7, 1)]);
        until_acknowledged(&context, &mut waiters[0]).await;
        until(&context, || parts.consumer.heights() == vec![7]).await;
        assert_eq!(parts.consumer.totals(), vec![201]);
    });
}

#[test]
#[should_panic(expected = "marshal's input differs from the one a state sync target executed")]
fn a_base_that_executed_another_input_halts() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            checkpoint: true,
            ..Parts::default()
        };
        let (executor, mut inbox, mailbox) = parts.start(&context).await;
        report(&mut inbox, &[(3, 5)]);
        mailbox.sync_to(certified(3, 2, 100)).await;
        let _ = executor.await;
    });
}

#[test]
fn sync_acknowledges_the_inputs_it_is_certain_to_reach() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            adder: Adder {
                reach: Reach::Record(8),
                ..Adder::default()
            },
            checkpoint: true,
            ..Parts::default()
        };
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;

        // Without a target, every input is held.
        let mut waiters = report(&mut inbox, &[(2, 1), (3, 2), (4, 1), (5, 1)]);
        context.sleep(Duration::from_millis(10)).await;
        assert!(!acknowledged(&mut waiters[0]));

        // The first target covers the inputs at or below it.
        let base = certified(3, 2, 100);
        mailbox.sync_to(Arc::clone(&base)).await;
        until_acknowledged(&context, &mut waiters[1]).await;
        assert!(acknowledged(&mut waiters[0]));
        assert!(!acknowledged(&mut waiters[2]));

        // A recorded update covers the inputs up to it, and later inputs are held again.
        let recorded = child(&child(&base, 1), 1);
        mailbox.sync_to(Arc::clone(&recorded)).await;
        until_acknowledged(&context, &mut waiters[3]).await;
        assert!(acknowledged(&mut waiters[2]));
        let mut later = report(&mut inbox, &[(6, 1), (7, 1)]);
        context.sleep(Duration::from_millis(10)).await;
        assert!(!acknowledged(&mut later[0]));
        assert!(parts.adder.resumed.lock().is_empty());

        // The sync reaches the newest update, which covers the rest.
        let reached = child(&child(&child(&recorded, 1), 1), 1);
        mailbox.sync_to(Arc::clone(&reached)).await;
        until(&context, || *parts.adder.resumed.lock() == vec![8]).await;
        until_acknowledged(&context, &mut later[1]).await;
        assert!(acknowledged(&mut later[0]));
        report(&mut inbox, &[(8, 1), (9, 4)]);
        until(&context, || parts.consumer.heights() == vec![9]).await;
        assert_eq!(parts.consumer.totals(), vec![reached.total + 4]);
    });
}

#[test]
fn a_floor_jump_before_the_first_target_drops_the_held_inputs() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            checkpoint: true,
            ..Parts::default()
        };
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;

        // Marshal delivers from its old floor, then jumps to the installed one.
        let mut stale = report(&mut inbox, &[(1, 1), (2, 1)]);
        let mut waiters = report(&mut inbox, &[(10, 1), (11, 2)]);
        until_acknowledged(&context, &mut stale[1]).await;
        assert!(acknowledged(&mut stale[0]));
        assert!(!acknowledged(&mut waiters[0]));

        let base = certified(10, 1, 100);
        mailbox.sync_to(Arc::clone(&base)).await;
        until(&context, || parts.consumer.heights() == vec![11]).await;
        assert!(acknowledged(&mut waiters[0]));
        assert_eq!(parts.consumer.totals(), vec![102]);
    });
}

#[test]
fn a_floor_jump_that_arrives_after_the_first_target_drops_the_held_inputs() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            adder: Adder {
                reach: Reach::Record(12),
                ..Adder::default()
            },
            checkpoint: true,
            ..Parts::default()
        };
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;

        // The first target reaches the executor before marshal's first input from the floor
        // installed for it, and covers the inputs held from the old floor.
        let mut stale = report(&mut inbox, &[(1, 1), (2, 1)]);
        let base = certified(10, 1, 100);
        mailbox.sync_to(Arc::clone(&base)).await;
        until_acknowledged(&context, &mut stale[1]).await;
        let mut waiters = report(&mut inbox, &[(10, 1), (11, 2), (12, 3)]);
        until_acknowledged(&context, &mut waiters[0]).await;
        assert!(!acknowledged(&mut waiters[1]));

        // The sync reaches a newer target, and execution resumes after it.
        let reached = child(&child(&base, 2), 3);
        mailbox.sync_to(Arc::clone(&reached)).await;
        until(&context, || *parts.adder.resumed.lock() == vec![12]).await;
        until_acknowledged(&context, &mut waiters[2]).await;
        report(&mut inbox, &[(13, 4)]);
        until(&context, || parts.consumer.heights() == vec![13]).await;
        assert_eq!(parts.consumer.totals(), vec![reached.total + 4]);
    });
}

#[test]
#[should_panic(expected = "marshal skipped inputs after a state sync target")]
fn a_floor_jump_past_the_recorded_target_halts() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            adder: Adder {
                reach: Reach::Record(100),
                ..Adder::default()
            },
            checkpoint: true,
            ..Parts::default()
        };
        let (executor, mut inbox, mailbox) = parts.start(&context).await;
        mailbox.sync_to(certified(3, 2, 100)).await;
        report(&mut inbox, &[(4, 1), (6, 1)]);
        let _ = executor.await;
    });
}

#[test]
#[should_panic(expected = "marshal's input differs from the one a state sync target executed")]
fn a_target_that_executed_another_input_halts_once_the_input_arrives() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            adder: Adder {
                reach: Reach::Record(100),
                ..Adder::default()
            },
            checkpoint: true,
            ..Parts::default()
        };
        let (executor, mut inbox, mailbox) = parts.start(&context).await;
        let base = certified(3, 2, 100);
        mailbox.sync_to(Arc::clone(&base)).await;
        mailbox.sync_to(child(&child(&base, 1), 1)).await;
        report(&mut inbox, &[(3, 2), (4, 1), (5, 7)]);
        let _ = executor.await;
    });
}

#[test]
fn a_target_below_the_inputs_marshal_delivers_is_ignored() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            checkpoint: true,
            ..Parts::default()
        };
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;

        // Marshal already passed the input after block 3, so a base there would miss inputs.
        let mut waiters = report(&mut inbox, &[(10, 1), (11, 2)]);
        assert!(mailbox.sync_to(certified(3, 2, 100)).await);
        context.sleep(Duration::from_millis(10)).await;
        assert!(parts.adder.synced.lock().is_empty());
        assert!(!acknowledged(&mut waiters[0]));

        // A target the inputs continue from starts the sync.
        let base = certified(10, 1, 100);
        assert!(mailbox.sync_to(Arc::clone(&base)).await);
        until_acknowledged(&context, &mut waiters[0]).await;
        until(&context, || parts.consumer.heights() == vec![11]).await;
        assert_eq!(parts.consumer.totals(), vec![102]);
    });
}

#[test]
fn a_floor_jump_after_the_base_redelivers_the_inputs_it_holds() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            checkpoint: true,
            ..Parts::default()
        };
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;

        // The sync reaches its target at once, before marshal's jump to the floor installed for
        // it, so the inputs held from marshal's old floor are admitted after the base.
        let mut stale = report(&mut inbox, &[(11, 2), (12, 3)]);
        let base = certified(10, 1, 100);
        assert!(mailbox.sync_to(Arc::clone(&base)).await);
        until(&context, || parts.consumer.heights() == vec![11, 12]).await;

        // Marshal jumps back and delivers the same inputs again. They are not executed again,
        // and only their new acknowledgements wait on the consumer.
        let mut waiters = report(&mut inbox, &[(10, 1), (11, 2), (12, 3), (13, 4)]);
        until_acknowledged(&context, &mut waiters[0]).await;
        until_acknowledged(&context, &mut stale[0]).await;
        until_acknowledged(&context, &mut stale[1]).await;
        until(&context, || parts.consumer.heights() == vec![11, 12, 13]).await;
        assert!(!acknowledged(&mut waiters[1]));
        for height in 11..=13 {
            parts.consumer.apply(height);
        }
        for waiter in &mut waiters[1..] {
            until_acknowledged(&context, waiter).await;
        }
        assert_eq!(parts.consumer.totals(), vec![102, 105, 109]);
    });
}

#[test]
fn a_replayed_checkpoint_below_the_synced_base_is_ignored_after_restart() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            checkpoint: true,
            ..Parts::default()
        };
        let (executor, mut inbox, mailbox) = parts.start(&context).await;
        let base = certified(10, 1, 100);
        assert!(mailbox.sync_to(Arc::clone(&base)).await);
        let mut waiters = report(&mut inbox, &[(10, 1), (11, 2)]);
        until(&context, || parts.consumer.heights() == vec![11]).await;
        parts.consumer.apply(11);
        until_acknowledged(&context, &mut waiters[1]).await;
        executor.abort();
        let _ = executor.await;

        // Aggregation replays a checkpoint of a block this node never executed, then the base's.
        let restarted_context = context.child("restarted");
        let (executor, _inbox, mailbox) = parts.start(&restarted_context).await;
        mailbox.certified(Height::new(5), Sha256::hash(&[b"never executed"]));
        mailbox.certified(Height::new(10), base.digest());
        assert_eq!(
            mailbox.block_at(Height::new(10)).await,
            Some(Arc::clone(&base))
        );
        assert!(executor.now_or_never().is_none());
    });
}

#[test]
fn a_target_above_the_synced_block_is_checked_once_executed() {
    deterministic::Runner::default().start(|context| async move {
        let parts = Parts {
            adder: Adder {
                reach: Reach::Stale,
                ..Adder::default()
            },
            checkpoint: true,
            ..Parts::default()
        };
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;

        // The sync reaches block 3 although block 6 was offered, and recorded, meanwhile.
        let base = certified(3, 2, 100);
        let later = child(&child(&child(&base, 1), 1), 1);
        mailbox.sync_to(Arc::clone(&base)).await;
        mailbox.sync_to(Arc::clone(&later)).await;
        until(&context, || *parts.adder.resumed.lock() == vec![3]).await;

        // Execution passes the heights below the recorded block and reproduces it.
        report(&mut inbox, &[(4, 1), (5, 1), (6, 1), (7, 1)]);
        until(&context, || parts.consumer.heights() == vec![4, 5, 6, 7]).await;
        assert_eq!(parts.consumer.block(6), later);
    });
}

#[test]
fn certified_blocks_reach_the_application_once_executed() {
    deterministic::Runner::default().start(|mut context| async move {
        let parts = Parts::default();
        let (_executor, mut inbox, mailbox) = parts.start(&context).await;
        let mut checkpoints = TestCheckpoints::new(mailbox, NZU64!(2));
        let inputs = [(1, 1), (2, 1), (3, 1), (4, 1), (5, 1)];
        let chain = expected_chain(&inputs);

        // Checkpoint one certifies height three before it is executed.
        let digest = chain[3].digest();
        checkpoints.report(Activity::Certified(certificate(&mut context, 1, digest)));
        report(&mut inbox, &inputs[..2]);
        until(&context, || parts.consumer.heights().len() == 2).await;
        assert!(parts.adder.certified.lock().is_empty());
        report(&mut inbox, &inputs[2..]);
        until(&context, || *parts.adder.certified.lock() == vec![3]).await;

        // An older checkpoint is ignored, and a newer one of an executed block is reported at once.
        let digest = chain[1].digest();
        checkpoints.report(Activity::Certified(certificate(&mut context, 0, digest)));
        until(&context, || parts.consumer.heights().len() == 5).await;
        let digest = chain[5].digest();
        checkpoints.report(Activity::Certified(certificate(&mut context, 2, digest)));
        until(&context, || *parts.adder.certified.lock() == vec![3, 5]).await;
    });
}
