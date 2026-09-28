//! The executor actor.

use super::{
    Context, Execute, Executed as _,
    mailbox::{Inbox, Input, Mailbox, Message, Subscriber},
    store::{Store, StoreConfig},
};
use commonware_actor::{
    Feedback,
    mailbox::{self as actor_mailbox, Receiver},
};
use commonware_codec::Read;
use commonware_consensus::{
    Block as _, Heightable as _, Reporter,
    ancestry::AncestorStream,
    marshal::{Delivery, Finalized, Ledger},
    types::{Epoch, Height, OutputIndex},
};
use commonware_cryptography::Digestible;
use commonware_macros::select_loop;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{
        Gauge, GaugeExt as _, MetricsExt as _,
        histogram::{self, Buckets, Timed},
    },
};
use commonware_storage::{Context as StorageContext, translator::Translator};
use commonware_utils::{
    Acknowledgement,
    acknowledgement::{Exact, ExactWaiter},
};
use futures::{FutureExt as _, future::BoxFuture};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, VecDeque},
    future,
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{debug, error, warn};

/// Configuration of an [`Executor`].
pub struct Config<X, R, T: Translator, C> {
    /// The application that executes inputs.
    pub execute: X,
    /// Receives each executed block, in order, and acknowledges it once applied.
    pub consumer: R,
    /// The engine marshal's acknowledgement window: how many inputs it delivers before one is
    /// acknowledged.
    pub ack_window: NonZeroUsize,
    /// The epoch of every input.
    pub epoch: Epoch,
    /// Storage of the executed chain.
    pub store: StoreConfig<T, C>,
    /// Capacity of the executor's mailbox.
    pub mailbox_size: NonZeroUsize,
}

/// The execution of one input.
struct Execution<B, D, A> {
    height: Height,
    /// Digest of the input.
    input: D,
    /// Released to marshal once the consumer applied the block.
    acknowledgement: A,
    block: BoxFuture<'static, B>,
    timer: histogram::Timer,
}

/// A block delivered to the consumer and awaiting its acknowledgement.
struct Delivered<A> {
    height: Height,
    /// Released to marshal once the consumer applied the block.
    acknowledgement: A,
    applied: ExactWaiter,
}

/// Executes a finalized stream of inputs into a chain of blocks.
///
/// See the [module documentation](super).
pub struct Executor<E, X, L, R, T, A>
where
    E: Rng + Spawner + Metrics + Clock + StorageContext,
    X: Execute<E>,
    L: Ledger<Block = X::Input>,
    R: Reporter<Activity = Finalized<X::Block>>,
    T: Translator,
    A: Acknowledgement,
{
    context: ContextCell<E>,
    execute: X,
    /// The engine's marshal, which delivers the inputs and is pruned behind the consumer, once
    /// the executor starts.
    marshal: Option<L>,
    consumer: R,
    epoch: Epoch,
    store: Store<E, T, X::Block>,
    /// Inputs from the engine's marshal, until it drops every [`Inbox`].
    inbox: Option<Receiver<Input<X::Input, A>>>,
    mailbox: Receiver<Message<X::Block>>,
    /// The executed chain, which backs each execution's ancestry.
    chain: Mailbox<X::Block>,

    /// Blocks from the applied block through the newest executed one, oldest first.
    line: VecDeque<Arc<X::Block>>,
    /// Index of the next input marshal will deliver.
    expected: Height,
    /// Inputs awaiting execution, in index order.
    inputs: VecDeque<Finalized<X::Input, A>>,
    /// The execution in flight, if any.
    execution: Option<Execution<X::Block, <X::Input as Digestible>::Digest, A>>,
    /// Blocks delivered to the consumer and awaiting its acknowledgement, oldest first.
    delivered: VecDeque<Delivered<A>>,
    /// Height below which the chain and marshal were last pruned.
    pruned: Height,
    /// Subscribers to blocks not yet executed, by height.
    subscribers: BTreeMap<Height, Vec<Subscriber<X::Block>>>,
    /// Height of the newest certified checkpoint whose block this executor executed and found
    /// identical, if any.
    checkpoint: Option<Height>,
    /// The newest certified checkpoint above the executed chain, checked once its block executes.
    certified: Option<(Height, <X::Block as Digestible>::Digest)>,

    executed_height: Gauge,
    applied_height: Gauge,
    execution_duration: Timed,
    ancestor_fetch_duration: Timed,
}

impl<E, X, L, R, T, A> Executor<E, X, L, R, T, A>
where
    E: Rng + Spawner + Metrics + Clock + StorageContext,
    X: Execute<E>,
    L: Ledger<Block = X::Input>,
    R: Reporter<Activity = Finalized<X::Block>>,
    T: Translator,
    A: Acknowledgement,
{
    /// Opens the executed chain and returns the executor, the inbox the engine's marshal reports
    /// inputs to, and the executed chain for consumers.
    ///
    /// The engine's marshal is supplied to [`start`](Self::start), so it can be built with the
    /// inbox as its application.
    ///
    /// An empty chain starts from the application's genesis block. Otherwise the executor resumes
    /// after the highest block its consumer applied, which is where marshal redelivers from. Either
    /// way, the application learns that block through [`Execute::resume`].
    pub async fn init<U>(
        context: E,
        config: Config<X, R, T, <X::Block as Read>::Cfg>,
    ) -> (Self, Inbox<U>, Mailbox<X::Block>)
    where
        U: Delivery<Block = X::Input, Acknowledgement = A>,
    {
        let Config {
            mut execute,
            consumer,
            ack_window,
            epoch,
            store,
            mailbox_size,
        } = config;
        let (store, tip) = Store::init(context.child("store"), store, || execute.genesis()).await;
        let tip = Arc::new(tip);
        execute.resume(Arc::clone(&tip));
        let applied = store.applied();
        let (inputs, inbox) = actor_mailbox::new(context.child("inbox"), mailbox_size);
        let (sender, mailbox) = actor_mailbox::new(context.child("mailbox"), mailbox_size);
        let chain = Mailbox::new(sender, ack_window, epoch);
        let executed_height =
            context.gauge("executed_height", "Height of the newest executed block");
        let applied_height = context.gauge(
            "applied_height",
            "Height of the newest block the consumer applied",
        );
        let execution_duration = Timed::new(context.histogram(
            "execution_duration",
            "Histogram of time taken to execute an input, in seconds",
            Buckets::LOCAL,
        ));
        let ancestor_fetch_duration = Timed::new(context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::LOCAL,
        ));
        let _ = executed_height.try_set(applied.get());
        let _ = applied_height.try_set(applied.get());
        let executor = Self {
            context: ContextCell::new(context),
            execute,
            marshal: None,
            consumer,
            epoch,
            store,
            inbox: Some(inbox),
            mailbox,
            chain: chain.clone(),
            line: VecDeque::from([tip]),
            expected: applied.next(),
            inputs: VecDeque::new(),
            execution: None,
            delivered: VecDeque::new(),
            pruned: Height::zero(),
            subscribers: BTreeMap::new(),
            checkpoint: None,
            certified: None,
            executed_height,
            applied_height,
            execution_duration,
            ancestor_fetch_duration,
        };
        (executor, Inbox::new(inputs), chain)
    }

    /// Starts the executor on `marshal`, the engine's marshal that reports to its [`Inbox`].
    ///
    /// # Panics
    ///
    /// Panics if `marshal`'s acknowledgement window is not the configured one.
    pub fn start(mut self, marshal: L) -> Handle<()> {
        assert_eq!(
            marshal.ack_window(),
            self.chain.ack_window(),
            "marshal's acknowledgement window is not the configured one"
        );
        self.marshal = Some(marshal);
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.start_execution();
            },
            on_stopped => {
                debug!("executor stopped");
            },
            input = next_input(&mut self.inbox) => match input {
                Some(input) => self.admit(input),
                None => self.inbox = None,
            },
            Some(message) = self.mailbox.recv() else break => {
                if !self.handle(message).await {
                    break;
                }
            },
            block = next_execution(&mut self.execution) => {
                if !self.executed(block).await {
                    break;
                }
            },
            applied = next_applied(&mut self.delivered) => {
                if applied.is_err() || !self.applied().await {
                    warn!("consumer dropped a block without acknowledging it");
                    break;
                }
            },
        }
    }

    /// Handles a request. Returns `false` if the executor must halt.
    async fn handle(&mut self, message: Message<X::Block>) -> bool {
        match message {
            Message::Block { height, response } => {
                let _ = response.send(self.block(height).await);
            }
            Message::Subscribe { height, subscriber } => self.subscribe(height, subscriber).await,
            Message::Prune { below } => self.prune(below).await,
            Message::Certified { height, digest } => return self.certified(height, digest).await,
            Message::Diverged { height } => {
                error!(%height, "executed block diverges from the one honest validators certified");
                return false;
            }
        }
        true
    }

    /// Records that a checkpoint certified `digest` as the block at `height`, checking it against
    /// the executed chain now or once that block executes. Returns `false` if the executed chain
    /// diverges from it.
    async fn certified(
        &mut self,
        height: Height,
        digest: <X::Block as Digestible>::Digest,
    ) -> bool {
        let newest = self
            .certified
            .map(|(certified, _)| certified)
            .max(self.checkpoint);
        if newest.is_some_and(|newest| newest >= height) {
            return true;
        }
        let executed = self.line.back().expect("line holds the applied block");
        if height > executed.height() {
            self.certified = Some((height, digest));
            return true;
        }
        // Nothing is pruned past the newest checkpoint, so a newer one's block is retained.
        let block = self
            .block(height)
            .await
            .expect("a block above the newest checkpoint is retained");
        self.matches_certified(height, &block, digest)
    }

    /// Checks `block`, executed at `height`, against the digest a checkpoint certified there,
    /// making it the newest checkpoint if they match. Returns `false` if they differ.
    fn matches_certified(
        &mut self,
        height: Height,
        block: &X::Block,
        digest: <X::Block as Digestible>::Digest,
    ) -> bool {
        if block.digest() != digest {
            error!(%height, "executed block diverges from the one honest validators certified");
            return false;
        }
        self.checkpoint = Some(height);
        true
    }

    /// Calls `subscriber` with the block at `height` once it is executed, or drops it if that
    /// block is executed but no longer retained.
    async fn subscribe(&mut self, height: Height, subscriber: Subscriber<X::Block>) {
        let executed = self
            .line
            .back()
            .expect("line holds the applied block")
            .height();
        if height > executed {
            self.subscribers.entry(height).or_default().push(subscriber);
            return;
        }
        if let Some(block) = self.block(height).await {
            subscriber(&block);
        }
    }

    /// Queues an input for execution, or acknowledges one the consumer already applied.
    fn admit(&mut self, input: Finalized<X::Input, A>) {
        let index = Height::new(input.index.get());
        if index <= self.store.applied() {
            input.acknowledgement.acknowledge();
            return;
        }
        assert_eq!(
            index, self.expected,
            "marshal must deliver each input once, in index order"
        );
        self.expected = index.next();
        self.inputs.push_back(input);
    }

    /// Starts executing the oldest queued input on top of the newest executed block.
    fn start_execution(&mut self) {
        if self.execution.is_some() {
            return;
        }
        let Some(input) = self.inputs.pop_front() else {
            return;
        };
        let parent = Arc::clone(self.line.back().expect("line holds the applied block"));
        let context = Context {
            epoch: self.epoch,
            height: parent.height().next(),
            input: input.block.digest(),
        };
        let ancestry = AncestorStream::new(
            Arc::new(self.context.child("ancestry")),
            self.chain.clone(),
            [parent],
            self.ancestor_fetch_duration.clone(),
        );
        let mut execute = self.execute.clone();
        let runtime = self.context.child("execute");
        let block = input.block;
        self.execution = Some(Execution {
            height: context.height,
            input: context.input,
            acknowledgement: input.acknowledgement,
            block: async move { execute.execute((runtime, context), ancestry, block).await }
                .boxed(),
            timer: self.execution_duration.timer(self.context.as_ref()),
        });
    }

    /// Archives and delivers a block the application executed. Returns whether the consumer still
    /// accepts blocks.
    async fn executed(&mut self, block: X::Block) -> bool {
        let Execution {
            height,
            input,
            acknowledgement,
            timer,
            ..
        } = self.execution.take().expect("an execution was in flight");
        timer.observe(self.context.as_ref());
        let parent = self.line.back().expect("line holds the applied block");
        assert_eq!(
            block.height(),
            height,
            "executed block has the wrong height"
        );
        assert_eq!(
            block.parent(),
            parent.digest(),
            "executed block has the wrong parent"
        );
        assert_eq!(
            block.input(),
            Some(input),
            "executed block has the wrong input"
        );

        // A block archived before a crash must be the one execution produces again.
        if self
            .store
            .executed()
            .is_some_and(|executed| height <= executed)
        {
            let archived = self
                .store
                .get(height)
                .await
                .expect("archived block above the applied cursor is missing");
            assert_eq!(
                archived.digest(),
                block.digest(),
                "execution is not deterministic"
            );
        } else {
            self.store.put(&block).await;
        }
        let _ = self.executed_height.try_set(height.get());

        if let Some((_, digest)) = self
            .certified
            .take_if(|(certified, _)| *certified == height)
            && !self.matches_certified(height, &block, digest)
        {
            return false;
        }

        let block = Arc::new(block);
        for subscriber in self.subscribers.remove(&height).into_iter().flatten() {
            subscriber(&block);
        }
        self.line.push_back(Arc::clone(&block));
        let (applied, waiter) = Exact::handle();
        self.delivered.push_back(Delivered {
            height,
            acknowledgement,
            applied: waiter,
        });
        let delivery = Finalized {
            index: OutputIndex::new(height.get()),
            block,
            acknowledgement: applied,
        };
        if self.consumer.report(delivery) == Feedback::Closed {
            warn!("consumer stopped accepting blocks");
            return false;
        }
        true
    }

    /// Makes the oldest delivered block, which the consumer applied, durable along with every
    /// contiguous block it has also applied, then acknowledges their inputs to marshal.
    ///
    /// Returns `false` if the consumer dropped one of those blocks without acknowledging it.
    async fn applied(&mut self) -> bool {
        let oldest = self
            .delivered
            .pop_front()
            .expect("an applied block was delivered");
        let mut through = oldest.height;
        let mut released = vec![oldest.acknowledgement];
        while let Some(next) = self.delivered.front_mut() {
            match (&mut next.applied).now_or_never() {
                Some(Ok(())) => {}
                Some(Err(_)) => return false,
                None => break,
            }
            let next = self
                .delivered
                .pop_front()
                .expect("the next block was delivered");
            through = next.height;
            released.push(next.acknowledgement);
        }
        self.store.apply(through).await;
        let _ = self.applied_height.try_set(through.get());
        while self
            .line
            .front()
            .is_some_and(|block| block.height() < through)
        {
            self.line.pop_front();
        }
        for acknowledgement in released {
            acknowledgement.acknowledge();
        }
        true
    }

    /// Returns the executed block at `height`, if retained.
    ///
    /// Blocks from the applied one up are served from memory, since they may not be durable yet.
    async fn block(&mut self, height: Height) -> Option<Arc<X::Block>> {
        let applied = self
            .line
            .front()
            .expect("line holds the applied block")
            .height();
        if height >= applied {
            let offset = usize::try_from(height.get() - applied.get()).ok()?;
            return self.line.get(offset).cloned();
        }
        self.store.get(height).await.map(Arc::new)
    }

    /// Prunes executed blocks below `below`, and asks marshal to prune the inputs they executed.
    ///
    /// Nothing is pruned before a checkpoint is certified. Neither prune passes the newest certified
    /// checkpoint, which a peer resumes from, nor the applied block, which the next execution
    /// builds on.
    async fn prune(&mut self, below: Height) {
        let Some(checkpoint) = self.checkpoint else {
            debug!(%below, "no certified checkpoint to prune behind");
            return;
        };
        let below = below.min(self.store.applied()).min(checkpoint);
        if below <= self.pruned {
            return;
        }
        self.pruned = below;
        self.store.prune(below).await;
        let marshal = self
            .marshal
            .clone()
            .expect("a running executor has a marshal");
        self.context
            .child("prune")
            .spawn(move |_| async move { marshal.prune(OutputIndex::new(below.get())).await });
    }
}

/// Waits for the execution in flight, if any.
async fn next_execution<B, D, A>(execution: &mut Option<Execution<B, D, A>>) -> B {
    match execution {
        Some(execution) => (&mut execution.block).await,
        None => future::pending().await,
    }
}

/// Waits for the next input, or forever once marshal dropped every [`Inbox`].
async fn next_input<I, A>(inbox: &mut Option<Receiver<Input<I, A>>>) -> Option<Finalized<I, A>>
where
    I: Send + Sync + 'static,
    A: Send + 'static,
{
    match inbox {
        Some(inbox) => inbox.recv().await.map(|Input(input)| input),
        None => future::pending().await,
    }
}

/// Waits for the consumer to acknowledge the oldest delivered block, if any.
async fn next_applied<A>(
    delivered: &mut VecDeque<Delivered<A>>,
) -> Result<(), commonware_utils::acknowledgement::Canceled> {
    match delivered.front_mut() {
        Some(delivered) => (&mut delivered.applied).await,
        None => future::pending().await,
    }
}
