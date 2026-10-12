//! The executor actor.

use super::{
    Context, Execute, Executed as _, Update,
    mailbox::{Final, Inbox, Input, Mailbox, Message, Subscriber},
    store::{Opened, Store, StoreConfig},
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
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{
        Gauge, GaugeExt as _, MetricsExt as _,
        histogram::{self, Buckets, Timed},
    },
};
use commonware_storage::{Context as StorageContext, translator::Translator};
use commonware_utils::{
    Acknowledgement, NZUsize,
    acknowledgement::{Canceled, Exact, ExactWaiter},
    channel::{fallible::OneshotExt as _, oneshot, ring},
};
use futures::{FutureExt as _, future::BoxFuture};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    future,
    hash::Hash,
    mem,
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{debug, error, warn};

/// Where an executor with an empty chain starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// From the application's genesis block.
    Genesis,
    /// From a block a checkpoint certifies, once one is offered through [`Mailbox::sync_to`] and
    /// the application syncs its state to it.
    Checkpoint,
}

/// Configuration of an [`Executor`].
pub struct Config<X, R, T: Translator, C> {
    /// The application that executes inputs.
    pub execute: X,
    /// Receives each executed block, in order, and acknowledges it once applied.
    pub consumer: R,
    /// The engine marshal's acknowledgement window: how many inputs it delivers before one is
    /// acknowledged.
    pub ack_window: NonZeroUsize,
    /// The epoch [`Checkpoints`](super::Checkpoints) reports to aggregation, whose validator set
    /// certifies every checkpoint.
    pub epoch: Epoch,
    /// Where an empty chain starts. Ignored once the chain has a base or a sync target.
    pub start: Start,
    /// Storage of the executed chain.
    pub store: StoreConfig<T, C>,
    /// Capacity of the executor's mailbox.
    pub mailbox_size: NonZeroUsize,
}

/// Why an [`Executor`] halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Halt {
    /// Validators certified or signed a block other than the executed one at this height, so
    /// the executed chain diverges from the one honest validators executed.
    #[error("executed block at height {0} diverges from honest validators")]
    Diverged(Height),
    /// The consumer stopped accepting blocks.
    #[error("consumer stopped accepting blocks")]
    ConsumerClosed,
    /// The consumer dropped a block without acknowledging it.
    #[error("consumer dropped a block without acknowledging it")]
    Unacknowledged,
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

/// A state sync toward the newest offered target.
struct Syncing<B: Send + Sync> {
    /// The newest target.
    target: Arc<B>,
    /// Height of the newest target the sync is certain to reach: the first target, or an update
    /// the application recorded. The base is at or above it.
    recorded: Height,
    /// Offers targets above the first to the application.
    updates: ring::Sender<Update<B>>,
    /// Updates not yet recorded, by increasing height, each with the signal of its recording.
    unrecorded: VecDeque<(Height, oneshot::Receiver<()>)>,
    /// Targets at or above the next input, by height, to check against the input at their height.
    offered: BTreeMap<Height, Arc<B>>,
    /// Resolves to the block the application synced its state to.
    base: BoxFuture<'static, Arc<B>>,
}

/// A block delivered to the consumer and awaiting its acknowledgement.
struct Delivered<A> {
    height: Height,
    /// Released to marshal once the consumer applied the block.
    acknowledgement: A,
    applied: ExactWaiter,
}

/// The preparations of inputs ahead of their execution in the current run.
///
/// Every input with a running or finished preparation is final and not yet delivered, so marshal
/// delivers it later unless a floor skips it, which it never does once the chain has a base. Its
/// entry is released once the input finishes executing or is acknowledged without executing, so
/// the entries are bounded by the final inputs marshal has not delivered.
struct Preparations<D> {
    /// Preparations, running or finished, of inputs that have not settled, by input digest.
    prepared: HashMap<D, Handle<()>>,
    /// The newest inputs that settled, by starting to execute or being acknowledged without
    /// executing, oldest first.
    ///
    /// After a restart, marshal redelivers inputs from its acknowledgement floor, at most an
    /// acknowledgement window below the applied cursor, and may report them final first. The
    /// executor seeds this with the inputs of that window, and keeping that many settled inputs
    /// keeps such reports from preparing inputs that will not execute.
    settled: VecDeque<D>,
    /// The members of `settled`.
    recent: HashSet<D>,
    capacity: NonZeroUsize,
}

impl<D: Copy + Eq + Hash> Preparations<D> {
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            prepared: HashMap::new(),
            settled: VecDeque::new(),
            recent: HashSet::new(),
            capacity,
        }
    }

    /// Returns whether `input` was neither prepared nor settled in this run.
    fn wanted(&self, input: &D) -> bool {
        !self.prepared.contains_key(input) && !self.recent.contains(input)
    }

    fn insert(&mut self, input: D, preparation: Handle<()>) {
        self.prepared.insert(input, preparation);
    }

    /// Records that `input` started executing or was acknowledged without executing.
    fn settle(&mut self, input: D) {
        if !self.recent.insert(input) {
            return;
        }
        self.settled.push_back(input);
        if self.settled.len() > self.capacity.get() {
            let oldest = self.settled.pop_front().expect("settled is not empty");
            self.recent.remove(&oldest);
        }
    }

    /// Aborts the preparation of `input`, which finished executing or was acknowledged without
    /// executing.
    fn release(&mut self, input: &D) {
        if let Some(preparation) = self.prepared.remove(input) {
            preparation.abort();
        }
    }
}

/// Executes a finalized stream of inputs into a chain of blocks.
///
/// Marshal must deliver every input after the applied one, once and in index order. The executor
/// does not follow a floor installed on marshal.
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
    store: Store<E, T, X::Block>,
    /// Inputs from the engine's marshal, until it drops every [`Inbox`].
    inbox: Option<Receiver<Input<X::Input, A>>>,
    /// Inputs the engine's marshal reports final before it orders them, until it drops every
    /// [`Inbox`].
    finals: Option<Receiver<Final<X::Input>>>,
    mailbox: Receiver<Message<X::Block>>,
    /// The executed chain, which backs each execution's ancestry.
    chain: Mailbox<X::Block>,

    /// Blocks from the applied block through the newest executed one, oldest first, or empty
    /// while the chain has no base.
    line: VecDeque<Arc<X::Block>>,
    /// The state sync that gives a chain without a base its base, once a target is known.
    syncing: Option<Syncing<X::Block>>,
    /// Index of the next input marshal will deliver.
    expected: Height,
    /// Inputs awaiting execution, in index order, or, while the chain has no base, the inputs the
    /// sync may not reach, held unacknowledged.
    inputs: VecDeque<Finalized<X::Input, A>>,
    /// The execution in flight, if any.
    execution: Option<Execution<X::Block, <X::Input as Digestible>::Digest, A>>,
    /// Blocks delivered to the consumer and awaiting its acknowledgement, oldest first.
    delivered: VecDeque<Delivered<A>>,
    /// Preparations of inputs ahead of their execution.
    preparations: Preparations<<X::Input as Digestible>::Digest>,
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
    /// An empty chain starts from the application's genesis block, or with [`Start::Checkpoint`]
    /// waits for a state sync. Otherwise the executor resumes after the highest block its consumer
    /// applied, which is where marshal redelivers from, or continues an interrupted state sync. The
    /// application learns the block execution resumes from through [`Execute::resume`].
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
            start,
            store,
            mailbox_size,
        } = config;
        let (store, opened) =
            Store::init(context.child("store"), store, start, || execute.genesis()).await;
        let (line, target) = match opened {
            Opened::Applied(tip) => {
                let tip = Arc::new(tip);
                execute.resume(Arc::clone(&tip));
                (VecDeque::from([tip]), None)
            }
            Opened::Syncing(target) => (VecDeque::new(), target.map(Arc::new)),
        };
        let applied = store.applied();
        let mut preparations = Preparations::new(ack_window);
        if !line.is_empty() {
            // Marshal redelivers the inputs from its acknowledgement floor, which trails the
            // applied cursor by at most an acknowledgement window, and may report them final
            // before it does. They are acknowledged without executing, so none is prepared.
            let oldest = applied
                .get()
                .saturating_sub(ack_window.get() as u64 - 1)
                .max(1);
            for height in oldest..=applied.get() {
                if let Some(input) = store
                    .get(Height::new(height))
                    .await
                    .and_then(|block| block.input())
                {
                    preparations.settle(input);
                }
            }
        }
        let (inputs, inbox) = actor_mailbox::new(context.child("inbox"), mailbox_size);
        let (finals_sender, finals) = actor_mailbox::new(context.child("finals"), mailbox_size);
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
        let mut executor = Self {
            context: ContextCell::new(context),
            execute,
            marshal: None,
            consumer,
            store,
            inbox: Some(inbox),
            finals: Some(finals),
            mailbox,
            chain: chain.clone(),
            line,
            syncing: None,
            expected: applied.next(),
            inputs: VecDeque::new(),
            execution: None,
            delivered: VecDeque::new(),
            preparations,
            pruned: Height::zero(),
            subscribers: BTreeMap::new(),
            checkpoint: None,
            certified: None,
            executed_height,
            applied_height,
            execution_duration,
            ancestor_fetch_duration,
        };
        executor.syncing = target.map(|target| executor.start_sync(target));
        (executor, Inbox::new(inputs, finals_sender), chain)
    }

    /// Starts the executor on `marshal`, the engine's marshal that reports to its [`Inbox`].
    ///
    /// The handle resolves once the executor stops, or with why it halted.
    ///
    /// # Panics
    ///
    /// Panics if `marshal`'s acknowledgement window is not the configured one.
    pub fn start(mut self, marshal: L) -> Handle<Result<(), Halt>> {
        assert_eq!(
            marshal.ack_window(),
            self.chain.ack_window(),
            "marshal's acknowledgement window is not the configured one"
        );
        self.marshal = Some(marshal);
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) -> Result<(), Halt> {
        if self.line.is_empty() && !self.sync().await? {
            return Ok(());
        }
        select_loop! {
            self.context,
            on_start => {
                self.start_execution();
            },
            on_stopped => {
                debug!("executor stopped");
            },
            input = next_input(&mut self.inbox) => match input {
                Some(input) => self.admit(input, true).await,
                None => self.inbox = None,
            },
            Some(message) = self.mailbox.recv() else break => {
                self.handle(message).await?;
            },
            block = next_execution(&mut self.execution) => {
                self.executed(block).await?;
            },
            applied = next_applied(&mut self.delivered) => {
                if applied.is_err() {
                    return Err(Halt::Unacknowledged);
                }
                self.applied().await?;
            },
            // Served last, so execution, acknowledgements, and ordered inputs always win.
            input = next_final(&mut self.finals) => match input {
                Some(input) => self.prepare(input),
                None => self.finals = None,
            },
        }
        Ok(())
    }

    /// Handles a request.
    async fn handle(&mut self, message: Message<X::Block>) -> Result<(), Halt> {
        match message {
            Message::Block { height, response } => {
                response.send_lossy(self.block(height).await);
            }
            Message::Subscribe { height, subscriber } => self.subscribe(height, subscriber).await,
            Message::Prune { below } => self.prune(below).await,
            Message::Certified { height, digest } => return self.certified(height, digest).await,
            Message::Diverged { height } => {
                error!(%height, "executed block diverges from the one honest validators signed");
                return Err(Halt::Diverged(height));
            }
            Message::Target { response, .. } | Message::AwaitsFloor { response } => {
                response.send_lossy(false);
            }
            Message::ResumedAfter { response, .. } | Message::HasBase { response } => {
                response.send_lossy(true);
            }
        }
        Ok(())
    }

    /// Runs the state sync of a chain without a base, holding the inputs it may not reach
    /// unacknowledged, then installs the block it reaches. Returns `false` if the executor stopped
    /// first.
    async fn sync(&mut self) -> Result<bool, Halt> {
        // Index of the input after the newest one marshal delivered, once it delivered one.
        let mut next = None;
        let base = loop {
            select! {
                _ = self.context.stopped() => {
                    debug!("executor stopped");
                    return Ok(false);
                },
                input = next_input(&mut self.inbox) => match input {
                    Some(input) => self.hold(input, &mut next),
                    None => self.inbox = None,
                },
                message = self.mailbox.recv() => {
                    let Some(message) = message else {
                        return Ok(false);
                    };
                    self.handle_syncing(message, next).await?;
                },
                progress = next_progress(&mut self.syncing) => match progress {
                    Progress::Recorded(height) => self.recorded(height),
                    Progress::Reached(base) => break base,
                },
                // The application has no state to prepare against until the sync reaches a
                // base, so final inputs are discarded.
                input = next_final(&mut self.finals) => {
                    if input.is_none() {
                        self.finals = None;
                    }
                },
            }
        };
        self.install(base).await?;
        Ok(true)
    }

    /// Handles a request while the chain has no base. `next` is the index of the input after the
    /// newest one marshal delivered, once it delivered one.
    async fn handle_syncing(
        &mut self,
        message: Message<X::Block>,
        next: Option<Height>,
    ) -> Result<(), Halt> {
        match message {
            Message::Block { response, .. } => {
                response.send_lossy(None);
            }
            Message::Subscribe { height, subscriber } => {
                self.subscribers.entry(height).or_default().push(subscriber);
            }
            Message::Prune { .. } => {}
            Message::Certified { height, digest } => {
                if self
                    .certified
                    .is_none_or(|(certified, _)| certified < height)
                {
                    self.certified = Some((height, digest));
                }
            }
            Message::Diverged { height } => {
                error!(%height, "honest validators signed a block other than one offered to sync to");
                return Err(Halt::Diverged(height));
            }
            Message::Target { block, response } => {
                self.offer(block).await;
                response.send_lossy(true);
            }
            Message::AwaitsFloor { response } => {
                response.send_lossy(self.syncing.is_none());
            }
            Message::ResumedAfter { index, response } => {
                response.send_lossy(
                    next.is_some_and(|next| next.get() > index.get().saturating_add(1)),
                );
            }
            Message::HasBase { response } => {
                response.send_lossy(false);
            }
        }
        Ok(())
    }

    /// Makes `block` the sync target if it is above the current one, starting the sync if none
    /// runs yet.
    ///
    /// A target below the inputs marshal delivers is ignored: marshal has already passed the
    /// input after it, so a base there would miss inputs.
    async fn offer(&mut self, block: Arc<X::Block>) {
        if let Some(lowest) = self.inputs.front()
            && block.height().get().saturating_add(1) < lowest.index.get()
        {
            debug!(height = %block.height(), lowest = %lowest.index, "target is below marshal's inputs");
            return;
        }
        if let Some(syncing) = &self.syncing {
            if block.height() == syncing.target.height() {
                assert_eq!(
                    block.digest(),
                    syncing.target.digest(),
                    "checkpoints certify two blocks at one height"
                );
            }
            if block.height() <= syncing.target.height() {
                return;
            }
        }
        if let Some(input) = self
            .inputs
            .iter()
            .find(|input| input.index.get() == block.height().get())
        {
            check_input(block.as_ref(), input);
        }
        self.store.persist_target(&block).await;
        match &mut self.syncing {
            Some(syncing) => {
                syncing.offered.insert(block.height(), Arc::clone(&block));
                let (recorded, record) = oneshot::channel();
                syncing.unrecorded.push_back((block.height(), record));
                syncing.updates.send_lossy(Update {
                    block: Arc::clone(&block),
                    recorded,
                });
                syncing.target = block;
            }
            None => {
                let syncing = self.start_sync(block);
                let recorded = syncing.recorded;
                self.syncing = Some(syncing);
                self.recorded(recorded);
            }
        }
    }

    /// Holds an input that arrived while the chain has no base, or acknowledges it if the sync is
    /// certain to reach a block at or above it. `next` is the index of the input after the
    /// previous one.
    ///
    /// Marshal may jump to a newly installed floor, which supersedes the inputs held from the old
    /// one. The jump may reach the executor after the first target, but never resumes the stream
    /// above the newest target the sync is certain to reach, which the base is at or above.
    fn hold(&mut self, input: Finalized<X::Input, A>, next: &mut Option<Height>) {
        let index = Height::new(input.index.get());
        if next.is_some_and(|next| next != index) {
            assert!(
                self.syncing
                    .as_ref()
                    .is_none_or(|syncing| index.get() <= syncing.recorded.get().saturating_add(1)),
                "marshal skipped inputs after a state sync target"
            );
            debug!(%index, "marshal moved its floor");
            for held in self.inputs.drain(..) {
                held.acknowledgement.acknowledge();
            }
        }
        *next = Some(index.next());
        let Some(syncing) = &mut self.syncing else {
            self.inputs.push_back(input);
            return;
        };
        while syncing
            .offered
            .first_key_value()
            .is_some_and(|(height, _)| *height < index)
        {
            syncing.offered.pop_first();
        }
        if let Some(target) = syncing.offered.remove(&index) {
            check_input(target.as_ref(), &input);
        }
        if index <= syncing.recorded {
            input.acknowledgement.acknowledge();
            return;
        }
        self.inputs.push_back(input);
    }

    /// Records that the sync is certain to reach a block at or above `height`, and acknowledges
    /// the held inputs up to it.
    fn recorded(&mut self, height: Height) {
        let syncing = self.syncing.as_mut().expect("a sync runs");
        syncing.recorded = syncing.recorded.max(height);
        let recorded = syncing.recorded;
        while self
            .inputs
            .front()
            .is_some_and(|input| input.index.get() <= recorded.get())
        {
            let input = self.inputs.pop_front().expect("an input is held");
            input.acknowledgement.acknowledge();
        }
    }

    /// Starts the application's state sync toward `target`.
    fn start_sync(&self, target: Arc<X::Block>) -> Syncing<X::Block> {
        let (updates, receiver) = ring::channel(NZUsize!(1));
        let mut execute = self.execute.clone();
        let first = Arc::clone(&target);
        Syncing {
            recorded: target.height(),
            offered: BTreeMap::from([(target.height(), Arc::clone(&target))]),
            target,
            updates,
            unrecorded: VecDeque::new(),
            base: async move { execute.sync(first, receiver).await }.boxed(),
        }
    }

    /// Makes `base`, the block the state sync reached, the applied block, and admits the inputs
    /// held while syncing.
    async fn install(&mut self, base: Arc<X::Block>) -> Result<(), Halt> {
        let syncing = self.syncing.take().expect("a sync reached the base");
        let height = base.height();
        assert!(
            height <= syncing.target.height(),
            "state sync reached a block above its newest target"
        );
        assert!(
            height >= syncing.recorded,
            "state sync reached a block below a target it recorded"
        );
        let offered = self
            .store
            .get(height)
            .await
            .expect("state sync reached a block it was never offered");
        assert_eq!(
            offered.digest(),
            base.digest(),
            "state sync reached a block other than the one offered at its height"
        );
        // The base was archived when it was offered, so it only needs to become the applied block.
        self.store.apply(height).await;
        let _ = self.executed_height.try_set(height.get());
        let _ = self.applied_height.try_set(height.get());
        self.line.push_back(Arc::clone(&base));
        self.expected = height.next();
        self.execute.resume(Arc::clone(&base));
        if let Some(input) = base.input() {
            self.preparations.settle(input);
        }

        // Blocks below the base were never executed here, so their subscribers are dropped.
        let later = self.subscribers.split_off(&height.next());
        for (subscribed, subscribers) in mem::replace(&mut self.subscribers, later) {
            if subscribed == height {
                for subscriber in subscribers {
                    subscriber(&base);
                }
            }
        }
        for input in mem::take(&mut self.inputs) {
            self.admit(input, false).await;
        }

        // The base is a certified block, and a checkpoint reported while syncing is checked
        // against it or against the block that executes at its height.
        match self.certified.take() {
            Some((certified, digest)) if certified == height => {
                self.matches_certified(&base, digest)
            }
            pending => {
                self.certified = pending.filter(|(certified, _)| *certified > height);
                self.checkpointed(&base);
                Ok(())
            }
        }
    }

    /// Records that a checkpoint certified `digest` as the block at `height`, checking it against
    /// the executed chain now or once that block executes.
    async fn certified(
        &mut self,
        height: Height,
        digest: <X::Block as Digestible>::Digest,
    ) -> Result<(), Halt> {
        let newest = self
            .certified
            .map(|(certified, _)| certified)
            .max(self.checkpoint);
        if newest.is_some_and(|newest| newest >= height) {
            return Ok(());
        }
        let executed = self.line.back().expect("line holds the applied block");
        if height > executed.height() {
            self.certified = Some((height, digest));
            return Ok(());
        }
        // Pruning never passes a checkpoint this executor verified, so a block that is no longer
        // retained is covered by a newer one. Aggregation replays such certificates on restart,
        // before the newest checkpoint is verified again.
        let Some(block) = self.block(height).await else {
            debug!(%height, "certified block is no longer retained");
            return Ok(());
        };
        self.matches_certified(&block, digest)
    }

    /// Checks an executed `block` against the digest a checkpoint certified at its height, making
    /// it the newest checkpoint if they match.
    fn matches_certified(
        &mut self,
        block: &Arc<X::Block>,
        digest: <X::Block as Digestible>::Digest,
    ) -> Result<(), Halt> {
        if block.digest() != digest {
            error!(
                height = %block.height(),
                "executed block diverges from the one honest validators certified"
            );
            return Err(Halt::Diverged(block.height()));
        }
        self.checkpointed(block);
        Ok(())
    }

    /// Makes `block` the newest checkpoint, and tells the application.
    fn checkpointed(&mut self, block: &Arc<X::Block>) {
        self.checkpoint = Some(block.height());
        self.execute.certified(Arc::clone(block));
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
    ///
    /// With `prepare`, an input queued behind others that have not executed is prepared, unless
    /// it already was.
    async fn admit(&mut self, input: Finalized<X::Input, A>, prepare: bool) {
        let index = Height::new(input.index.get());
        if index <= self.store.applied() {
            let digest = input.block.digest();
            self.preparations.settle(digest);
            self.preparations.release(&digest);
            // An applied block is durable, so a retained one must have executed this input. The
            // genesis block executed none, and marshal's block at its index is the engine's.
            if let Some(block) = self.store.get(index).await
                && let Some(executed) = block.input()
            {
                assert_eq!(
                    executed,
                    input.block.digest(),
                    "marshal redelivered an input other than the one executed"
                );
            }
            input.acknowledgement.acknowledge();
            return;
        }
        if index < self.expected {
            self.redeliver(input);
            return;
        }
        assert_eq!(
            index, self.expected,
            "marshal must deliver each input once, in index order"
        );
        self.expected = index.next();
        if prepare && (self.execution.is_some() || !self.inputs.is_empty()) {
            self.prepare(Arc::clone(&input.block));
        }
        self.inputs.push_back(input);
    }

    /// Prepares `input` on a task of its own, unless the chain has no base or `input` was
    /// already prepared or settled in this run.
    fn prepare(&mut self, input: Arc<X::Input>) {
        let digest = input.digest();
        if self.line.is_empty() || !self.preparations.wanted(&digest) {
            return;
        }
        let execute = self.execute.clone();
        // Spawning calls its closure on this task, so the call to `prepare` is deferred into the
        // spawned future.
        let preparation = self
            .context
            .child("prepare")
            .spawn(move |context| async move { execute.prepare(context, input).await });
        self.preparations.insert(digest, preparation);
    }

    /// Takes the acknowledgement of an input above the applied one that marshal delivers again
    /// after moving its floor, as when its jump to a floor installed for a state sync reaches the
    /// executor after the base. The input is queued, executing, or delivered, and marshal no longer
    /// counts the acknowledgement it carried before, which is released.
    fn redeliver(&mut self, input: Finalized<X::Input, A>) {
        let height = Height::new(input.index.get());
        let digest = input.block.digest();
        let (executed, acknowledgement) = if let Some(queued) = self
            .inputs
            .iter_mut()
            .find(|queued| queued.index == input.index)
        {
            (queued.block.digest(), &mut queued.acknowledgement)
        } else if let Some(execution) = self
            .execution
            .as_mut()
            .filter(|execution| execution.height == height)
        {
            (execution.input, &mut execution.acknowledgement)
        } else {
            let block = self
                .line
                .iter()
                .find(|block| block.height() == height)
                .expect("an input above the applied one is queued, executing, or delivered");
            let delivered = self
                .delivered
                .iter_mut()
                .find(|delivered| delivered.height == height)
                .expect("an executed block above the applied one is delivered");
            (
                block.input().expect("an executed block has an input"),
                &mut delivered.acknowledgement,
            )
        };
        assert_eq!(
            executed, digest,
            "marshal redelivered an input other than the one executed"
        );
        debug!(%height, "marshal redelivered an input after moving its floor");
        mem::replace(acknowledgement, input.acknowledgement).acknowledge();
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
            height: parent.height().next(),
            input: input.block.digest(),
        };
        let ancestry = AncestorStream::new(
            Arc::new(self.context.child("ancestry")),
            self.chain.clone(),
            [parent],
            self.ancestor_fetch_duration.clone(),
        );
        let execute = self.execute.clone();
        let runtime = self.context.child("execute");
        let block = input.block;
        self.preparations.settle(context.input);
        self.execution = Some(Execution {
            height: context.height,
            input: context.input,
            acknowledgement: input.acknowledgement,
            block: execute.execute((runtime, context), ancestry, block).boxed(),
            timer: self.execution_duration.timer(self.context.as_ref()),
        });
    }

    /// Archives and delivers a block the application executed, unless it diverges from a
    /// certified checkpoint or the consumer stopped.
    async fn executed(&mut self, block: X::Block) -> Result<(), Halt> {
        let Execution {
            height,
            input,
            acknowledgement,
            timer,
            ..
        } = self.execution.take().expect("an execution was in flight");
        timer.observe(self.context.as_ref());
        self.preparations.release(&input);
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

        // A block archived before a crash, or recorded as a state sync target, must be the one
        // execution produces. A crash may lose any unsynced block, not only a suffix, so each
        // height is checked on its own.
        match self.store.get(height).await {
            Some(archived) => assert_eq!(
                archived.digest(),
                block.digest(),
                "execution is not deterministic, or diverges from a certified target"
            ),
            None => self.store.put(&block).await,
        }
        let _ = self.executed_height.try_set(height.get());

        let block = Arc::new(block);
        if let Some((_, digest)) = self
            .certified
            .take_if(|(certified, _)| *certified == height)
        {
            self.matches_certified(&block, digest)?;
        }
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
            return Err(Halt::ConsumerClosed);
        }
        Ok(())
    }

    /// Makes the oldest delivered block, which the consumer applied, durable along with every
    /// contiguous block it has also applied, then acknowledges their inputs to marshal.
    ///
    /// Halts if the consumer dropped one of those blocks without acknowledging it.
    async fn applied(&mut self) -> Result<(), Halt> {
        let oldest = self
            .delivered
            .pop_front()
            .expect("an applied block was delivered");
        let mut through = oldest.height;
        let mut released = vec![oldest.acknowledgement];
        while let Some(next) = self.delivered.front_mut() {
            match (&mut next.applied).now_or_never() {
                Some(Ok(())) => {}
                Some(Err(_)) => return Err(Halt::Unacknowledged),
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
        Ok(())
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
        self.context.child("prune").spawn(move |_| async move {
            if let Err(error) = marshal.prune(OutputIndex::new(below.get())).await {
                warn!(%error, %below, "marshal did not prune");
            }
        });
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

/// Waits for the next input reported final, or forever once marshal dropped every [`Inbox`].
async fn next_final<I>(finals: &mut Option<Receiver<Final<I>>>) -> Option<Arc<I>>
where
    I: Send + Sync + 'static,
{
    match finals {
        Some(finals) => finals.recv().await.map(|Final(input)| input),
        None => future::pending().await,
    }
}

/// Checks that `input` is the one `target`, a block a checkpoint certifies at its index, executed.
fn check_input<B, I, A>(target: &B, input: &Finalized<I, A>)
where
    B: super::Executed<I::Digest>,
    I: Digestible,
{
    assert_eq!(
        target.input(),
        Some(input.block.digest()),
        "marshal's input differs from the one a state sync target executed"
    );
}

/// Progress of a state sync.
enum Progress<B> {
    /// The application recorded an update at this height.
    Recorded(Height),
    /// The application synced its state to this block.
    Reached(Arc<B>),
}

/// Waits for the state sync to progress, if one runs.
async fn next_progress<B: Send + Sync>(syncing: &mut Option<Syncing<B>>) -> Progress<B> {
    let Some(syncing) = syncing else {
        return future::pending().await;
    };
    select! {
        base = &mut syncing.base => Progress::Reached(base),
        height = next_record(&mut syncing.unrecorded) => Progress::Recorded(height),
    }
}

/// Waits for the application to record the oldest unrecorded update, skipping updates it dropped
/// unrecorded, and returns its height.
async fn next_record(unrecorded: &mut VecDeque<(Height, oneshot::Receiver<()>)>) -> Height {
    while let Some((height, record)) = unrecorded.front_mut() {
        let height = *height;
        let recorded = record.await.is_ok();
        unrecorded.pop_front();
        if recorded {
            return height;
        }
    }
    future::pending().await
}

/// Waits for the consumer to acknowledge the oldest delivered block, if any.
async fn next_applied<A>(delivered: &mut VecDeque<Delivered<A>>) -> Result<(), Canceled> {
    match delivered.front_mut() {
        Some(delivered) => (&mut delivered.applied).await,
        None => future::pending().await,
    }
}
