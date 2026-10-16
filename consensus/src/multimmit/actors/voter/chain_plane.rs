//! One producer chain's application validation, run on its own task.
//!
//! Each validator runs one chain plane per producer chain. The machine sends a plane every
//! authenticated block whose full acceptance waits on the application's verdict, and the height of
//! the chain's locally accepted tip, at or below which a verdict no longer matters. The plane runs
//! [`Automaton::verify`] on each block, at most `validation_items` at once, and returns every
//! verdict tagged with the process generation that requested it. The plane decides no protocol
//! fact: the machine alone judges whether a verdict still matters.
//!
//! ```text
//! voter                                        chain plane
//!   |-- validate(block) -------------------------->| queue block, run Automaton::verify
//!   |-- accepted(height) ------------------------->| drop and cancel work at or below height
//!   |-- reconfigure(generation, accepted) -------->| drop all work, restart above accepted
//!   |<----------------------- ValidationCompletion | one verdict per completed validation
//! ```
//!
//! The plane holds only volatile state. After a restart the voter starts fresh planes, and the
//! machine requests again the verdicts it still needs.
//!
//! The voter never blocks on a plane. The mailbox drops a block at or below the latest accepted
//! height it sent, since the plane would drop it on arrival. Commands beyond `mailbox_size` wait in
//! a [`PlaneOverflow`], which keeps only what the plane would still act on: the latest
//! reconfiguration, the highest accepted height, and the blocks above it. Its size is bounded by
//! the blocks above the accepted tip the machine routes to the chain, not by how long the plane
//! stalls.

use crate::{
    Automaton,
    multimmit::{
        actors::util::reliable_policy,
        machine::{BlockValidity, ChainCommand, Generation, ValidationCompletion},
        types::{BlockRef, ChainId, Context, SignedTransactionBlock},
    },
    types::Height,
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Overflow, Policy},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Counter, Histogram, HistogramExt as _},
};
use commonware_utils::{channel::oneshot, futures::Pool};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
    time::SystemTime,
};

// Verdicts are bounded by the blocks the machine routes to the plane and must not be lost.
reliable_policy!(impl<D: Digest> for ValidationCompletion<D>);

/// A command from the voter to one chain plane.
enum PlaneCommand<V: Variant, D: Digest> {
    /// Run the application's verification of one authenticated block.
    Validate(Arc<SignedTransactionBlock<V, D>>),
    /// The chain's accepted tip reached this height.
    Accepted(Height),
    /// A new process generation began; drop all work and restart above the accepted height.
    Reconfigure(Reconfiguration),
}

/// The process generation and accepted height a plane restarts from.
#[derive(Clone, Copy)]
struct Reconfiguration {
    generation: Generation,
    accepted: Height,
}

impl<V: Variant, D: Digest> PlaneCommand<V, D> {
    /// Returns the command for one machine-issued chain command.
    fn from_chain(command: ChainCommand<V, D>) -> Self {
        match command {
            ChainCommand::Validate(block) => Self::Validate(block),
            ChainCommand::Accepted(height) => Self::Accepted(height),
        }
    }
}

impl<V: Variant, D: Digest> Policy for PlaneCommand<V, D> {
    type Overflow = PlaneOverflow<V, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push(message);
    }
}

/// The commands waiting behind a full plane queue, reduced to what the plane would still act on.
///
/// The plane drops every block at or below its accepted height, ignores an accepted height that does
/// not advance it, and drops all work on a reconfiguration. The overflow applies the same rules as
/// commands arrive: a reconfiguration discards every command queued before it, an accepted height
/// keeps only the highest one and drops the blocks it covers, and a block at or below a queued
/// accepted height is dropped.
///
/// It delivers the reconfiguration, then the accepted height, then the blocks in arrival order.
/// Every retained block sits above every queued accepted height, so delivering the height first
/// changes nothing, and draining the overflow leaves the plane in the state the full command
/// sequence would have.
///
/// # Bound
///
/// The overflow holds at most two control commands plus blocks above every queued accepted height.
/// The machine routes a block once while it retains it, so the retained blocks are blocks the
/// machine still holds for the chain, which its artifact cache bounds however long the plane
/// stalls.
pub(crate) struct PlaneOverflow<V: Variant, D: Digest> {
    reconfiguration: Option<Reconfiguration>,
    accepted: Option<Height>,
    /// Blocks above every queued accepted height, in arrival order.
    blocks: VecDeque<Arc<SignedTransactionBlock<V, D>>>,
}

impl<V: Variant, D: Digest> Default for PlaneOverflow<V, D> {
    fn default() -> Self {
        Self {
            reconfiguration: None,
            accepted: None,
            blocks: VecDeque::new(),
        }
    }
}

impl<V: Variant, D: Digest> PlaneOverflow<V, D> {
    /// Retains `command` unless the plane would ignore it, dropping what it supersedes.
    fn push(&mut self, command: PlaneCommand<V, D>) {
        match command {
            PlaneCommand::Reconfigure(reconfiguration) => {
                *self = Self::default();
                self.reconfiguration = Some(reconfiguration);
            }
            PlaneCommand::Accepted(height) => {
                if self.covers(height) {
                    return;
                }
                self.blocks.retain(|block| block.header().height() > height);
                self.accepted = Some(height);
            }
            PlaneCommand::Validate(block) => {
                if self.covers(block.header().height()) {
                    return;
                }
                self.blocks.push_back(block);
            }
        }
    }

    /// Returns whether a queued accepted height, which the plane applies first, covers `height`.
    fn covers(&self, height: Height) -> bool {
        [
            self.reconfiguration
                .map(|reconfiguration| reconfiguration.accepted),
            self.accepted,
        ]
        .into_iter()
        .flatten()
        .any(|accepted| height <= accepted)
    }

    /// Removes the next command in delivery order.
    fn pop(&mut self) -> Option<PlaneCommand<V, D>> {
        if let Some(reconfiguration) = self.reconfiguration.take() {
            return Some(PlaneCommand::Reconfigure(reconfiguration));
        }
        if let Some(height) = self.accepted.take() {
            return Some(PlaneCommand::Accepted(height));
        }
        self.blocks.pop_front().map(PlaneCommand::Validate)
    }

    /// Returns a command the queue could not take to the front of the delivery order.
    fn unpop(&mut self, command: PlaneCommand<V, D>) {
        match command {
            PlaneCommand::Reconfigure(reconfiguration) => {
                self.reconfiguration = Some(reconfiguration);
            }
            PlaneCommand::Accepted(height) => self.accepted = Some(height),
            PlaneCommand::Validate(block) => self.blocks.push_front(block),
        }
    }
}

impl<V: Variant, D: Digest> Overflow<PlaneCommand<V, D>> for PlaneOverflow<V, D> {
    fn is_empty(&self) -> bool {
        self.reconfiguration.is_none() && self.accepted.is_none() && self.blocks.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(PlaneCommand<V, D>) -> Option<PlaneCommand<V, D>>,
    {
        while let Some(command) = self.pop() {
            if let Some(command) = push(command) {
                self.unpop(command);
                break;
            }
        }
    }
}

/// Configuration for one chain plane.
pub(crate) struct Config<A, D: Digest> {
    /// The producer chain this plane serves.
    pub(crate) chain: ChainId,
    /// Validates block payloads.
    pub(crate) automaton: A,
    /// Most application validations in flight at once.
    pub(crate) validation_items: NonZeroUsize,
    /// Receives verdicts.
    pub(crate) verdicts: mailbox::Sender<ValidationCompletion<D>>,
    /// Observes application validation latency.
    pub(crate) latency: Histogram,
    /// Counts blocks the application rejected.
    pub(crate) invalid: Counter,
    /// Counts validations the application could not complete.
    pub(crate) unavailable: Counter,
    /// Commands the queue holds before the rest wait in its [`PlaneOverflow`].
    pub(crate) mailbox_size: NonZeroUsize,
}

/// Commands to one chain plane.
pub(crate) struct Mailbox<V: Variant, D: Digest> {
    chain: ChainId,
    commands: mailbox::Sender<PlaneCommand<V, D>>,
    /// The plane's accepted height once it applies every command sent so far.
    sent: Height,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    /// Returns the producer chain the plane serves.
    pub(crate) const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Records the accepted height the plane starts above.
    pub(crate) const fn started(&mut self, accepted: Height) {
        self.sent = accepted;
    }

    /// Delivers one command the machine issued for this chain.
    ///
    /// A block the plane would drop on arrival is never sent, which keeps accepted blocks the
    /// machine replays out of a stalled plane's queue.
    pub(crate) fn command(&mut self, command: ChainCommand<V, D>) -> Feedback {
        self.send(PlaneCommand::from_chain(command))
    }

    /// Moves the plane to process generation `generation` above accepted height `accepted`.
    pub(crate) fn reconfigure(&mut self, generation: Generation, accepted: Height) -> Feedback {
        self.send(PlaneCommand::Reconfigure(Reconfiguration {
            generation,
            accepted,
        }))
    }

    fn send(&mut self, command: PlaneCommand<V, D>) -> Feedback {
        match &command {
            PlaneCommand::Validate(block) if block.header().height() <= self.sent => {
                return Feedback::Ok;
            }
            PlaneCommand::Validate(_) => {}
            PlaneCommand::Accepted(height) => self.sent = self.sent.max(*height),
            PlaneCommand::Reconfigure(reconfiguration) => self.sent = reconfiguration.accepted,
        }
        self.commands.enqueue(command)
    }
}

/// One completed application validation, or its cancellation.
enum Verified<D: Digest> {
    /// The application reached a verdict, or ended without one.
    Completed {
        block: BlockRef<D>,
        validity: BlockValidity,
        started_at: SystemTime,
    },
    /// The validation was cancelled because its block was accepted.
    Cancelled,
}

/// One chain plane before it starts.
pub(crate) struct Actor<E, H, A, V>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    V: Variant,
{
    context: E,
    config: Config<A, H::Digest>,
    commands: mailbox::Receiver<PlaneCommand<V, H::Digest>>,
}

impl<E, H, A, V> Actor<E, H, A, V>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    V: Variant,
{
    /// Creates the plane and its command mailbox.
    pub(crate) fn new(context: E, config: Config<A, H::Digest>) -> (Self, Mailbox<V, H::Digest>) {
        let (commands, receiver) = mailbox::new(context.child("commands"), config.mailbox_size);
        let chain = config.chain;
        (
            Self {
                context,
                config,
                commands: receiver,
            },
            Mailbox {
                chain,
                commands,
                sent: Height::zero(),
            },
        )
    }

    /// Starts the plane in process generation `generation` above accepted height `accepted`.
    ///
    /// The plane lives until the runtime stops or the voter drops the mailbox; later generations
    /// reconfigure it.
    pub(crate) fn start(self, generation: Generation, accepted: Height) -> Handle<()> {
        let Self {
            context,
            config,
            commands,
        } = self;
        let mut running = Running::<_, H, _, _> {
            context: ContextCell::new(context),
            config,
            commands,
            generation,
            accepted,
            queued: VecDeque::new(),
            known: BTreeSet::new(),
            running: BTreeMap::new(),
        };
        spawn_cell!(running.context, running.run())
    }
}

/// One running chain plane.
struct Running<E, H, A, V>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    V: Variant,
{
    context: ContextCell<E>,
    config: Config<A, H::Digest>,
    commands: mailbox::Receiver<PlaneCommand<V, H::Digest>>,
    generation: Generation,
    accepted: Height,
    /// Blocks awaiting a validation slot, in arrival order.
    queued: VecDeque<Arc<SignedTransactionBlock<V, H::Digest>>>,
    /// Every queued or running block, so a repeated request does not validate twice.
    known: BTreeSet<BlockRef<H::Digest>>,
    /// Running validations and the senders that cancel them.
    running: BTreeMap<BlockRef<H::Digest>, oneshot::Sender<()>>,
}

impl<E, H, A, V> Running<E, H, A, V>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    V: Variant,
{
    /// Drains commands and validation completions until the voter drops the mailbox or the runtime
    /// stops.
    async fn run(mut self) {
        let mut verifies: Pool<'static, Verified<H::Digest>> = Pool::default();
        select_loop! {
            self.context,
            on_stopped => {},
            Some(command) = self.commands.recv() else break => {
                self.handle_command(command, &mut verifies);
                self.dispatch(&mut verifies);
            },
            done = verifies.next_completed() => {
                if !self.handle_verified(done) {
                    break;
                }
                self.dispatch(&mut verifies);
            },
        }
    }

    fn handle_command(
        &mut self,
        command: PlaneCommand<V, H::Digest>,
        verifies: &mut Pool<'static, Verified<H::Digest>>,
    ) {
        match command {
            PlaneCommand::Validate(block) => {
                let header = block.header();
                if header.height() <= self.accepted || !self.known.insert(header.block_ref::<H>()) {
                    return;
                }
                self.queued.push_back(block);
            }
            PlaneCommand::Accepted(height) => {
                if height <= self.accepted {
                    return;
                }
                self.accepted = height;
                self.queued.retain(|block| block.header().height() > height);
                self.known.retain(|block| block.height() > height);
                // Dropping a cancel sender ends its validation.
                self.running.retain(|block, _| block.height() > height);
            }
            PlaneCommand::Reconfigure(Reconfiguration {
                generation,
                accepted,
            }) => {
                self.generation = generation;
                self.accepted = accepted;
                self.queued.clear();
                self.known.clear();
                self.running.clear();
                *verifies = Pool::default();
            }
        }
    }

    /// Starts queued validations while slots are free.
    fn dispatch(&mut self, verifies: &mut Pool<'static, Verified<H::Digest>>) {
        while self.running.len() < self.config.validation_items.get() {
            let Some(block) = self.queued.pop_front() else {
                return;
            };
            let header = block.header();
            let reference = header.block_ref::<H>();
            let context = Context::from(header);
            let commitment = header.body_digest();
            let (cancel, cancelled) = oneshot::channel();
            self.running.insert(reference, cancel);
            let mut automaton = self.config.automaton.clone();
            let started_at = self.context.current();
            verifies.push(async move {
                select! {
                    verdict = async {
                        let receiver = automaton.verify(context, commitment).await;
                        receiver.await.ok()
                    } => {
                        let validity = match verdict {
                            Some(true) => BlockValidity::Valid,
                            Some(false) => BlockValidity::Invalid,
                            None => BlockValidity::Unavailable,
                        };
                        Verified::Completed { block: reference, validity, started_at }
                    },
                    _ = cancelled => Verified::Cancelled,
                }
            });
        }
    }

    /// Reports one finished validation. Returns `false` once the voter stopped receiving verdicts.
    fn handle_verified(&mut self, done: Verified<H::Digest>) -> bool {
        let Verified::Completed {
            block,
            validity,
            started_at,
        } = done
        else {
            return true;
        };
        if self.running.remove(&block).is_none() {
            return true;
        }
        self.known.remove(&block);
        self.config
            .latency
            .observe_between(started_at, self.context.current());
        match validity {
            BlockValidity::Invalid => {
                self.config.invalid.inc();
            }
            BlockValidity::Unavailable => {
                self.config.unavailable.inc();
            }
            BlockValidity::Valid => {}
        }
        self.config
            .verdicts
            .enqueue(ValidationCompletion::new(self.generation, block, validity))
            .accepted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Heightable as _,
        multimmit::mocks::{Committee, MockApplication},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Runner as _, Supervisor as _, deterministic, telemetry::metrics::MetricsExt as _,
    };
    use commonware_utils::NZUsize;
    use std::time::Duration;

    type Block = Arc<SignedTransactionBlock<MinPk, Sha256Digest>>;
    type Command = PlaneCommand<MinPk, Sha256Digest>;
    type Completion = ValidationCompletion<Sha256Digest>;

    fn block(committee: &Committee<MinPk>, height: u64, fork: u8) -> Block {
        let parent = BlockRef::new(
            ChainId::new(0),
            Height::new(height - 1),
            Sha256::hash(&[&[fork, 0]]),
        );
        let header = committee.header(&parent, Sha256::hash(&[&[fork, 1]]));
        Arc::new(committee.sign_header(header))
    }

    fn reconfigure(generation: u64, accepted: u64) -> Command {
        PlaneCommand::Reconfigure(Reconfiguration {
            generation: Generation::new(generation),
            accepted: Height::new(accepted),
        })
    }

    /// Delivered commands, reduced to comparable values.
    #[derive(Debug, PartialEq, Eq)]
    enum Delivered {
        Validate(u64),
        Accepted(u64),
        Reconfigure(u64),
    }

    impl From<Command> for Delivered {
        fn from(command: Command) -> Self {
            match command {
                PlaneCommand::Validate(block) => Self::Validate(block.header().height().get()),
                PlaneCommand::Accepted(height) => Self::Accepted(height.get()),
                PlaneCommand::Reconfigure(reconfiguration) => {
                    Self::Reconfigure(reconfiguration.accepted.get())
                }
            }
        }
    }

    fn drain(overflow: &mut PlaneOverflow<MinPk, Sha256Digest>) -> Vec<Delivered> {
        let mut delivered = Vec::new();
        overflow.drain(|command| {
            delivered.push(command.into());
            None
        });
        delivered
    }

    #[test]
    fn overflow_keeps_only_work_the_plane_would_act_on() {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let mut overflow = PlaneOverflow::default();
        overflow.push(PlaneCommand::Validate(block(&committee, 1, 0)));
        overflow.push(reconfigure(1, 2));
        overflow.push(PlaneCommand::Validate(block(&committee, 2, 0)));
        overflow.push(PlaneCommand::Validate(block(&committee, 3, 0)));
        overflow.push(PlaneCommand::Validate(block(&committee, 4, 0)));
        overflow.push(PlaneCommand::Accepted(Height::new(3)));
        overflow.push(PlaneCommand::Accepted(Height::new(1)));
        overflow.push(PlaneCommand::Validate(block(&committee, 3, 1)));
        overflow.push(PlaneCommand::Validate(block(&committee, 5, 0)));
        assert_eq!(
            drain(&mut overflow),
            [
                Delivered::Reconfigure(2),
                Delivered::Accepted(3),
                Delivered::Validate(4),
                Delivered::Validate(5),
            ]
        );
        assert!(overflow.is_empty());
    }

    #[test]
    fn overflow_returns_a_refused_command_to_the_front() {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let mut overflow = PlaneOverflow::default();
        overflow.push(PlaneCommand::Accepted(Height::new(1)));
        overflow.push(PlaneCommand::Validate(block(&committee, 2, 0)));
        overflow.push(PlaneCommand::Validate(block(&committee, 3, 0)));
        let mut accepted = 0;
        overflow.drain(|command| {
            if accepted == 2 {
                return Some(command);
            }
            accepted += 1;
            None
        });
        assert_eq!(drain(&mut overflow), [Delivered::Validate(3)]);
    }

    /// One chain plane under test, together with the endpoints the voter would hold.
    struct Plane {
        context: deterministic::Context,
        application: MockApplication,
        mailbox: Mailbox<MinPk, Sha256Digest>,
        verdicts: mailbox::Receiver<Completion>,
        invalid: Counter,
        unavailable: Counter,
    }

    impl Plane {
        /// Creates a plane for chain zero and its mailbox, without starting it.
        fn new(
            context: &deterministic::Context,
            application: MockApplication,
            validation_items: usize,
        ) -> (
            Actor<deterministic::Context, Sha256, MockApplication, MinPk>,
            Self,
        ) {
            let (sender, verdicts) = mailbox::new(context.child("verdicts"), NZUsize!(16));
            let invalid = context.counter("invalid", "blocks the application rejected");
            let unavailable = context.counter("unavailable", "validations without a verdict");
            let (actor, mailbox) = Actor::new(
                context.child("plane"),
                Config {
                    chain: ChainId::new(0),
                    automaton: application.clone(),
                    validation_items: NonZeroUsize::new(validation_items).unwrap(),
                    verdicts: sender,
                    latency: context.histogram("latency", "validation latency", [1.0]),
                    invalid: invalid.clone(),
                    unavailable: unavailable.clone(),
                    mailbox_size: NZUsize!(16),
                },
            );
            let plane = Self {
                context: context.child("harness"),
                application,
                mailbox,
                verdicts,
                invalid,
                unavailable,
            };
            (actor, plane)
        }

        /// Starts a plane in generation `generation` above accepted height `accepted`.
        fn start(
            context: &deterministic::Context,
            application: MockApplication,
            validation_items: usize,
            generation: u64,
            accepted: u64,
        ) -> (Handle<()>, Self) {
            let (actor, mut plane) = Self::new(context, application, validation_items);
            plane.mailbox.started(Height::new(accepted));
            let handle = actor.start(Generation::new(generation), Height::new(accepted));
            (handle, plane)
        }

        fn validate(&mut self, block: &Block) -> Feedback {
            self.mailbox
                .command(ChainCommand::Validate(Arc::clone(block)))
        }

        async fn verdict(&mut self) -> Completion {
            self.verdicts.recv().await.expect("plane sends a verdict")
        }

        /// Lets every runnable task finish, then asserts no verdict is pending.
        async fn assert_quiet(&mut self) {
            self.context.sleep(Duration::from_secs(1)).await;
            assert!(self.verdicts.try_recv().is_err(), "unexpected verdict");
        }

        /// Heights the application was asked to verify, in ascending order.
        fn verified(&self) -> Vec<u64> {
            let mut heights: Vec<_> = self
                .application
                .log()
                .lock()
                .verifications
                .iter()
                .map(|(context, _)| context.height().get())
                .collect();
            heights.sort_unstable();
            heights
        }
    }

    fn completion(generation: u64, block: &Block, validity: BlockValidity) -> Completion {
        ValidationCompletion::new(
            Generation::new(generation),
            block.header().block_ref::<Sha256>(),
            validity,
        )
    }

    fn heights(heights: impl IntoIterator<Item = u64>) -> Vec<Height> {
        heights.into_iter().map(Height::new).collect()
    }

    #[test_traced]
    fn verdicts_map_application_results() {
        for (result, validity, invalid, unavailable) in [
            (Some(true), BlockValidity::Valid, 0, 0),
            (Some(false), BlockValidity::Invalid, 1, 0),
            (None, BlockValidity::Unavailable, 0, 1),
        ] {
            deterministic::Runner::default().start(|context| async move {
                let committee = Committee::<MinPk>::builder(7, 6).build();
                let application = MockApplication::builder().verify_result(result).build();
                let (_handle, mut plane) = Plane::start(&context, application, 1, 3, 1);
                let block = block(&committee, 2, 0);
                assert_eq!(plane.validate(&block), Feedback::Ok);
                assert_eq!(plane.verdict().await, completion(3, &block, validity));
                assert_eq!(plane.invalid.get(), invalid);
                assert_eq!(plane.unavailable.get(), unavailable);
                plane.assert_quiet().await;
            });
        }
    }

    #[test_traced]
    fn validations_in_flight_are_bounded() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(7, 6).build();
            let application = MockApplication::new();
            let mut gates = application.gate_verification_heights(heights([1, 2, 3]));
            let (_handle, mut plane) = Plane::start(&context, application, 2, 0, 0);
            let blocks: Vec<_> = (1..=3).map(|height| block(&committee, height, 0)).collect();
            for block in &blocks {
                plane.validate(block);
            }
            gates[0].wait_started().await;
            gates[1].wait_started().await;
            plane.assert_quiet().await;
            assert_eq!(plane.verified(), [1, 2]);

            gates[0].release();
            assert_eq!(
                plane.verdict().await,
                completion(0, &blocks[0], BlockValidity::Valid)
            );
            gates[2].wait_started().await;
            assert_eq!(plane.verified(), [1, 2, 3]);

            gates[1].release();
            assert_eq!(
                plane.verdict().await,
                completion(0, &blocks[1], BlockValidity::Valid)
            );
            gates[2].release();
            assert_eq!(
                plane.verdict().await,
                completion(0, &blocks[2], BlockValidity::Valid)
            );
            plane.assert_quiet().await;
        });
    }

    #[test_traced]
    fn repeated_block_is_validated_once() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(7, 6).build();
            let application = MockApplication::new();
            let mut gates = application.gate_verification_heights(heights([1]));
            let (_handle, mut plane) = Plane::start(&context, application, 1, 0, 0);
            let running = block(&committee, 1, 0);
            let queued = block(&committee, 2, 0);
            plane.validate(&running);
            plane.validate(&queued);
            gates[0].wait_started().await;
            plane.validate(&running);
            plane.validate(&queued);

            gates[0].release();
            assert_eq!(
                plane.verdict().await,
                completion(0, &running, BlockValidity::Valid)
            );
            assert_eq!(
                plane.verdict().await,
                completion(0, &queued, BlockValidity::Valid)
            );
            plane.assert_quiet().await;
            assert_eq!(plane.verified(), [1, 2]);
        });
    }

    #[test_traced]
    fn accepted_height_drops_and_cancels_accepted_work() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(7, 6).build();
            let application = MockApplication::new();
            let mut gates = application.gate_verification_heights(heights([2, 3]));
            let (_handle, mut plane) = Plane::start(&context, application, 2, 0, 0);
            let blocks: Vec<_> = [2, 3, 1, 4]
                .into_iter()
                .map(|height| block(&committee, height, 0))
                .collect();
            for block in &blocks {
                plane.validate(block);
            }
            gates[0].wait_started().await;
            gates[1].wait_started().await;

            assert_eq!(
                plane
                    .mailbox
                    .command(ChainCommand::Accepted(Height::new(2))),
                Feedback::Ok
            );
            gates[0].wait_cancelled().await;
            assert_eq!(
                plane.verdict().await,
                completion(0, &blocks[3], BlockValidity::Valid)
            );
            gates[1].release();
            assert_eq!(
                plane.verdict().await,
                completion(0, &blocks[1], BlockValidity::Valid)
            );
            plane.assert_quiet().await;
            assert_eq!(plane.verified(), [2, 3, 4]);
        });
    }

    #[test_traced]
    fn mailbox_skips_blocks_the_plane_would_drop() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(7, 6).build();
            let (mut actor, mut plane) = Plane::new(&context, MockApplication::new(), 1);
            let blocks: Vec<_> = (1..=5).map(|height| block(&committee, height, 0)).collect();
            plane.mailbox.started(Height::new(1));
            plane.validate(&blocks[0]);
            plane.validate(&blocks[1]);
            plane
                .mailbox
                .command(ChainCommand::Accepted(Height::new(3)));
            plane.validate(&blocks[2]);
            plane
                .mailbox
                .command(ChainCommand::Accepted(Height::new(2)));
            plane.validate(&blocks[2]);
            plane.validate(&blocks[3]);
            plane
                .mailbox
                .reconfigure(Generation::new(1), Height::new(1));
            plane.validate(&blocks[1]);
            plane
                .mailbox
                .reconfigure(Generation::new(2), Height::new(4));
            plane.validate(&blocks[3]);
            plane.validate(&blocks[4]);

            let mut delivered = Vec::new();
            while let Ok(command) = actor.commands.try_recv() {
                delivered.push(Delivered::from(command));
            }
            assert_eq!(
                delivered,
                [
                    Delivered::Validate(2),
                    Delivered::Accepted(3),
                    Delivered::Accepted(2),
                    Delivered::Validate(4),
                    Delivered::Reconfigure(1),
                    Delivered::Validate(2),
                    Delivered::Reconfigure(4),
                    Delivered::Validate(5),
                ]
            );
        });
    }

    #[test_traced]
    fn reconfiguration_drops_work_and_tags_later_verdicts() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(7, 6).build();
            let application = MockApplication::new();
            let mut gates = application.gate_verification_heights(heights([1]));
            let (_handle, mut plane) = Plane::start(&context, application, 1, 1, 0);
            let running = block(&committee, 1, 0);
            let queued = block(&committee, 2, 0);
            plane.validate(&running);
            plane.validate(&queued);
            gates[0].wait_started().await;

            assert_eq!(
                plane
                    .mailbox
                    .reconfigure(Generation::new(2), Height::new(1)),
                Feedback::Ok
            );
            gates[0].wait_cancelled().await;
            plane.assert_quiet().await;
            assert_eq!(plane.verified(), [1]);

            plane.validate(&running);
            plane.validate(&queued);
            assert_eq!(
                plane.verdict().await,
                completion(2, &queued, BlockValidity::Valid)
            );
            plane.assert_quiet().await;
            assert_eq!(plane.verified(), [1, 2]);
        });
    }

    #[test_traced]
    fn closed_verdict_receiver_stops_the_plane() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(7, 6).build();
            let (handle, mut plane) = Plane::start(&context, MockApplication::new(), 1, 0, 0);
            let (_, closed) = mailbox::new(context.child("closed"), NZUsize!(1));
            drop(std::mem::replace(&mut plane.verdicts, closed));
            plane.validate(&block(&committee, 1, 0));
            handle.await.expect("plane ends without error");
            assert_eq!(plane.verified(), [1]);
            assert_eq!(plane.validate(&block(&committee, 2, 0)), Feedback::Closed);
        });
    }
}
