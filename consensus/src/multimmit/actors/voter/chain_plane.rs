//! One producer chain's data-availability eligibility, run on its own task.
//!
//! Each validator runs one chain plane per producer chain. The voter routes a block to its chain's
//! plane once the machine has assigned its observation identity and recorded its ancestry. The plane
//! stores the block, runs application validation on the shared pool, and offers the contiguous
//! eligible run above the certified anchor. The machine alone detects forks and records the durable
//! one-vote-per-height DA choice; the plane only validates and offers.
//!
//! ```text
//! voter                                        chain plane
//!   |-- observe(block) --------------------------->| store block, schedule validation
//!   |                                              | run Automaton::verify on the shared pool
//!   |-- anchor_advanced(anchor) ------------------>| settle blocks, cancel their validations
//!   |-- chosen(choices) -------------------------->| replace the eligibility read-copy
//!   |<------------------ DaVotesOffer(run) --------| offer the contiguous eligible run
//! ```
//!
//! The plane holds only volatile state. After a restart the voter starts fresh planes seeded with
//! the certified anchors and durable choices, and blocks refill from re-observed gossip.
//!
//! The voter never blocks on a plane. The mailbox marks a block at or below the latest anchor it
//! sent as settled, since the plane would settle it on arrival. Commands beyond `mailbox_size` wait
//! in a [`PlaneOverflow`], which drops settled blocks and keeps only what the plane would still act
//! on: the latest reconfiguration and choices, the anchors that still advance the plane, and the
//! observed blocks above them. Its size is bounded by the unsettled blocks the machine routes to
//! the chain, not by how long the plane stalls or how often the machine replays settled blocks.

use super::actor::ChainUpdate;
use crate::{
    Automaton,
    multimmit::{
        machine::{
            BlockValidity, ChainEligibility, DaChoice, DaVotesOffer, EligibleRun, Generation,
            ObservedBlock, ValidationCompletion, ValidationId, ValidationOutcome, ValidatorCommand,
        },
        types::{BlockRef, ChainId, Context},
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
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    ops::ControlFlow,
    sync::Arc,
    time::SystemTime,
};

/// A command from the voter to one chain plane.
///
/// The machine authenticates, orders, and identity-stamps every block before it crosses this
/// boundary, so the plane never re-derives a protocol fact.
enum ChainPlaneCommand<V: Variant, D: Digest> {
    /// A command the machine issued for this chain.
    Validator(ValidatorCommand<V, D>),
    /// A new process generation began; drop volatile state and re-seed the anchor.
    Reconfigure(Reconfiguration<D>),
    /// A block at or below the latest anchor sent, which the plane settles on arrival.
    ///
    /// The mailbox sends this in place of the block, so the plane wakes as it would have, and a
    /// full queue drops it instead of retaining the block.
    Settled,
}

/// The process generation and certified anchor a plane restarts from.
#[derive(Clone, Copy)]
struct Reconfiguration<D: Digest> {
    generation: Generation,
    anchor: BlockRef<D>,
}

impl<V: Variant, D: Digest> Policy for ChainPlaneCommand<V, D> {
    type Overflow = PlaneOverflow<V, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push(message);
    }
}

/// The commands waiting behind a full plane queue, reduced to what the plane would still act on.
///
/// The plane settles every block at or below its certified anchor, ignores an anchor that does not
/// advance it, replaces its DA-choice read-copy wholesale, and drops all volatile state on a
/// reconfiguration. The overflow applies the same rules as commands arrive:
///
/// - A reconfiguration discards every command queued before it.
/// - An anchor at or below the highest queued anchor is dropped. A higher one replaces the queued
///   anchor on its side of the queued choices and drops the observed blocks it settles.
/// - New choices replace the queued choices, and the highest anchor queued so far moves ahead of
///   them.
/// - An observed block at or below the highest queued anchor is dropped.
///
/// It delivers the reconfiguration, the anchor queued before the choices, the choices, the anchor
/// queued after them, and then the observed blocks in arrival order. The choices keep their place
/// relative to the anchors because the plane derives its DA-choice cursor from the anchor current
/// when they apply. Every retained block sits above every queued anchor, so reordering it after the
/// anchors and choices changes nothing. Draining the overflow therefore leaves the plane in the
/// state the full command sequence would have, and a dropped block is one the plane settles before
/// it could matter.
///
/// # Bound
///
/// The overflow holds at most four control commands (a reconfiguration, two anchors, and one set of
/// choices) plus observed blocks above the mailbox watermark and every queued anchor: the mailbox's
/// watermark marks a block at or below the latest anchor sent before it as settled and the overflow
/// drops it, which excludes the settled blocks the machine replays, and a later queued anchor drops
/// the blocks it settles. The machine routes a block once while it retains it and retains it until
/// the chain's certified anchor passes it, reporting that advance in the same step. The retained
/// blocks are therefore blocks the machine still holds, at most its retained blocks for the chain,
/// which the machine's artifact cache bounds however long the plane stalls.
pub(crate) struct PlaneOverflow<V: Variant, D: Digest> {
    reconfiguration: Option<Reconfiguration<D>>,
    /// The highest anchor queued before the queued choices, or with no choices queued.
    anchor: Option<BlockRef<D>>,
    choices: Option<Vec<DaChoice<D>>>,
    /// The highest anchor queued after the queued choices.
    anchor_after_choices: Option<BlockRef<D>>,
    /// Observed blocks above every queued anchor, in arrival order.
    observed: VecDeque<ObservedBlock<V, D>>,
}

impl<V: Variant, D: Digest> Default for PlaneOverflow<V, D> {
    fn default() -> Self {
        Self {
            reconfiguration: None,
            anchor: None,
            choices: None,
            anchor_after_choices: None,
            observed: VecDeque::new(),
        }
    }
}

impl<V: Variant, D: Digest> PlaneOverflow<V, D> {
    /// Retains `command` unless the plane would ignore it, dropping what it supersedes.
    fn push(&mut self, command: ChainPlaneCommand<V, D>) {
        match command {
            ChainPlaneCommand::Reconfigure(reconfiguration) => {
                *self = Self::default();
                self.reconfiguration = Some(reconfiguration);
            }
            ChainPlaneCommand::Validator(ValidatorCommand::AnchorAdvanced(anchor)) => {
                if self.settles(anchor.height()) {
                    return;
                }
                self.observed
                    .retain(|observed| observed.block.header().height() > anchor.height());
                if self.choices.is_some() {
                    self.anchor_after_choices = Some(anchor);
                } else {
                    self.anchor = Some(anchor);
                }
            }
            ChainPlaneCommand::Validator(ValidatorCommand::Chosen(choices)) => {
                if let Some(anchor) = self.anchor_after_choices.take() {
                    self.anchor = Some(anchor);
                }
                self.choices = Some(choices);
            }
            ChainPlaneCommand::Validator(ValidatorCommand::Observe(observed)) => {
                if self.settles(observed.block.header().height()) {
                    return;
                }
                self.observed.push_back(observed);
            }
            ChainPlaneCommand::Settled => {}
        }
    }

    /// Returns whether a queued anchor, which the plane applies first, settles `height`.
    fn settles(&self, height: Height) -> bool {
        [
            self.reconfiguration
                .map(|reconfiguration| reconfiguration.anchor),
            self.anchor,
            self.anchor_after_choices,
        ]
        .into_iter()
        .flatten()
        .any(|anchor| height <= anchor.height())
    }

    /// Removes the next command in delivery order.
    fn pop(&mut self) -> Option<ChainPlaneCommand<V, D>> {
        if let Some(reconfiguration) = self.reconfiguration.take() {
            return Some(ChainPlaneCommand::Reconfigure(reconfiguration));
        }
        if let Some(anchor) = self.anchor.take() {
            return Some(ChainPlaneCommand::Validator(
                ValidatorCommand::AnchorAdvanced(anchor),
            ));
        }
        if let Some(choices) = self.choices.take() {
            return Some(ChainPlaneCommand::Validator(ValidatorCommand::Chosen(
                choices,
            )));
        }
        if let Some(anchor) = self.anchor_after_choices.take() {
            return Some(ChainPlaneCommand::Validator(
                ValidatorCommand::AnchorAdvanced(anchor),
            ));
        }
        self.observed
            .pop_front()
            .map(|observed| ChainPlaneCommand::Validator(ValidatorCommand::Observe(observed)))
    }

    /// Returns a command the queue could not take to the front of the delivery order.
    ///
    /// Every slot ahead of the one it came from is already empty, and a returned anchor is
    /// delivered ahead of any choices still queued, which is the slot it left.
    fn unpop(&mut self, command: ChainPlaneCommand<V, D>) {
        match command {
            ChainPlaneCommand::Reconfigure(reconfiguration) => {
                self.reconfiguration = Some(reconfiguration);
            }
            ChainPlaneCommand::Validator(ValidatorCommand::AnchorAdvanced(anchor)) => {
                self.anchor = Some(anchor);
            }
            ChainPlaneCommand::Validator(ValidatorCommand::Chosen(choices)) => {
                self.choices = Some(choices);
            }
            ChainPlaneCommand::Validator(ValidatorCommand::Observe(observed)) => {
                self.observed.push_front(observed);
            }
            // The overflow never retains one, so none comes back.
            ChainPlaneCommand::Settled => {}
        }
    }
}

impl<V: Variant, D: Digest> Overflow<ChainPlaneCommand<V, D>> for PlaneOverflow<V, D> {
    fn is_empty(&self) -> bool {
        self.reconfiguration.is_none()
            && self.anchor.is_none()
            && self.choices.is_none()
            && self.anchor_after_choices.is_none()
            && self.observed.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(ChainPlaneCommand<V, D>) -> Option<ChainPlaneCommand<V, D>>,
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
pub(crate) struct Config<A, V: Variant, D: Digest> {
    /// The producer chain this plane serves.
    pub(crate) chain: ChainId,
    /// Validates block payloads.
    pub(crate) automaton: A,
    /// Blocks the plane keeps above the anchor, and the most one offer carries.
    pub(crate) pipeline_depth: usize,
    /// Most application validations in flight at once.
    pub(crate) validation_items: usize,
    /// Most block bytes under validation at once.
    pub(crate) validation_bytes: usize,
    /// Receives eligible-run offers.
    pub(crate) updates: mailbox::Sender<ChainUpdate<V, D>>,
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
    commands: mailbox::Sender<ChainPlaneCommand<V, D>>,
    sent: SentAnchor,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    /// Returns the producer chain the plane serves.
    pub(crate) const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Records the anchor the plane starts above, which settles every block at or below it.
    pub(crate) const fn started(&mut self, anchor: BlockRef<D>) {
        self.sent = SentAnchor(anchor.height());
    }

    /// Delivers one command the machine issued for this chain; a block the plane would settle on
    /// arrival goes as [`ChainPlaneCommand::Settled`].
    pub(crate) fn command(&mut self, command: ValidatorCommand<V, D>) -> Feedback {
        self.send(ChainPlaneCommand::Validator(command))
    }

    /// Moves the plane to process generation `generation` with certified anchor `anchor`.
    pub(crate) fn reconfigure(&mut self, generation: Generation, anchor: BlockRef<D>) -> Feedback {
        self.send(ChainPlaneCommand::Reconfigure(Reconfiguration {
            generation,
            anchor,
        }))
    }

    fn send(&mut self, command: ChainPlaneCommand<V, D>) -> Feedback {
        self.commands.enqueue(self.sent.mark(command))
    }
}

/// The height of the plane's anchor once it applies every command sent so far.
///
/// The plane settles a block at or below its anchor on arrival. The mailbox replaces such a block
/// with [`ChainPlaneCommand::Settled`], which a full queue drops: this watermark is what keeps
/// settled blocks the machine replays out of a stalled plane's queue.
#[derive(Clone, Copy, Default)]
struct SentAnchor(Height);

impl SentAnchor {
    /// Returns `command`, or [`ChainPlaneCommand::Settled`] for a block the plane would settle on
    /// arrival, recording the anchor the command sets.
    fn mark<V: Variant, D: Digest>(
        &mut self,
        command: ChainPlaneCommand<V, D>,
    ) -> ChainPlaneCommand<V, D> {
        match &command {
            ChainPlaneCommand::Validator(ValidatorCommand::Observe(observed))
                if observed.block.header().height() <= self.0 =>
            {
                return ChainPlaneCommand::Settled;
            }
            ChainPlaneCommand::Validator(ValidatorCommand::AnchorAdvanced(anchor)) => {
                self.0 = self.0.max(anchor.height());
            }
            ChainPlaneCommand::Reconfigure(reconfiguration) => {
                self.0 = reconfiguration.anchor.height();
            }
            _ => {}
        }
        command
    }
}

/// One completed application validation, or its cancellation.
enum Verified {
    /// The application reached a verdict for this live validation.
    Completed {
        /// The completed validation identity.
        completion: ValidationCompletion,
        /// When the validation began.
        started_at: SystemTime,
    },
    /// The validation was cancelled because its block settled; its result is discarded.
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
    config: Config<A, V, H::Digest>,
    commands: mailbox::Receiver<ChainPlaneCommand<V, H::Digest>>,
}

impl<E, H, A, V> Actor<E, H, A, V>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    V: Variant,
{
    /// Creates the plane and its command mailbox.
    pub(crate) fn new(
        context: E,
        config: Config<A, V, H::Digest>,
    ) -> (Self, Mailbox<V, H::Digest>) {
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
                sent: SentAnchor::default(),
            },
        )
    }

    /// Starts the plane in process generation `generation` above certified anchor `anchor`.
    ///
    /// The plane lives until the runtime stops or the voter drops the mailbox; later generations
    /// reconfigure it.
    pub(crate) fn start(self, generation: Generation, anchor: BlockRef<H::Digest>) -> Handle<()> {
        let Self {
            context,
            config,
            commands,
        } = self;
        let eligibility = ChainEligibility::new(
            config.chain,
            config.pipeline_depth as u64,
            config.validation_items,
            config.validation_bytes,
            anchor,
            generation,
        );
        let mut running = Running::<_, H, _, _> {
            context: ContextCell::new(context),
            config,
            commands,
            eligibility,
            last_offer: Vec::new(),
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
    config: Config<A, V, H::Digest>,
    commands: mailbox::Receiver<ChainPlaneCommand<V, H::Digest>>,
    eligibility: ChainEligibility<V, H::Digest>,
    /// The last run offered to the voter, to suppress redundant offers.
    last_offer: Vec<BlockRef<H::Digest>>,
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
        let mut verifies: Pool<'static, Verified> = Pool::default();
        let mut cancels: BTreeMap<ValidationId, oneshot::Sender<()>> = BTreeMap::new();
        select_loop! {
            self.context,
            on_stopped => {},
            Some(command) = self.commands.recv() else break => {
                self.handle_command(command, &mut verifies, &mut cancels);
                self.dispatch(&mut verifies, &mut cancels);
                if self.offer().is_break() {
                    break;
                }
            },
            done = verifies.next_completed() => {
                self.handle_verified(done, &mut cancels);
                self.dispatch(&mut verifies, &mut cancels);
                if self.offer().is_break() {
                    break;
                }
            },
        }
    }

    fn handle_command(
        &mut self,
        command: ChainPlaneCommand<V, H::Digest>,
        verifies: &mut Pool<'static, Verified>,
        cancels: &mut BTreeMap<ValidationId, oneshot::Sender<()>>,
    ) {
        match command {
            ChainPlaneCommand::Validator(ValidatorCommand::Observe(ObservedBlock {
                id,
                observation,
                block,
                custodied,
            })) => self
                .eligibility
                .observe::<H>(id, observation, block, custodied),
            ChainPlaneCommand::Validator(ValidatorCommand::AnchorAdvanced(anchor)) => {
                for id in self.eligibility.advance_anchor(anchor) {
                    cancels.remove(&id);
                }
            }
            ChainPlaneCommand::Validator(ValidatorCommand::Chosen(choices)) => {
                self.eligibility.note_chosen(choices)
            }
            ChainPlaneCommand::Settled => {}
            ChainPlaneCommand::Reconfigure(Reconfiguration { generation, anchor }) => {
                self.eligibility.reconfigure(generation, anchor);
                cancels.clear();
                *verifies = Pool::default();
                self.last_offer.clear();
            }
        }
    }

    /// Dispatches every ready application validation this chain can start.
    fn dispatch(
        &mut self,
        verifies: &mut Pool<'static, Verified>,
        cancels: &mut BTreeMap<ValidationId, oneshot::Sender<()>>,
    ) {
        while let Some(job) = self.eligibility.ready_validation() {
            let issued = job.issued();
            let block = Arc::clone(job.block_arc());
            let context = Context::from(block.header());
            let commitment = block.header().body_digest();
            let (cancel, cancelled) = oneshot::channel();
            cancels.insert(issued.id(), cancel);
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
                        Verified::Completed {
                            completion: ValidationCompletion::new(issued, validity),
                            started_at,
                        }
                    },
                    _ = cancelled => Verified::Cancelled,
                }
            });
        }
    }

    fn handle_verified(
        &mut self,
        done: Verified,
        cancels: &mut BTreeMap<ValidationId, oneshot::Sender<()>>,
    ) {
        let Verified::Completed {
            completion,
            started_at,
        } = done
        else {
            return;
        };
        self.config
            .latency
            .observe_between(started_at, self.context.current());
        cancels.remove(&completion.issued().id());
        match self.eligibility.complete_validation(completion) {
            ValidationOutcome::Invalid(_) => {
                self.config.invalid.inc();
            }
            ValidationOutcome::Deferred => {
                self.config.unavailable.inc();
            }
            ValidationOutcome::Retained | ValidationOutcome::Stale => {}
        }
    }

    /// Offers the voter this chain's current eligible run, unless it matches the last offer.
    /// Breaks once the voter stopped receiving offers.
    fn offer(&mut self) -> ControlFlow<()> {
        let EligibleRun { run, ready_through } =
            self.eligibility.eligible_run(self.config.pipeline_depth);
        let refs = run
            .iter()
            .map(|block| block.header().block_ref::<H>())
            .collect::<Vec<_>>();
        if refs == self.last_offer {
            return ControlFlow::Continue(());
        }
        self.last_offer = refs;
        let update = DaVotesOffer {
            generation: self.eligibility.generation(),
            chain: self.config.chain,
            candidates: run,
            ready_through,
        };
        if self.config.updates.enqueue(update.into()).accepted() {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            machine::Observation,
            types::{ArtifactId, Attestation, SignedTransactionBlock, TransactionBlockHeader},
        },
        types::{Epoch, Participant},
    };
    use commonware_codec::types::lazy::Lazy;
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Additive as _;
    use commonware_utils::TestRng;
    use rand::TryRng as _;

    type Command = ChainPlaneCommand<MinPk, Sha256Digest>;
    type Overflowed = PlaneOverflow<MinPk, Sha256Digest>;

    const CHAIN: ChainId = ChainId::new(0);
    const PIPELINE: u64 = 4;

    fn digest(height: u64, fork: u8) -> Sha256Digest {
        Sha256::hash(&[&height.to_be_bytes(), &[fork]])
    }

    fn header(height: u64, fork: u8) -> TransactionBlockHeader<Sha256Digest> {
        TransactionBlockHeader::new(
            Epoch::new(1),
            CHAIN,
            Height::new(height),
            digest(height - 1, 0),
            digest(height, fork),
        )
        .unwrap()
    }

    fn observe(height: u64, fork: u8, index: u32) -> Command {
        let header = header(height, fork);
        ChainPlaneCommand::Validator(ValidatorCommand::Observe(ObservedBlock {
            id: ArtifactId::new(header.digest::<Sha256>()),
            observation: Observation::new(0, index),
            block: Arc::new(SignedTransactionBlock::new(
                header,
                Attestation::new(
                    Participant::new(0),
                    Lazy::from(<MinPk as Variant>::Signature::zero()),
                ),
            )),
            custodied: false,
        }))
    }

    fn anchor_at(height: u64) -> BlockRef<Sha256Digest> {
        BlockRef::new(CHAIN, Height::new(height), digest(height, 0))
    }

    fn anchor(height: u64) -> Command {
        ChainPlaneCommand::Validator(ValidatorCommand::AnchorAdvanced(anchor_at(height)))
    }

    fn chosen(heights: impl IntoIterator<Item = u64>) -> Command {
        ChainPlaneCommand::Validator(ValidatorCommand::Chosen(
            heights
                .into_iter()
                .map(|height| {
                    let header = header(height, 0);
                    let block_ref = header.block_ref::<Sha256>();
                    DaChoice::for_test(header, block_ref)
                })
                .collect(),
        ))
    }

    fn reconfigure(generation: u64, height: u64) -> Command {
        ChainPlaneCommand::Reconfigure(Reconfiguration {
            generation: Generation::new(generation),
            anchor: anchor_at(height),
        })
    }

    /// Applies `command` to `eligibility` exactly as the running plane does.
    fn apply(eligibility: &mut ChainEligibility<MinPk, Sha256Digest>, command: Command) {
        match command {
            ChainPlaneCommand::Validator(ValidatorCommand::Observe(observed)) => eligibility
                .observe::<Sha256>(
                    observed.id,
                    observed.observation,
                    observed.block,
                    observed.custodied,
                ),
            ChainPlaneCommand::Validator(ValidatorCommand::AnchorAdvanced(anchor)) => {
                eligibility.advance_anchor(anchor);
            }
            ChainPlaneCommand::Validator(ValidatorCommand::Chosen(choices)) => {
                eligibility.note_chosen(choices);
            }
            ChainPlaneCommand::Reconfigure(Reconfiguration { generation, anchor }) => {
                eligibility.reconfigure(generation, anchor);
            }
            ChainPlaneCommand::Settled => {}
        }
    }

    fn eligibility() -> ChainEligibility<MinPk, Sha256Digest> {
        ChainEligibility::new(
            CHAIN,
            PIPELINE,
            64,
            1 << 20,
            anchor_at(0),
            Generation::new(0),
        )
    }

    /// A command's kind and the height it names, for asserting delivery order.
    #[derive(Debug, PartialEq, Eq)]
    enum Delivered {
        Reconfigure(u64),
        Anchor(u64),
        Chosen(Vec<u64>),
        Observe(u64),
        Settled,
    }

    fn drain_all(overflow: &mut Overflowed) -> Vec<Delivered> {
        let mut delivered = Vec::new();
        overflow.drain(|command| {
            delivered.push(match command {
                ChainPlaneCommand::Reconfigure(reconfiguration) => {
                    Delivered::Reconfigure(reconfiguration.anchor.height().get())
                }
                ChainPlaneCommand::Validator(ValidatorCommand::AnchorAdvanced(anchor)) => {
                    Delivered::Anchor(anchor.height().get())
                }
                ChainPlaneCommand::Validator(ValidatorCommand::Chosen(choices)) => {
                    Delivered::Chosen(
                        choices
                            .iter()
                            .map(|choice| choice.header().height().get())
                            .collect(),
                    )
                }
                ChainPlaneCommand::Validator(ValidatorCommand::Observe(observed)) => {
                    Delivered::Observe(observed.block.header().height().get())
                }
                ChainPlaneCommand::Settled => Delivered::Settled,
            });
            None
        });
        delivered
    }

    fn control_commands(overflow: &Overflowed) -> usize {
        usize::from(overflow.reconfiguration.is_some())
            + usize::from(overflow.anchor.is_some())
            + usize::from(overflow.choices.is_some())
            + usize::from(overflow.anchor_after_choices.is_some())
    }

    #[test]
    fn overflow_stays_bounded_while_the_plane_stalls() {
        let mut overflow = Overflowed::default();
        let mut index = 0;
        for height in PIPELINE + 1..=2_000u64 {
            // The producer runs the pipeline ahead of the certified anchor, an equivocating
            // producer adds a fork at every height, and a late fork of a settled height arrives.
            let certified = height - PIPELINE;
            for command in [
                observe(height, 0, index),
                observe(height, 1, index + 1),
                anchor(certified),
                observe(certified, 2, index + 2),
                chosen(certified + 1..height),
            ] {
                Policy::handle(&mut overflow, command);
                assert!(control_commands(&overflow) <= 4);
                assert!(
                    overflow.observed.len() <= 2 * (PIPELINE as usize + 1),
                    "only blocks above the newest anchor are retained"
                );
            }
            index += 3;
        }
        assert!(
            overflow
                .observed
                .iter()
                .all(|observed| observed.block.header().height().get() > 2_000 - PIPELINE)
        );
    }

    #[test]
    fn coalescing_keeps_the_latest_choices_and_the_highest_anchor() {
        let mut overflow = Overflowed::default();
        for command in [
            anchor(3),
            chosen([4]),
            anchor(5),
            chosen([6, 7]),
            // An anchor the plane has already passed and a block it settled are dropped.
            anchor(4),
            anchor(7),
            observe(6, 0, 0),
            observe(9, 0, 1),
        ] {
            Policy::handle(&mut overflow, command);
        }
        assert_eq!(
            drain_all(&mut overflow),
            [
                Delivered::Anchor(5),
                Delivered::Chosen(vec![6, 7]),
                Delivered::Anchor(7),
                Delivered::Observe(9),
            ]
        );

        // A reconfiguration supersedes everything before it and lowers the anchor that settles
        // later blocks.
        for command in [
            anchor(8),
            chosen([9]),
            observe(10, 0, 2),
            reconfigure(1, 2),
            observe(3, 0, 3),
            anchor(1),
        ] {
            Policy::handle(&mut overflow, command);
        }
        assert_eq!(
            drain_all(&mut overflow),
            [Delivered::Reconfigure(2), Delivered::Observe(3)]
        );
        assert!(overflow.is_empty());
    }

    /// The plane mailbox's watermark and a bounded ready queue in front of a [`PlaneOverflow`],
    /// refilled after each receive as the actor mailbox does.
    struct Queue {
        sent: SentAnchor,
        ready: VecDeque<Command>,
        overflow: Overflowed,
        capacity: usize,
    }

    impl Queue {
        fn new(capacity: usize) -> Self {
            Self {
                sent: SentAnchor::default(),
                ready: VecDeque::new(),
                overflow: Overflowed::default(),
                capacity,
            }
        }

        fn send(&mut self, command: Command) {
            let command = self.sent.mark(command);
            if self.overflow.is_empty() && self.ready.len() < self.capacity {
                self.ready.push_back(command);
            } else {
                Policy::handle(&mut self.overflow, command);
            }
        }

        fn recv(&mut self) -> Option<Command> {
            self.refill();
            let command = self.ready.pop_front();
            self.refill();
            command
        }

        fn refill(&mut self) {
            let (ready, capacity) = (&mut self.ready, self.capacity);
            self.overflow.drain(|command| {
                if ready.len() < capacity {
                    ready.push_back(command);
                    None
                } else {
                    Some(command)
                }
            });
        }
    }

    /// Returns `seed`'s adversarial command sequence: blocks, forks, and late copies at random
    /// heights, anchors that arrive out of order and below the plane's anchor, choice sets, and
    /// reconfigurations that lower the anchor.
    fn adversarial(seed: u64) -> Vec<Command> {
        let mut rng = TestRng::new(seed);
        let mut draw = |bound: u32| rng.try_next_u32().unwrap() % bound;
        let mut generation = 0;
        (0..48)
            .map(|index| match draw(20) {
                0..=8 => observe(u64::from(draw(12)) + 1, draw(3) as u8, index),
                9..=13 => anchor(u64::from(draw(13))),
                14..=17 => {
                    let low = u64::from(draw(12)) + 1;
                    let high = low + u64::from(draw(6));
                    chosen((low..=high).filter(|height| *height <= 12))
                }
                _ => {
                    generation += 1;
                    reconfigure(generation, u64::from(draw(7)))
                }
            })
            .collect()
    }

    #[test]
    fn drained_overflow_leaves_the_plane_in_the_full_sequence_state() {
        for seed in 0..1_000 {
            let mut expected = eligibility();
            for command in adversarial(seed) {
                apply(&mut expected, command);
            }

            let mut rng = TestRng::new(seed ^ 0x5eed);
            let mut queue = Queue::new(rng.try_next_u32().unwrap() as usize % 4 + 1);
            let mut stalled = eligibility();
            for command in adversarial(seed) {
                // The plane falls behind: most sends land before it receives again.
                if rng.try_next_u32().unwrap().is_multiple_of(4)
                    && let Some(received) = queue.recv()
                {
                    apply(&mut stalled, received);
                }
                queue.send(command);
            }
            while let Some(received) = queue.recv() {
                apply(&mut stalled, received);
            }

            // Equal states mean every dropped block was one the plane settles anyway: an
            // unsettled block dropped by the overflow would still be retained in `expected`.
            assert_eq!(
                stalled.snapshot_for_test(),
                expected.snapshot_for_test(),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn settled_replays_never_queue_behind_a_stalled_plane() {
        let mut queue = Queue::new(1);
        let mut expected = eligibility();
        let mut stalled = eligibility();
        // Applies the command to the reference plane and sends an identical copy.
        let send = |queue: &mut Queue,
                    expected: &mut ChainEligibility<MinPk, Sha256Digest>,
                    command: &dyn Fn() -> Command| {
            apply(expected, command());
            queue.send(command());
        };

        // The anchor enters the ready queue and a later block overflows behind it. The plane then
        // receives the anchor, which refills the block out of the overflow: no anchor stays queued.
        send(&mut queue, &mut expected, &|| anchor(100));
        send(&mut queue, &mut expected, &|| observe(101, 0, 0));
        apply(&mut stalled, queue.recv().unwrap());
        assert!(queue.overflow.is_empty());

        // The machine replays settled blocks while the plane stalls: none of them queue.
        for index in 1..=10_000u32 {
            let height = u64::from(index % 100) + 1;
            send(&mut queue, &mut expected, &|| observe(height, 0, index));
            assert!(queue.overflow.observed.is_empty());
            assert_eq!(control_commands(&queue.overflow), 0);
        }

        // An unsettled block still queues, and the drained plane matches the full sequence.
        send(&mut queue, &mut expected, &|| observe(102, 0, 10_001));
        assert_eq!(queue.overflow.observed.len(), 1);
        while let Some(received) = queue.recv() {
            apply(&mut stalled, received);
        }
        assert_eq!(stalled.snapshot_for_test(), expected.snapshot_for_test());
    }
}
