//! One producer chain's remote validator data-availability plane, run on its own work-stealing task.
//!
//! Stage 2 of the DA-plane sharding lifts every remote producer chain's block store,
//! application-validation scheduling, and data-availability-vote eligibility off the single serial
//! voter thread into one task per chain. Central (the serial [`super::CoreState`] owner) still mints
//! each observation identity, records producer ancestry, detects forks, and alone mints the durable
//! one-vote-per-height DA choice. This task only validates and offers the contiguous eligible run
//! central then reserves.
//!
//! ```text
//! central                                   per-chain validator task
//! -------                                   ------------------------
//! mint identity + record ancestry --Observe--> store block, schedule application validation
//!                                           run Automaton::verify on the shared pool
//! advance certified anchor ------AnchorAdvanced--> settle blocks, cancel settled validations
//! mint durable DA choice ------------Chosen-----> advance the eligibility read-copy
//! reserve DA votes + frontier <---DaVoteReady---- offer the contiguous eligible run
//! ```
//!
//! The task holds only volatile, rebuildable state. On restart central replays its durable state,
//! respawns a fresh task, and re-seeds the certified anchor and chosen votes; blocks refill from
//! re-observed gossip. A saturated command mailbox backpressures central admission for this chain
//! alone and is never fatal.

use super::{da::DaTaskUpdate, *};
use crate::multimmit::machine::{
    ArtifactId, BlockValidity, DaChoice, EligibleRun, Observation, PerChainValidator,
    ValidationCompletion, ValidationId, ValidationOutcome,
};
use commonware_actor::mailbox::{Policy, Sender as ChainSender};
use commonware_macros::{select, select_loop};
use commonware_runtime::telemetry::metrics::Counter;

/// A command from central to one remote validator plane.
///
/// Central authenticates, orders, and identity-stamps every block before it crosses this boundary,
/// so the plane never re-derives a protocol fact.
pub(super) enum ValidatorCommand<V: Variant, D: Digest> {
    /// An authenticated block central routed to this chain, with the observation identity it minted.
    Observe {
        /// The observation identity central assigned.
        id: ArtifactId<D>,
        /// The observation order central assigned.
        observation: Observation,
        /// The authenticated block.
        block: Arc<SignedTransactionBlock<V, D>>,
        /// Whether this is the local producer's own custodied block (valid without a check).
        custodied: bool,
    },
    /// The chain's certified anchor advanced; blocks at or below it are settled.
    AnchorAdvanced(BlockRef<D>),
    /// Central's durable DA choices above the anchor, replacing the eligibility read-copy.
    Chosen(Vec<DaChoice<D>>),
    /// A new process generation began; drop volatile state and re-seed the anchor.
    Reconfigure {
        /// The new process generation.
        generation: u64,
        /// The certified anchor of the new generation.
        anchor: BlockRef<D>,
    },
}

impl<V: Variant, D: Digest> Policy for ValidatorCommand<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
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

/// One remote validator plane bound to one chain and one process generation.
pub(super) struct ValidatorPlane<E, H, A, V>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    V: Variant,
{
    context: E,
    automaton: A,
    validator: PerChainValidator<V, H::Digest>,
    updates: ChainSender<DaTaskUpdate<V, H::Digest>>,
    chain: ChainId,
    /// The most eligible blocks one offer carries: the pipeline depth, the eligibility bound.
    run_cap: usize,
    /// The last run offered to central, to suppress redundant offers.
    last_offer: Vec<BlockRef<H::Digest>>,
    latency: Histogram,
    invalid: Counter,
    unavailable: Counter,
}

impl<E, H, A, V> ValidatorPlane<E, H, A, V>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    V: Variant,
{
    /// Builds a validator plane bound to one chain and one process generation.
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new(
        context: E,
        automaton: A,
        validator: PerChainValidator<V, H::Digest>,
        updates: ChainSender<DaTaskUpdate<V, H::Digest>>,
        chain: ChainId,
        run_cap: usize,
        latency: Histogram,
        invalid: Counter,
        unavailable: Counter,
    ) -> Self {
        Self {
            context,
            automaton,
            validator,
            updates,
            chain,
            run_cap,
            last_offer: Vec::new(),
            latency,
            invalid,
            unavailable,
        }
    }

    /// Drains commands and validation completions until central closes the channel or the runtime
    /// stops.
    pub(super) async fn run(
        mut self,
        mut commands: mailbox::Receiver<ValidatorCommand<V, H::Digest>>,
    ) {
        let mut verifies: Pool<Verified> = Pool::default();
        let mut cancels: BTreeMap<ValidationId, oneshot::Sender<()>> = BTreeMap::new();
        select_loop! {
            self.context,
            on_stopped => {
                drop(shutdown);
            },
            Some(command) = commands.recv() else break => {
                self.handle_command(command, &mut verifies, &mut cancels);
                self.dispatch(&mut verifies, &mut cancels);
                if !self.offer() {
                    break;
                }
            },
            done = verifies.next_completed() => {
                self.handle_verified(done, &mut cancels);
                self.dispatch(&mut verifies, &mut cancels);
                if !self.offer() {
                    break;
                }
            },
        }
    }

    fn handle_command(
        &mut self,
        command: ValidatorCommand<V, H::Digest>,
        verifies: &mut Pool<Verified>,
        cancels: &mut BTreeMap<ValidationId, oneshot::Sender<()>>,
    ) {
        match command {
            ValidatorCommand::Observe {
                id,
                observation,
                block,
                custodied,
            } => self
                .validator
                .observe::<H>(id, observation, block, custodied),
            ValidatorCommand::AnchorAdvanced(anchor) => {
                for id in self.validator.advance_anchor(anchor) {
                    cancels.remove(&id);
                }
            }
            ValidatorCommand::Chosen(choices) => self.validator.note_chosen(choices),
            ValidatorCommand::Reconfigure { generation, anchor } => {
                self.validator.reconfigure(generation, anchor);
                cancels.clear();
                *verifies = Pool::default();
                self.last_offer.clear();
            }
        }
    }

    /// Dispatches every ready application validation this chain can start.
    fn dispatch(
        &mut self,
        verifies: &mut Pool<Verified>,
        cancels: &mut BTreeMap<ValidationId, oneshot::Sender<()>>,
    ) {
        while let Some(job) = self.validator.ready_validation() {
            let id = job.id();
            let generation = job.generation();
            let block = Arc::clone(job.block_arc());
            let context = Context::from(block.header());
            let commitment = block.header().body_digest();
            let (cancel, cancelled) = oneshot::channel();
            cancels.insert(id, cancel);
            let mut automaton = self.automaton.clone();
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
                            completion: ValidationCompletion::new(id, generation, validity),
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
        self.latency
            .observe_between(started_at, self.context.current());
        cancels.remove(&completion.id());
        match self.validator.complete_validation(completion) {
            ValidationOutcome::Invalid(_) => {
                self.invalid.inc();
            }
            ValidationOutcome::Deferred => {
                self.unavailable.inc();
            }
            ValidationOutcome::Retained | ValidationOutcome::Stale => {}
        }
    }

    /// Offers central this chain's current eligible run, unless it matches the last offer. Returns
    /// whether central's update channel is still open.
    fn offer(&mut self) -> bool {
        let EligibleRun { run, ready_through } = self.validator.eligible_run(self.run_cap);
        let refs = run
            .iter()
            .map(|block| block.header().block_ref::<H>())
            .collect::<Vec<_>>();
        if refs == self.last_offer {
            return true;
        }
        self.last_offer = refs;
        self.updates
            .enqueue(DaTaskUpdate::DaVoteReady {
                generation: self.validator.generation(),
                chain: self.chain,
                candidates: run,
                ready_through,
            })
            .accepted()
    }
}
