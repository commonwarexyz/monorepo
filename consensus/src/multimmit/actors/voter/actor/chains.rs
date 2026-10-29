//! The DA recovery tasks and the per-chain plane tasks the voter starts and reconfigures.

use super::{DigestOf, Fatal, VoterTypes, live::Live};
use crate::multimmit::{
    actors::{
        util::reliable_policy,
        voter::{
            chain_plane,
            config::chain_validation_parallelism,
            da_recovery::{self, DaUpdate},
            telemetry::metrics::Metrics,
        },
    },
    config::{Profile, Role},
    machine::{
        CoreState, CryptoCompletion, DaVotesOffer, Generation, Input, StepStatus, ValidatorCommand,
    },
    scheme::bls12381_threshold::Scheme,
    types::ChainId,
};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_p2p::Sender;
use commonware_runtime::Supervisor as _;
use std::{num::NonZeroUsize, sync::Arc};

/// A result from one of the chain tasks, which share one queue to the voter.
pub(crate) enum ChainUpdate<V: Variant, D: Digest> {
    /// An own-chain certificate from the DA recovery task.
    Recovered(DaUpdate<V, D>),
    /// A chain plane's current eligible DA-vote run.
    DaVoteReady(DaVotesOffer<V, D>),
}

// Results beyond the queue's capacity are retained without bound, in arrival order, so no task
// blocks on the voter.
reliable_policy!(impl<V: Variant, D: Digest> for ChainUpdate<V, D>);

impl<V: Variant, D: Digest> From<DaUpdate<V, D>> for ChainUpdate<V, D> {
    fn from(update: DaUpdate<V, D>) -> Self {
        Self::Recovered(update)
    }
}

impl<V: Variant, D: Digest> From<DaVotesOffer<V, D>> for ChainUpdate<V, D> {
    fn from(offer: DaVotesOffer<V, D>) -> Self {
        Self::DaVoteReady(offer)
    }
}

/// The DA recovery task over `T`.
type DaActor<T> = da_recovery::Actor<
    <T as VoterTypes>::Context,
    <T as VoterTypes>::Hasher,
    <T as VoterTypes>::PublicKey,
    <T as VoterTypes>::Variant,
    <T as VoterTypes>::Strategy,
>;

/// One chain plane over `T`.
type PlaneActor<T> = chain_plane::Actor<
    <T as VoterTypes>::Context,
    <T as VoterTypes>::Hasher,
    <T as VoterTypes>::Automaton,
    <T as VoterTypes>::Variant,
>;

/// One chain task: its command mailbox, and its actor until the first generation starts it.
struct Task<A, M> {
    mailbox: M,
    unstarted: Option<A>,
}

/// The DA recovery task over `T`.
type DaTask<T> = Task<DaActor<T>, da_recovery::Mailbox<<T as VoterTypes>::Variant, DigestOf<T>>>;

/// One chain plane task over `T`.
type PlaneTask<T> =
    Task<PlaneActor<T>, chain_plane::Mailbox<<T as VoterTypes>::Variant, DigestOf<T>>>;

/// The DA recovery tasks and one plane per producer chain.
///
/// The tasks are built at startup and started on the first process generation. They live until the
/// runtime stops or the voter exits, and every later generation reconfigures them.
pub(crate) struct ChainTasks<T: VoterTypes> {
    /// The DA recovery task of each chain whose certificates this validator recovers.
    da: Vec<DaTask<T>>,
    /// Each producer chain's plane, indexed by chain.
    planes: Vec<PlaneTask<T>>,
    /// DA recovery certificates and every plane's DA-vote offers.
    updates: Option<mailbox::Receiver<ChainUpdate<T::Variant, DigestOf<T>>>>,
    /// Keeps the result queue open for the voter's life, so tasks that all exit early never read
    /// as a closed input that would stop the voter without a fatal error.
    _sender: Option<mailbox::Sender<ChainUpdate<T::Variant, DigestOf<T>>>>,
}

impl<T: VoterTypes> Default for ChainTasks<T> {
    /// Returns no tasks, as for an observer.
    fn default() -> Self {
        Self {
            da: Vec::new(),
            planes: Vec::new(),
            updates: None,
            _sender: None,
        }
    }
}

impl<T: VoterTypes> ChainTasks<T> {
    /// Builds the tasks a validator runs under `profile`; an observer runs none.
    ///
    /// Every validator runs one plane per producer chain, and one DA recovery task for each chain
    /// whose certificates it recovers: the chain it produces, and every receipt chain.
    pub(crate) fn new(
        context: &T::Context,
        profile: &Profile<<T::Hasher as Hasher>::Digest>,
        scheme: &Arc<Scheme<T::PublicKey, T::Variant>>,
        strategy: T::Strategy,
        automaton: &T::Automaton,
        metrics: &Metrics,
        mailbox_size: NonZeroUsize,
    ) -> Self {
        let Role::Validator(participant) = profile.role() else {
            return Self::default();
        };
        let protocol = profile.protocol();
        let codec = protocol.codec_config();
        let (sender, updates) = mailbox::new(context.child("da_updates"), mailbox_size);
        let own_chain = protocol.producer_chain(participant);
        let da = codec
            .chain_ids()
            .zip(protocol.chain_limits().iter())
            .filter(|(chain, _)| Some(*chain) == own_chain || protocol.receipt_chain(*chain))
            .map(|(chain, limits)| {
                let (actor, mailbox) = DaActor::<T>::new(
                    context.child("da").with_attribute("chain", chain),
                    da_recovery::Config {
                        scheme: Arc::clone(scheme),
                        strategy: strategy.clone(),
                        chain,
                        da_quorum: codec.da_quorum(),
                        recovery_slots: limits.pipeline_window() as usize,
                        updates: sender.clone(),
                        latency: metrics.da_recovery_latency.clone(),
                        fallbacks: metrics.da_recovery_fallbacks.clone(),
                        mailbox_size,
                    },
                );
                Task {
                    mailbox,
                    unstarted: Some(actor),
                }
            })
            .collect();
        let planes = codec
            .chain_ids()
            .zip(protocol.chain_limits().iter())
            .map(|(chain, limits)| {
                let validation_items = chain_validation_parallelism(profile, limits);
                let validation_bytes =
                    validation_items.saturating_mul(profile.resources().max_artifact_bytes());
                PlaneActor::<T>::new(
                    context.child("validator"),
                    chain_plane::Config {
                        chain,
                        automaton: automaton.clone(),
                        pipeline_window: limits.pipeline_window() as usize,
                        validation_items,
                        validation_bytes,
                        updates: sender.clone(),
                        latency: metrics.validation_latency.clone(),
                        invalid: metrics.invalid_blocks.clone(),
                        unavailable: metrics.unavailable_validations.clone(),
                        mailbox_size,
                    },
                )
            })
            .map(|(actor, mailbox)| Task {
                mailbox,
                unstarted: Some(actor),
            })
            .collect();
        Self {
            da,
            planes,
            updates: Some(updates),
            _sender: Some(sender),
        }
    }

    /// Drops every task's command queue, so each started task exits.
    #[cfg(test)]
    pub(crate) fn close_commands(&mut self) {
        self.da.clear();
        self.planes.clear();
    }

    /// Moves the tasks to process generation `generation`, seeded from `machine`.
    ///
    /// The first generation starts each task; every later one reconfigures it.
    pub(crate) fn enter(
        &mut self,
        generation: Generation,
        machine: &CoreState<T::Hasher, T::Variant>,
    ) {
        for da in &mut self.da {
            let certified = machine.machine().certified_height(da.mailbox.chain());
            match da.unstarted.take() {
                Some(actor) => {
                    da.mailbox.started(certified);
                    actor.start(generation, certified);
                }
                None => {
                    let _ = da.mailbox.reconfigure(generation, certified);
                }
            }
        }
        for plane in &mut self.planes {
            let anchor = machine.machine().certified_anchor(plane.mailbox.chain());
            match plane.unstarted.take() {
                Some(actor) => {
                    plane.mailbox.started(anchor);
                    actor.start(generation, anchor);
                }
                None => {
                    let _ = plane.mailbox.reconfigure(generation, anchor);
                }
            }
            seed_chosen(&mut plane.mailbox, machine);
        }
    }

    /// Returns `chain`'s DA recovery task, when this validator recovers its certificates.
    pub(crate) fn da(
        &mut self,
        chain: ChainId,
    ) -> Option<&mut da_recovery::Mailbox<T::Variant, DigestOf<T>>> {
        self.da
            .iter_mut()
            .map(|task| &mut task.mailbox)
            .find(|mailbox| mailbox.chain() == chain)
    }

    /// Returns `chain`'s plane.
    pub(crate) fn plane(
        &mut self,
        chain: ChainId,
    ) -> Option<&mut chain_plane::Mailbox<T::Variant, DigestOf<T>>> {
        self.planes
            .get_mut(chain.get() as usize)
            .map(|task| &mut task.mailbox)
    }

    /// Returns the queue of task results, absent for an observer.
    pub(crate) const fn updates(
        &mut self,
    ) -> Option<&mut mailbox::Receiver<ChainUpdate<T::Variant, DigestOf<T>>>> {
        self.updates.as_mut()
    }
}

/// Replaces `plane`'s copy of the machine's durable DA choices for its chain.
fn seed_chosen<H, V>(plane: &mut chain_plane::Mailbox<V, H::Digest>, machine: &CoreState<H, V>)
where
    H: Hasher,
    V: Variant,
{
    let _ = plane.command(ValidatorCommand::Chosen(
        machine.machine().chosen_choices(plane.chain()),
    ));
}

impl<T, S> Live<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Applies one result returned by a chain task.
    ///
    /// Results from a superseded generation are dropped, as stale async completions are elsewhere:
    /// a recovered certificate here, and a plane's offer by the machine's generation check.
    pub(crate) fn chain_update(
        &mut self,
        update: ChainUpdate<T::Variant, DigestOf<T>>,
    ) -> Result<(), Fatal> {
        match update {
            ChainUpdate::Recovered(DaUpdate {
                generation,
                block,
                certificate,
            }) => {
                if self.tasks.is_stale(generation) {
                    self.telemetry.metrics.stale.inc();
                    return Ok(());
                }
                self.track_in_round(|core| {
                    core.enqueue(Input::Crypto(CryptoCompletion::DaCertificate {
                        block,
                        certificate,
                    }))
                })?;
            }
            ChainUpdate::DaVoteReady(offer) => {
                let status = self.machine.offer(offer);
                if matches!(status, StepStatus::StaleCompletion) {
                    self.telemetry.metrics.stale.inc();
                }
            }
        }
        Ok(())
    }
}
