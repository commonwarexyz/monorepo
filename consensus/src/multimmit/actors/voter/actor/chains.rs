//! The DA recovery tasks and the per-chain plane tasks the voter starts and reconfigures.

use super::{DigestOf, Fatal, VoterTypes, live::Live};
use crate::Reporter as _;
use crate::multimmit::{
    actors::voter::{
        chain_plane,
        config::chain_validation_parallelism,
        da_recovery::{self, DaUpdate, ReceiptUpdate},
        telemetry::metrics::Metrics,
    },
    config::{Profile, Role},
    machine::{
        CoreState, CryptoCompletion, DaVotesOffer, Generation, Input, StepStatus, ValidatorCommand,
    },
    scheme::{Generic, Scheme},
    types::{Activity, ChainId},
};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, Hasher};
use commonware_p2p::Sender;
use commonware_runtime::Supervisor as _;
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};

/// A result from one of the chain tasks, which share one queue to the voter.
pub(crate) enum ChainUpdate<S: Scheme, D: Digest> {
    /// An own-chain certificate from the DA recovery task.
    Recovered(DaUpdate<S, D>),
    /// An own payment chain's receipt from the DA recovery task.
    Receipt(ReceiptUpdate<S, D>),
    /// A chain plane's current eligible DA-vote run.
    DaVoteReady(DaVotesOffer<S, D>),
}

/// Results beyond the queue's capacity are retained in arrival order, so no task blocks on the
/// voter, but a chain's DA-vote offer replaces any offer of the same chain still retained: the
/// machine keeps only a chain's latest offer and re-checks its generation, so a superseded offer
/// carries nothing. Retained work is therefore at most one offer per chain plus the recovery
/// certificates and receipts, which the recovery and receipt windows bound.
impl<S: Scheme, D: Digest> mailbox::Policy for ChainUpdate<S, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if let Self::DaVoteReady(offer) = &message {
            let chain = offer.chain;
            overflow.retain(|retained| {
                !matches!(retained, Self::DaVoteReady(previous) if previous.chain == chain)
            });
        }
        overflow.push_back(message);
    }
}

impl<S: Scheme, D: Digest> From<DaUpdate<S, D>> for ChainUpdate<S, D> {
    fn from(update: DaUpdate<S, D>) -> Self {
        Self::Recovered(update)
    }
}

impl<S: Scheme, D: Digest> From<ReceiptUpdate<S, D>> for ChainUpdate<S, D> {
    fn from(update: ReceiptUpdate<S, D>) -> Self {
        Self::Receipt(update)
    }
}

impl<S: Scheme, D: Digest> From<DaVotesOffer<S, D>> for ChainUpdate<S, D> {
    fn from(offer: DaVotesOffer<S, D>) -> Self {
        Self::DaVoteReady(offer)
    }
}

/// The DA recovery task over `T`.
type DaActor<T> = da_recovery::Actor<
    <T as VoterTypes>::Context,
    <T as VoterTypes>::Hasher,
    <T as VoterTypes>::Scheme,
    <T as VoterTypes>::Strategy,
>;

/// One chain plane over `T`.
type PlaneActor<T> = chain_plane::Actor<
    <T as VoterTypes>::Context,
    <T as VoterTypes>::Hasher,
    <T as VoterTypes>::Automaton,
    <T as VoterTypes>::Scheme,
>;

/// One chain task: its command mailbox, and its actor until the first generation starts it.
struct Task<A, M> {
    mailbox: M,
    unstarted: Option<A>,
}

/// The DA recovery task over `T`.
type DaTask<T> = Task<DaActor<T>, da_recovery::Mailbox<<T as VoterTypes>::Scheme, DigestOf<T>>>;

/// One chain plane task over `T`.
type PlaneTask<T> =
    Task<PlaneActor<T>, chain_plane::Mailbox<<T as VoterTypes>::Scheme, DigestOf<T>>>;

/// The DA recovery tasks and one plane per producer chain.
///
/// The tasks are built at startup and started on the first process generation. They live until the
/// runtime stops or the voter exits, and every later generation reconfigures them.
pub(crate) struct ChainTasks<T: VoterTypes> {
    /// The DA recovery task of the chain this validator produces.
    da: Vec<DaTask<T>>,
    /// Each producer chain's plane, indexed by chain.
    planes: Vec<PlaneTask<T>>,
    /// DA recovery certificates and every plane's DA-vote offers.
    updates: Option<mailbox::Receiver<ChainUpdate<T::Scheme, DigestOf<T>>>>,
    /// Keeps the result queue open for the voter's life, so tasks that all exit early never read
    /// as a closed input that would stop the voter without a fatal error.
    _sender: Option<mailbox::Sender<ChainUpdate<T::Scheme, DigestOf<T>>>>,
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
    /// Every validator runs one plane per producer chain, and a producer runs one DA recovery task
    /// for its own chain.
    pub(crate) fn new(
        context: &T::Context,
        profile: &Profile<<T::Hasher as Hasher>::Digest>,
        scheme: &Arc<Generic<T::Scheme>>,
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
            .filter(|(chain, _)| Some(*chain) == own_chain)
            .map(|(chain, limits)| {
                // A payment chain's producer keeps collecting votes toward receipts for a
                // pipeline window of certified heights.
                let receipt_window = if protocol.payment_chain(chain) {
                    u64::from(limits.pipeline_window())
                } else {
                    0
                };
                let (actor, mailbox) = DaActor::<T>::new(
                    context.child("da"),
                    da_recovery::Config {
                        scheme: Arc::clone(scheme),
                        strategy: strategy.clone(),
                        chain,
                        da_quorum: codec.da_quorum(),
                        recovery_slots: limits.pipeline_window() as usize,
                        receipt_window,
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
        machine: &CoreState<T::Hasher, T::Scheme>,
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

    /// Returns `chain`'s DA recovery task, when this validator produces it.
    pub(crate) fn da(
        &mut self,
        chain: ChainId,
    ) -> Option<&mut da_recovery::Mailbox<T::Scheme, DigestOf<T>>> {
        self.da
            .iter_mut()
            .map(|task| &mut task.mailbox)
            .find(|mailbox| mailbox.chain() == chain)
    }

    /// Returns `chain`'s plane.
    pub(crate) fn plane(
        &mut self,
        chain: ChainId,
    ) -> Option<&mut chain_plane::Mailbox<T::Scheme, DigestOf<T>>> {
        self.planes
            .get_mut(chain.get() as usize)
            .map(|task| &mut task.mailbox)
    }

    /// Returns the queue of task results, absent for an observer.
    pub(crate) const fn updates(
        &mut self,
    ) -> Option<&mut mailbox::Receiver<ChainUpdate<T::Scheme, DigestOf<T>>>> {
        self.updates.as_mut()
    }
}

/// Replaces `plane`'s copy of the machine's durable DA choices for its chain.
fn seed_chosen<H, S>(plane: &mut chain_plane::Mailbox<S, H::Digest>, machine: &CoreState<H, S>)
where
    H: Hasher,
    S: Scheme,
{
    let _ = plane.command(ValidatorCommand::Chosen(
        machine.machine().chosen_choices(plane.chain()),
    ));
}

impl<T, Sn> Live<T, Sn>
where
    T: VoterTypes,
    Sn: Sender<PublicKey = T::PublicKey>,
{
    /// Applies one result returned by a chain task.
    ///
    /// Results from a superseded generation are dropped, as stale async completions are elsewhere:
    /// a recovered certificate here, and a plane's offer by the machine's generation check.
    pub(crate) fn chain_update(
        &mut self,
        update: ChainUpdate<T::Scheme, DigestOf<T>>,
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
            ChainUpdate::Receipt(ReceiptUpdate {
                generation,
                receipt,
            }) => {
                if self.tasks.is_stale(generation) {
                    self.telemetry.metrics.stale.inc();
                    return Ok(());
                }
                self.telemetry.metrics.receipts.inc();
                let _ = self.reporter.report(Activity::Receipt { receipt });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{machine::Generation, mocks::Bls},
        types::Height,
    };
    use commonware_actor::mailbox::Policy as _;
    use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest as D};

    fn offer(chain: u32, through: u64) -> ChainUpdate<Bls<MinPk>, D> {
        ChainUpdate::DaVoteReady(DaVotesOffer {
            generation: Generation::new(1),
            chain: ChainId::new(chain),
            candidates: Vec::new(),
            ready_through: Height::new(through),
        })
    }

    #[test]
    fn retained_offers_keep_only_the_latest_of_each_chain() {
        let mut overflow = VecDeque::new();
        for (chain, through) in [(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)] {
            ChainUpdate::handle(&mut overflow, offer(chain, through));
        }
        let retained = overflow
            .iter()
            .map(|update| match update {
                ChainUpdate::DaVoteReady(offer) => (offer.chain.get(), offer.ready_through.get()),
                ChainUpdate::Recovered(_) | ChainUpdate::Receipt(_) => {
                    unreachable!("only offers were retained")
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(retained, vec![(0, 3), (1, 2)]);
    }
}
