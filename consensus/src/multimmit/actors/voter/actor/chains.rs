//! The per-chain plane tasks the voter starts and reconfigures.

use super::{DigestOf, Fatal, VoterTypes, live::Live};
use crate::{
    multimmit::{
        actors::voter::{chain_plane, telemetry::metrics::Metrics, validation_parallelism},
        config::{Profile, Role},
        machine::{ChainProgress, Generation, Input, ValidationCompletion},
        types::ChainId,
    },
    types::Height,
};
use commonware_actor::mailbox;
use commonware_cryptography::Hasher;
use commonware_p2p::Sender;
use commonware_runtime::Supervisor as _;
use std::num::NonZeroUsize;

/// One chain plane over `T`.
type PlaneActor<T> = chain_plane::Actor<
    <T as VoterTypes>::Context,
    <T as VoterTypes>::Hasher,
    <T as VoterTypes>::Automaton,
    <T as VoterTypes>::Variant,
>;

/// One chain plane: its command mailbox, and its actor until the first generation starts it.
struct PlaneTask<T: VoterTypes> {
    mailbox: chain_plane::Mailbox<T::Variant, DigestOf<T>>,
    unstarted: Option<PlaneActor<T>>,
}

/// One plane per producer chain.
///
/// The planes are built at startup and started on the first process generation. They live until
/// the runtime stops or the voter exits, and every later generation reconfigures them.
pub(crate) struct ChainTasks<T: VoterTypes> {
    /// Each producer chain's plane, indexed by chain.
    planes: Vec<PlaneTask<T>>,
    /// Every plane's verdicts.
    verdicts: Option<mailbox::Receiver<ValidationCompletion<DigestOf<T>>>>,
    /// Keeps the verdict queue open for the voter's life, so planes that all exit early never read
    /// as a closed input that would stop the voter without a fatal error.
    _sender: Option<mailbox::Sender<ValidationCompletion<DigestOf<T>>>>,
}

impl<T: VoterTypes> Default for ChainTasks<T> {
    /// Returns no planes, as for an observer.
    fn default() -> Self {
        Self {
            planes: Vec::new(),
            verdicts: None,
            _sender: None,
        }
    }
}

impl<T: VoterTypes> ChainTasks<T> {
    /// Builds the planes a validator runs under `profile`; an observer runs none.
    pub(crate) fn new(
        context: &T::Context,
        profile: &Profile<<T::Hasher as Hasher>::Digest>,
        automaton: &T::Automaton,
        metrics: &Metrics,
        mailbox_size: NonZeroUsize,
    ) -> Self {
        let Role::Validator(_) = profile.role() else {
            return Self::default();
        };
        let (sender, verdicts) = mailbox::new(context.child("verdicts"), mailbox_size);
        let validation_items = NonZeroUsize::new(validation_parallelism(profile))
            .expect("validated profiles admit one validation per chain");
        let planes = profile
            .codec()
            .chain_ids()
            .map(|chain| {
                let (actor, mailbox) = PlaneActor::<T>::new(
                    context.child("validator"),
                    chain_plane::Config {
                        chain,
                        automaton: automaton.clone(),
                        validation_items,
                        verdicts: sender.clone(),
                        latency: metrics.validation_latency.clone(),
                        invalid: metrics.invalid_blocks.clone(),
                        unavailable: metrics.unavailable_validations.clone(),
                        mailbox_size,
                    },
                );
                PlaneTask {
                    mailbox,
                    unstarted: Some(actor),
                }
            })
            .collect();
        Self {
            planes,
            verdicts: Some(verdicts),
            _sender: Some(sender),
        }
    }

    /// Moves the planes to process generation `generation`, each above its chain's accepted tip
    /// in `progress`.
    ///
    /// The first generation starts each plane; every later one reconfigures it. The floor is the
    /// accepted tip the live path reports through
    /// [`ChainCommand::Accepted`](crate::multimmit::machine::ChainCommand::Accepted), so a plane drops
    /// exactly the blocks whose verdicts the machine no longer needs.
    pub(crate) fn enter(&mut self, generation: Generation, progress: &[ChainProgress]) {
        for plane in &mut self.planes {
            let accepted = accepted_tip(progress, plane.mailbox.chain());
            match plane.unstarted.take() {
                Some(actor) => {
                    plane.mailbox.started(accepted);
                    actor.start(generation, accepted);
                }
                None => {
                    let _ = plane.mailbox.reconfigure(generation, accepted);
                }
            }
        }
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

    /// Returns the queue of plane verdicts, absent for an observer.
    pub(crate) const fn verdicts(
        &mut self,
    ) -> Option<&mut mailbox::Receiver<ValidationCompletion<DigestOf<T>>>> {
        self.verdicts.as_mut()
    }
}

impl<T, S> Live<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Admits one plane verdict; the machine drops a verdict from a superseded generation.
    pub(crate) fn validated(
        &mut self,
        completion: ValidationCompletion<DigestOf<T>>,
    ) -> Result<(), Fatal> {
        self.track_in_round(|core, now| core.enqueue(Input::Validated(completion), now))?;
        Ok(())
    }
}

/// Returns the height of `chain`'s accepted tip in `progress`.
fn accepted_tip(progress: &[ChainProgress], chain: ChainId) -> Height {
    progress
        .iter()
        .find(|progress| progress.chain() == chain)
        .map_or_else(Height::zero, |progress| progress.accepted())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        config::Role,
        machine::{
            BlockValidity,
            testing::fixtures::{committee, path, receive, started, validate},
        },
    };

    #[test]
    fn planes_restart_above_the_accepted_tip_rather_than_the_final_height() {
        let committee = committee(43);
        let mut driver = started(&committee, Role::Observer);
        let chain = ChainId::new(1);
        let blocks = path(&committee, chain, 2);
        receive(&mut driver, &blocks);
        for block in &blocks {
            validate(&mut driver, block, BlockValidity::Valid);
        }

        // Both blocks are accepted, and none is known final.
        let inspection = driver.inspect();
        let progress = inspection.chain_progress()[chain.index()];
        assert_eq!(progress.accepted(), Height::new(2));
        assert_eq!(progress.finalized(), Height::zero());
        assert_eq!(
            accepted_tip(inspection.chain_progress(), chain),
            Height::new(2)
        );
    }
}
