//! The application the secondary half of the compromised identity runs in the
//! reshare Twins target.
//!
//! It deviates only in what it proposes, by replacing the payload the
//! [`reshare::Application`](commonware_glue::dkg::reshare::Application)
//! wrapper selected for a block:
//!
//! - a dealer log in the early half of an epoch;
//! - in the inclusion window, a dealer log another dealer signed;
//! - an epoch description on a block that does not end an epoch;
//! - on the block that ends an epoch, a wrong epoch description (the newest
//!   one it has seen, the right one with the other outcome, or the right one
//!   with its two player sets exchanged), or no payload.
//!
//! It accepts every block it is asked to verify, as the correct application
//! does.
//!
//! Which deviations are armed, and in which rounds one is taken, is drawn once
//! from the run's tape and then indexed by round, so clones invoked
//! concurrently agree. The material a deviation proposes is what the
//! application has seen: the dealer logs of blocks other identities proposed,
//! the newest epoch description, and one dealer log the harness signs with the
//! compromised identity's key before the run.

use super::{
    Info, MockGroup, PublicKey, RESHARE_NAMESPACE,
    app::{App, Block, BlockContext, BlockPayload, Input},
    scheme::Scheme,
};
use crate::stateful::runner::unattributed;
use commonware_consensus::{
    Application, CertifiableBlock as _, Heightable as _,
    marshal::ancestry::Ancestry,
    types::{EpochPhase, Epocher as _, FixedEpocher, Height, Round},
};
use commonware_cryptography::{
    Digested,
    bls12381::{
        dkg::feldman_desmedt::{Dealer, Info as RoundInfo, Reveal, SignedDealerLog},
        primitives::{group::Share, sharing::Mode},
    },
    ed25519,
};
use commonware_glue::dkg::{
    ReshareBlock as _,
    types::{EpochOutcome, Payload},
};
use commonware_utils::{FuzzRng, N3f1, sync::Mutex};
use rand::RngExt as _;
use std::{
    mem,
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Rounds covered by a plan before it repeats.
const PLAN_ROUNDS: usize = 64;

/// Dealer logs of other proposers the application remembers.
const REMEMBERED_LOGS: usize = 8;

/// A signed dealer log over the mock group.
type Log = SignedDealerLog<MockGroup, PublicKey>;

/// One deviation the faulty application may take when it proposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Carry a dealer log in the early half of an epoch.
    EarlyLog,
    /// Carry a dealer log another dealer signed, in the inclusion window.
    ForeignLog,
    /// Carry an epoch description on a block that does not end an epoch.
    MisplacedInfo,
    /// Carry a wrong epoch description on the block that ends an epoch.
    WrongInfo,
    /// Carry no payload on the block that ends an epoch.
    NoPayload,
}

impl Fault {
    const ALL: [Self; 5] = [
        Self::EarlyLog,
        Self::ForeignLog,
        Self::MisplacedInfo,
        Self::WrongInfo,
        Self::NoPayload,
    ];
}

/// Where in its epoch a block sits, which decides the deviations that apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// Before the midpoint.
    Early,
    /// From the midpoint up to, but not including, the final block.
    Inclusion,
    /// The final block.
    Final,
}

impl Fault {
    const fn applies(self, place: Place) -> bool {
        matches!(
            (self, place),
            (Self::EarlyLog, Place::Early)
                | (Self::ForeignLog, Place::Inclusion)
                | (Self::MisplacedInfo, Place::Early | Place::Inclusion)
                | (Self::WrongInfo | Self::NoPayload, Place::Final)
        )
    }
}

/// Which deviations are armed and in which rounds one is taken, generated
/// once from the run's byte tape.
#[derive(Clone)]
pub(super) struct Plan {
    armed: Arc<[Fault]>,

    /// Of eight rounds, the number in which a block that does not end an
    /// epoch deviates.
    density: u8,
    samples: Arc<[[u8; 2]; PLAN_ROUNDS]>,
}

impl Plan {
    /// Draw a plan from `rng`.
    pub(super) fn new(rng: &mut FuzzRng) -> Self {
        // Every deviation stays armed unless the tape turns it off, so the
        // adversary keeps its reach as the rest of the input mutates.
        let mut arming = [0u8; Fault::ALL.len()];
        rng.fill(&mut arming[..]);
        let armed = Fault::ALL
            .into_iter()
            .zip(arming)
            .filter(|(_, sample)| sample % 8 != 0)
            .map(|(fault, _)| fault)
            .collect();
        let mut density = [0u8; 1];
        rng.fill(&mut density[..]);
        let mut samples = [[0u8; 2]; PLAN_ROUNDS];
        for sample in &mut samples {
            rng.fill(&mut sample[..]);
        }
        Self {
            armed,
            density: density[0] % 4 + 1,
            samples: Arc::new(samples),
        }
    }

    /// A plan that never deviates.
    #[cfg(test)]
    pub(super) fn idle() -> Self {
        Self {
            armed: Arc::new([]),
            density: 1,
            samples: Arc::new([[0u8; 2]; PLAN_ROUNDS]),
        }
    }

    /// A plan that takes `fault` wherever it applies.
    #[cfg(test)]
    fn always(fault: Fault) -> Self {
        Self {
            armed: Arc::new([fault]),
            density: 8,
            samples: Arc::new([[0u8; 2]; PLAN_ROUNDS]),
        }
    }

    /// The deviation to take in `round` for a block at `place`, of those
    /// `available`, and a byte that selects among its variants.
    fn at(
        &self,
        round: Round,
        place: Place,
        available: impl Fn(Fault) -> bool,
    ) -> Option<(Fault, u8)> {
        let slot = round
            .epoch()
            .get()
            .wrapping_mul(31)
            .wrapping_add(round.view().get());
        let [sample, variant] = self.samples[(slot % PLAN_ROUNDS as u64) as usize];

        // The final block is proposed once an epoch, so it deviates in half
        // of the rounds whatever the density.
        let density = if place == Place::Final {
            4
        } else {
            self.density
        };
        if sample % 8 >= density {
            return None;
        }
        let candidates: Vec<Fault> = self
            .armed
            .iter()
            .copied()
            .filter(|fault| fault.applies(place) && available(*fault))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        Some((
            candidates[usize::from(sample >> 3) % candidates.len()],
            variant,
        ))
    }
}

/// What the application has seen that a deviation may propose.
struct Seen {
    /// Dealer logs carried by blocks other identities proposed, oldest first.
    foreign: Vec<Log>,
    /// The newest epoch description: the run's first, then each one carried
    /// by a final block.
    info: Info,
}

/// A dealer log signed with `signer`'s key for the first ceremony, by a dealer
/// no player acknowledged.
///
/// Returns `None` if the identity does not deal in the first ceremony.
pub(super) fn spare_log(
    rng: &mut FuzzRng,
    genesis: &Info,
    signer: &ed25519::PrivateKey,
    share: Option<Share>,
    sharing_mode: Mode,
) -> Option<Log> {
    let round = RoundInfo::<MockGroup, PublicKey>::new::<N3f1>(
        RESHARE_NAMESPACE,
        genesis.epoch.get(),
        Some(genesis.output.clone()),
        sharing_mode,
        Reveal::V1,
        genesis.output.players().clone(),
        genesis.players.clone(),
    )
    .ok()?;
    let (dealer, _, _) =
        Dealer::<MockGroup, ed25519::PrivateKey>::start::<N3f1>(rng, round, signer.clone(), share)
            .ok()?;
    Some(dealer.finalize::<N3f1>())
}

/// The application the compromised identity's secondary half runs.
#[derive(Clone)]
pub(super) struct Faulty {
    inner: App,
    plan: Plan,
    identity: PublicKey,
    epocher: FixedEpocher,
    spare: Option<Log>,
    seen: Arc<Mutex<Seen>>,
    deviations: Arc<AtomicUsize>,
}

impl Faulty {
    /// The faulty application of `identity`, which follows `plan` from the
    /// epoch `genesis` describes, on a chain of `blocks_per_epoch` blocks per
    /// epoch.
    pub(super) fn new(
        plan: Plan,
        identity: PublicKey,
        genesis: Info,
        spare: Option<Log>,
        blocks_per_epoch: NonZeroU64,
    ) -> Self {
        Self {
            inner: App,
            plan,
            identity,
            epocher: FixedEpocher::new(blocks_per_epoch),
            spare,
            seen: Arc::new(Mutex::new(Seen {
                foreign: Vec::new(),
                info: genesis,
            })),
            deviations: Arc::default(),
        }
    }

    /// The number of proposals in which the application replaced the
    /// selected payload so far, shared with every clone.
    pub(super) fn deviations(&self) -> Arc<AtomicUsize> {
        self.deviations.clone()
    }

    /// Where the block at `height` sits in its epoch.
    fn place(&self, height: Height) -> Option<Place> {
        let bounds = self.epocher.containing(height)?;
        Some(if bounds.last() == height {
            Place::Final
        } else if bounds.phase() == EpochPhase::Early {
            Place::Early
        } else {
            Place::Inclusion
        })
    }

    /// Remember what `block` carries.
    fn remember(&self, block: &Block) {
        let mut seen = self.seen.lock();
        match block.payload() {
            Some(Payload::DealerLog(log)) => {
                if block.context().leader == self.identity || seen.foreign.contains(&log) {
                    return;
                }
                if seen.foreign.len() == REMEMBERED_LOGS {
                    seen.foreign.remove(0);
                }
                seen.foreign.push(log);
            }
            Some(Payload::EpochInfo(info)) if self.place(block.height()) == Some(Place::Final) => {
                seen.info = info;
            }
            Some(Payload::EpochInfo(_)) | None => {}
        }
    }

    /// The payload to propose at `height` in `round` in place of `selected`.
    fn payload(
        &self,
        round: Round,
        height: Height,
        selected: Option<BlockPayload>,
    ) -> Option<BlockPayload> {
        let Some(place) = self.place(height) else {
            return selected;
        };
        let mut seen = self.seen.lock();
        let available = |fault: Fault| match fault {
            Fault::EarlyLog => self.spare.is_some() || !seen.foreign.is_empty(),
            Fault::ForeignLog => !seen.foreign.is_empty(),
            Fault::WrongInfo => matches!(selected, Some(Payload::EpochInfo(_))),
            Fault::MisplacedInfo | Fault::NoPayload => true,
        };
        let Some((fault, variant)) = self.plan.at(round, place, available) else {
            if let Some(Payload::EpochInfo(info)) = &selected {
                seen.info = info.clone();
            }
            return selected;
        };
        self.deviations.fetch_add(1, Ordering::Relaxed);
        let variant = usize::from(variant);
        match fault {
            Fault::EarlyLog => {
                // The spare log is one more choice after the remembered ones.
                let choices = seen.foreign.len() + usize::from(self.spare.is_some());
                let log = seen
                    .foreign
                    .get(variant % choices)
                    .or(self.spare.as_ref())
                    .expect("an available early log has a source");
                Some(Payload::DealerLog(log.clone()))
            }
            Fault::ForeignLog => {
                let log = &seen.foreign[variant % seen.foreign.len()];
                Some(Payload::DealerLog(log.clone()))
            }
            Fault::MisplacedInfo => Some(Payload::EpochInfo(seen.info.clone())),
            Fault::WrongInfo => {
                let Some(Payload::EpochInfo(right)) = selected else {
                    unreachable!("a wrong description is available only for a selected one");
                };
                let mut wrong = right.clone();
                match variant % 3 {
                    // The newest description the application has seen, which
                    // is the ending epoch's unless the right one was seen.
                    0 => wrong = seen.info.clone(),
                    // The right description with the other outcome.
                    1 => {}
                    // The two announced player sets exchanged.
                    _ => mem::swap(&mut wrong.players, &mut wrong.next_players),
                }

                // A variant that reproduces the right description reports
                // the other outcome instead, so the description is wrong.
                if wrong == right {
                    wrong.outcome = match right.outcome {
                        EpochOutcome::Success => EpochOutcome::Failure,
                        EpochOutcome::Failure => EpochOutcome::Success,
                    };
                }
                Some(Payload::EpochInfo(wrong))
            }
            Fault::NoPayload => None,
        }
    }
}

impl<E: Send> Application<E> for Faulty {
    type SigningScheme = Scheme;
    type Context = BlockContext;
    type Block = Block;
    type Input = Input;

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Digested<Self::Block>> {
        let height = ancestry.peek()?.height().next();

        // The application is called inside the half's task and is the
        // harness's code, not the half's.
        let payload = unattributed(|| self.payload(context.1.round, height, input.payload));
        self.inner
            .propose(
                context,
                ancestry,
                Input {
                    upstream: (),
                    payload,
                },
            )
            .await
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        if let Some(block) = ancestry.peek() {
            unattributed(|| self.remember(block.inner()));
        }
        self.inner.verify(context, ancestry).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{COMMITTEE, EPOCH_LENGTH, fixtures::described, signers};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, View},
    };
    use commonware_cryptography::{Digest as _, Signer as _, sha256};

    /// The description of epoch zero among the first four identities, and
    /// their shares in identity order.
    fn genesis() -> (Info, Vec<Share>) {
        described(5, Epoch::zero())
    }

    /// The faulty application of the first identity under `plan`.
    fn application(plan: Plan) -> (Faulty, Info) {
        let (info, shares) = genesis();
        let signer = signers(COMMITTEE.get()).remove(0);
        let spare = spare_log(
            &mut FuzzRng::new(vec![1, 2, 3]),
            &info,
            &signer,
            Some(shares[0].clone()),
            Mode::NonZeroCounter,
        );
        assert!(spare.is_some());
        let faulty = Faulty::new(plan, signer.public_key(), info.clone(), spare, EPOCH_LENGTH);
        (faulty, info)
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    /// A block at `height` that `leader` proposed with `payload`.
    fn block(leader: PublicKey, height: u64, payload: Option<BlockPayload>) -> Block {
        Block::new(
            Context {
                round: round(height),
                leader,
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            sha256::Digest::EMPTY,
            Height::new(height),
            payload,
        )
    }

    const EARLY: Height = Height::new(3);
    const LATE: Height = Height::new(EPOCH_LENGTH.get() / 2 + 2);
    const FINAL: Height = Height::new(EPOCH_LENGTH.get() - 1);

    #[test]
    fn idle_plan_proposes_what_was_selected() {
        let (faulty, info) = application(Plan::idle());
        let selected = Some(Payload::EpochInfo(info));
        for height in [EARLY, LATE, FINAL] {
            assert!(faulty.payload(round(1), height, None).is_none());
            assert!(faulty.payload(round(1), height, selected.clone()) == selected);
        }
    }

    #[test]
    fn spare_log_is_signed_by_the_identity_and_fits_its_round() {
        let (info, shares) = genesis();
        let signer = signers(COMMITTEE.get()).remove(1);
        let log = spare_log(
            &mut FuzzRng::new(vec![9]),
            &info,
            &signer,
            Some(shares[1].clone()),
            Mode::NonZeroCounter,
        )
        .expect("a dealer of the first ceremony signs a log");
        let round = RoundInfo::<MockGroup, PublicKey>::new::<N3f1>(
            RESHARE_NAMESPACE,
            0,
            Some(info.output.clone()),
            Mode::NonZeroCounter,
            Reveal::V1,
            info.output.players().clone(),
            info.players.clone(),
        )
        .expect("the round is valid");
        let (dealer, _) = log.check(&round).expect("the log is signed for the round");
        assert_eq!(dealer, signer.public_key());

        // An identity that does not deal in the first ceremony signs none.
        let outsider = signers(COMMITTEE.get() + 1)
            .into_iter()
            .find(|signer| {
                info.output
                    .players()
                    .position(&signer.public_key())
                    .is_none()
            })
            .expect("one identity is outside the committee");
        assert!(
            spare_log(
                &mut FuzzRng::new(vec![9]),
                &info,
                &outsider,
                None,
                Mode::NonZeroCounter
            )
            .is_none()
        );
    }

    #[test]
    fn early_log_is_proposed_only_before_the_midpoint() {
        let (faulty, _) = application(Plan::always(Fault::EarlyLog));
        assert!(matches!(
            faulty.payload(round(1), EARLY, None),
            Some(Payload::DealerLog(_))
        ));
        assert!(faulty.payload(round(1), LATE, None).is_none());
        assert!(faulty.payload(round(1), FINAL, None).is_none());
    }

    #[test]
    fn foreign_log_is_one_another_identity_proposed() {
        let (faulty, _) = application(Plan::always(Fault::ForeignLog));
        let own = faulty.spare.clone().expect("the fixture signs a spare log");

        // Nothing to propose until another identity's block carried a log,
        // and the identity's own blocks do not count.
        assert!(faulty.payload(round(1), LATE, None).is_none());
        faulty.remember(&block(
            faulty.identity.clone(),
            LATE.get(),
            Some(Payload::DealerLog(own.clone())),
        ));
        assert!(faulty.payload(round(1), LATE, None).is_none());

        let other = signers(COMMITTEE.get()).remove(2).public_key();
        faulty.remember(&block(
            other,
            LATE.get(),
            Some(Payload::DealerLog(own.clone())),
        ));
        assert!(faulty.payload(round(1), LATE, None) == Some(Payload::DealerLog(own)));
        assert!(faulty.payload(round(1), EARLY, None).is_none());
    }

    #[test]
    fn misplaced_description_is_proposed_off_the_boundary() {
        let (faulty, info) = application(Plan::always(Fault::MisplacedInfo));
        for height in [EARLY, LATE] {
            assert!(
                faulty.payload(round(1), height, None) == Some(Payload::EpochInfo(info.clone()))
            );
        }
        assert!(faulty.payload(round(1), FINAL, None).is_none());
    }

    #[test]
    fn boundary_deviations_replace_the_selected_description() {
        let (info, _) = genesis();
        let mut next = info.clone();
        next.epoch = Epoch::new(1);
        let selected = Some(Payload::EpochInfo(next.clone()));

        let (faulty, _) = application(Plan::always(Fault::NoPayload));
        assert!(faulty.payload(round(1), FINAL, selected.clone()).is_none());
        assert!(faulty.payload(round(1), LATE, selected.clone()) == selected);

        // The first variant proposes the description of the ending epoch.
        let (faulty, _) = application(Plan::always(Fault::WrongInfo));
        assert!(
            faulty.payload(round(1), FINAL, selected.clone()) == Some(Payload::EpochInfo(info))
        );
        assert!(faulty.payload(round(1), FINAL, None).is_none());

        // Once the right description is the newest one seen, the variant
        // would reproduce it, and reports the other outcome instead.
        let other = signers(COMMITTEE.get()).remove(2).public_key();
        faulty.remember(&block(other, FINAL.get(), selected.clone()));
        let Some(Payload::EpochInfo(wrong)) = faulty.payload(round(1), FINAL, selected) else {
            panic!("a wrong description is still a description");
        };
        assert_eq!(wrong.outcome, EpochOutcome::Failure);
        assert_eq!(wrong.epoch, next.epoch);
        assert_eq!(faulty.deviations().load(Ordering::Relaxed), 2);
    }

    #[test]
    fn plan_is_a_function_of_the_tape() {
        let draw = |tape: Vec<u8>| {
            let plan = Plan::new(&mut FuzzRng::new(tape));
            (plan.armed.to_vec(), plan.density, *plan.samples)
        };
        assert_eq!(draw(vec![1, 2, 3]), draw(vec![1, 2, 3]));
        assert_ne!(draw(vec![1, 2, 3]).2, draw(vec![3, 2, 1]).2);

        // Across tapes every deviation is armed and each is sometimes not.
        let plans: Vec<_> = (0..=255u8).map(|byte| draw(vec![byte])).collect();
        for fault in Fault::ALL {
            assert!(plans.iter().any(|(armed, _, _)| armed.contains(&fault)));
            assert!(plans.iter().any(|(armed, _, _)| !armed.contains(&fault)));
        }
    }
}
