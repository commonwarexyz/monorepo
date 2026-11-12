//! The libFuzzer-facing input of the state-sync target.
//!
//! It is decoded the way the other DKG inputs are (see [`super::input`]): the
//! input is expanded into a seeded stream, the structured controls are drawn
//! from the head of the stream, and the rest is the run's tape.
//!
//! The session controls are the ones every driver over correct reshare
//! engines draws. The others describe the late joiner: which identity it is,
//! the height the other four apply before it starts, its own restart, how
//! many restarts the schedule over all five holds, and when the first of
//! them is due. The links of this target are fixed, so the input has no link
//! controls and no cuts.
//!
//! The join height is drawn by its place in an epoch, so that the heights
//! around which the joiner's entry changes are as likely as the stretches
//! between them: the midpoint, up to which a floor lets the joiner play the
//! epoch's ceremony, and the final block, past which the floor is in the
//! next epoch. The first outage of the schedule is drawn in steps of ten
//! milliseconds from none, so that it can crash a node the joiner's probe is
//! asking.

use super::{
    EPOCH_LENGTH, RESHARE_IDENTITIES,
    environment::{DOWNTIME_STEP, MAX_DOWNTIME_STEPS},
    input::STREAM_BYTES,
    reshare_restarts_input::SessionControls,
};
use crate::{input::stream, stateful::input::tape};
use arbitrary::{Arbitrary, Unstructured};
use std::{fmt, time::Duration};

/// Largest restart schedule over all nodes a run may draw.
pub(super) const MAX_RESTARTS: u8 = 3;

/// The unit of the delay before the joiner's own restart.
const RESTART_STEP: Duration = Duration::from_millis(10);

/// Most steps the delay before the joiner's own restart holds before it is
/// doubled. A sync takes around a hundred simulated milliseconds, so the
/// undoubled delays land inside it.
pub(super) const MAX_RESTART_STEPS: u8 = 15;

/// Most times the delay before the joiner's own restart is doubled, so that
/// the restart can also land in any later part of the joiner's first epochs.
pub(super) const MAX_RESTART_DOUBLINGS: u8 = 6;

/// A delay of `steps` steps of [`RESTART_STEP`], doubled `doublings` times
/// and no more than [`MAX_RESTART_DOUBLINGS`] times. The joiner's own restart
/// and the first outage of the schedule are both delayed like this.
fn delay(steps: u8, doublings: u8) -> Duration {
    RESTART_STEP * u32::from(steps) * (1 << doublings.min(MAX_RESTART_DOUBLINGS))
}

/// Where in its epoch a join height lies. Each is as likely as the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Place {
    /// Before the midpoint: a floor here lets the joiner play the ceremony.
    Early,
    /// At the midpoint, the last height whose floor lets the joiner play.
    Midpoint,
    /// Past the midpoint and before the final block: the joiner follows.
    Late,
    /// At the final block of the epoch, which carries the next description.
    Boundary,
}

impl Place {
    /// Every place, in the order of the heights of an epoch.
    pub(super) const ALL: [Self; 4] = [Self::Early, Self::Midpoint, Self::Late, Self::Boundary];

    /// The place of the height at `position` in its epoch.
    pub(super) const fn of(position: u8) -> Self {
        let length = EPOCH_LENGTH.get() as u8;
        let midpoint = length / 2;
        if position < midpoint {
            Self::Early
        } else if position == midpoint {
            Self::Midpoint
        } else if position < length - 1 {
            Self::Late
        } else {
            Self::Boundary
        }
    }

    /// The position in its epoch of a height at this place, chosen by
    /// `sample` among the heights of the place.
    const fn position(self, sample: u8) -> u8 {
        let length = EPOCH_LENGTH.get() as u8;
        let midpoint = length / 2;
        match self {
            Self::Early => sample % midpoint,
            Self::Midpoint => midpoint,
            Self::Late => midpoint + 1 + sample % (length - midpoint - 2),
            Self::Boundary => length - 1,
        }
    }
}

/// When the first outage of the schedule over all nodes is due, from the
/// start of the schedule's clock, which starts when the joiner does.
///
/// The schedule's own sampler draws no delay under fifty milliseconds, and
/// the joiner's probe has its first replies after about twenty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirstOutage {
    /// Steps of ten simulated milliseconds, before doubling.
    pub steps: u8,
    /// Times the delay is doubled.
    pub doublings: u8,
}

impl FirstOutage {
    /// How long after the schedule's clock starts its first outage is due.
    pub fn delay(&self) -> Duration {
        delay(self.steps, self.doublings)
    }
}

impl Arbitrary<'_> for FirstOutage {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        // Half the delays are not doubled, and so fall in the first 150
        // milliseconds after the clock starts. Both controls are drawn
        // whichever applies, so that the bytes after them do not move.
        let steps = u.int_in_range(0..=MAX_RESTART_STEPS)?;
        let near: bool = u.arbitrary()?;
        let doublings = u.int_in_range(1..=MAX_RESTART_DOUBLINGS)?;
        Ok(Self {
            steps,
            doublings: if near { 0 } else { doublings },
        })
    }
}

/// The joiner's own restart: a crash a chosen delay after the joiner starts,
/// and how long it stays down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinerRestart {
    /// Steps of ten simulated milliseconds between the joiner's start and its
    /// crash, before doubling.
    pub steps: u8,
    /// Times the delay is doubled.
    pub doublings: u8,
    /// Steps of a hundred simulated milliseconds the joiner stays down.
    pub downtime: u8,
}

impl JoinerRestart {
    /// How long after the joiner starts it is crashed.
    pub fn delay(&self) -> Duration {
        delay(self.steps, self.doublings)
    }

    /// How long the joiner stays down.
    pub fn down(&self) -> Duration {
        DOWNTIME_STEP * u32::from(self.downtime.max(1))
    }
}

impl Arbitrary<'_> for JoinerRestart {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            steps: u.int_in_range(0..=MAX_RESTART_STEPS)?,
            doublings: u.int_in_range(0..=MAX_RESTART_DOUBLINGS)?,
            downtime: u.int_in_range(1..=MAX_DOWNTIME_STEPS)?,
        })
    }
}

/// One run of the state-sync target.
///
/// Every identity is correct here. Four of them start at genesis and the
/// fifth joins late through the probe and DKG state sync.
#[derive(Clone)]
pub struct DkgStateSyncFuzzInput {
    /// The epochs to complete and their committees.
    pub session: SessionControls,
    /// The identity that joins late, as a position in identity order.
    pub joiner: u8,
    /// The height the identities that start at genesis apply before the
    /// joiner starts. It lies in one of the epochs the run is asked to
    /// complete.
    pub join_height: u8,
    /// The joiner's own restart, or none.
    pub joiner_restart: Option<JoinerRestart>,
    /// Number of scheduled crash/restart events over every node, the joiner
    /// included.
    pub restarts: u8,
    /// When the first of those events is due after the joiner starts.
    pub first_outage: FirstOutage,
    /// Byte tape seeding the deterministic runtime, the trusted deal, and
    /// the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for DkgStateSyncFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgStateSyncFuzzInput")
            .field("session", &self.session)
            .field("joiner", &self.joiner)
            .field("join_height", &self.join_height)
            .field("joiner_restart", &self.joiner_restart)
            .field("restarts", &self.restarts)
            .field("first_outage", &self.first_outage)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for DkgStateSyncFuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let stream = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);
        let session: SessionControls = u.arbitrary()?;
        let joiner = u.int_in_range(0..=RESHARE_IDENTITIES as u8 - 1)?;

        // Any height of any epoch the run is asked to complete: the epoch
        // first, so that each is as likely as the others whatever their
        // number, then the place in it, then the height at that place. Each
        // is drawn from a whole byte, so that neither the number of epochs
        // nor the place moves the bytes the later controls are drawn from.
        let length = EPOCH_LENGTH.get() as u8;
        let epoch = u.arbitrary::<u8>()? % session.epochs;
        let place = Place::ALL[usize::from(u.arbitrary::<u8>()?) % Place::ALL.len()];
        let join_height = epoch * length + place.position(u.arbitrary()?);

        // Half the runs restart the joiner on its own clock. The restart is
        // drawn whether or not the run has one, so that the bytes after it
        // do not move.
        let restarted: bool = u.arbitrary()?;
        let restart: JoinerRestart = u.arbitrary()?;
        Ok(Self {
            session,
            joiner,
            join_height,
            joiner_restart: restarted.then_some(restart),
            restarts: u.int_in_range(0..=MAX_RESTARTS)?,
            first_outage: u.arbitrary()?,
            raw_bytes: tape(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::MAX_EPOCHS;
    use commonware_consensus::types::{Epoch, EpochPhase, Epocher as _, FixedEpocher, Height};
    use commonware_cryptography::bls12381::primitives::sharing::Mode;

    fn decode(bytes: &[u8]) -> DkgStateSyncFuzzInput {
        DkgStateSyncFuzzInput::arbitrary(&mut Unstructured::new(bytes)).unwrap()
    }

    /// Every one-byte input and every seventh two-byte input, decoded.
    fn sessions() -> Vec<DkgStateSyncFuzzInput> {
        let one = (0..=u8::MAX).map(|byte| decode(&[byte]));
        let two = (0..=u16::MAX)
            .step_by(7)
            .map(|seed| decode(&seed.to_le_bytes()));
        one.chain(two).collect()
    }

    /// The epoch `height` lies in and the phase of that epoch.
    fn position(height: u8) -> (Epoch, EpochPhase) {
        let bounds = FixedEpocher::new(EPOCH_LENGTH)
            .containing(Height::new(u64::from(height)))
            .expect("every height belongs to an epoch");
        (bounds.epoch(), bounds.phase())
    }

    #[test]
    fn empty_input_samples_a_whole_session() {
        let input = decode(&[]);
        assert!(input.raw_bytes.len() > STREAM_BYTES / 2);
        assert!((1..=MAX_EPOCHS).contains(&input.session.epochs));
        assert!(u32::from(input.joiner) < RESHARE_IDENTITIES);
    }

    #[test]
    fn short_inputs_vary_every_control() {
        let sessions = sessions();
        let any = |holds: &dyn Fn(&DkgStateSyncFuzzInput) -> bool| sessions.iter().any(holds);

        // The session.
        for epochs in 1..=MAX_EPOCHS {
            assert!(any(&|input| input.session.epochs == epochs));
        }
        assert!(any(
            &|input| input.session.sharing_mode == Mode::RootsOfUnity
        ));
        assert!(any(
            &|input| input.session.sharing_mode == Mode::NonZeroCounter
        ));

        // The joiner is any identity, in the first committee or outside it.
        for identity in 0..RESHARE_IDENTITIES as u8 {
            assert!(any(&|input| input.joiner == identity));
            assert!(any(&|input| input.session.outsider == identity));
        }
        assert!(any(&|input| input.joiner == input.session.outsider));
        assert!(any(&|input| input.joiner != input.session.outsider));

        // The join height falls in every phase of every epoch of a run, at
        // the first and at the last height of each, whatever the number of
        // epochs the run is asked for.
        for epochs in 1..=MAX_EPOCHS {
            for epoch in 0..u64::from(epochs) {
                for phase in [EpochPhase::Early, EpochPhase::Midpoint, EpochPhase::Late] {
                    assert!(
                        any(&|input| input.session.epochs == epochs
                            && position(input.join_height) == (Epoch::new(epoch), phase)),
                        "no run of {epochs} epochs joins in the {phase:?} phase of epoch {epoch}",
                    );
                }
                let first = epoch as u8 * EPOCH_LENGTH.get() as u8;
                let last = first + EPOCH_LENGTH.get() as u8 - 1;
                assert!(any(&|input| input.join_height == first));
                assert!(any(&|input| input.join_height == last));
            }
        }

        // The joiner's own restart: none, inside its sync, and long after.
        assert!(any(&|input| input.joiner_restart.is_none()));
        let restart = |holds: &dyn Fn(&JoinerRestart) -> bool| {
            sessions
                .iter()
                .any(|input| input.joiner_restart.as_ref().is_some_and(holds))
        };
        assert!(restart(&|restart| restart.delay() == Duration::ZERO));
        for step in 1..=u32::from(MAX_RESTART_STEPS) {
            assert!(restart(&|restart| restart.delay() == RESTART_STEP * step));
        }
        assert!(restart(&|restart| restart.delay() > Duration::from_secs(5)));
        for doublings in 0..=MAX_RESTART_DOUBLINGS {
            assert!(restart(&|restart| restart.doublings == doublings));
        }
        assert!(restart(&|restart| restart.down() == DOWNTIME_STEP));
        assert!(restart(
            &|restart| restart.down() == DOWNTIME_STEP * u32::from(MAX_DOWNTIME_STEPS)
        ));

        // The schedule over all nodes: none to three restarts.
        for restarts in 0..=MAX_RESTARTS {
            assert!(any(&|input| input.restarts == restarts));
        }

        // Its first outage: with the joiner's start, every ten milliseconds
        // of the 150 after it, and seconds later.
        for step in 0..=u32::from(MAX_RESTART_STEPS) {
            assert!(any(
                &|input| input.first_outage.delay() == RESTART_STEP * step
            ));
        }
        for doublings in 0..=MAX_RESTART_DOUBLINGS {
            assert!(any(&|input| input.first_outage.doublings == doublings));
        }
        assert!(any(
            &|input| input.first_outage.delay() > Duration::from_secs(5)
        ));
    }

    /// The places of an epoch: the midpoint and the final block are single
    /// heights, and every height has one place.
    #[test]
    fn every_height_of_an_epoch_has_a_place() {
        let length = EPOCH_LENGTH.get() as u8;
        let mut heights = [0usize; 4];
        for at in 0..length {
            let place = Place::of(at);
            let phase = position(at).1;
            let last = at == length - 1;
            match place {
                Place::Early => assert_eq!(phase, EpochPhase::Early),
                Place::Midpoint => assert_eq!(phase, EpochPhase::Midpoint),
                Place::Late => assert!(phase == EpochPhase::Late && !last),
                Place::Boundary => assert!(phase == EpochPhase::Late && last),
            }
            let index = Place::ALL
                .iter()
                .position(|other| *other == place)
                .expect("every place is listed");
            heights[index] += 1;
        }
        assert_eq!(heights, [16, 1, 14, 1]);

        // A place draws each of its heights, and no other.
        for place in Place::ALL {
            let drawn: std::collections::BTreeSet<u8> =
                (0..=u8::MAX).map(|sample| place.position(sample)).collect();
            let own: std::collections::BTreeSet<u8> =
                (0..length).filter(|at| Place::of(*at) == place).collect();
            assert_eq!(drawn, own, "{place:?}");
        }
    }

    /// Each place of a join height holds about a quarter of the sessions,
    /// and each third of the sessions of three epochs joins in one of them.
    #[test]
    fn join_heights_fall_evenly_on_the_places_of_an_epoch() {
        let sessions = sessions();
        let share = |holds: &dyn Fn(&DkgStateSyncFuzzInput) -> bool| {
            sessions.iter().filter(|input| holds(input)).count() * 100 / sessions.len()
        };
        let length = EPOCH_LENGTH.get() as u8;
        for place in Place::ALL {
            let share = share(&|input| Place::of(input.join_height % length) == place);
            assert!((20..=30).contains(&share), "{place:?}: {share}%");
        }

        // The first outage of the schedule is due within the joiner's
        // discovery in a large share of the sessions.
        let near = share(&|input| input.first_outage.delay() <= Duration::from_millis(20));
        assert!((10..=30).contains(&near), "{near}%");
    }

    /// The controls are drawn independently: every joiner meets every phase
    /// of a join, with and without its own restart, under every size of
    /// schedule.
    #[test]
    fn short_inputs_combine_the_controls() {
        let sessions = sessions();
        for joiner in 0..RESHARE_IDENTITIES as u8 {
            for phase in [EpochPhase::Early, EpochPhase::Midpoint, EpochPhase::Late] {
                assert!(sessions.iter().any(|input| {
                    input.joiner == joiner && position(input.join_height).1 == phase
                }));
            }
            for restarts in 0..=MAX_RESTARTS {
                for restarted in [false, true] {
                    assert!(sessions.iter().any(|input| {
                        input.joiner == joiner
                            && input.restarts == restarts
                            && input.joiner_restart.is_some() == restarted
                    }));
                }
            }
        }
    }

    #[test]
    fn controls_stay_within_their_bounds() {
        for input in sessions() {
            assert!((1..=MAX_EPOCHS).contains(&input.session.epochs));
            assert!(u32::from(input.joiner) < RESHARE_IDENTITIES);
            assert!(
                u64::from(input.join_height) < u64::from(input.session.epochs) * EPOCH_LENGTH.get()
            );
            assert!(input.restarts <= MAX_RESTARTS);
            if let Some(restart) = input.joiner_restart {
                assert!(restart.steps <= MAX_RESTART_STEPS);
                assert!(restart.doublings <= MAX_RESTART_DOUBLINGS);
                assert!((1..=MAX_DOWNTIME_STEPS).contains(&restart.downtime));
                assert!(restart.delay() <= RESTART_STEP * 15 * 64);
            }
            assert!(input.first_outage.steps <= MAX_RESTART_STEPS);
            assert!(input.first_outage.doublings <= MAX_RESTART_DOUBLINGS);
        }
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let (first, second) = (decode(&bytes), decode(&bytes));
        assert_eq!(first.session, second.session);
        assert_eq!(first.joiner, second.joiner);
        assert_eq!(first.join_height, second.join_height);
        assert_eq!(first.joiner_restart, second.joiner_restart);
        assert_eq!(first.restarts, second.restarts);
        assert_eq!(first.first_outage, second.first_outage);
        assert_eq!(first.raw_bytes, second.raw_bytes);
    }

    /// The bytes past the head of an input are the controls themselves, so a
    /// byte mutated there changes only what is drawn from it.
    #[test]
    fn bytes_past_the_head_are_the_controls() {
        let mut bytes = vec![0u8; 32];
        let base = decode(&bytes);
        assert_eq!(base.session.epochs, 1);
        assert_eq!(base.joiner, 0);
        assert_eq!(base.join_height, 0);
        assert_eq!(base.joiner_restart, None);
        assert_eq!(base.restarts, 0);
        assert_eq!(base.first_outage.delay(), Duration::ZERO);

        // The first byte past the head is the first control drawn.
        bytes[crate::input::SEED_BYTES] = 2;
        let changed = decode(&bytes);
        assert_eq!(changed.session.epochs, 3);
        assert_eq!(changed.joiner, base.joiner);
        assert_eq!(changed.restarts, base.restarts);
        assert_eq!(changed.raw_bytes, base.raw_bytes);
    }

    /// The joiner's restart is drawn whether or not the run has one, so the
    /// byte that decides whether it has one changes no other control and
    /// leaves the tape where it was.
    #[test]
    fn toggling_the_joiner_restart_changes_no_other_field() {
        // The byte the flag is drawn from is the one byte past the head
        // whose lowest bit gives an input of zeros a restart.
        let zeros = vec![0u8; 48];
        let flags: Vec<usize> = (crate::input::SEED_BYTES..zeros.len())
            .filter(|at| {
                let mut bytes = zeros.clone();
                bytes[*at] = 1;
                decode(&bytes).joiner_restart.is_some()
            })
            .collect();
        let [flag] = flags[..] else {
            panic!("one byte decides the joiner's restart: {flags:?}");
        };

        let mut restarts = std::collections::BTreeSet::new();
        for seed in 0..=u8::MAX {
            let mut bytes: Vec<u8> = (0..zeros.len() as u8)
                .map(|at| at.wrapping_mul(37).wrapping_add(seed))
                .collect();
            bytes[flag] &= !1;
            let without = decode(&bytes);
            bytes[flag] |= 1;
            let with = decode(&bytes);
            assert_eq!(without.joiner_restart, None);
            let restart = with.joiner_restart.expect("the flag is set");
            restarts.insert((restart.steps, restart.doublings, restart.downtime));
            assert_eq!(with.session, without.session);
            assert_eq!(with.joiner, without.joiner);
            assert_eq!(with.join_height, without.join_height);
            assert_eq!(with.restarts, without.restarts);
            assert_eq!(with.first_outage, without.first_outage);
            assert_eq!(with.raw_bytes, without.raw_bytes);
        }

        // The bytes after the flag are the restart's own.
        assert!(restarts.len() > 100, "{}", restarts.len());
    }

    #[test]
    fn joiner_restart_names_its_delay_and_downtime() {
        let restart = |steps, doublings, downtime| JoinerRestart {
            steps,
            doublings,
            downtime,
        };
        assert_eq!(restart(0, 6, 1).delay(), Duration::ZERO);
        assert_eq!(restart(7, 0, 1).delay(), Duration::from_millis(70));
        assert_eq!(restart(15, 6, 1).delay(), Duration::from_millis(9_600));
        assert_eq!(restart(1, 1, 3).down(), Duration::from_millis(300));

        // Values past the bounds of a decoded input stay bounded.
        assert_eq!(restart(1, 200, 0).delay(), Duration::from_millis(640));
        assert_eq!(restart(1, 0, 0).down(), DOWNTIME_STEP);

        // The first outage of the schedule has the same unit and doubling.
        let first = |steps, doublings| FirstOutage { steps, doublings };
        assert_eq!(first(0, 3).delay(), Duration::ZERO);
        assert_eq!(first(2, 0).delay(), Duration::from_millis(20));
        assert_eq!(first(15, 6).delay(), Duration::from_millis(9_600));
        assert_eq!(first(1, 200).delay(), Duration::from_millis(640));
    }

    #[test]
    fn debug_elides_the_tape() {
        let rendered = format!("{:?}", decode(&[7; 40]));
        assert!(rendered.contains("raw_bytes_len"));
        assert!(!rendered.contains("raw_bytes:"));
        assert!(rendered.contains("epochs:"));
        assert!(rendered.contains("joiner:"));
        assert!(rendered.contains("join_height:"));
        assert!(rendered.contains("joiner_restart:"));
        assert!(rendered.contains("restarts:"));
        assert!(rendered.contains("first_outage:"));
    }
}
