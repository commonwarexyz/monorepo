//! The libFuzzer-facing input of the reshare restart target.
//!
//! It is decoded the way the other DKG inputs are (see [`super::input`]): the
//! input is expanded into a seeded stream, the structured controls are drawn
//! from the head of the stream, and the rest is the run's tape.
//!
//! The controls come in two groups. [`SessionControls`] describe the reshare
//! session and nothing of an adversary or of the environment, so any driver
//! that runs correct reshare engines can draw them. [`EnvironmentControls`]
//! describe the crash schedule and the links, as in the bootstrap restart
//! target.

use super::{
    EnvironmentControls, MAX_EPOCHS, RESHARE_IDENTITIES, Rotation,
    input::{STREAM_BYTES, sharing_mode},
    reshare_input::ROTATIONS,
};
use crate::{input::stream, stateful::input::tape};
use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::sharing::Mode;
use std::fmt;

/// The reshare session of a run: how many epochs it is asked to complete and
/// the committee of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionControls {
    /// Epochs the run is asked to complete, from one to three.
    pub epochs: u8,
    /// How the ceremonies, and the trusted deal before them, assign
    /// evaluation points to participants.
    pub sharing_mode: Mode,
    /// The identity outside the first committee, as a position in identity
    /// order.
    pub outsider: u8,
    /// How the player set changes from one epoch's ceremony to the next.
    /// Later epochs keep the last set.
    pub rotations: [Rotation; ROTATIONS],
}

impl Arbitrary<'_> for SessionControls {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            epochs: u.int_in_range(1..=MAX_EPOCHS)?,
            sharing_mode: sharing_mode(u)?,
            outsider: u.int_in_range(0..=RESHARE_IDENTITIES as u8 - 1)?,
            rotations: u.arbitrary()?,
        })
    }
}

/// One run of the reshare restart target.
///
/// Every identity is correct here; the only faults are environmental.
#[derive(Clone)]
pub struct DkgReshareRestartsFuzzInput {
    /// The epochs to complete and their committees.
    pub session: SessionControls,
    /// The crash schedule's size and the link conditions.
    pub environment: EnvironmentControls,
    /// Byte tape seeding the deterministic runtime, the trusted deal, and
    /// the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for DkgReshareRestartsFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgReshareRestartsFuzzInput")
            .field("session", &self.session)
            .field("environment", &self.environment)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for DkgReshareRestartsFuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let stream = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);
        Ok(Self {
            session: u.arbitrary()?,
            environment: EnvironmentControls::sample(u, RESHARE_IDENTITIES as u8)?,
            raw_bytes: tape(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        COMMITTEE, Cut, CutScope,
        input::{
            MAX_CUT_DELAY_STEPS, MAX_CUT_STEPS, MAX_CUTS, MAX_LATENCY_MS, MAX_RESTARTS,
            MAX_SHORT_CUT_STEPS, MIN_DELIVERY_PERCENT,
        },
    };

    fn decode(bytes: &[u8]) -> DkgReshareRestartsFuzzInput {
        DkgReshareRestartsFuzzInput::arbitrary(&mut Unstructured::new(bytes)).unwrap()
    }

    /// Every one-byte input and every seventh two-byte input, decoded.
    fn sessions() -> Vec<DkgReshareRestartsFuzzInput> {
        let one = (0..=u8::MAX).map(|byte| decode(&[byte]));
        let two = (0..=u16::MAX)
            .step_by(7)
            .map(|seed| decode(&seed.to_le_bytes()));
        one.chain(two).collect()
    }

    #[test]
    fn empty_input_samples_a_whole_session() {
        let input = decode(&[]);
        assert!(input.raw_bytes.len() > STREAM_BYTES / 2);
        assert!((1..=MAX_EPOCHS).contains(&input.session.epochs));
        assert!(input.environment.restarts >= 1);
    }

    #[test]
    fn short_inputs_vary_every_session_control() {
        let sessions = sessions();
        let any = |holds: &dyn Fn(&SessionControls) -> bool| {
            sessions.iter().any(|input| holds(&input.session))
        };
        for epochs in 1..=MAX_EPOCHS {
            assert!(any(&|session| session.epochs == epochs));
        }
        assert!(any(&|session| session.sharing_mode == Mode::RootsOfUnity));
        assert!(any(&|session| session.sharing_mode == Mode::NonZeroCounter));
        for outsider in 0..RESHARE_IDENTITIES as u8 {
            assert!(any(&|session| session.outsider == outsider));
        }
        for ceremony in 0..ROTATIONS {
            assert!(any(&|session| session.rotations[ceremony] == Rotation::Stay));
            for member in 0..COMMITTEE.get() as u8 {
                assert!(any(
                    &|session| session.rotations[ceremony] == Rotation::Replace(member)
                ));
            }
        }
        assert!(any(&|session| {
            session
                .rotations
                .iter()
                .all(|rotation| *rotation == Rotation::Stay)
        }));
    }

    #[test]
    fn short_inputs_vary_every_environment_control() {
        let sessions = sessions();
        let any = |holds: &dyn Fn(&EnvironmentControls) -> bool| {
            sessions.iter().any(|input| holds(&input.environment))
        };
        for restarts in 1..=MAX_RESTARTS {
            assert!(any(&|environment| environment.restarts == restarts));
        }
        for cuts in 0..=usize::from(MAX_CUTS) {
            assert!(any(&|environment| environment.cuts.len() == cuts));
        }
        assert!(any(&|environment| environment.links.delivery_percent == 100));
        assert!(any(&|environment| environment.links.delivery_percent < 80));
        assert!(any(&|environment| environment.links.latency_ms < 10));
        assert!(any(&|environment| environment.links.latency_ms > 90));
        assert!(any(&|environment| environment.links.jitter_ms == 0));
        assert!(any(&|environment| environment.links.jitter_ms > 50));
        let cut = |holds: &dyn Fn(&Cut) -> bool| {
            sessions
                .iter()
                .any(|input| input.environment.cuts.iter().any(holds))
        };
        assert!(cut(&|cut| cut.scope == CutScope::Inbound));
        assert!(cut(&|cut| cut.scope == CutScope::Outbound));
        assert!(cut(&|cut| cut.scope == CutScope::Both));
        assert!(cut(&|cut| matches!(cut.scope, CutScope::To(_))));
        assert!(cut(&|cut| cut.delay == 0));
        assert!(cut(&|cut| cut.delay == MAX_CUT_DELAY_STEPS));
        assert!(cut(&|cut| cut.duration == 1));
        assert!(cut(&|cut| cut.duration > MAX_SHORT_CUT_STEPS));

        // A cut may name any of the five identities, the outside one too.
        for identity in 0..RESHARE_IDENTITIES as u8 {
            assert!(cut(&|cut| cut.identity == identity));
            assert!(cut(&|cut| cut.scope == CutScope::To(identity)));
        }
    }

    /// The two groups of controls are drawn independently: every number of
    /// epochs meets every size of schedule.
    #[test]
    fn short_inputs_combine_the_controls() {
        let sessions = sessions();
        for epochs in 1..=MAX_EPOCHS {
            for restarts in 1..=MAX_RESTARTS {
                assert!(sessions.iter().any(|input| {
                    input.session.epochs == epochs && input.environment.restarts == restarts
                }));
            }
        }
    }

    #[test]
    fn controls_stay_within_their_bounds() {
        for input in sessions() {
            assert!((1..=MAX_EPOCHS).contains(&input.session.epochs));
            assert!(u32::from(input.session.outsider) < RESHARE_IDENTITIES);
            for rotation in input.session.rotations {
                if let Rotation::Replace(member) = rotation {
                    assert!(u32::from(member) < COMMITTEE.get());
                }
            }
            let EnvironmentControls {
                restarts,
                links,
                cuts,
            } = input.environment;
            assert!((1..=MAX_RESTARTS).contains(&restarts));
            assert!((1..=MAX_LATENCY_MS).contains(&links.latency_ms));
            assert!(links.jitter_ms <= links.latency_ms);
            assert!((MIN_DELIVERY_PERCENT..=100).contains(&links.delivery_percent));
            assert!(cuts.len() <= usize::from(MAX_CUTS));
            for cut in cuts {
                assert!(cut.delay <= MAX_CUT_DELAY_STEPS);
                assert!((1..=MAX_CUT_STEPS).contains(&cut.duration));
                assert!(u32::from(cut.identity) < RESHARE_IDENTITIES);
                if let CutScope::To(peer) = cut.scope {
                    assert!(u32::from(peer) < RESHARE_IDENTITIES);
                    assert_ne!(peer, cut.identity);
                }
            }
        }
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let (first, second) = (decode(&bytes), decode(&bytes));
        assert_eq!(first.session, second.session);
        assert_eq!(first.environment, second.environment);
        assert_eq!(first.raw_bytes, second.raw_bytes);
    }

    /// The bytes past the head of an input are the controls themselves, so a
    /// byte mutated there changes only what is drawn from it.
    #[test]
    fn bytes_past_the_head_are_the_controls() {
        let mut bytes = vec![0u8; 24];
        let base = decode(&bytes);
        assert_eq!(base.session.epochs, 1);

        // The first byte past the head is the first control drawn.
        bytes[crate::input::SEED_BYTES] = 2;
        let changed = decode(&bytes);
        assert_eq!(changed.session.epochs, 3);
        assert_eq!(
            SessionControls {
                epochs: 1,
                ..changed.session
            },
            base.session
        );
        assert_eq!(changed.environment, base.environment);
        assert_eq!(changed.raw_bytes, base.raw_bytes);
    }

    #[test]
    fn debug_elides_the_tape() {
        let rendered = format!("{:?}", decode(&[7; 40]));
        assert!(rendered.contains("raw_bytes_len"));
        assert!(!rendered.contains("raw_bytes:"));
        assert!(rendered.contains("epochs:"));
        assert!(rendered.contains("rotations:"));
        assert!(rendered.contains("restarts:"));
        assert!(rendered.contains("delivery_percent:"));
    }
}
