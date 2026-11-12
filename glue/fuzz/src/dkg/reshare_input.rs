//! The libFuzzer-facing input of the reshare Twins target.
//!
//! It is decoded the way the bootstrap input is (see [`super::input`]): the
//! input is expanded into a seeded stream, the structured controls are drawn
//! from the head of the stream, and the rest is the run's tape.

use super::{
    COMMITTEE, DkgMask, MAX_EPOCHS, RESHARE_IDENTITIES,
    input::{STREAM_BYTES, sharing_mode},
};
use crate::{input::stream, stateful::input::tape};
use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::sharing::Mode;
use std::fmt;

/// Identities other than the compromised one, each of which a mask assigns a
/// side.
pub(super) const PEERS: usize = RESHARE_IDENTITIES as usize - 1;

/// Rotations a run draws. The description of the last epoch a run completes
/// names the players of the epoch after it and of the one after that, so the
/// schedule reaches two epochs past the last ceremony.
pub(super) const ROTATIONS: usize = MAX_EPOCHS as usize + 2;

/// How the players of one epoch's ceremony follow from the set before them:
/// the first committee for epoch zero, and the players of the epoch before
/// for every other epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotation {
    /// The set stays the same.
    Stay,
    /// The identity outside the set replaces the member at this position of
    /// the set, in identity order.
    Replace(u8),
}

impl Arbitrary<'_> for Rotation {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        // The set changes in half of the draws.
        let members = COMMITTEE.get() as u8;
        let sample = u.int_in_range(0..=2 * members - 1)?;
        Ok(if sample < members {
            Self::Replace(sample)
        } else {
            Self::Stay
        })
    }
}

/// One run of the reshare Twins target.
#[derive(Clone)]
pub struct DkgReshareFuzzInput {
    /// Selects one case from the sampled twins scenario set.
    pub case_selector: u16,
    /// Repeat one partition pattern across the adversarial prefix of every
    /// epoch.
    pub sustained: bool,
    /// Epochs the run is asked to complete, from one to three.
    pub epochs: u8,
    /// Which half each other identity exchanges ceremony messages with, for
    /// each epoch's ceremony. Later epochs are not masked.
    pub masks: [DkgMask<PEERS>; MAX_EPOCHS as usize],
    /// How the ceremonies, and the trusted deal before them, assign
    /// evaluation points to participants.
    pub sharing_mode: Mode,
    /// The identity outside the first committee, as a position in identity
    /// order.
    pub outsider: u8,
    /// How the player set changes from one epoch's ceremony to the next.
    /// Later epochs keep the last set.
    pub rotations: [Rotation; ROTATIONS],
    /// Byte tape seeding the deterministic runtime, the scenario sampler, the
    /// trusted deal, and the faulty application.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for DkgReshareFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgReshareFuzzInput")
            .field("case_selector", &self.case_selector)
            .field("sustained", &self.sustained)
            .field("epochs", &self.epochs)
            .field("masks", &self.masks)
            .field("sharing_mode", &self.sharing_mode)
            .field("outsider", &self.outsider)
            .field("rotations", &self.rotations)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for DkgReshareFuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let stream = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);
        Ok(Self {
            case_selector: u.arbitrary()?,
            sustained: u.arbitrary()?,
            epochs: u.int_in_range(1..=MAX_EPOCHS)?,
            masks: u.arbitrary()?,
            sharing_mode: sharing_mode(u)?,
            outsider: u.int_in_range(0..=RESHARE_IDENTITIES as u8 - 1)?,
            rotations: u.arbitrary()?,
            raw_bytes: tape(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> DkgReshareFuzzInput {
        DkgReshareFuzzInput::arbitrary(&mut Unstructured::new(bytes)).unwrap()
    }

    #[test]
    fn empty_input_samples_a_whole_session() {
        let input = decode(&[]);
        assert!(input.raw_bytes.len() > STREAM_BYTES / 2);
        assert!((1..=MAX_EPOCHS).contains(&input.epochs));
    }

    #[test]
    fn short_inputs_cover_every_control() {
        let sessions: Vec<_> = (0..=255u8).map(|byte| decode(&[byte])).collect();
        let any = |holds: &dyn Fn(&DkgReshareFuzzInput) -> bool| sessions.iter().any(holds);
        assert!(any(&|session| session.sustained));
        assert!(any(&|session| !session.sustained));
        for epochs in 1..=MAX_EPOCHS {
            assert!(any(&|session| session.epochs == epochs));
        }
        for outsider in 0..RESHARE_IDENTITIES as u8 {
            assert!(any(&|session| session.outsider == outsider));
        }
        assert!(any(&|session| session.sharing_mode == Mode::RootsOfUnity));
        assert!(any(&|session| session.sharing_mode == Mode::NonZeroCounter));
        assert!(any(&|session| session.masks[0] == DkgMask::WHOLE));
        assert!(any(&|session| session.masks[0] != DkgMask::WHOLE));
        assert!(any(&|session| session.masks[0] != session.masks[1]));
        assert!(any(&|session| session.rotations[0] == Rotation::Stay));
        for member in 0..COMMITTEE.get() as u8 {
            assert!(any(
                &|session| session.rotations[0] == Rotation::Replace(member)
            ));
        }
        assert!(any(&|session| {
            session
                .rotations
                .iter()
                .all(|rotation| *rotation == Rotation::Stay)
        }));
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let (first, second) = (decode(&bytes), decode(&bytes));
        assert_eq!(first.case_selector, second.case_selector);
        assert_eq!(first.masks, second.masks);
        assert_eq!(first.rotations, second.rotations);
        assert_eq!(first.raw_bytes, second.raw_bytes);
    }

    #[test]
    fn debug_elides_the_tape() {
        let rendered = format!("{:?}", decode(&[7; 40]));
        assert!(rendered.contains("raw_bytes_len"));
        assert!(!rendered.contains("raw_bytes:"));
    }
}
