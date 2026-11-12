//! The libFuzzer-facing inputs and their `Arbitrary` implementations.
//!
//! An input is first expanded into a seeded stream (see [`crate::input::stream`]),
//! so that a short input still samples a whole session. The structured
//! controls are drawn from the head of that stream and the rest becomes the
//! run's tape, which seeds the deterministic runtime and every sampler in the
//! harness. The tape is never printed in `Debug` output.

use super::COMMITTEE;
use crate::{input::stream, stateful::input::tape};
use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::sharing::Mode;
use commonware_p2p::simulated::Link;
use commonware_utils::Probability;
use std::{fmt, time::Duration};

/// Bytes of the stream a session is sampled from: the controls take a few and
/// the rest is the tape.
pub(super) const STREAM_BYTES: usize = 1 << 10;

/// Which half of the compromised identity another identity exchanges ceremony
/// messages with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The primary half only.
    Primary,
    /// The secondary half only.
    Secondary,
    /// Both halves.
    Both,
}

impl Arbitrary<'_> for Side {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=2)? {
            0 => Self::Primary,
            1 => Self::Secondary,
            _ => Self::Both,
        })
    }
}

/// The DKG mask of one ceremony: the side of each of the `PEERS` identities
/// other than the compromised one, in identity order. A bootstrap runs among
/// the committee, so its mask covers one identity fewer than the committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DkgMask<const PEERS: usize = { COMMITTEE.get() as usize - 1 }>(pub [Side; PEERS]);

impl<const PEERS: usize> DkgMask<PEERS> {
    /// The mask under which both halves exchange ceremony messages with
    /// every identity.
    pub const WHOLE: Self = Self([Side::Both; PEERS]);
}

impl<const PEERS: usize> Arbitrary<'_> for DkgMask<PEERS> {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

/// Draw the sharing mode a run's ceremonies use.
pub(super) fn sharing_mode(u: &mut Unstructured<'_>) -> arbitrary::Result<Mode> {
    Ok(if u.arbitrary()? {
        Mode::RootsOfUnity
    } else {
        Mode::NonZeroCounter
    })
}

/// One run of the bootstrap Twins target.
#[derive(Clone)]
pub struct DkgBootstrapFuzzInput {
    /// Selects one case from the sampled twins scenario set.
    pub case_selector: u16,
    /// Repeat one partition pattern across the adversarial prefix.
    pub sustained: bool,
    /// Which half each other identity exchanges ceremony messages with.
    pub mask: DkgMask,
    /// How the ceremony assigns evaluation points to participants.
    pub sharing_mode: Mode,
    /// Byte tape seeding the deterministic runtime and the scenario sampler.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for DkgBootstrapFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgBootstrapFuzzInput")
            .field("case_selector", &self.case_selector)
            .field("sustained", &self.sustained)
            .field("mask", &self.mask)
            .field("sharing_mode", &self.sharing_mode)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for DkgBootstrapFuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let stream = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);
        Ok(Self {
            case_selector: u.arbitrary()?,
            sustained: u.arbitrary()?,
            mask: u.arbitrary()?,
            sharing_mode: sharing_mode(u)?,
            raw_bytes: tape(u)?,
        })
    }
}

/// Largest restart schedule a restart run may draw.
pub(super) const MAX_RESTARTS: u8 = 4;

/// Most temporary cuts a restart run may draw.
pub(super) const MAX_CUTS: u8 = 3;

/// Longest mean latency a link of a restart run may have, in milliseconds.
pub(super) const MAX_LATENCY_MS: u8 = 100;

/// Lowest share of its messages a link of a restart run may deliver, in
/// percent.
pub(super) const MIN_DELIVERY_PERCENT: u8 = 75;

/// Most steps a cut may wait before it starts.
pub(super) const MAX_CUT_DELAY_STEPS: u8 = 16;

/// Most steps a cut usually lasts.
pub(super) const MAX_SHORT_CUT_STEPS: u8 = 16;

/// Most steps a cut may last: long enough to outlast a ceremony that a
/// crashed identity and the cut itself slow down.
pub(super) const MAX_CUT_STEPS: u8 = 64;

/// The conditions of every link among the correct nodes of a restart run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkControls {
    /// Mean latency of a delivery, in milliseconds.
    pub latency_ms: u8,
    /// Standard deviation of the latency, in milliseconds.
    pub jitter_ms: u8,
    /// Share of the messages a link delivers, in percent. A link never
    /// corrupts what it delivers.
    pub delivery_percent: u8,
}

impl LinkControls {
    /// The link these controls name.
    pub fn link(self) -> Link {
        let delivered = u64::from(self.delivery_percent.min(100));
        Link {
            latency: Duration::from_millis(u64::from(self.latency_ms)),
            jitter: Duration::from_millis(u64::from(self.jitter_ms)),
            success_rate: Probability::new(delivered, 100)
                .expect("a percentage of at most 100 is a probability"),
        }
    }
}

impl Arbitrary<'_> for LinkControls {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let latency_ms = u.int_in_range(1..=MAX_LATENCY_MS)?;
        let jitter_ms = u.int_in_range(0..=latency_ms)?;

        // Half the runs lose nothing, so every crash point is also explored
        // over links that only delay.
        let delivery_percent = if u.arbitrary()? {
            100
        } else {
            u.int_in_range(MIN_DELIVERY_PERCENT..=100)?
        };
        Ok(Self {
            latency_ms,
            jitter_ms,
            delivery_percent,
        })
    }
}

/// Which links of one identity a cut removes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CutScope {
    /// Every link into the identity: it sends and hears nothing back.
    Inbound,
    /// Every link out of the identity: it hears and is not heard.
    Outbound,
    /// Every link of the identity, in both directions.
    Both,
    /// The one link from the identity to the peer at this index, modulo the
    /// number of identities. A cut that names the identity itself removes
    /// nothing.
    To(u8),
}

/// A temporary cut: some links of one identity deliver nothing for a while
/// and are then restored. Cuts run one after another and never overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cut {
    /// Steps of half a simulated second between the end of the previous cut,
    /// or the start of the run, and the start of this one.
    pub delay: u8,
    /// Steps of half a simulated second the cut lasts.
    pub duration: u8,
    /// The identity whose links are cut, modulo the number of identities.
    pub identity: u8,
    /// Which of its links are cut.
    pub scope: CutScope,
}

impl Cut {
    /// Draw a cut among `identities` identities.
    fn sample(u: &mut Unstructured<'_>, identities: u8) -> arbitrary::Result<Self> {
        let delay = u.int_in_range(0..=MAX_CUT_DELAY_STEPS)?;

        // Most cuts are short next to the ceremony, so that it goes on around
        // them. One in four may last as long as the ceremony does.
        let duration = if u.int_in_range(0..=3)? == 0 {
            u.int_in_range(1..=MAX_CUT_STEPS)?
        } else {
            u.int_in_range(1..=MAX_SHORT_CUT_STEPS)?
        };
        let identity = u.int_in_range(0..=identities - 1)?;
        let scope = match u.int_in_range(0..=3)? {
            0 => CutScope::Inbound,
            1 => CutScope::Outbound,
            2 => CutScope::Both,
            _ => {
                // Any identity but the one cut.
                let offset = u.int_in_range(1..=identities - 1)?;
                CutScope::To((identity + offset) % identities)
            }
        };
        Ok(Self {
            delay,
            duration,
            identity,
            scope,
        })
    }
}

/// The environment faults of a restart run: how many crashes its schedule
/// holds and the conditions of the links among its correct nodes.
///
/// The schedule itself, which identity each event crashes, when, and for how
/// long, is drawn from the run's tape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentControls {
    /// Number of scheduled crash/restart events over correct identities.
    pub restarts: u8,
    /// The conditions of every link.
    pub links: LinkControls,
    /// Temporary cuts, in the order they run.
    pub cuts: Vec<Cut>,
}

impl EnvironmentControls {
    /// Draw the environment of a run over `identities` identities.
    pub(super) fn sample(u: &mut Unstructured<'_>, identities: u8) -> arbitrary::Result<Self> {
        // A run with no restart exercises nothing a restart target exists
        // for, so the schedule always has at least one event.
        let restarts = u.int_in_range(1..=MAX_RESTARTS)?;
        let links = u.arbitrary()?;
        let cuts = (0..u.int_in_range(0..=MAX_CUTS)?)
            .map(|_| Cut::sample(u, identities))
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            restarts,
            links,
            cuts,
        })
    }
}

/// One run of the bootstrap restart target.
///
/// Every identity is correct here; the only faults are environmental.
#[derive(Clone)]
pub struct DkgBootstrapRestartsFuzzInput {
    /// How the ceremony assigns evaluation points to participants.
    pub sharing_mode: Mode,
    /// The crash schedule's size and the link conditions.
    pub environment: EnvironmentControls,
    /// Byte tape seeding the deterministic runtime and the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for DkgBootstrapRestartsFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgBootstrapRestartsFuzzInput")
            .field("sharing_mode", &self.sharing_mode)
            .field("environment", &self.environment)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for DkgBootstrapRestartsFuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let stream = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);
        Ok(Self {
            sharing_mode: sharing_mode(u)?,
            environment: EnvironmentControls::sample(u, COMMITTEE.get() as u8)?,
            raw_bytes: tape(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> DkgBootstrapFuzzInput {
        DkgBootstrapFuzzInput::arbitrary(&mut Unstructured::new(bytes)).unwrap()
    }

    #[test]
    fn empty_input_samples_a_whole_session() {
        let input = decode(&[]);
        assert!(input.raw_bytes.len() > STREAM_BYTES / 2);
    }

    #[test]
    fn short_inputs_differ_in_their_controls() {
        let sessions: Vec<_> = (0..=255u8)
            .map(|byte| {
                let input = decode(&[byte]);
                (
                    input.case_selector,
                    input.sustained,
                    input.mask,
                    input.sharing_mode,
                )
            })
            .collect();
        assert!(sessions.iter().any(|session| session.1));
        assert!(sessions.iter().any(|session| !session.1));
        assert!(sessions.iter().any(|session| session.2 == DkgMask::WHOLE));
        assert!(sessions.iter().any(|session| session.2 != DkgMask::WHOLE));
        assert!(
            sessions
                .iter()
                .any(|session| session.3 == Mode::RootsOfUnity)
        );
        assert!(
            sessions
                .iter()
                .any(|session| session.3 == Mode::NonZeroCounter)
        );
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let (first, second) = (decode(&bytes), decode(&bytes));
        assert_eq!(first.case_selector, second.case_selector);
        assert_eq!(first.mask, second.mask);
        assert_eq!(first.raw_bytes, second.raw_bytes);
    }

    #[test]
    fn debug_elides_the_tape() {
        let rendered = format!("{:?}", decode(&[7; 40]));
        assert!(rendered.contains("raw_bytes_len"));
        assert!(!rendered.contains("raw_bytes:"));
    }

    fn decode_restarts(bytes: &[u8]) -> DkgBootstrapRestartsFuzzInput {
        DkgBootstrapRestartsFuzzInput::arbitrary(&mut Unstructured::new(bytes)).unwrap()
    }

    /// Every seventh two-byte input, decoded.
    fn restart_sessions() -> Vec<DkgBootstrapRestartsFuzzInput> {
        (0..=u16::MAX)
            .step_by(7)
            .map(|seed| decode_restarts(&seed.to_le_bytes()))
            .collect()
    }

    #[test]
    fn empty_restart_input_samples_a_whole_session() {
        let input = decode_restarts(&[]);
        assert!(input.raw_bytes.len() > STREAM_BYTES / 2);
        assert!(input.environment.restarts >= 1);
    }

    #[test]
    fn short_restart_inputs_differ_in_their_controls() {
        let sessions = restart_sessions();
        let any = |holds: fn(&DkgBootstrapRestartsFuzzInput) -> bool| sessions.iter().any(holds);
        assert!(any(|input| input.sharing_mode == Mode::RootsOfUnity));
        assert!(any(|input| input.sharing_mode == Mode::NonZeroCounter));
        for restarts in 1..=MAX_RESTARTS {
            assert!(
                sessions
                    .iter()
                    .any(|input| input.environment.restarts == restarts)
            );
        }
        for cuts in 0..=usize::from(MAX_CUTS) {
            assert!(
                sessions
                    .iter()
                    .any(|input| input.environment.cuts.len() == cuts)
            );
        }
        assert!(any(|input| input.environment.links.delivery_percent == 100));
        assert!(any(|input| input.environment.links.delivery_percent < 100));
        assert!(any(|input| input.environment.links.latency_ms < 10));
        assert!(any(|input| input.environment.links.latency_ms > 90));
        let cut = |holds: fn(&Cut) -> bool| {
            sessions
                .iter()
                .any(|input| input.environment.cuts.iter().any(holds))
        };
        assert!(cut(|cut| cut.scope == CutScope::Inbound));
        assert!(cut(|cut| cut.scope == CutScope::Outbound));
        assert!(cut(|cut| cut.scope == CutScope::Both));
        assert!(cut(|cut| matches!(cut.scope, CutScope::To(_))));
        assert!(cut(|cut| cut.delay == 0));
        assert!(cut(|cut| cut.duration > MAX_SHORT_CUT_STEPS));
    }

    #[test]
    fn restart_controls_stay_within_their_bounds() {
        for input in restart_sessions() {
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
                assert!(u32::from(cut.identity) < COMMITTEE.get());
                if let CutScope::To(peer) = cut.scope {
                    assert!(u32::from(peer) < COMMITTEE.get());
                    assert_ne!(peer, cut.identity);
                }
            }
        }
    }

    #[test]
    fn restart_decoding_is_deterministic() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let (first, second) = (decode_restarts(&bytes), decode_restarts(&bytes));
        assert_eq!(first.sharing_mode, second.sharing_mode);
        assert_eq!(first.environment, second.environment);
        assert_eq!(first.raw_bytes, second.raw_bytes);
    }

    #[test]
    fn restart_debug_elides_the_tape() {
        let rendered = format!("{:?}", decode_restarts(&[7; 40]));
        assert!(rendered.contains("raw_bytes_len"));
        assert!(!rendered.contains("raw_bytes:"));
        assert!(rendered.contains("restarts:"));
        assert!(rendered.contains("delivery_percent:"));
    }

    #[test]
    fn link_controls_name_their_link() {
        let link = LinkControls {
            latency_ms: 40,
            jitter_ms: 7,
            delivery_percent: 80,
        }
        .link();
        assert_eq!(link.latency, Duration::from_millis(40));
        assert_eq!(link.jitter, Duration::from_millis(7));
        assert_eq!(link.success_rate, Probability::new(4, 5).unwrap());

        // A percentage past 100 delivers everything.
        let link = LinkControls {
            latency_ms: 1,
            jitter_ms: 0,
            delivery_percent: 200,
        }
        .link();
        assert_eq!(link.success_rate, Probability::new(1, 1).unwrap());
    }
}
