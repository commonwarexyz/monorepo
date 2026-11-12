//! The libFuzzer-facing input of the probe target.
//!
//! It is decoded the way the bootstrap input is (see [`super::input`]): the
//! input is expanded into a seeded stream, the structured controls are drawn
//! from the head of the stream, and the rest is the run's tape.
//!
//! The event program reuses the stateful probe target's [`ProbeEvent`]. Its
//! events read as follows here, where a source builds responses of three
//! kinds. A source selector names a source by its remainder modulo the source
//! count and one of that source's responses by its quotient: zero is the
//! newest, and each step goes back one distinct response.
//!
//! - `Subscribe` and `Unsubscribe` open and drop an artifact subscription on
//!   the discovering probe.
//! - `Attach` attaches a node's marshal to its probe: node zero is the
//!   discovering probe, which then serves once no subscription is pending, and
//!   the others are the sources, which answer nothing until attached.
//! - `Release` delivers a response a source built, from that source.
//!   `Duplicate` delivers again what the source last delivered.
//! - `Replay` delivers a source's response from the identity that is tracked
//!   and is not a dealer.
//! - `Truncate` delivers a strict prefix of a source's response from that
//!   source, and `Fragment` from any identity.
//! - `Junk` delivers bytes that start with no tag of the probe's wire format.
//!   Bytes that start with one are not sent.
//! - `Advance` lets deterministic time pass, possibly across a retry.
//!
//! The program is not drawn uniformly. A session that discovers a boundary
//! needs its sources attached, a subscription, and several releases in a row,
//! so the program opens with the attachments and the subscription unless the
//! stream withholds them, and half of what follows are releases in an order
//! that suits a discovery. Every event kind still occurs within a handful of
//! short inputs.

use super::input::sharing_mode;
use crate::{
    input::stream,
    stateful::{
        MAX_ADVANCE_STEPS, MAX_RAW_PAYLOAD, MAX_SOURCE_HEIGHT, NUM_SOURCES, ProbeEvent, input::tape,
    },
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::sharing::Mode;
use std::fmt;

/// Bytes of the stream a session is sampled from: the controls take at most
/// about half of it and the rest is the tape.
const STREAM_BYTES: usize = 1 << 11;

/// Sources of a run.
pub(super) const SOURCES: usize = NUM_SOURCES as usize;

/// Highest epoch the discovering probe's bootstrap checkpoint may name. The
/// fabricated chain's highest finalization is in this epoch.
const MAX_BOOTSTRAP_EPOCH: u8 = 2;

/// Longest event program a run may draw, its opening included.
const MAX_EVENTS: usize = 32;

/// Longest body a program may draw after its opening.
const MAX_BODY: usize = MAX_EVENTS - SOURCES - 1;

/// Furthest a drawn selector goes back from a source's newest response. A
/// source builds responses of three kinds.
const MAX_BACK: u8 = 2;

/// One run of the probe target.
#[derive(Clone)]
pub struct DkgProbeFuzzInput {
    /// The finalized height each source holds; zero holds none. The height
    /// decides the epoch of the source's latest finalization and which
    /// boundary blocks it can serve.
    pub sources: [u8; SOURCES],
    /// Whether each source holds the foreign chain, which is signed under
    /// another dealt key, instead of the fabricated chain.
    pub foreign: [bool; SOURCES],
    /// The epoch of the checkpoint the discovering probe bootstraps from.
    /// Latest finalizations below it are stale.
    pub bootstrap_epoch: u8,
    /// The height of the fabricated chain's finalization the discovering
    /// probe is given as the floor an interrupted sync persisted, if any.
    /// Latest finalizations below its epoch are stale.
    pub floor: Option<u8>,
    /// How the trusted deals assign evaluation points to participants.
    pub sharing_mode: Mode,
    /// The adversarial event program.
    pub events: Vec<ProbeEvent>,
    /// Byte tape seeding the deterministic runtime and the trusted deals.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for DkgProbeFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgProbeFuzzInput")
            .field("sources", &self.sources)
            .field("foreign", &self.foreign)
            .field("bootstrap_epoch", &self.bootstrap_epoch)
            .field("floor", &self.floor)
            .field("sharing_mode", &self.sharing_mode)
            .field("events", &self.events)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

/// Draw a source.
fn source(u: &mut Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(0..=NUM_SOURCES - 1)
}

/// Draw a source and one of its responses: the newest three times in four,
/// and otherwise one or two distinct responses before it.
fn response(u: &mut Unstructured<'_>) -> arbitrary::Result<u8> {
    let back = match u.int_in_range(0..=7u8)? {
        0..=5 => 0,
        6 => 1,
        _ => MAX_BACK,
    };
    Ok(source(u)? + back * NUM_SOURCES)
}

/// Draw a sending identity: a source, or the identity that is not a dealer.
fn origin(u: &mut Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(0..=NUM_SOURCES)
}

/// Every order the sources can be released in.
const ORDERS: [[u8; SOURCES]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

/// Consecutive scripted releases of one source.
const STREAK: usize = 3;

/// The releases a program is scripted to make: the sources in a drawn order,
/// each [`STREAK`] times in a row, starting from the last release of the
/// first.
///
/// A discovery needs the latest finalizations of two sources and then the
/// boundary finalization and the block of one, which is one release of a
/// source followed by three of another.
struct Script {
    order: [u8; SOURCES],
    cursor: usize,
}

impl Script {
    fn new(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            order: ORDERS[u.int_in_range(0..=ORDERS.len() - 1)?],
            cursor: STREAK - 1,
        })
    }

    /// The source of the next scripted release.
    fn next(&mut self) -> u8 {
        let source = self.order[(self.cursor / STREAK) % SOURCES];
        self.cursor += 1;
        source
    }
}

/// Draw one event of the program's body. Half of the draws make the script's
/// next release, of the source's newest response. The others draw any event,
/// a release of any response of any source included, and one attachment in
/// ten is the discovering probe's.
fn event(u: &mut Unstructured<'_>, script: &mut Script) -> arbitrary::Result<ProbeEvent> {
    Ok(match u.int_in_range(0..=31u8)? {
        0..=15 => ProbeEvent::Release {
            source: script.next(),
        },
        16..=17 => ProbeEvent::Release {
            source: response(u)?,
        },
        18..=19 => ProbeEvent::Subscribe,
        20 => ProbeEvent::Unsubscribe,
        21..=23 => ProbeEvent::Attach {
            node: match u.int_in_range(0..=9u8)? {
                0 => 0,
                sample => 1 + (sample - 1) % NUM_SOURCES,
            },
        },
        24 => ProbeEvent::Duplicate { source: source(u)? },
        25..=26 => ProbeEvent::Replay {
            source: response(u)?,
        },
        27..=28 => ProbeEvent::Truncate {
            source: response(u)?,
            keep: u.arbitrary()?,
        },
        29 => ProbeEvent::Fragment {
            origin: origin(u)?,
            source: response(u)?,
            keep: u.arbitrary()?,
        },
        30 => {
            let len = u.int_in_range(1..=MAX_RAW_PAYLOAD)?;
            ProbeEvent::Junk {
                origin: origin(u)?,
                payload: u.bytes(usize::from(len))?.to_vec(),
            }
        }
        _ => ProbeEvent::Advance {
            steps: u.int_in_range(1..=MAX_ADVANCE_STEPS)?,
        },
    })
}

/// Draw the event program: an opening that attaches each source and
/// subscribes, each seven times in eight, followed by the body.
fn program(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<ProbeEvent>> {
    let mut events = Vec::with_capacity(MAX_EVENTS);
    for node in 1..=NUM_SOURCES {
        if u.int_in_range(0..=7u8)? != 0 {
            events.push(ProbeEvent::Attach { node });
        }
    }
    if u.int_in_range(0..=7u8)? != 0 {
        events.push(ProbeEvent::Subscribe);
    }
    let body = u.int_in_range(0..=MAX_BODY)?;
    let mut script = Script::new(u)?;
    for _ in 0..body {
        events.push(event(u, &mut script)?);
    }
    Ok(events)
}

/// Whether [`program`] can draw `events`: the opening, any part of which may
/// be withheld, and then a body of events that [`event`] draws.
#[cfg(test)]
pub(super) fn drawable(events: &[ProbeEvent]) -> bool {
    let opening = (1..=NUM_SOURCES)
        .map(|node| ProbeEvent::Attach { node })
        .chain([ProbeEvent::Subscribe]);
    let mut opened = 0;
    for event in opening {
        if events.get(opened) == Some(&event) {
            opened += 1;
        }
    }
    let response = |selector: u8| selector < NUM_SOURCES * (MAX_BACK + 1);
    let body = &events[opened..];
    body.len() <= MAX_BODY
        && body.iter().all(|event| match event {
            ProbeEvent::Subscribe | ProbeEvent::Unsubscribe => true,
            ProbeEvent::Attach { node } => *node <= NUM_SOURCES,
            ProbeEvent::Release { source }
            | ProbeEvent::Replay { source }
            | ProbeEvent::Truncate { source, .. } => response(*source),
            ProbeEvent::Duplicate { source } => *source < NUM_SOURCES,
            ProbeEvent::Fragment { origin, source, .. } => {
                *origin <= NUM_SOURCES && response(*source)
            }
            ProbeEvent::Junk { origin, payload } => {
                *origin <= NUM_SOURCES
                    && (1..=usize::from(MAX_RAW_PAYLOAD)).contains(&payload.len())
            }
            ProbeEvent::Advance { steps } => (1..=MAX_ADVANCE_STEPS).contains(steps),
        })
}

impl Arbitrary<'_> for DkgProbeFuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let stream = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);

        // The sources follow one chain, so their heights are drawn around a
        // common tip: half of them hold it, a quarter are a block behind, an
        // eighth two blocks, and an eighth hold nothing.
        let tip = u.int_in_range(1..=MAX_SOURCE_HEIGHT)?;
        let mut sources = [0u8; SOURCES];
        for height in &mut sources {
            *height = match u.int_in_range(0..=7u8)? {
                0..=3 => tip,
                4..=5 => tip - 1,
                6 => tip.saturating_sub(2),
                _ => 0,
            };
        }

        // A floor needs two sources of the fabricated chain, so a source
        // holds the foreign one in a quarter of the draws.
        let mut foreign = [false; SOURCES];
        for foreign in &mut foreign {
            *foreign = u.int_in_range(0..=3u8)? == 0;
        }

        // Five runs in eight bootstrap from epoch zero, where no finalization
        // is stale, and one in eight resumes from a persisted floor.
        let bootstrap_epoch = match u.int_in_range(0..=7u8)? {
            0..=4 => 0,
            5..=6 => 1,
            _ => MAX_BOOTSTRAP_EPOCH,
        };
        let floor = if u.int_in_range(0..=7u8)? == 0 {
            Some(u.int_in_range(1..=MAX_SOURCE_HEIGHT)?)
        } else {
            None
        };
        Ok(Self {
            sources,
            foreign,
            bootstrap_epoch,
            floor,
            sharing_mode: sharing_mode(u)?,
            events: program(u)?,
            raw_bytes: tape(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::discriminant;

    fn decode(bytes: &[u8]) -> DkgProbeFuzzInput {
        DkgProbeFuzzInput::arbitrary(&mut Unstructured::new(bytes)).unwrap()
    }

    #[test]
    fn empty_input_samples_a_whole_session() {
        let input = decode(&[]);
        assert!(input.raw_bytes.len() > STREAM_BYTES / 4);
        assert!(input.events.len() <= MAX_EVENTS);
    }

    #[test]
    fn short_inputs_cover_every_control_and_event() {
        let sessions: Vec<_> = (0..=255u8).map(|byte| decode(&[byte])).collect();
        let any = |holds: &dyn Fn(&DkgProbeFuzzInput) -> bool| sessions.iter().any(holds);
        for height in 0..=MAX_SOURCE_HEIGHT {
            assert!(any(&|session| session.sources[0] == height));
        }
        assert!(any(&|session| session.foreign == [false; SOURCES]));
        assert!(any(&|session| session.foreign.contains(&true)));
        for epoch in 0..=MAX_BOOTSTRAP_EPOCH {
            assert!(any(&|session| session.bootstrap_epoch == epoch));
        }
        assert!(any(&|session| session.floor.is_none()));
        for height in 1..=MAX_SOURCE_HEIGHT {
            assert!(any(&|session| session.floor == Some(height)));
        }
        assert!(any(&|session| session.sharing_mode == Mode::RootsOfUnity));
        assert!(any(&|session| session.sharing_mode == Mode::NonZeroCounter));

        // Every event kind occurs, every node is attached, and every identity
        // sends a fragment and junk.
        let kinds = [
            ProbeEvent::Subscribe,
            ProbeEvent::Unsubscribe,
            ProbeEvent::Attach { node: 0 },
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Duplicate { source: 0 },
            ProbeEvent::Replay { source: 0 },
            ProbeEvent::Truncate { source: 0, keep: 0 },
            ProbeEvent::Fragment {
                origin: 0,
                source: 0,
                keep: 0,
            },
            ProbeEvent::Junk {
                origin: 0,
                payload: Vec::new(),
            },
            ProbeEvent::Advance { steps: 1 },
        ];
        let events = || sessions.iter().flat_map(|session| session.events.iter());
        for kind in &kinds {
            let count = events()
                .filter(|event| discriminant(*event) == discriminant(kind))
                .count();
            assert!(count >= sessions.len() / 8, "{kind:?} occurs {count} times");
        }
        for node in 0..=NUM_SOURCES {
            assert!(events().any(|event| *event == ProbeEvent::Attach { node }));
            assert!(events().any(|event| {
                matches!(event, ProbeEvent::Fragment { origin, .. } if *origin == node)
            }));
            assert!(
                events().any(
                    |event| matches!(event, ProbeEvent::Junk { origin, .. } if *origin == node)
                )
            );
        }

        // A selector reaches each of a source's older responses.
        for back in 0..=MAX_BACK {
            assert!(events().any(|event| {
                matches!(event, ProbeEvent::Replay { source } if source / NUM_SOURCES == back)
            }));
        }

        // Most sessions open with every source attached and a subscription,
        // and some do not. Programs of every length up to the bound occur.
        let opened = sessions
            .iter()
            .filter(|session| {
                session.events.len() > SOURCES
                    && session.events[..SOURCES]
                        .iter()
                        .all(|event| matches!(event, ProbeEvent::Attach { .. }))
                    && session.events[SOURCES] == ProbeEvent::Subscribe
            })
            .count();
        assert!(opened > sessions.len() / 2 && opened < sessions.len());
        assert!(any(&|session| session.events.len() <= SOURCES + 1));
        assert!(any(&|session| session.events.len() >= MAX_EVENTS - 1));
    }

    /// The predicate the fixed-input tests are held to accepts what the
    /// decoder draws and nothing past a bound of the decoder.
    #[test]
    fn drawable_programs_are_those_the_decoder_draws() {
        for byte in 0..=255u8 {
            let session = decode(&[byte]);
            assert!(drawable(&session.events), "{:?}", session.events);
        }
        let release = ProbeEvent::Release { source: 0 };
        assert!(drawable(&vec![release.clone(); MAX_BODY]));
        assert!(!drawable(&vec![release.clone(); MAX_BODY + 1]));
        let mut opened = vec![ProbeEvent::Attach { node: 2 }, ProbeEvent::Subscribe];
        opened.extend(vec![release; MAX_BODY]);
        assert!(drawable(&opened));
        for event in [
            ProbeEvent::Attach {
                node: NUM_SOURCES + 1,
            },
            ProbeEvent::Release {
                source: NUM_SOURCES * (MAX_BACK + 1),
            },
            ProbeEvent::Duplicate {
                source: NUM_SOURCES,
            },
            ProbeEvent::Fragment {
                origin: NUM_SOURCES + 1,
                source: 0,
                keep: 0,
            },
            ProbeEvent::Junk {
                origin: 0,
                payload: Vec::new(),
            },
            ProbeEvent::Junk {
                origin: 0,
                payload: vec![9; usize::from(MAX_RAW_PAYLOAD) + 1],
            },
            ProbeEvent::Advance { steps: 0 },
            ProbeEvent::Advance {
                steps: MAX_ADVANCE_STEPS + 1,
            },
        ] {
            assert!(!drawable(std::slice::from_ref(&event)), "{event:?}");
        }
    }

    #[test]
    fn scripted_releases_walk_the_sources_in_streaks() {
        let mut script = Script {
            order: [2, 0, 1],
            cursor: STREAK - 1,
        };
        let released: Vec<u8> = (0..10).map(|_| script.next()).collect();
        assert_eq!(released, [2, 0, 0, 0, 1, 1, 1, 2, 2, 2]);
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let (first, second) = (decode(&bytes), decode(&bytes));
        assert_eq!(first.sources, second.sources);
        assert_eq!(first.events, second.events);
        assert_eq!(first.raw_bytes, second.raw_bytes);
    }

    #[test]
    fn debug_elides_the_tape() {
        let rendered = format!("{:?}", decode(&[7; 40]));
        assert!(rendered.contains("raw_bytes_len"));
        assert!(!rendered.contains("raw_bytes:"));
    }
}
