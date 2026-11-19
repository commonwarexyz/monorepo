#![no_main]

//! Run a [Lookahead] ahead of a scripted scan and check what it hands out against a model, and
//! hint arbitrary spans with [prefetch] and [prefetch_lines].
//!
//! The scan consumes one or more items between calls, or steps back over items it consumed, as a
//! misused cursor would. Before each call the harness checks that:
//! - the call returns exactly the items within `distance` of the scan's next item that no earlier
//!   call returned, in scan order,
//! - it panics exactly when the tail starts more than `distance + 1` items before the first item
//!   no earlier call returned,
//! - over a scan consumed one item at a time, every item comes up exactly once.
//!
//! The hints have no observable effect, so the oracle for them is that no address, length, or
//! line cap faults, panics, or hangs.

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::{
    FuzzRng,
    prefetch::{Lookahead, prefetch, prefetch_lines},
};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::panic::{self, AssertUnwindSafe};

/// Maximum number of items a scan holds.
const MAX_ITEMS: usize = 64;
/// Maximum number of scripted moves. Once they run out, the scan consumes one item per call.
const MAX_MOVES: usize = 32;
/// Maximum number of items a move consumes or steps back over.
const MAX_STEP: usize = 8;
/// Maximum number of spans hinted per input.
const MAX_SPANS: usize = 8;
/// Longest span hinted without a line cap, in elements, as hint sites over short spans pass.
const MAX_UNCAPPED: usize = 1 << 12;
/// Bytes of the stream an input is sampled from, several times the largest input.
const STREAM_BYTES: usize = 1 << 12;
/// Bytes of the input's head that seed the stream.
const SEED_BYTES: usize = 8;

/// The cursor's distance, near zero or near the largest distance.
#[derive(Arbitrary, Debug)]
enum Distance {
    Near(u8),
    Far(u8),
}

#[derive(Arbitrary, Debug)]
enum Move {
    /// Consume at least one item.
    Consume(u8),
    /// Step back over items the scan consumed.
    Rewind(u8),
}

/// A span at an address that need not be valid.
#[derive(Arbitrary, Debug)]
struct Span {
    addr: usize,
    len: usize,
    /// Most lines to hint, or `None` for no cap.
    max_lines: Option<u8>,
}

#[derive(Debug)]
struct FuzzInput {
    items: usize,
    distance: usize,
    moves: Vec<Move>,
    spans: Vec<Span>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes, which would script no move. The input's
        // head therefore seeds a fixed-size stream of [`FuzzRng`] output that the rest of the
        // input overwrites from its start, so every input, even an empty one, samples a whole
        // scan.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let u = &mut Unstructured::new(&stream);

        let items = MAX_ITEMS - u.int_in_range(0..=MAX_ITEMS)?;
        let distance = match u.arbitrary()? {
            Distance::Near(offset) => usize::from(offset) % (MAX_ITEMS + 2),
            Distance::Far(offset) => usize::MAX - usize::from(offset),
        };
        Ok(Self {
            items,
            distance,
            moves: (0..u.int_in_range(0..=MAX_MOVES)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            spans: (0..u.int_in_range(1..=MAX_SPANS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
        })
    }
}

/// Run `f`, returning whether it panicked instead of aborting.
fn panics(f: impl FnOnce()) -> bool {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(hook);
    result.is_err()
}

fn scan(items: usize, distance: usize, moves: Vec<Move>) {
    let items: Vec<usize> = (0..items).collect();
    let mut ahead = Lookahead::new(distance);
    let mut moves = moves.into_iter();
    let mut consumed = 0;
    // Model: the first item no call has returned.
    let mut unreturned: usize = 0;
    let mut hinted = Vec::new();
    let mut one_by_one = true;

    loop {
        let remaining = &items[consumed..];
        if unreturned.saturating_sub(consumed) > distance.saturating_add(1) {
            assert!(
                panics(|| {
                    ahead.advance(remaining);
                }),
                "a tail starting too far back must panic"
            );
            return;
        }
        let returned = ahead.advance(remaining);
        let end = consumed + remaining.len().min(distance.saturating_add(1));
        assert_eq!(returned, &items[unreturned.max(consumed)..end]);
        for item in returned {
            prefetch(item);
        }
        hinted.extend_from_slice(returned);
        unreturned = end;

        if consumed == items.len() {
            break;
        }
        match moves.next() {
            Some(Move::Consume(step)) => {
                let step = 1 + usize::from(step) % MAX_STEP;
                one_by_one &= step == 1;
                consumed = (consumed + step).min(items.len());
            }
            Some(Move::Rewind(step)) => {
                one_by_one = false;
                consumed -= (usize::from(step) % (MAX_STEP + 1)).min(consumed);
            }
            None => consumed += 1,
        }
    }

    assert!(
        hinted.windows(2).all(|pair| pair[0] < pair[1]),
        "an item came up twice or out of order"
    );
    if one_by_one {
        assert_eq!(hinted, items, "a one-by-one scan must hint every item once");
    }
}

fn hint<T>(span: &Span) {
    let (len, max_lines) = match span.max_lines {
        Some(cap) => (span.len, usize::from(cap)),
        None => (span.len % MAX_UNCAPPED, usize::MAX),
    };
    let ptr = std::ptr::without_provenance::<T>(span.addr);
    prefetch(ptr);
    prefetch_lines(ptr, len, max_lines);
}

fn fuzz(input: FuzzInput) {
    scan(input.items, input.distance, input.moves);
    for span in &input.spans {
        hint::<u8>(span);
        hint::<u64>(span);
        hint::<[u8; 96]>(span);
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
