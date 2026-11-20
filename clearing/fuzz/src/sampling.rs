//! How the clearing targets sample a plan from their input: the input's stream, weighted choices,
//! amounts relative to a balance, epochs relative to the ledger's, batches and queue counts.

use crate::MAX_BATCH;
use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::FuzzRng;
use rand_core::Rng as _;

/// Bytes of each of the two seeds the input's head holds, and of the runtime's entropy.
pub const SEED_BYTES: usize = 8;
pub const ENTROPY_BYTES: usize = 32;

/// Weights of the amount kinds, in the order Few, Share, Over, Huge.
pub const SIZE_WEIGHTS: [u8; 4] = [6, 8, 1, 1];

/// Units a few-units amount spans, starting at zero.
pub const FEW_SPAN: u8 = 16;

/// Units past the base an overspend spans.
pub const OVER_SPAN: u8 = 8;

/// Units below the largest amount a near-largest amount spans.
pub const HUGE_SPAN: u8 = 16;

/// Weights of the epoch a request names, in the order current, previous, next. An honest
/// operator admits only a request that can settle in its epoch.
pub const SHIFT_WEIGHTS: [u8; 3] = [14, 1, 1];

/// One count in this many lies one outside its queue's bounds.
pub const OUTSIDE_ONE_IN: u8 = 8;

/// Returns the stream a plan is sampled from, `len` bytes long, and the bytes of the runtime's
/// entropy.
///
/// libFuzzer starts from inputs of a few bytes and lengthens them slowly. The input's head
/// therefore seeds a fixed-size stream that the bytes after it overwrite from its start, so every
/// input, even an empty one, samples a whole plan, and bytes past the stream's size are ignored.
/// The head's even bytes seed the plan's stream and its odd bytes seed the runtime's entropy.
pub fn stream(
    u: &mut Unstructured<'_>,
    len: usize,
) -> arbitrary::Result<(Vec<u8>, [u8; ENTROPY_BYTES])> {
    let head = u.bytes(u.len().min(2 * SEED_BYTES))?;
    let seed: Vec<_> = head.iter().step_by(2).copied().collect();
    let mut schedule: Vec<_> = head.iter().skip(1).step_by(2).copied().collect();
    if schedule.is_empty() {
        schedule.clone_from(&seed);
    }
    let mut stream = vec![0; len];
    FuzzRng::new(seed).fill_bytes(&mut stream);
    let literal = u.bytes(u.len().min(len))?;
    stream[..literal.len()].copy_from_slice(literal);
    let mut entropy = [0; ENTROPY_BYTES];
    FuzzRng::new(schedule).fill_bytes(&mut entropy);
    Ok((stream, entropy))
}

/// Returns the index of an entry of `weights`, drawn in proportion to the entry.
pub fn weighted(u: &mut Unstructured<'_>, weights: &[u8]) -> arbitrary::Result<usize> {
    let sum: u8 = weights.iter().sum();
    let draw = u.int_in_range(0..=sum - 1)?;
    let mut total = 0;
    Ok(weights
        .iter()
        .position(|weight| {
            total += weight;
            draw < total
        })
        .expect("the draw is below the sum"))
}

/// An amount relative to what the account involved holds.
#[derive(Clone, Copy, Debug)]
pub enum Size {
    /// A few units, sometimes zero.
    Few(u8),
    /// A share of the base in 255ths, so payments stay mostly affordable.
    Share(u8),
    /// Just past the base, an overspend by a few units.
    Over(u8),
    /// Near the largest amount, where sums of requests overflow.
    Huge(u8),
}

impl<'a> Arbitrary<'a> for Size {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match weighted(u, &SIZE_WEIGHTS)? {
            0 => Self::Few(u.arbitrary()?),
            1 => Self::Share(u.arbitrary()?),
            2 => Self::Over(u.arbitrary()?),
            _ => Self::Huge(u.arbitrary()?),
        })
    }
}

impl Size {
    /// Returns the amount relative to `base`.
    pub fn resolve(self, base: u64) -> u64 {
        match self {
            Self::Few(x) => u64::from(x % FEW_SPAN),
            Self::Share(x) => u64::try_from(u128::from(base) * u128::from(x) / u128::from(u8::MAX))
                .expect("a share fits"),
            Self::Over(x) => base.saturating_add(1 + u64::from(x % OVER_SPAN)),
            Self::Huge(x) => u64::MAX - u64::from(x % HUGE_SPAN),
        }
    }
}

/// The epoch a request names, relative to the one the ledger expects a close of.
#[derive(Clone, Copy, Debug)]
pub enum Shift {
    Current,
    Previous,
    Next,
}

impl<'a> Arbitrary<'a> for Shift {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match weighted(u, &SHIFT_WEIGHTS)? {
            0 => Self::Current,
            1 => Self::Previous,
            _ => Self::Next,
        })
    }
}

/// Returns a batch of one to [`MAX_BATCH`] receivers.
pub fn batch(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<(u8, Size)>> {
    (0..u.int_in_range(1..=MAX_BATCH)?)
        .map(|_| Ok((u.arbitrary()?, u.arbitrary()?)))
        .collect()
}

/// Returns a count of a queue with `required` required and `len` queued requests, one time in
/// [`OUTSIDE_ONE_IN`] one outside these bounds.
pub fn count(required: usize, len: usize, choice: u8) -> usize {
    let (outside, choice) = (
        choice.is_multiple_of(OUTSIDE_ONE_IN),
        usize::from(choice / OUTSIDE_ONE_IN),
    );
    match (outside, choice.is_multiple_of(2)) {
        (false, _) => required + choice % (len - required + 1),
        (true, true) => len + 1,
        (true, false) => required.checked_sub(1).unwrap_or(len + 1),
    }
}
