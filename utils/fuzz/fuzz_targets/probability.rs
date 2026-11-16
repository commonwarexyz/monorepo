#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{Runner, deterministic};
use commonware_utils::{
    Entropy, FuzzRng, Probability, ScriptedRng, probability, probability::InvalidProbability,
};
use core::convert::Infallible;
use libfuzzer_sys::fuzz_target;
use rand_core::{Rng, TryRng};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

/// Number of possible `u64` samples, and the model's threshold of probability one.
const SCALE: u128 = 1 << 64;

/// Most probabilities a plan constructs. Each is compared with every earlier one, so order,
/// equality, and hashing are checked across all three constructors.
const MAX_OPS: usize = 32;

/// Largest shift of a grid value below the grid. Converting a large threshold to `f64` leaves
/// about 11 trailing zero bits, so shifts up to 16 move it off the grid only some of the time.
const MAX_SHIFT: u8 = 16;

/// The smallest interior probability, 2^-64, and the largest `f64` below one.
const MIN_INTERIOR: f64 = f64::from_bits((1023 - 64) << 52);
const BELOW_ONE: f64 = f64::from_bits(1.0f64.to_bits() - 1);

/// Values a float is built around: both zeros, the endpoints, the extreme interior values, a
/// decimal that maps exactly, and values `from_f64` must refuse. A few units in the last place
/// from these reach subnormals, NaN payloads, and the values just off the grid.
const SPECIALS: [f64; 14] = [
    0.0,
    -0.0,
    1.0,
    0.5,
    0.98,
    MIN_INTERIOR,
    BELOW_ONE,
    f64::EPSILON,
    f64::MIN_POSITIVE,
    f64::from_bits(1),
    -1.0,
    f64::NAN,
    f64::INFINITY,
    f64::NEG_INFINITY,
];

/// Bytes of the stream a plan is sampled from, several times the largest plan, of the input's head
/// that seeds the stream, and of the stream's tail that seeds the runtime.
const STREAM_BYTES: usize = 1 << 11;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

/// Uniform numerators and denominators are almost never close, so most fractions are built around
/// the boundary at one.
#[derive(Arbitrary, Debug)]
enum Fraction {
    Raw(u64, u64),
    /// `offset` below the denominator, at or just under one.
    Below {
        denominator: u64,
        offset: u8,
    },
    /// `offset` above the denominator, at or just over one.
    Above {
        denominator: u64,
        offset: u8,
    },
    /// Small ratios, including a zero denominator.
    Small(u8, u8),
}

/// Uniform bits are almost never in `[0, 1]` and on the grid of 2^-64, so most floats are built on
/// the grid or next to a notable value.
#[derive(Arbitrary, Debug)]
enum Float {
    Bits(u64),
    /// A special value itself.
    Special(u8),
    /// A special value moved by `ulps` units in the last place.
    Near {
        special: u8,
        ulps: i8,
    },
    /// `threshold` (rounded to `f64`) times 2^-(64 + shift), on the grid when `shift` is zero.
    Grid {
        threshold: u64,
        shift: u8,
    },
}

#[derive(Arbitrary, Debug)]
enum Op {
    Ratio { fraction: Fraction, factor: u32 },
    Float(Float),
    Sampled(Probability),
}

#[derive(Debug)]
struct Plan {
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for Plan {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a plan
        // sampled from so few bytes would hold one ratio of zeros. The input's head therefore
        // seeds a fixed-size stream of [`FuzzRng`] output that the rest of the input overwrites
        // from its start, so every input, even an empty one, samples a whole plan, and a byte
        // mutated past the head changes only what is sampled from it.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let (plan, entropy) = stream.split_at(stream.len() - ENTROPY_BYTES);
        let u = &mut Unstructured::new(plan);

        Ok(Self {
            ops: (0..u.int_in_range(1..=MAX_OPS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
}

impl Fraction {
    fn resolve(self) -> (u64, u64) {
        match self {
            Self::Raw(numerator, denominator) => (numerator, denominator),
            Self::Below {
                denominator,
                offset,
            } => (denominator.saturating_sub(offset.into()), denominator),
            Self::Above {
                denominator,
                offset,
            } => (denominator.saturating_add(offset.into()), denominator),
            Self::Small(numerator, denominator) => (numerator.into(), denominator.into()),
        }
    }
}

impl Float {
    fn value(self) -> f64 {
        match self {
            Self::Bits(bits) => f64::from_bits(bits),
            Self::Special(special) => SPECIALS[special as usize % SPECIALS.len()],
            Self::Near { special, ulps } => {
                let special = SPECIALS[special as usize % SPECIALS.len()];
                f64::from_bits(special.to_bits().wrapping_add_signed(ulps.into()))
            }
            Self::Grid { threshold, shift } => {
                let shift = u64::from(shift % (MAX_SHIFT + 1));
                threshold as f64 * f64::from_bits((1023 - 64 - shift) << 52)
            }
        }
    }
}

/// Returns the threshold `value` maps to, or `None` if it is outside `[0, 1]` or between two
/// multiples of 2^-64. Scaling by a power of two is exact, so `value` is on the grid exactly when
/// the scaled value is an integer.
fn on_grid(value: f64) -> Option<u128> {
    if !(0.0..=1.0).contains(&value) {
        return None;
    }
    let scaled = value * SCALE as f64;
    (scaled.fract() == 0.0).then_some(scaled as u128)
}

/// Returns how many `u64` samples `p` accepts, by bisecting over scripted samples. A probability
/// sampled through `Arbitrary` has no other model, so `check` holds every other method to the
/// threshold the sampler reveals.
fn accepted(p: Probability) -> u128 {
    let (mut low, mut high) = (0, SCALE);
    while low < high {
        let mid = (low + high) / 2;
        if p.sample(&mut ScriptedRng::new([mid as u64])) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low
}

/// Forwards the runtime's samples and records each one drawn.
struct Recorder<'a> {
    rng: &'a mut deterministic::Context,
    drawn: Vec<u64>,
}

impl TryRng for Recorder<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("sampling must draw a whole u64");
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let sample = self.rng.next_u64();
        self.drawn.push(sample);
        Ok(sample)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        panic!("sampling must draw a whole u64");
    }
}

fn hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Checks `p` against `threshold`, the number of `u64` samples the model says it accepts.
fn check(p: Probability, threshold: u128, context: &mut deterministic::Context) {
    assert_eq!(p.is_zero(), threshold == 0);
    assert_eq!(p.is_one(), threshold == SCALE);

    // The samples just below and at the threshold pin it. The endpoints draw nothing, which a
    // script without samples enforces.
    match threshold {
        0 => assert!(!p.sample(&mut ScriptedRng::new([]))),
        SCALE => assert!(p.sample(&mut ScriptedRng::new([]))),
        _ => {
            let threshold = threshold as u64;
            assert!(p.sample(&mut ScriptedRng::new([threshold - 1])));
            assert!(!p.sample(&mut ScriptedRng::new([threshold])));
        }
    }

    // A sample from the runtime draws exactly one `u64` strictly between the endpoints and none
    // at them.
    let mut recorder = Recorder {
        rng: context,
        drawn: Vec::new(),
    };
    let sampled = p.sample(&mut recorder);
    match recorder.drawn[..] {
        [] => assert!((p.is_zero() && !sampled) || (p.is_one() && sampled)),
        [sample] => {
            assert!(!p.is_zero() && !p.is_one());
            assert_eq!(sampled, u128::from(sample) < threshold);
        }
        _ => panic!("sampling drew {} samples", recorder.drawn.len()),
    }

    // The approximation is in [0, 1], is an endpoint only at an endpoint, and is within one unit
    // of the threshold's 53-bit significand, exact when the threshold fits one.
    let value = p.as_f64();
    assert!((0.0..=1.0).contains(&value));
    assert_eq!(value == 0.0, threshold == 0);
    assert_eq!(value == 1.0, threshold == SCALE);
    let scaled = (value * SCALE as f64) as u128;
    let bits = u128::BITS - threshold.leading_zeros();
    let unit = 1u128 << bits.saturating_sub(f64::MANTISSA_DIGITS);
    assert!(scaled.abs_diff(threshold) <= unit);
    if bits <= f64::MANTISSA_DIGITS + threshold.trailing_zeros() {
        assert_eq!(scaled, threshold);
    }
    assert_eq!(format!("{p:?}"), format!("{value:?}"));

    // The approximation is on the grid, so it maps back to a probability with the same
    // approximation.
    let rounded = Probability::from_f64(value).expect("approximation must be on the grid");
    assert_eq!(rounded.as_f64(), value);
}

fn run(plan: Plan) {
    let Plan { ops, entropy } = plan;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|mut context| async move {
        // Oracle: the threshold of every probability constructed so far.
        let mut seen: Vec<(Probability, u128)> = Vec::new();

        for op in ops {
            let (p, threshold) = match op {
                Op::Ratio { fraction, factor } => {
                    let (numerator, denominator) = fraction.resolve();
                    let p = Probability::new(numerator, denominator);

                    // A ratio is refused exactly when it is undefined or exceeds one.
                    assert_eq!(p.is_some(), denominator != 0 && numerator <= denominator);
                    let Some(p) = p else {
                        continue;
                    };
                    assert_eq!(probability!(numerator, denominator), p);

                    // Equal ratios round to the same threshold.
                    let factor = u64::from(factor);
                    if let (Some(n), Some(d)) = (
                        numerator.checked_mul(factor),
                        denominator.checked_mul(factor),
                    ) && factor != 0
                    {
                        assert_eq!(Probability::new(n, d), Some(p));
                    }

                    // Ratios round down to a multiple of 2^-64, and one sits at its own threshold.
                    let threshold = if numerator == denominator {
                        SCALE
                    } else {
                        (u128::from(numerator) << 64) / u128::from(denominator)
                    };
                    (p, threshold)
                }
                Op::Float(float) => {
                    let value = float.value();
                    let p = Probability::from_f64(value);
                    let threshold = on_grid(value);

                    // A float is refused exactly when it is outside [0, 1] or off the grid, and
                    // `TryFrom` agrees.
                    assert_eq!(p.is_some(), threshold.is_some());
                    assert_eq!(Probability::try_from(value), p.ok_or(InvalidProbability));
                    let (Some(p), Some(threshold)) = (p, threshold) else {
                        continue;
                    };

                    // The exact value is preserved. Below one, t / (2^64 - 1) exceeds t / 2^64 by
                    // less than 2^-64, so the ratio constructor rounds down to the same threshold.
                    assert_eq!(p.as_f64(), value);
                    if threshold < SCALE {
                        assert_eq!(Probability::new(threshold as u64, u64::MAX), Some(p));
                    }
                    (p, threshold)
                }
                Op::Sampled(p) => (p, accepted(p)),
            };
            check(p, threshold, &mut context);

            // Global invariants against every earlier probability. Order, equality, and hashing
            // follow the threshold, and the approximation never reverses the order.
            for &(other, other_threshold) in &seen {
                assert_eq!(p.cmp(&other), threshold.cmp(&other_threshold));
                assert_eq!(p == other, threshold == other_threshold);
                if p == other {
                    assert_eq!(hash(&p), hash(&other));
                }
                if p <= other {
                    assert!(p.as_f64() <= other.as_f64());
                }
            }
            seen.push((p, threshold));
        }
    });
}

fuzz_target!(|plan: Plan| {
    run(plan);
});
