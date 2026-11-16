#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Copying, DecodeExt as _, Error, FixedSize, U256, Uint};
use commonware_runtime::{Runner, deterministic};
use commonware_utils::{Amount, Entropy, FuzzRng};
use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use num_traits::{One as _, Zero as _};
use rand_core::Rng as _;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

/// A width whose top limb is partial, so its encoding drops the limb's unused bytes.
type U72 = Uint<72, 2>;

/// A width that ends inside a byte, so decoding must refuse the bits beyond it.
type U36 = Uint<36, 1>;

/// Bytes of the widest amount, enough to sample any value of every width.
const MAX_BYTES: usize = U256::SIZE;

/// Most operations a plan applies. Every balance stays within its width, so a few dozen operations
/// already drive it across both boundaries many times.
const MAX_OPS: usize = 32;

/// Most amounts a batch credits. Order only matters when some running sum overflows, which a
/// handful of near-boundary amounts already reaches.
const MAX_BATCH: usize = 8;

/// Operands near a boundary sit less than this far from it, so two of them often meet it exactly.
const MAX_OFFSET: u8 = 16;

/// Bytes of the stream a plan is sampled from, several times the largest plan, of the input's head
/// that seeds the stream, and of the stream's tail that seeds the runtime.
const STREAM_BYTES: usize = 1 << 12;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

/// Every primitive implementation and three [`Uint`] shapes: whole limbs, a partial top limb,
/// and a width that ends inside a byte.
#[derive(Arbitrary, Debug)]
enum Width {
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    U72,
    U36,
}

/// Uniform values of a wide amount almost never sit next to a boundary, so most operands are
/// offsets from the boundaries where addition and subtraction overflow.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Operand {
    /// `offset` above zero.
    Low(u8),
    /// `offset` below the largest value.
    High(u8),
    /// `offset` from half the modulus, where two operands sum to the modulus.
    Half(i8),
    /// Any value, reduced to the width.
    Raw([u8; MAX_BYTES]),
}

/// How many bytes a decode reads relative to the encoded size.
#[derive(Arbitrary, Debug)]
enum Len {
    Short,
    Exact,
    Long,
}

#[derive(Arbitrary, Debug)]
enum Op {
    Pair(Operand, Operand),
    Credit(Operand),
    Debit(Operand),
    Wrap {
        operand: Operand,
        add: bool,
    },
    Batch(#[arbitrary(with = batch)] Vec<Operand>),
    Decode {
        bytes: [u8; MAX_BYTES + 1],
        len: Len,
    },
}

fn batch(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<Operand>> {
    (0..u.int_in_range(0..=MAX_BATCH)?)
        .map(|_| u.arbitrary())
        .collect()
}

#[derive(Debug)]
struct Plan {
    width: Width,
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for Plan {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a plan
        // sampled from so few bytes would hold one operation on zero. The input's head therefore
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
            width: u.arbitrary()?,
            ops: (0..u.int_in_range(1..=MAX_OPS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
}

/// An amount the model converts exactly.
trait Modeled: Amount {
    /// Width in bits.
    const BITS: usize;

    /// Returns the amount holding `value`, which must be below `2^BITS`.
    fn from_model(value: &BigUint) -> Self;

    /// Returns the value of the amount.
    fn to_model(self) -> BigUint;
}

macro_rules! impl_modeled {
    ($($type:ty),*) => {
        $(
            impl Modeled for $type {
                const BITS: usize = <$type>::BITS as usize;

                fn from_model(value: &BigUint) -> Self {
                    Self::try_from(value).expect("value exceeds the width")
                }

                fn to_model(self) -> BigUint {
                    BigUint::from(self)
                }
            }
        )*
    };
}

impl_modeled!(u8, u16, u32, u64, u128);

impl<const BITS: usize, const LIMBS: usize> Modeled for Uint<BITS, LIMBS> {
    const BITS: usize = BITS;

    fn from_model(value: &BigUint) -> Self {
        let mut digits = value.iter_u64_digits();
        let limbs = core::array::from_fn(|_| digits.next().unwrap_or(0));
        assert!(digits.next().is_none(), "value exceeds the width");
        Self::from_limbs(limbs)
    }

    fn to_model(self) -> BigUint {
        self.as_limbs()
            .iter()
            .rev()
            .fold(BigUint::zero(), |value, limb| (value << 64) + *limb)
    }
}

impl Operand {
    /// Returns the value of the operand at a width of `bits`, which is at least 8.
    fn value(self, bits: usize) -> BigUint {
        let modulus = BigUint::one() << bits;
        let half = BigUint::one() << (bits - 1);
        match self {
            Self::Low(offset) => BigUint::from(offset % MAX_OFFSET),
            Self::High(offset) => modulus - 1u8 - offset % MAX_OFFSET,
            Self::Half(offset) if offset < 0 => half - offset.unsigned_abs() % MAX_OFFSET,
            Self::Half(offset) => half + offset.unsigned_abs() % MAX_OFFSET,
            Self::Raw(bytes) => BigUint::from_bytes_be(&bytes) % modulus,
        }
    }
}

fn hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Checks every operation on two amounts against arbitrary-precision arithmetic.
fn check_pair<T: Modeled>(a: &BigUint, b: &BigUint, modulus: &BigUint) {
    let (x, y) = (T::from_model(a), T::from_model(b));

    // Addition wraps to the width and overflows exactly when the sum reaches the modulus.
    let sum = a + b;
    let overflowed = sum >= *modulus;
    assert_eq!(
        x.overflowing_add(y),
        (T::from_model(&(&sum % modulus)), overflowed)
    );
    assert_eq!(x.checked_add(y), (!overflowed).then(|| T::from_model(&sum)));
    assert_eq!(x.overflowing_add(y), y.overflowing_add(x));

    // Subtraction wraps to the width and is negative exactly when the subtrahend is larger.
    let negative = a < b;
    let difference = (a + modulus - b) % modulus;
    assert_eq!(x.overflowing_sub(y), (T::from_model(&difference), negative));
    assert_eq!(
        x.checked_sub(y),
        (!negative).then(|| T::from_model(&difference))
    );

    // Subtracting undoes adding, and is negative exactly when adding overflowed.
    let (wrapped, overflowed) = x.overflowing_add(y);
    assert_eq!(wrapped.overflowing_sub(y), (x, overflowed));

    // Zero is the identity and the least amount.
    assert_eq!(x.checked_add(T::ZERO), Some(x));
    assert_eq!(x.checked_sub(T::ZERO), Some(x));
    assert_eq!(x.checked_sub(x), Some(T::ZERO));
    assert_eq!(T::ZERO.checked_sub(x), (x == T::ZERO).then_some(T::ZERO));

    // Amounts order numerically, and only equal amounts share an encoding.
    assert_eq!(x.cmp(&y), a.cmp(b));
    assert_eq!(x.encode() == y.encode(), a == b);
    if x == y {
        assert_eq!(hash(&x), hash(&y));
    }
}

fn apply<T: Modeled>(ops: Vec<Op>, context: &mut deterministic::Context) {
    let modulus = BigUint::one() << T::BITS;
    assert_eq!(T::SIZE, T::BITS.div_ceil(8));

    // Oracle: the value of a balance moved only through `Amount`. A credit that would overflow
    // and a debit that would go negative leave it unchanged.
    let mut balance = T::ZERO;
    let mut model = BigUint::zero();

    for op in ops {
        match op {
            Op::Pair(a, b) => {
                check_pair::<T>(&a.value(T::BITS), &b.value(T::BITS), &modulus);
            }
            Op::Credit(operand) => {
                let amount = operand.value(T::BITS);
                let credited = balance.checked_add(T::from_model(&amount));
                let sum = &model + amount;
                assert_eq!(credited.is_some(), sum < modulus);
                if let Some(credited) = credited {
                    balance = credited;
                    model = sum;
                }
            }
            Op::Debit(operand) => {
                let amount = operand.value(T::BITS);
                let debited = balance.checked_sub(T::from_model(&amount));
                assert_eq!(debited.is_some(), amount <= model);
                if let Some(debited) = debited {
                    balance = debited;
                    model -= amount;
                }
            }
            Op::Wrap { operand, add } => {
                // The balance moves around the modulus, flagged exactly when it crosses the
                // boundary between the largest value and zero.
                let amount = operand.value(T::BITS);
                let (wrapped, crossed) = if add {
                    balance.overflowing_add(T::from_model(&amount))
                } else {
                    balance.overflowing_sub(T::from_model(&amount))
                };
                let shifted = if add {
                    &model + amount
                } else {
                    &model + &modulus - amount
                };
                assert_eq!(crossed, (shifted >= modulus) == add);
                balance = wrapped;
                model = shifted % &modulus;
            }
            Op::Batch(operands) => {
                let mut amounts: Vec<_> = operands.iter().map(|o| o.value(T::BITS)).collect();
                for i in (1..amounts.len()).rev() {
                    let j = context.next_u64() % (i as u64 + 1);
                    amounts.swap(i, j as usize);
                }
                let credited = amounts.iter().try_fold(balance, |balance, amount| {
                    balance.checked_add(T::from_model(amount))
                });

                // Amounts are never negative, so no running sum exceeds the total and a batch
                // fits in any order exactly when its total does.
                let total = &model + amounts.iter().sum::<BigUint>();
                assert_eq!(credited.is_some(), total < modulus);
                if let Some(credited) = credited {
                    balance = credited;
                    model = total;
                }
            }
            Op::Decode { bytes, len } => {
                // Bytes holding a value within the width decode to it and re-encode unchanged,
                // and any other bytes are refused, so every value has exactly one encoding.
                let value = BigUint::from_bytes_be(&bytes[..T::SIZE]);
                let fits = value < modulus;
                let read = match len {
                    Len::Short => T::SIZE - 1,
                    Len::Exact => T::SIZE,
                    Len::Long => T::SIZE + 1,
                };
                match (&len, T::decode(Copying(&bytes[..read]))) {
                    (Len::Short, Err(Error::EndOfBuffer)) => {}
                    (Len::Exact, Ok(amount)) if fits => {
                        assert_eq!(amount.to_model(), value);
                        assert_eq!(amount.encode().as_ref(), &bytes[..read]);
                    }
                    (Len::Exact | Len::Long, Err(Error::Invalid(..))) if !fits => {}
                    (Len::Long, Err(Error::ExtraData(1))) if fits => {}
                    (len, decoded) => panic!("{len:?} bytes of {value} decoded to {decoded:?}"),
                }
            }
        }

        // Global invariants after every op. The balance matches the oracle, sits at or above
        // zero, and survives an encoding round trip at the fixed width.
        assert_eq!(balance.to_model(), model);
        assert!(T::ZERO <= balance);
        let encoded = balance.encode();
        assert_eq!(encoded.len(), T::SIZE);
        assert_eq!(T::decode(encoded).unwrap(), balance);
    }
}

fn run(plan: Plan) {
    let Plan {
        width,
        ops,
        entropy,
    } = plan;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|mut context| async move {
        match width {
            Width::U8 => apply::<u8>(ops, &mut context),
            Width::U16 => apply::<u16>(ops, &mut context),
            Width::U32 => apply::<u32>(ops, &mut context),
            Width::U64 => apply::<u64>(ops, &mut context),
            Width::U128 => apply::<u128>(ops, &mut context),
            Width::U256 => apply::<U256>(ops, &mut context),
            Width::U72 => apply::<U72>(ops, &mut context),
            Width::U36 => apply::<U36>(ops, &mut context),
        }
    });
}

fuzz_target!(|plan: Plan| {
    run(plan);
});
