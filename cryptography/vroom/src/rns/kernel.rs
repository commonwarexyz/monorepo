use super::{
    BITS, LANES, MASK, WORD,
    bounds::Bound,
    parameters::{Conversion, LaneParameters},
};
use core::array;

pub(crate) type Lanes = [u64; LANES];

#[derive(Clone, Copy, Debug)]
pub(crate) struct RawWide {
    pub(crate) high: Lanes,
    pub(crate) low: Lanes,
}

impl RawWide {
    pub(crate) const ZERO: Self = Self {
        high: [0; LANES],
        low: [0; LANES],
    };
}

pub(crate) trait Kernel: Copy + core::fmt::Debug + Send + Sync + 'static {
    fn madd(self, accumulator: RawWide, a: &Lanes, b: &Lanes) -> RawWide;
    fn prepare<L: Bound, const TO: i64>(self, input: &Lanes, parameters: &LaneParameters) -> Lanes;
    fn reduce(self, input: &RawWide, parameters: &LaneParameters) -> Lanes;
    fn change_base<const B: usize>(
        self,
        input: &[Lanes; B],
        accumulator: &[RawWide; B],
        conversion: &Conversion,
        no_k: bool,
    ) -> [RawWide; B];
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Portable;

impl Kernel for Portable {
    #[inline(always)]
    fn madd(self, accumulator: RawWide, a: &Lanes, b: &Lanes) -> RawWide {
        let products: [u128; LANES] = array::from_fn(|i| u128::from(a[i]) * u128::from(b[i]));
        RawWide {
            high: array::from_fn(|i| {
                accumulator.high[i].wrapping_add((products[i] >> WORD) as u64)
            }),
            low: array::from_fn(|i| accumulator.low[i].wrapping_add(products[i] as u64 & MASK)),
        }
    }

    #[inline(always)]
    fn prepare<L: Bound, const TO: i64>(self, input: &Lanes, parameters: &LaneParameters) -> Lanes {
        array::from_fn(|i| {
            prepare_lane(
                input[i],
                parameters.moduli[i],
                parameters.complement[i],
                L::INTERVAL.lower,
                L::INTERVAL.upper,
                TO,
            )
        })
    }

    #[inline(always)]
    fn reduce(self, input: &RawWide, parameters: &LaneParameters) -> Lanes {
        array::from_fn(|i| {
            reduce_lane(
                input.high[i],
                input.low[i],
                parameters.moduli[i],
                parameters.inverse[i],
            )
        })
    }

    #[inline(always)]
    fn change_base<const B: usize>(
        self,
        input: &[Lanes; B],
        accumulator: &[RawWide; B],
        conversion: &Conversion,
        no_k: bool,
    ) -> [RawWide; B] {
        array::from_fn(|b| convert_wide(&input[b], accumulator[b], conversion, no_k))
    }
}

pub(crate) const fn quotient(input: &Lanes, fraction: &Lanes) -> u64 {
    let mut total = 0u128;
    let mut i = 0;
    while i < LANES {
        total += input[i] as u128 * fraction[i] as u128;
        i += 1;
    }
    (total >> 64) as u64
}

pub(crate) const fn reduce_lane(high: u64, low: u64, modulus: u64, inverse: u64) -> u64 {
    let high = high.wrapping_add(low >> WORD);
    let q = low.wrapping_mul(inverse) & MASK;
    high.wrapping_add(modulus)
        .wrapping_sub(((q as u128 * modulus as u128) >> WORD) as u64)
}

pub(crate) const fn prepare_lane(
    mut value: u64,
    modulus: u64,
    complement: u64,
    lower: i64,
    mut upper: i64,
    stop: i64,
) -> u64 {
    if lower < 0 {
        let offset = lower.unsigned_abs().next_power_of_two() as i64;
        value = value.wrapping_add((offset as u64) * modulus);
        upper += offset;
    }
    if upper <= stop {
        return value;
    }
    if (stop == 1 && upper > 4) || (stop > 1 && upper > 2 * stop) {
        value = (value & ((1 << BITS) - 1)) + (value >> BITS) * complement;
        upper = 2;
    }
    let mut power = 1i64;
    while power <= (upper - stop) / 2 {
        power *= 2;
    }
    while power > 0 {
        if upper - stop >= power {
            let reduced = value.wrapping_sub(power as u64 * modulus);
            value = if value < reduced { value } else { reduced };
        }
        power /= 2;
    }
    value
}

pub(crate) const fn convert_wide(
    input: &Lanes,
    mut out: RawWide,
    conversion: &Conversion,
    no_k: bool,
) -> RawWide {
    let mut row = 0;
    while row < LANES {
        let mut column = 0;
        while column < LANES {
            let product = input[row] as u128 * conversion.matrix[row][column] as u128;
            out.high[column] = out.high[column].wrapping_add((product >> WORD) as u64);
            out.low[column] = out.low[column].wrapping_add(product as u64 & MASK);
            column += 1;
        }
        row += 1;
    }
    if !no_k {
        let k = quotient(input, &conversion.fraction);
        let mut i = 0;
        while i < LANES {
            let first = (k & MASK) as u128 * conversion.correction[i] as u128;
            let second = (k >> WORD) as u128 * conversion.correction_shift[i] as u128;
            out.high[i] = out.high[i]
                .wrapping_add((first >> WORD) as u64)
                .wrapping_add((second >> WORD) as u64);
            out.low[i] = out.low[i]
                .wrapping_add(first as u64 & MASK)
                .wrapping_add(second as u64 & MASK);
            i += 1;
        }
    }
    out
}
