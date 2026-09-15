//! Arm NEON kernels for the 16-lane, 26-bit RNS representation.

use super::{
    BITS, LANES, WORD,
    bounds::Bound,
    kernel::{Kernel, Lanes, RawWide},
    parameters::{Conversion, LaneParameters},
};
use core::arch::aarch64::*;

const WIDTH: usize = 4;
const WIDE_WIDTH: usize = 2;
const WORD_SHIFT: i32 = 32;
const BITS_SHIFT: i32 = 26;
const ELEMENT_MASK: u32 = (1 << BITS) - 1;
const _: () = assert!(WORD == WORD_SHIFT as u32 && BITS == BITS_SHIFT as u32);

/// The Arm NEON backend token.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Backend;

impl Backend {
    #[inline(always)]
    pub(super) const fn new() -> Self {
        Self
    }
}

#[inline(always)]
fn narrow4(values: &Lanes, offset: usize) -> uint32x4_t {
    assert!(offset + WIDTH <= LANES);
    // SAFETY: The offset assertion covers both two-lane loads, and every supported AArch64
    // target provides NEON. Callers prove that each lane fits in one 32-bit word.
    unsafe {
        vcombine_u32(
            vmovn_u64(vld1q_u64(values.as_ptr().add(offset))),
            vmovn_u64(vld1q_u64(values.as_ptr().add(offset + WIDE_WIDTH))),
        )
    }
}

#[inline(always)]
fn mac4(accumulator: &mut RawWide, offset: usize, a: uint32x4_t, b: uint32x4_t) {
    assert!(offset + WIDTH <= LANES);
    // SAFETY: The offset assertion covers every two-lane load and store. VMULL produces the
    // complete 32x32-bit products before their word halves are accumulated independently.
    unsafe {
        let first = vmull_u32(vget_low_u32(a), vget_low_u32(b));
        let second = vmull_high_u32(a, b);
        let low = accumulator.low.as_mut_ptr().add(offset);
        let high = accumulator.high.as_mut_ptr().add(offset);

        vst1q_u64(low, vaddw_u32(vld1q_u64(low), vmovn_u64(first)));
        vst1q_u64(
            high,
            vaddq_u64(vld1q_u64(high), vshrq_n_u64::<WORD_SHIFT>(first)),
        );
        vst1q_u64(
            low.add(WIDE_WIDTH),
            vaddw_u32(vld1q_u64(low.add(WIDE_WIDTH)), vmovn_u64(second)),
        );
        vst1q_u64(
            high.add(WIDE_WIDTH),
            vaddq_u64(
                vld1q_u64(high.add(WIDE_WIDTH)),
                vshrq_n_u64::<WORD_SHIFT>(second),
            ),
        );
    }
}

#[inline(always)]
fn mac_scalar(accumulator: &mut RawWide, coefficients: &Lanes, scalar: u32) {
    // SAFETY: Duplicating a scalar has no memory or lane preconditions.
    let scalar = unsafe { vdupq_n_u32(scalar) };
    for offset in (0..LANES).step_by(WIDTH) {
        mac4(accumulator, offset, narrow4(coefficients, offset), scalar);
    }
}

#[inline(always)]
fn scale_power_of_two(input: uint64x2_t, power: u64) -> uint64x2_t {
    // SAFETY: Immediate vector shifts have no memory preconditions. The preparation bounds
    // restrict every reachable public power to this fixed dispatch.
    unsafe {
        match power {
            1 => input,
            2 => vshlq_n_u64::<1>(input),
            4 => vshlq_n_u64::<2>(input),
            8 => vshlq_n_u64::<3>(input),
            16 => vshlq_n_u64::<4>(input),
            32 => vshlq_n_u64::<5>(input),
            64 => vshlq_n_u64::<6>(input),
            128 => vshlq_n_u64::<7>(input),
            256 => vshlq_n_u64::<8>(input),
            512 => vshlq_n_u64::<9>(input),
            1024 => vshlq_n_u64::<10>(input),
            2048 => vshlq_n_u64::<11>(input),
            4096 => vshlq_n_u64::<12>(input),
            8192 => vshlq_n_u64::<13>(input),
            _ => unreachable!("bound multiple is not a supported power of two"),
        }
    }
}

#[inline(always)]
fn add_offset(values: &mut Lanes, moduli: &Lanes, offset: u64) {
    assert!(offset.is_power_of_two());
    for lane in (0..LANES).step_by(WIDE_WIDTH) {
        // SAFETY: Each iteration accesses exactly `lane..lane + 2`. The bound owner proves
        // that the shifted modulus and adjusted nonnegative representative fit in `u64`.
        unsafe {
            let value = vld1q_u64(values.as_ptr().add(lane));
            let modulus = vld1q_u64(moduli.as_ptr().add(lane));
            let shifted = scale_power_of_two(modulus, offset);
            vst1q_u64(values.as_mut_ptr().add(lane), vaddq_u64(value, shifted));
        }
    }
}

#[inline(always)]
fn mask_reduce(values: &Lanes, parameters: &LaneParameters) -> Lanes {
    let mut output = [0u64; LANES];
    for offset in (0..LANES).step_by(WIDTH) {
        // SAFETY: Each iteration loads four input, complement, and output lanes. The input
        // bound proves the shifted lanes fit `u32`; `c <= 153` proves the MLA result is below
        // `2^32`, so widening the result back to storage lanes is exact.
        unsafe {
            let first = vld1q_u64(values.as_ptr().add(offset));
            let second = vld1q_u64(values.as_ptr().add(offset + WIDE_WIDTH));
            let high = vcombine_u32(
                vshrn_n_u64::<BITS_SHIFT>(first),
                vshrn_n_u64::<BITS_SHIFT>(second),
            );
            let low = vandq_u32(
                vcombine_u32(vmovn_u64(first), vmovn_u64(second)),
                vdupq_n_u32(ELEMENT_MASK),
            );
            let complement = narrow4(&parameters.complement, offset);
            let reduced = vmlaq_u32(low, high, complement);
            vst1q_u64(
                output.as_mut_ptr().add(offset),
                vmovl_u32(vget_low_u32(reduced)),
            );
            vst1q_u64(
                output.as_mut_ptr().add(offset + WIDE_WIDTH),
                vmovl_high_u32(reduced),
            );
        }
    }
    output
}

#[inline(always)]
fn min_sub(values: &mut Lanes, moduli: &Lanes, upper: i64, stop: i64) {
    let mut power = 1i64;
    while power <= (upper - stop) / 2 {
        power *= 2;
    }
    while power > 0 {
        if upper - stop >= power {
            for lane in (0..LANES).step_by(WIDE_WIDTH) {
                // SAFETY: Each iteration accesses exactly `lane..lane + 2`. `power` is a
                // power of two and the bound owner proves `power * modulus < 2^64`. On
                // underflow the wrapped difference is larger, so the unsigned selection
                // retains the original value.
                unsafe {
                    let value = vld1q_u64(values.as_ptr().add(lane));
                    let modulus = vld1q_u64(moduli.as_ptr().add(lane));
                    let multiple = scale_power_of_two(modulus, power as u64);
                    let reduced = vsubq_u64(value, multiple);
                    let underflow = vcltq_u64(value, reduced);
                    vst1q_u64(
                        values.as_mut_ptr().add(lane),
                        vbslq_u64(underflow, value, reduced),
                    );
                }
            }
        }
        power /= 2;
    }
}

#[inline(always)]
fn quotient(input: &Lanes, fraction: &Lanes) -> u64 {
    // SAFETY: Constructing a zero vector has no preconditions.
    let mut total_low = unsafe { vdupq_n_u64(0) };
    let mut total_high = total_low;
    for lane in (0..LANES).step_by(WIDE_WIDTH) {
        // SAFETY: Each iteration loads exactly `lane..lane + 2`. Inputs fit one word while
        // fractions use both words. The two vector accumulators retain every carry.
        unsafe {
            let input = vmovn_u64(vld1q_u64(input.as_ptr().add(lane)));
            let fraction = vld1q_u64(fraction.as_ptr().add(lane));
            let product_low = vmull_u32(input, vmovn_u64(fraction));
            let product_high = vmull_u32(input, vshrn_n_u64::<WORD_SHIFT>(fraction));

            let shifted_high = vshlq_n_u64::<WORD_SHIFT>(product_high);
            let lane_low = vaddq_u64(product_low, shifted_high);
            let lane_carry = vandq_u64(vcltq_u64(lane_low, product_low), vdupq_n_u64(1));
            let lane_high = vaddq_u64(vshrq_n_u64::<WORD_SHIFT>(product_high), lane_carry);

            let next_low = vaddq_u64(total_low, lane_low);
            let total_carry = vandq_u64(vcltq_u64(next_low, total_low), vdupq_n_u64(1));
            total_low = next_low;
            total_high = vaddq_u64(vaddq_u64(total_high, lane_high), total_carry);
        }
    }

    // SAFETY: Both accumulators contain two initialized lanes. Adding their 128-bit values
    // completes the horizontal reduction; the quotient contract proves the high word fits.
    unsafe {
        let carry = vgetq_lane_u64::<0>(total_low)
            .overflowing_add(vgetq_lane_u64::<1>(total_low))
            .1;
        vgetq_lane_u64::<0>(total_high)
            .wrapping_add(vgetq_lane_u64::<1>(total_high))
            .wrapping_add(u64::from(carry))
    }
}

impl Kernel for Backend {
    #[inline(always)]
    fn madd(self, mut accumulator: RawWide, a: &Lanes, b: &Lanes) -> RawWide {
        for offset in (0..LANES).step_by(WIDTH) {
            mac4(
                &mut accumulator,
                offset,
                narrow4(a, offset),
                narrow4(b, offset),
            );
        }
        accumulator
    }

    #[inline(always)]
    fn prepare<L: Bound, const TO: i64>(self, input: &Lanes, parameters: &LaneParameters) -> Lanes {
        const {
            assert!(TO >= 1);
            assert!(L::INTERVAL.lower > -(1 << 13));
            assert!(L::INTERVAL.upper < 1 << 13);
        }
        let mut values = *input;
        let lower = L::INTERVAL.lower;
        let mut upper = L::INTERVAL.upper;
        if lower < 0 {
            let offset = lower.unsigned_abs().next_power_of_two();
            add_offset(&mut values, &parameters.moduli, offset);
            upper += offset as i64;
        }
        if upper <= TO {
            return values;
        }
        if (TO == 1 && upper > 4) || (TO > 1 && upper > 2 * TO) {
            assert!(upper <= u32::MAX as i64);
            assert!((upper as u128) * 153 + u128::from(ELEMENT_MASK) <= u128::from(u32::MAX));
            values = mask_reduce(&values, parameters);
            upper = 2;
        }
        min_sub(&mut values, &parameters.moduli, upper, TO);
        values
    }

    #[inline(always)]
    fn reduce(self, input: &RawWide, parameters: &LaneParameters) -> Lanes {
        let mut output = [0u64; LANES];
        for lane in (0..LANES).step_by(WIDE_WIDTH) {
            // SAFETY: Each iteration accesses exactly `lane..lane + 2`. The wide contract
            // proves `high + (low >> WORD)` is a nonnegative bounded word value. Moduli and
            // inverses fit `u32`, and the redundant result is below 46 moduli and `2^32`.
            unsafe {
                let low = vld1q_u64(input.low.as_ptr().add(lane));
                let high = vaddq_u64(
                    vld1q_u64(input.high.as_ptr().add(lane)),
                    vshrq_n_u64::<WORD_SHIFT>(low),
                );
                let modulus = vmovn_u64(vld1q_u64(parameters.moduli.as_ptr().add(lane)));
                let inverse = vmovn_u64(vld1q_u64(parameters.inverse.as_ptr().add(lane)));
                let q = vmovn_u64(vmull_u32(vmovn_u64(low), inverse));
                let h = vshrn_n_u64::<WORD_SHIFT>(vmull_u32(q, modulus));
                let reduced = vmovn_u64(vsubw_u32(vaddw_u32(high, modulus), h));
                vst1q_u64(output.as_mut_ptr().add(lane), vmovl_u32(reduced));
            }
        }
        output
    }

    #[inline(always)]
    fn change_base<const B: usize>(
        self,
        input: &[Lanes; B],
        accumulator: &[RawWide; B],
        conversion: &Conversion,
        no_k: bool,
    ) -> [RawWide; B] {
        let mut output = *accumulator;
        for (row, matrix_row) in conversion.matrix.iter().enumerate() {
            for offset in (0..LANES).step_by(WIDTH) {
                let coefficients = narrow4(matrix_row, offset);
                for batch in 0..B {
                    debug_assert!(input[batch][row] <= u64::from(u32::MAX));
                    // SAFETY: Duplicating a caller-proved word-sized input has no memory or
                    // lane preconditions.
                    let value = unsafe { vdupq_n_u32(input[batch][row] as u32) };
                    mac4(&mut output[batch], offset, coefficients, value);
                }
            }
        }
        if !no_k {
            for batch in 0..B {
                let k = quotient(&input[batch], &conversion.fraction);
                mac_scalar(&mut output[batch], &conversion.correction, k as u32);
                mac_scalar(
                    &mut output[batch],
                    &conversion.correction_shift,
                    (k >> WORD) as u32,
                );
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{bounds::Range, kernel::Portable},
        *,
    };

    fn inverse32(odd: u64) -> u64 {
        let mut inverse = odd as u32;
        for _ in 0..5 {
            inverse = inverse.wrapping_mul(2u32.wrapping_sub((odd as u32).wrapping_mul(inverse)));
        }
        u64::from(inverse)
    }

    fn parameters() -> LaneParameters {
        let moduli = core::array::from_fn(|i| (1u64 << BITS) - (10 * i as u64 + 1));
        LaneParameters {
            complement: moduli.map(|modulus| (1 << BITS) - modulus),
            inverse: moduli.map(inverse32),
            moduli,
        }
    }

    fn generated(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn assert_wide_eq<const B: usize>(actual: &[RawWide; B], expected: &[RawWide; B]) {
        for (actual, expected) in actual.iter().zip(expected) {
            assert_eq!(actual.high, expected.high);
            assert_eq!(actual.low, expected.low);
        }
    }

    fn check_change_base<const B: usize>(
        backend: Backend,
        parameters: &LaneParameters,
        state: &mut u64,
    ) {
        let input: [Lanes; B] = core::array::from_fn(|_| {
            core::array::from_fn(|i| generated(state) % (64 * parameters.moduli[i]))
        });
        let accumulator: [RawWide; B] = core::array::from_fn(|_| RawWide {
            high: core::array::from_fn(|_| generated(state)),
            low: core::array::from_fn(|_| generated(state)),
        });
        let conversion = Conversion {
            matrix: core::array::from_fn(|_| {
                core::array::from_fn(|i| generated(state) % parameters.moduli[i])
            }),
            fraction: core::array::from_fn(|_| generated(state)),
            correction: core::array::from_fn(|i| generated(state) % parameters.moduli[i]),
            correction_shift: core::array::from_fn(|i| generated(state) % parameters.moduli[i]),
        };

        for no_k in [false, true] {
            assert_wide_eq(
                &backend.change_base(&input, &accumulator, &conversion, no_k),
                &Portable.change_base(&input, &accumulator, &conversion, no_k),
            );
        }
    }

    #[test]
    fn kernels_match_portable() {
        let backend = Backend::new();
        let parameters = parameters();
        let mut state = 0x3f84_d5b5_b547_0917;
        let rounds = if cfg!(miri) { 4 } else { 128 };
        for round in 0..rounds {
            let a = core::array::from_fn(|i| generated(&mut state) % (64 * parameters.moduli[i]));
            let b = core::array::from_fn(|i| generated(&mut state) % (64 * parameters.moduli[i]));
            let accumulator = RawWide {
                high: core::array::from_fn(|_| generated(&mut state)),
                low: core::array::from_fn(|_| generated(&mut state)),
            };
            assert_wide_eq(
                &[backend.madd(accumulator, &a, &b)],
                &[Portable.madd(accumulator, &a, &b)],
            );

            let positive =
                core::array::from_fn(|i| generated(&mut state) % (800 * parameters.moduli[i]));
            assert_eq!(
                backend.prepare::<Range<0, 800>, 4>(&positive, &parameters),
                Portable.prepare::<Range<0, 800>, 4>(&positive, &parameters)
            );
            let capacity =
                core::array::from_fn(|i| generated(&mut state) % (128 * parameters.moduli[i]));
            assert_eq!(
                backend.prepare::<Range<0, 128>, 64>(&capacity, &parameters),
                Portable.prepare::<Range<0, 128>, 64>(&capacity, &parameters)
            );
            let signed = core::array::from_fn(|i| {
                generated(&mut state)
                    .wrapping_rem(26 * parameters.moduli[i])
                    .wrapping_sub(24 * parameters.moduli[i])
            });
            assert_eq!(
                backend.prepare::<Range<-24, 2>, 4>(&signed, &parameters),
                Portable.prepare::<Range<-24, 2>, 4>(&signed, &parameters)
            );

            let mut wide = RawWide::ZERO;
            for i in 0..LANES {
                if round == 0 {
                    wide.high[i] = u64::MAX;
                    wide.low[i] = 1 << WORD;
                    continue;
                }
                let modulus = u128::from(parameters.moduli[i]);
                let value = ((u128::from(generated(&mut state)) << 64)
                    | u128::from(generated(&mut state)))
                    % (2848 * modulus * modulus);
                let normalized_high = (value >> WORD) as u64;
                let transfer = generated(&mut state) % (normalized_high.min(2847) + 1);
                wide.high[i] = normalized_high.wrapping_sub(transfer);
                wide.low[i] = value as u32 as u64 + (transfer << WORD);
            }
            assert_eq!(
                backend.reduce(&wide, &parameters),
                Portable.reduce(&wide, &parameters)
            );

            check_change_base::<0>(backend, &parameters, &mut state);
            check_change_base::<1>(backend, &parameters, &mut state);
            check_change_base::<3>(backend, &parameters, &mut state);
            check_change_base::<6>(backend, &parameters, &mut state);
            check_change_base::<12>(backend, &parameters, &mut state);
        }
    }
}
