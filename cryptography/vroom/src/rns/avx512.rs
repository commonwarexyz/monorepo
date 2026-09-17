//! AVX-512F and AVX-512 IFMA kernels for the eight-lane RNS representation.

use super::{
    BITS, LANES, WORD, WithBackend,
    bounds::Bound,
    kernel::{Kernel, Lanes, RawWide},
    parameters::{Conversion, LaneParameters},
};
use core::arch::x86_64::*;

/// Access token for the AVX-512 implementation.
///
/// The private field ensures native operations are only reachable after checking the exact CPU
/// features they require.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Backend(());

impl Backend {
    /// Constructs the backend when the CPU supports every instruction used by it.
    pub(super) fn new() -> Option<Self> {
        (is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma"))
            .then_some(Self(()))
    }

    /// Runs a complete operation inside one target-feature boundary.
    ///
    /// # Safety
    ///
    /// This may only be called on a token returned by [`Self::new`].
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn call<F: WithBackend>(self, operation: F) -> F::Output {
        operation.call(self)
    }
}

/// Loads one complete RNS value.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn load(input: &Lanes) -> __m512i {
    // SAFETY: `Lanes` contains exactly eight initialized `u64` values and the unaligned load reads
    // precisely those 64 bytes.
    unsafe { _mm512_loadu_si512(input.as_ptr().cast()) }
}

/// Stores one complete RNS value.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn store(input: __m512i) -> Lanes {
    let mut output = [0; LANES];
    // SAFETY: `output` contains space for exactly eight `u64` values and the unaligned store writes
    // precisely those 64 bytes.
    unsafe { _mm512_storeu_si512(output.as_mut_ptr().cast(), input) };
    output
}

/// Multiplies a vector by a power of two used by bounded preparation.
///
/// The bound system restricts lane multiples to fewer than `2^13`, so all reachable offsets and
/// modulus multiples are covered by this fixed public dispatch.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn scale_power_of_two(input: __m512i, power: i64) -> __m512i {
    // SAFETY: the backend token proves that AVX-512F is available.
    unsafe {
        match power {
            1 => input,
            2 => _mm512_slli_epi64::<1>(input),
            4 => _mm512_slli_epi64::<2>(input),
            8 => _mm512_slli_epi64::<3>(input),
            16 => _mm512_slli_epi64::<4>(input),
            32 => _mm512_slli_epi64::<5>(input),
            64 => _mm512_slli_epi64::<6>(input),
            128 => _mm512_slli_epi64::<7>(input),
            256 => _mm512_slli_epi64::<8>(input),
            512 => _mm512_slli_epi64::<9>(input),
            1024 => _mm512_slli_epi64::<10>(input),
            2048 => _mm512_slli_epi64::<11>(input),
            4096 => _mm512_slli_epi64::<12>(input),
            8192 => _mm512_slli_epi64::<13>(input),
            _ => unreachable!("bound multiple is not a supported power of two"),
        }
    }
}

/// Splits and accumulates eight independent 52-by-52-bit products.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn madd(accumulator: RawWide, a: &Lanes, b: &Lanes) -> RawWide {
    // SAFETY: the backend token proves that every intrinsic's required CPU feature is available.
    unsafe {
        let high = load(&accumulator.high);
        let low = load(&accumulator.low);
        let a = load(a);
        let b = load(b);
        RawWide {
            high: store(_mm512_madd52hi_epu64(high, a, b)),
            low: store(_mm512_madd52lo_epu64(low, a, b)),
        }
    }
}

/// Prepares a bounded lane vector for multiplication or a reduction boundary.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn prepare<L: Bound, const TO: i64>(input: &Lanes, parameters: &LaneParameters) -> Lanes {
    const {
        assert!(TO >= 1);
        assert!(L::INTERVAL.lower > -(1 << 13));
        assert!(L::INTERVAL.upper < 1 << 13);
    }

    // SAFETY: the backend token proves that every intrinsic's required CPU feature is available.
    unsafe {
        let modulus = load(&parameters.moduli);
        let mut value = load(input);
        let mut upper = L::INTERVAL.upper;
        if L::INTERVAL.lower < 0 {
            let mut offset = 1;
            while offset < -L::INTERVAL.lower {
                offset *= 2;
            }
            value = _mm512_add_epi64(value, scale_power_of_two(modulus, offset));
            upper += offset;
        }
        if upper <= TO {
            return store(value);
        }

        if (TO == 1 && upper > 4) || (TO > 1 && upper > 2 * TO) {
            let low = _mm512_and_si512(value, _mm512_set1_epi64(((1u64 << BITS) - 1) as i64));
            value = _mm512_madd52lo_epu64(
                low,
                _mm512_srli_epi64::<BITS>(value),
                load(&parameters.complement),
            );
            upper = 2;
        }

        let mut power = 1;
        while power <= (upper - TO) / 2 {
            power *= 2;
        }
        while power > 0 {
            if upper - TO >= power {
                let reduced = _mm512_sub_epi64(value, scale_power_of_two(modulus, power));
                value = _mm512_min_epu64(value, reduced);
            }
            power /= 2;
        }
        store(value)
    }
}

/// Applies the 52-bit Montgomery reduction after carrying the complete low accumulator.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn reduce(input: &RawWide, parameters: &LaneParameters) -> Lanes {
    // SAFETY: the backend token proves that every intrinsic's required CPU feature is available.
    unsafe {
        let low = load(&input.low);
        let high = _mm512_add_epi64(load(&input.high), _mm512_srli_epi64::<WORD>(low));
        let modulus = load(&parameters.moduli);
        let q = _mm512_madd52lo_epu64(_mm512_setzero_si512(), low, load(&parameters.inverse));
        let negative_modulus = _mm512_sub_epi64(_mm512_setzero_si512(), modulus);
        let negative_high = _mm512_madd52hi_epu64(negative_modulus, q, modulus);
        store(_mm512_sub_epi64(high, negative_high))
    }
}

/// Loads the fixed cyclic row `d` derived from an ordinary row-major conversion matrix.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn cyclic_row<const D: usize>(matrix: &[[u64; LANES]; LANES]) -> __m512i {
    const { assert!(D < LANES) };
    // SAFETY: the backend token proves that AVX-512F is available.
    unsafe {
        _mm512_set_epi64(
            matrix[(7 + LANES - D) % LANES][7] as i64,
            matrix[(6 + LANES - D) % LANES][6] as i64,
            matrix[(5 + LANES - D) % LANES][5] as i64,
            matrix[(4 + LANES - D) % LANES][4] as i64,
            matrix[(3 + LANES - D) % LANES][3] as i64,
            matrix[(2 + LANES - D) % LANES][2] as i64,
            matrix[(1 + LANES - D) % LANES][1] as i64,
            matrix[(LANES - D) % LANES][0] as i64,
        )
    }
}

/// Accumulates one row of the fixed cyclic no-k conversion.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn cyclic_step<const D: usize, const B: usize>(
    residues: &mut [__m512i; B],
    high: &mut [__m512i; B],
    low: &mut [__m512i; B],
    matrix: &[[u64; LANES]; LANES],
) {
    const { assert!(D < LANES) };
    // SAFETY: the backend token proves that every intrinsic's required CPU feature is available.
    unsafe {
        if D != 0 {
            let shift = _mm512_set_epi64(6, 5, 4, 3, 2, 1, 0, 7);
            for residue in residues.iter_mut() {
                *residue = _mm512_permutexvar_epi64(shift, *residue);
            }
        }
        let row = cyclic_row::<D>(matrix);
        for i in 0..B {
            high[i] = _mm512_madd52hi_epu64(high[i], row, residues[i]);
            low[i] = _mm512_madd52lo_epu64(low[i], row, residues[i]);
        }
    }
}

/// Changes RNS base using either BLS12-381's fixed no-k schedule or the corrected matrix path.
///
/// # Safety
///
/// The caller must hold a backend token created after checking AVX-512F and AVX-512 IFMA.
#[inline(always)]
unsafe fn change_base<const B: usize>(
    input: &[Lanes; B],
    accumulator: &[RawWide; B],
    conversion: &Conversion,
    no_k: bool,
) -> [RawWide; B] {
    // SAFETY: the private backend token proves that every intrinsic's required CPU feature is
    // available, independently of whether this always-inlined body is ultimately outlined.
    unsafe {
        let zero = _mm512_setzero_si512();
        let mut high = [zero; B];
        let mut low = [zero; B];
        for i in 0..B {
            high[i] = load(&accumulator[i].high);
            low[i] = load(&accumulator[i].low);
        }

        if no_k {
            let mut residues = [zero; B];
            for i in 0..B {
                residues[i] = load(&input[i]);
            }
            cyclic_step::<0, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
            cyclic_step::<1, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
            cyclic_step::<2, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
            cyclic_step::<3, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
            cyclic_step::<4, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
            cyclic_step::<5, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
            cyclic_step::<6, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
            cyclic_step::<7, B>(&mut residues, &mut high, &mut low, &conversion.matrix);
        } else {
            let mut quotient = [0u128; B];
            for (row, coefficients) in conversion.matrix.iter().enumerate() {
                let coefficients = load(coefficients);
                for batch in 0..B {
                    let scalar = input[batch][row];
                    quotient[batch] = quotient[batch]
                        .wrapping_add(u128::from(scalar) * u128::from(conversion.fraction[row]));
                    let scalar = _mm512_set1_epi64(scalar as i64);
                    high[batch] = _mm512_madd52hi_epu64(high[batch], coefficients, scalar);
                    low[batch] = _mm512_madd52lo_epu64(low[batch], coefficients, scalar);
                }
            }

            let correction = load(&conversion.correction);
            let correction_shift = load(&conversion.correction_shift);
            for batch in 0..B {
                let k = (quotient[batch] >> 64) as u64;
                let low_digit = _mm512_set1_epi64(k as i64);
                let high_digit = _mm512_set1_epi64((k >> WORD) as i64);
                high[batch] = _mm512_madd52hi_epu64(high[batch], correction, low_digit);
                low[batch] = _mm512_madd52lo_epu64(low[batch], correction, low_digit);
                high[batch] = _mm512_madd52hi_epu64(high[batch], correction_shift, high_digit);
                low[batch] = _mm512_madd52lo_epu64(low[batch], correction_shift, high_digit);
            }
        }

        let mut output = [RawWide {
            high: [0; LANES],
            low: [0; LANES],
        }; B];
        for i in 0..B {
            output[i] = RawWide {
                high: store(high[i]),
                low: store(low[i]),
            };
        }
        output
    }
}

impl Kernel for Backend {
    #[inline(always)]
    fn madd(self, accumulator: RawWide, a: &Lanes, b: &Lanes) -> RawWide {
        // SAFETY: this backend is only constructed after checking both required features.
        unsafe { madd(accumulator, a, b) }
    }

    #[inline(always)]
    fn prepare<L: Bound, const TO: i64>(self, input: &Lanes, parameters: &LaneParameters) -> Lanes {
        // SAFETY: this backend is only constructed after checking both required features.
        unsafe { prepare::<L, TO>(input, parameters) }
    }

    #[inline(always)]
    fn reduce(self, input: &RawWide, parameters: &LaneParameters) -> Lanes {
        // SAFETY: this backend is only constructed after checking both required features.
        unsafe { reduce(input, parameters) }
    }

    #[inline(always)]
    fn change_base<const B: usize>(
        self,
        input: &[Lanes; B],
        accumulator: &[RawWide; B],
        conversion: &Conversion,
        no_k: bool,
    ) -> [RawWide; B] {
        // SAFETY: this backend is only constructed after checking both required features.
        unsafe { change_base(input, accumulator, conversion, no_k) }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{MASK, bounds::Range, kernel::Portable},
        *,
    };

    const PARAMETERS: LaneParameters = LaneParameters {
        moduli: [
            1125899906842615,
            1125899906842609,
            1125899906842591,
            1125899906842559,
            1125899906842553,
            1125899906842549,
            1125899906842541,
            1125899906842511,
        ],
        complement: [9, 15, 33, 65, 71, 75, 83, 113],
        inverse: [
            875699927544263,
            3677939695685905,
            2285917992680479,
            3100555128074303,
            4138871488534153,
            735587939137181,
            1044509552131109,
            4015377543872367,
        ],
    };

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

    fn check_change_base<const B: usize>(backend: Backend, state: &mut u64) {
        let input: [Lanes; B] = core::array::from_fn(|_| {
            core::array::from_fn(|_| generated(state) & ((1 << BITS) - 1))
        });
        let accumulator: [RawWide; B] = core::array::from_fn(|_| RawWide {
            high: core::array::from_fn(|_| generated(state) & ((1 << 58) - 1)),
            low: core::array::from_fn(|_| generated(state) & ((1 << 61) - 1)),
        });
        let conversion = Conversion {
            matrix: core::array::from_fn(|row| {
                core::array::from_fn(|column| {
                    generated(state).wrapping_add((row * LANES + column) as u64) & ((1 << BITS) - 1)
                })
            }),
            fraction: core::array::from_fn(|_| generated(state)),
            correction: core::array::from_fn(|_| generated(state) & ((1 << BITS) - 1)),
            correction_shift: core::array::from_fn(|_| generated(state) & ((1 << BITS) - 1)),
        };

        for no_k in [false, true] {
            assert_wide_eq(
                &backend.change_base(&input, &accumulator, &conversion, no_k),
                &Portable.change_base(&input, &accumulator, &conversion, no_k),
            );
        }
    }

    #[test]
    fn preparation_folds_at_the_field_radix() {
        let Some(backend) = Backend::new() else {
            return;
        };
        let parameters = LaneParameters {
            moduli: [(1 << BITS) - 9; LANES],
            complement: [9; LANES],
            inverse: [0; LANES],
        };
        let input = [1 << BITS; LANES];

        assert_eq!(
            backend.prepare::<Range<0, 9>, 2>(&input, &parameters),
            Portable.prepare::<Range<0, 9>, 2>(&input, &parameters)
        );
    }

    #[test]
    fn kernels_match_portable() {
        let Some(backend) = Backend::new() else {
            return;
        };
        let mut state = 0x3f84_d5b5_b547_0917;
        for _ in 0..128 {
            let a = core::array::from_fn(|_| generated(&mut state) & ((1 << BITS) - 1));
            let b = core::array::from_fn(|_| generated(&mut state) & ((1 << BITS) - 1));
            let accumulator = RawWide {
                high: core::array::from_fn(|_| generated(&mut state) & ((1 << 58) - 1)),
                low: core::array::from_fn(|_| generated(&mut state) & ((1 << 61) - 1)),
            };
            assert_wide_eq(
                &[backend.madd(accumulator, &a, &b)],
                &[Portable.madd(accumulator, &a, &b)],
            );

            let low = generated(&mut state) & MASK;
            let wide = RawWide {
                high: [u64::MAX; LANES],
                low: [(1 << WORD) + low; LANES],
            };
            assert_eq!(
                backend.reduce(&wide, &PARAMETERS),
                Portable.reduce(&wide, &PARAMETERS)
            );

            let positive =
                core::array::from_fn(|i| generated(&mut state) % (8 * PARAMETERS.moduli[i]));
            assert_eq!(
                backend.prepare::<Range<0, 8>, 4>(&positive, &PARAMETERS),
                Portable.prepare::<Range<0, 8>, 4>(&positive, &PARAMETERS)
            );
            let signed =
                core::array::from_fn(|i| generated(&mut state) % (2 * PARAMETERS.moduli[i]));
            assert_eq!(
                backend.prepare::<Range<-4, 2>, 4>(&signed, &PARAMETERS),
                Portable.prepare::<Range<-4, 2>, 4>(&signed, &PARAMETERS)
            );

            check_change_base::<0>(backend, &mut state);
            check_change_base::<1>(backend, &mut state);
            check_change_base::<3>(backend, &mut state);
            check_change_base::<6>(backend, &mut state);
            check_change_base::<12>(backend, &mut state);
        }
    }
}
