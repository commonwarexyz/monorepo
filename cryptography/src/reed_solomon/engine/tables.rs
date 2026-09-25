//! Lookup tables used by [`Engine`] implementations.
//!
//! All tables are global and each is initialized at most once.
//!
//! # Tables
//!
//! | Table        | Size    | Used in encoding | Used in decoding | By engines         |
//! | ------------ | ------- | ---------------- | ---------------- | ------------------ |
//! | [`Exp`]      | 128 KiB | yes              | yes              | all                |
//! | [`Log`]      | 128 KiB | yes              | yes              | all                |
//! | [`LogWalsh`] | 128 KiB | -                | yes              | all                |
//! | Short Walsh  | < 128 KiB | -              | yes              | all                |
//! | [`Mul16`]    | 8 MiB   | yes              | yes              | [`NoSimd`]         |
//! | [`Mul128`]   | 8 MiB   | yes              | yes              | `Neon` `Avx2` `Ssse3` |
//! | `MulGfni`    | 2 MiB   | yes              | yes              | `Avx512` |
//! | [`Skew`]     | 128 KiB | yes              | yes              | all                |
//!
//! [`LogWalsh`] serves decoding domains of `GF_ORDER` positions. A smaller power-of-two
//! domain of `n` positions uses an `n`-entry short Walsh kernel, built on first use for
//! each `n`.
//!
//! [`NoSimd`]: crate::reed_solomon::engine::NoSimd
//! [`Engine`]: crate::reed_solomon::engine

use crate::reed_solomon::engine::{
    CANTOR_BASIS, GF_BITS, GF_MODULUS, GF_ORDER, GF_POLYNOMIAL, GfElement, fwht, utils,
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox;
#[cfg(feature = "std")]
use std::sync::{LazyLock, OnceLock};

/// Used by [`Naive`] engine for multiplications
/// and by all [`Engine`] implementations to initialize other tables.
///
/// Maps a logarithm to its field element. Entries `0` and `GF_MODULUS` both hold one.
///
/// [`Naive`]: crate::reed_solomon::engine::Naive
/// [`Engine`]: crate::reed_solomon::engine
pub type Exp = [GfElement; GF_ORDER];

/// Used by [`Naive`] engine for multiplications
/// and by all [`Engine`] implementations to initialize other tables.
///
/// Maps a field element to its logarithm in `0..GF_MODULUS`. Zero has no logarithm and maps
/// to `GF_MODULUS`.
///
/// [`Naive`]: crate::reed_solomon::engine::Naive
/// [`Engine`]: crate::reed_solomon::engine
pub type Log = [GfElement; GF_ORDER];

/// Used by `Neon`, `Avx2`, and `Ssse3` engines for multiplications.
///
/// Indexed by multiplier logarithm.
pub type Mul128 = [Multiply128lutT; GF_ORDER];

/// GFNI affine matrices indexed by multiplier logarithm.
///
/// Entry `GF_MODULUS` duplicates the identity at entry zero.
#[cfg(any(test, target_arch = "x86", target_arch = "x86_64"))]
pub(crate) type MulGfni = [MultiplyGfni; GF_ORDER];

/// GF2P8AFFINEQB matrices for multiplication by one field element.
///
/// Multiplication is a 16 x 16 binary linear map, split into four 8 x 8 maps between
/// the input and output byte halves. In each matrix, byte `7 - i` holds the row for output
/// bit `i`, and bit `j` of that row selects input bit `j`.
#[cfg(any(test, target_arch = "x86", target_arch = "x86_64"))]
#[derive(Clone, Debug)]
pub(crate) struct MultiplyGfni {
    /// Maps the low input byte to the low output byte.
    pub(crate) low_from_low: u64,
    /// Maps the high input byte to the low output byte.
    pub(crate) low_from_high: u64,
    /// Maps the low input byte to the high output byte.
    pub(crate) high_from_low: u64,
    /// Maps the high input byte to the high output byte.
    pub(crate) high_from_high: u64,
}

/// Multiplication lookup bytes for the four nibbles of a field element.
///
/// Byte `x` of `lo[i].to_ne_bytes()` and `hi[i].to_ne_bytes()` holds the low and high byte
/// of the product of `x << (4 * i)` and the multiplier.
#[derive(Clone, Debug)]
pub struct Multiply128lutT {
    /// Low product bytes for each nibble position.
    pub lo: [u128; 4],
    /// High product bytes for each nibble position.
    pub hi: [u128; 4],
}

/// Used by all [`Engine`] implementations in [`Engine::eval_poly`].
///
/// [`Engine`]: crate::reed_solomon::engine
/// [`Engine::eval_poly`]: crate::reed_solomon::engine::Engine::eval_poly
pub type LogWalsh = [GfElement; GF_ORDER];

/// Used by [`NoSimd`] engine for multiplications.
///
/// Entry `[log_m][i][x]` is the product of `x << (4 * i)` and the element with logarithm
/// `log_m`.
///
/// [`NoSimd`]: crate::reed_solomon::engine::NoSimd
pub type Mul16 = [[[GfElement; 16]; 4]; GF_ORDER];

/// Used by all [`Engine`] implementations for FFT and IFFT.
///
/// Holds the logarithms of the butterfly coefficients. A `GF_MODULUS` entry encodes a zero
/// coefficient.
///
/// [`Engine`]: crate::reed_solomon::engine
pub type Skew = [GfElement; GF_MODULUS as usize];

/// Struct holding the [`Exp`] and [`Log`] lookup tables.
pub struct ExpLog {
    /// Exponentiation table.
    pub exp: Box<Exp>,
    /// Logarithm table.
    pub log: Box<Log>,
}

/// Lazily initialized exponentiation and logarithm tables.
pub fn get_exp_log() -> &'static ExpLog {
    #[cfg(feature = "std")]
    {
        static EXP_LOG: LazyLock<ExpLog> = LazyLock::new(initialize_exp_log);
        &EXP_LOG
    }
    #[cfg(not(feature = "std"))]
    {
        static EXP_LOG: OnceBox<ExpLog> = OnceBox::new();
        EXP_LOG.get_or_init(|| Box::new(initialize_exp_log()))
    }
}

/// Lazily initialized logarithmic Walsh transform table.
pub fn get_log_walsh() -> &'static LogWalsh {
    #[cfg(feature = "std")]
    {
        static LOG_WALSH: LazyLock<Box<LogWalsh>> = LazyLock::new(initialize_log_walsh);
        &LOG_WALSH
    }
    #[cfg(not(feature = "std"))]
    {
        static LOG_WALSH: OnceBox<LogWalsh> = OnceBox::new();
        LOG_WALSH.get_or_init(initialize_log_walsh)
    }
}

/// Lazily initialized logarithmic Walsh transform table over the first `n` positions.
///
/// Entries are scaled by `n^-1` modulo [`GF_MODULUS`] because the unnormalized transform
/// applied twice multiplies by `n`. [`LogWalsh`] needs no scaling since `GF_ORDER` is 1
/// modulo [`GF_MODULUS`].
///
/// # Panics
///
/// If `n` is not a power of two below `GF_ORDER`.
pub(crate) fn get_short_log_walsh(n: usize) -> &'static [GfElement] {
    assert!(n.is_power_of_two() && n < GF_ORDER);
    let level = n.trailing_zeros() as usize;
    #[cfg(feature = "std")]
    {
        static KERNELS: [OnceLock<Vec<GfElement>>; GF_BITS] = [const { OnceLock::new() }; GF_BITS];
        KERNELS[level].get_or_init(|| initialize_short_log_walsh(n))
    }
    #[cfg(not(feature = "std"))]
    {
        static KERNELS: [OnceBox<Vec<GfElement>>; GF_BITS] = [const { OnceBox::new() }; GF_BITS];
        KERNELS[level].get_or_init(|| Box::new(initialize_short_log_walsh(n)))
    }
}

/// Lazily initialized multiplication table for the `NoSimd` engine.
pub fn get_mul16() -> &'static Mul16 {
    #[cfg(feature = "std")]
    {
        static MUL16: LazyLock<Box<Mul16>> = LazyLock::new(initialize_mul16);
        &MUL16
    }
    #[cfg(not(feature = "std"))]
    {
        static MUL16: OnceBox<Mul16> = OnceBox::new();
        MUL16.get_or_init(initialize_mul16)
    }
}

/// Lazily initialized multiplication table for SIMD engines.
pub fn get_mul128() -> &'static Mul128 {
    #[cfg(feature = "std")]
    {
        static MUL128: LazyLock<Box<Mul128>> = LazyLock::new(initialize_mul128);
        &MUL128
    }
    #[cfg(not(feature = "std"))]
    {
        static MUL128: OnceBox<Mul128> = OnceBox::new();
        MUL128.get_or_init(initialize_mul128)
    }
}

/// Lazily initialized GFNI affine multiplication table.
#[cfg(any(test, target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn get_mul_gfni() -> &'static MulGfni {
    #[cfg(feature = "std")]
    {
        static MUL_GFNI: LazyLock<Box<MulGfni>> = LazyLock::new(initialize_mul_gfni);
        &MUL_GFNI
    }
    #[cfg(not(feature = "std"))]
    {
        static MUL_GFNI: OnceBox<MulGfni> = OnceBox::new();
        MUL_GFNI.get_or_init(initialize_mul_gfni)
    }
}

/// Lazily initialized skew table used in FFT and IFFT operations.
pub fn get_skew() -> &'static Skew {
    #[cfg(feature = "std")]
    {
        static SKEW: LazyLock<Box<Skew>> = LazyLock::new(initialize_skew);
        &SKEW
    }
    #[cfg(not(feature = "std"))]
    {
        static SKEW: OnceBox<Skew> = OnceBox::new();
        SKEW.get_or_init(initialize_skew)
    }
}

/// Multiply `x` by `exp[log_m]` using [`Exp`] and [`Log`] tables.
#[inline(always)]
pub fn mul(x: GfElement, log_m: GfElement, exp: &Exp, log: &Log) -> GfElement {
    if x == 0 {
        0
    } else {
        exp[utils::add_mod(log[x as usize], log_m) as usize]
    }
}

/// Builds the [`Exp`] and [`Log`] tables for elements expressed in the [`CANTOR_BASIS`].
fn initialize_exp_log() -> ExpLog {
    let mut exp = Box::new([0; GF_ORDER]);
    let mut log = Box::new([0; GF_ORDER]);

    // Generate the LFSR table.
    let mut state = 1;
    for i in 0..GF_MODULUS {
        exp[state] = i;
        state <<= 1;
        if state >= GF_ORDER {
            state ^= GF_POLYNOMIAL;
        }
    }
    exp[0] = GF_MODULUS;

    // Convert to the Cantor basis.
    log[0] = 0;
    for (i, basis) in CANTOR_BASIS.iter().copied().enumerate().take(GF_BITS) {
        let width = 1usize << i;
        for j in 0..width {
            log[j + width] = log[j] ^ basis;
        }
    }
    for value in log.iter_mut() {
        *value = exp[*value as usize];
    }
    for (i, value) in log.iter().copied().enumerate() {
        exp[value as usize] = i as GfElement;
    }

    exp[GF_MODULUS as usize] = exp[0];

    ExpLog { exp, log }
}

/// Builds [`LogWalsh`], the FWHT of [`Log`] with entry zero replaced by zero.
fn initialize_log_walsh() -> Box<LogWalsh> {
    let log = get_exp_log().log.as_slice();

    let mut log_walsh: Box<LogWalsh> = Box::new([0; GF_ORDER]);

    log_walsh.copy_from_slice(log);
    log_walsh[0] = 0;
    fwht::fwht(log_walsh.as_mut(), GF_ORDER);

    log_walsh
}

/// Builds the kernel for [`get_short_log_walsh`], the FWHT of `log[..n]` with entry zero
/// replaced by zero, scaled by `n^-1` modulo `GF_MODULUS`.
///
/// `n` must be a power of two no larger than `GF_ORDER`.
fn initialize_short_log_walsh(n: usize) -> Vec<GfElement> {
    let log = &get_exp_log().log;
    let mut kernel = log[..n].to_vec();
    kernel[0] = 0;
    fwht::fwht(&mut kernel, n);

    // Scale by n^-1 = GF_ORDER / n modulo GF_MODULUS. Multiplying by 2^j modulo 2^16 - 1
    // rotates left by j bits, so the scale is a right rotation by log2(n).
    for factor in &mut kernel {
        *factor = factor.rotate_right(n.trailing_zeros());
    }
    kernel
}

/// Builds [`Mul16`] from [`Exp`] and [`Log`].
fn initialize_mul16() -> Box<Mul16> {
    let exp = &get_exp_log().exp;
    let log = &get_exp_log().log;
    let mut mul16 = vec![[[0; 16]; 4]; GF_ORDER];

    for log_m in 0..=GF_MODULUS {
        let lut = &mut mul16[log_m as usize];
        let [row0, row1, row2, row3] = lut;
        for (i, (((x0, x1), x2), x3)) in row0
            .iter_mut()
            .zip(row1.iter_mut())
            .zip(row2.iter_mut())
            .zip(row3.iter_mut())
            .enumerate()
        {
            *x0 = mul(i as GfElement, log_m, exp, log);
            *x1 = mul((i << 4) as GfElement, log_m, exp, log);
            *x2 = mul((i << 8) as GfElement, log_m, exp, log);
            *x3 = mul((i << 12) as GfElement, log_m, exp, log);
        }
    }

    mul16.into_boxed_slice().try_into().unwrap()
}

/// Builds [`Mul128`] with the byte layout described on [`Multiply128lutT`].
fn initialize_mul128() -> Box<Mul128> {
    // Based on:
    // https://github.com/catid/leopard/blob/22ddc7804998d31c8f1a2617ee720e063b1fa6cd/LeopardFF16.cpp#L375
    let exp = &get_exp_log().exp;
    let log = &get_exp_log().log;

    let mut mul128 = vec![
        Multiply128lutT {
            lo: [0; 4],
            hi: [0; 4],
        };
        GF_ORDER
    ];

    for log_m in 0..=GF_MODULUS {
        for i in 0..=3 {
            let mut prod_lo = [0u8; 16];
            let mut prod_hi = [0u8; 16];
            for x in 0..16 {
                let prod = mul((x << (i * 4)) as GfElement, log_m, exp, log);
                prod_lo[x] = prod as u8;
                prod_hi[x] = (prod >> 8) as u8;
            }
            mul128[log_m as usize].lo[i] = u128::from_ne_bytes(prod_lo);
            mul128[log_m as usize].hi[i] = u128::from_ne_bytes(prod_hi);
        }
    }

    mul128.into_boxed_slice().try_into().unwrap()
}

/// Builds [`MulGfni`] by combining one matrix per coefficient bit along a Gray code.
#[cfg(any(test, target_arch = "x86", target_arch = "x86_64"))]
fn initialize_mul_gfni() -> Box<MulGfni> {
    let exp = &get_exp_log().exp;
    let log = &get_exp_log().log;
    let mut table = vec![
        MultiplyGfni {
            low_from_low: 0,
            low_from_high: 0,
            high_from_low: 0,
            high_from_high: 0,
        };
        GF_ORDER
    ];

    let mut basis_matrices = [[0u64; 4]; GF_BITS];
    for (coefficient_bit, matrix) in basis_matrices.iter_mut().enumerate() {
        let log_m = log[1 << coefficient_bit];
        let mut rows = [[0u8; 8]; 4];
        for input_bit in 0..16 {
            let product = mul(1u16 << input_bit, log_m, exp, log);
            for output_bit in 0..16 {
                // Blocks follow the `MultiplyGfni` field order: 2 * output byte + input byte.
                let block = (output_bit / 8) * 2 + input_bit / 8;
                rows[block][output_bit % 8] |=
                    (((product >> output_bit) & 1) as u8) << (input_bit % 8);
            }
        }

        // GF2P8AFFINEQB reads row i from byte 7-i of each 64-bit matrix.
        *matrix = rows.map(u64::from_be_bytes);
    }

    // Multiplication is linear in the coefficient. After each basis-matrix XOR, `current` is
    // the multiplication matrix for `step ^ (step >> 1)` because consecutive binary-reflected
    // Gray codes differ in bit `step.trailing_zeros()`.
    let mut current = [0u64; 4];
    for step in 1..GF_ORDER {
        let toggled_bit = step.trailing_zeros() as usize;
        for (block, basis) in current.iter_mut().zip(basis_matrices[toggled_bit]) {
            *block ^= basis;
        }

        let coefficient = step ^ (step >> 1);
        let [low_from_low, low_from_high, high_from_low, high_from_high] = current;
        table[log[coefficient] as usize] = MultiplyGfni {
            low_from_low,
            low_from_high,
            high_from_low,
            high_from_high,
        };
    }

    // Exponents are taken modulo `GF_MODULUS`, the multiplicative group order, so exponent
    // `GF_MODULUS` intentionally duplicates the identity at exponent zero.
    let identity = table[0].clone();
    table[GF_MODULUS as usize] = identity;

    table.into_boxed_slice().try_into().unwrap()
}

/// Builds [`Skew`], the logarithms of the FFT butterfly coefficients.
///
/// A zero coefficient is stored as `GF_MODULUS`, the logarithm [`Log`] assigns to zero.
fn initialize_skew() -> Box<Skew> {
    let exp = &get_exp_log().exp;
    let log = &get_exp_log().log;

    let mut skew = Box::new([0; GF_MODULUS as usize]);

    let mut temp = [0; GF_BITS - 1];

    for (i, value) in temp.iter_mut().enumerate() {
        *value = 1 << (i + 1);
    }

    for m in 0..GF_BITS - 1 {
        let step: usize = 1 << (m + 1);

        skew[(1 << m) - 1] = 0;

        for (i, temp_i) in temp.iter().copied().enumerate().skip(m) {
            let s: usize = 1 << (i + 1);
            let mut j = (1 << m) - 1;
            while j < s {
                skew[j + s] = skew[j] ^ temp_i;
                j += step;
            }
        }

        temp[m] = GF_MODULUS - log[mul(temp[m], log[(temp[m] ^ 1) as usize], exp, log) as usize];

        for i in m + 1..GF_BITS - 1 {
            let sum = utils::add_mod(log[(temp[i] ^ 1) as usize], temp[m]);
            temp[i] = mul(temp[i], sum, exp, log);
        }
    }

    for value in skew.iter_mut() {
        *value = log[*value as usize];
    }

    skew
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul128_byte_layout() {
        let scalar = get_mul16();
        for (vector, scalar) in get_mul128().iter().zip(scalar.iter()) {
            for ((lo, hi), products) in vector.lo.iter().zip(&vector.hi).zip(scalar) {
                let lo = lo.to_ne_bytes();
                let hi = hi.to_ne_bytes();
                for (index, product) in products.iter().enumerate() {
                    assert_eq!(lo[index], *product as u8);
                    assert_eq!(hi[index], (product >> 8) as u8);
                }
            }
        }
    }

    /// Reference GF2P8AFFINEQB on one byte, without the affine constant.
    fn affine(matrix: u64, input: u8) -> u8 {
        let matrix = matrix.to_le_bytes();
        let mut output = 0;
        for output_bit in 0..8 {
            output |= ((matrix[7 - output_bit] & input).count_ones() as u8 & 1) << output_bit;
        }
        output
    }

    #[test]
    fn mul_gfni_matrix_semantics() {
        assert_eq!(
            core::mem::size_of::<MultiplyGfni>(),
            4 * core::mem::size_of::<u64>()
        );
        assert_eq!(core::mem::size_of::<MulGfni>(), 2 * 1024 * 1024);

        let exp_log = get_exp_log();
        for (log_m, matrices) in get_mul_gfni().iter().enumerate() {
            for input_bit in 0..16 {
                let input = 1u16 << input_bit;
                let input_lo = input as u8;
                let input_hi = (input >> 8) as u8;
                let output_lo = affine(matrices.low_from_low, input_lo)
                    ^ affine(matrices.low_from_high, input_hi);
                let output_hi = affine(matrices.high_from_low, input_lo)
                    ^ affine(matrices.high_from_high, input_hi);
                let actual = output_lo as u16 | (output_hi as u16) << 8;
                let expected = mul(input, log_m as GfElement, &exp_log.exp, &exp_log.log);
                assert_eq!(actual, expected, "log_m={log_m} input_bit={input_bit}");
            }
        }

        for log_m in [0, GF_MODULUS as usize] {
            let identity = &get_mul_gfni()[log_m];
            assert_eq!(identity.low_from_low, 0x0102_0408_1020_4080);
            assert_eq!(identity.low_from_high, 0);
            assert_eq!(identity.high_from_low, 0);
            assert_eq!(identity.high_from_high, 0x0102_0408_1020_4080);
        }
    }
}
