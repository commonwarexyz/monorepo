//! Lookup-tables used by [`Engine`]:s.
//!
//! All tables are global and each is initialized at most once.
//!
//! # Tables
//!
//! | Table        | Size    | Used in encoding | Used in decoding | By engines         |
//! | ------------ | ------- | ---------------- | ---------------- | ------------------ |
//! | [`Exp`]      | 128 kiB | yes              | yes              | all                |
//! | [`Log`]      | 128 kiB | yes              | yes              | all                |
//! | [`LogWalsh`] | 128 kiB | -                | yes              | all                |
//! | [`Mul16`]    | 8 MiB   | yes              | yes              | [`NoSimd`]         |
//! | [`Mul128`]   | 8 MiB   | yes              | yes              | `Neon` `Avx2` `Ssse3` |
//! | `MulGfni`    | 8 MiB   | yes              | yes              | `Avx512` |
//! | [`Skew`]     | 128 kiB | yes              | yes              | all                |
//!
//! [`NoSimd`]: crate::reed_solomon::engine::NoSimd
//! [`Engine`]: crate::reed_solomon::engine
//!

use crate::reed_solomon::engine::{
    CANTOR_BASIS, GF_BITS, GF_MODULUS, GF_ORDER, GF_POLYNOMIAL, GfElement, fwht, utils,
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox;
#[cfg(feature = "std")]
use std::sync::LazyLock;

// ======================================================================
// TYPE ALIASES - PUBLIC

/// Used by [`Naive`] engine for multiplications
/// and by all [`Engine`]:s to initialize other tables.
///
/// [`Naive`]: crate::reed_solomon::engine::Naive
/// [`Engine`]: crate::reed_solomon::engine
pub type Exp = [GfElement; GF_ORDER];

/// Used by [`Naive`] engine for multiplications
/// and by all [`Engine`]:s to initialize other tables.
///
/// [`Naive`]: crate::reed_solomon::engine::Naive
/// [`Engine`]: crate::reed_solomon::engine
pub type Log = [GfElement; GF_ORDER];

/// Nibble multiplication tables for SIMD engines.
pub type Mul128 = [Multiply128lutT; GF_ORDER];

/// GFNI affine matrices for all field multipliers.
#[cfg(any(test, target_arch = "x86", target_arch = "x86_64"))]
pub(crate) type MulGfni = [MultiplyGfni; GF_ORDER];

/// Ready-to-load affine operands for one field multiplier.
///
/// Multiplication is a 16 x 16 binary linear map, split into four 8 x 8 maps between
/// the input and output byte halves. Each map is repeated across four 64-bit lanes.
#[cfg(any(test, target_arch = "x86", target_arch = "x86_64"))]
#[derive(Clone, Debug)]
pub(crate) struct MultiplyGfni {
    /// Direct terms: `A` maps low input to low output, and `D` maps high input to high output.
    pub(crate) direct: [u64; 8],
    /// Cross terms: `B` maps high input to low output, and `C` maps low input to high output.
    pub(crate) cross: [u64; 8],
}

/// Multiplication lookup bytes for the four nibbles of a field element.
///
/// Each `u128` stores 16 bytes in native byte order, indexed by the nibble value.
#[derive(Clone, Debug)]
pub struct Multiply128lutT {
    /// Low product bytes for each nibble position.
    pub lo: [u128; 4],
    /// High product bytes for each nibble position.
    pub hi: [u128; 4],
}

/// Used by all [`Engine`]:s in [`Engine::eval_poly`].
///
/// [`Engine`]: crate::reed_solomon::engine
/// [`Engine::eval_poly`]: crate::reed_solomon::engine::Engine::eval_poly
pub type LogWalsh = [GfElement; GF_ORDER];

/// Used by [`NoSimd`] engine for multiplications.
///
/// [`NoSimd`]: crate::reed_solomon::engine::NoSimd
pub type Mul16 = [[[GfElement; 16]; 4]; GF_ORDER];

/// Used by all [`Engine`]:s for FFT and IFFT.
///
/// [`Engine`]: crate::reed_solomon::engine
pub type Skew = [GfElement; GF_MODULUS as usize];

// ======================================================================
// ExpLog - PUBLIC

/// Struct holding the [`Exp`] and [`Log`] lookup tables.
pub struct ExpLog {
    /// Exponentiation table.
    pub exp: Box<Exp>,
    /// Logarithm table.
    pub log: Box<Log>,
}

// ======================================================================
// STATIC - PUBLIC

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

// ======================================================================
// FUNCTIONS - PUBLIC - math

/// Multiply `x` by `exp[log_m]` using [`Exp`] and [`Log`] tables.
#[inline(always)]
pub fn mul(x: GfElement, log_m: GfElement, exp: &Exp, log: &Log) -> GfElement {
    if x == 0 {
        0
    } else {
        exp[utils::add_mod(log[x as usize], log_m) as usize]
    }
}

// ======================================================================
// FUNCTIONS - PRIVATE - initialize tables

fn initialize_exp_log() -> ExpLog {
    let mut exp = Box::new([0; GF_ORDER]);
    let mut log = Box::new([0; GF_ORDER]);

    // GENERATE LFSR TABLE

    let mut state = 1;
    for i in 0..GF_MODULUS {
        exp[state] = i;
        state <<= 1;
        if state >= GF_ORDER {
            state ^= GF_POLYNOMIAL;
        }
    }
    exp[0] = GF_MODULUS;

    // CONVERT TO CANTOR BASIS

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

fn initialize_log_walsh() -> Box<LogWalsh> {
    let log = get_exp_log().log.as_slice();

    let mut log_walsh: Box<LogWalsh> = Box::new([0; GF_ORDER]);

    log_walsh.copy_from_slice(log);
    log_walsh[0] = 0;
    fwht::fwht(log_walsh.as_mut(), GF_ORDER);

    log_walsh
}

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

#[cfg(any(test, target_arch = "x86", target_arch = "x86_64"))]
fn initialize_mul_gfni() -> Box<MulGfni> {
    let exp = &get_exp_log().exp;
    let log = &get_exp_log().log;
    let mut table = vec![
        MultiplyGfni {
            direct: [0; 8],
            cross: [0; 8],
        };
        GF_ORDER
    ];

    for log_m in 0..=GF_MODULUS {
        let mut rows = [[0u8; 8]; 4];
        for input_bit in 0..16 {
            let product = mul(1u16 << input_bit, log_m, exp, log);
            for output_bit in 0..16 {
                let block = (output_bit / 8) * 2 + input_bit / 8;
                rows[block][output_bit % 8] |=
                    (((product >> output_bit) & 1) as u8) << (input_bit % 8);
            }
        }

        // GF2P8AFFINEQB reads row i from byte 7-i of each 64-bit matrix.
        let [a, b, c, d] = rows.map(u64::from_be_bytes);
        table[log_m as usize] = MultiplyGfni {
            direct: [a, a, a, a, d, d, d, d],
            cross: [b, b, b, b, c, c, c, c],
        };
    }

    table.into_boxed_slice().try_into().unwrap()
}

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
        let exp_log = get_exp_log();
        for (log_m, matrices) in get_mul_gfni().iter().enumerate() {
            for input_bit in 0..16 {
                let input = 1u16 << input_bit;
                let input_lo = input as u8;
                let input_hi = (input >> 8) as u8;
                let output_lo =
                    affine(matrices.direct[0], input_lo) ^ affine(matrices.cross[0], input_hi);
                let output_hi =
                    affine(matrices.cross[4], input_lo) ^ affine(matrices.direct[4], input_hi);
                let actual = output_lo as u16 | (output_hi as u16) << 8;
                let expected = mul(input, log_m as GfElement, &exp_log.exp, &exp_log.log);
                assert_eq!(actual, expected, "log_m={log_m} input_bit={input_bit}");
            }
        }

        for log_m in [0, GF_MODULUS as usize] {
            let identity = &get_mul_gfni()[log_m];
            assert_eq!(identity.direct, [0x0102_0408_1020_4080; 8]);
            assert_eq!(identity.cross, [0; 8]);
        }
    }
}
