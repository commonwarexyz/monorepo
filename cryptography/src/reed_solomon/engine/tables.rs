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
//! | [`Mul128`]   | 8 MiB   | yes              | yes              | `Avx2` `Ssse3`     |
//! | [`Skew`]     | 128 kiB | yes              | yes              | all                |
//!
//! [`NoSimd`]: crate::reed_solomon::engine::NoSimd
//! [`Engine`]: crate::reed_solomon::engine
//!

use crate::reed_solomon::engine::{
    fwht, utils, GfElement, CANTOR_BASIS, GF_BITS, GF_MODULUS, GF_ORDER, GF_POLYNOMIAL,
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

/// Used by `Avx2` and `Ssse3` engines for multiplications.
pub type Mul128 = [Multiply128lutT; GF_ORDER];

/// Elements of the Mul128 table
#[derive(Clone, Debug)]
pub struct Multiply128lutT {
    /// Lower half of `GfElements`
    pub lo: [u128; 4],
    /// Upper half of `GfElements`
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

/// Calculates `x * log_m` using [`Exp`] and [`Log`] tables.
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

#[allow(clippy::needless_range_loop)]
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
    for i in 0..GF_BITS {
        let width = 1usize << i;
        for j in 0..width {
            log[j + width] = log[j] ^ CANTOR_BASIS[i];
        }
    }

    for i in 0..GF_ORDER {
        log[i] = exp[log[i] as usize];
    }

    for i in 0..GF_ORDER {
        exp[log[i] as usize] = i as GfElement;
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
        for i in 0..16 {
            lut[0][i] = mul(i as GfElement, log_m, exp, log);
            lut[1][i] = mul((i << 4) as GfElement, log_m, exp, log);
            lut[2][i] = mul((i << 8) as GfElement, log_m, exp, log);
            lut[3][i] = mul((i << 12) as GfElement, log_m, exp, log);
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
            mul128[log_m as usize].lo[i] = u128::from_le_bytes(prod_lo);
            mul128[log_m as usize].hi[i] = u128::from_le_bytes(prod_hi);
        }
    }

    mul128.into_boxed_slice().try_into().unwrap()
}

#[allow(clippy::needless_range_loop)]
fn initialize_skew() -> Box<Skew> {
    let exp = &get_exp_log().exp;
    let log = &get_exp_log().log;

    let mut skew = Box::new([0; GF_MODULUS as usize]);

    let mut temp = [0; GF_BITS - 1];

    for i in 1..GF_BITS {
        temp[i - 1] = 1 << i;
    }

    for m in 0..GF_BITS - 1 {
        let step: usize = 1 << (m + 1);

        skew[(1 << m) - 1] = 0;

        for i in m..GF_BITS - 1 {
            let s: usize = 1 << (i + 1);
            let mut j = (1 << m) - 1;
            while j < s {
                skew[j + s] = skew[j] ^ temp[i];
                j += step;
            }
        }

        temp[m] = GF_MODULUS - log[mul(temp[m], log[(temp[m] ^ 1) as usize], exp, log) as usize];

        for i in m + 1..GF_BITS - 1 {
            let sum = utils::add_mod(log[(temp[i] ^ 1) as usize], temp[m]);
            temp[i] = mul(temp[i], sum, exp, log);
        }
    }

    for i in 0..GF_MODULUS as usize {
        skew[i] = log[skew[i] as usize];
    }

    skew
}
