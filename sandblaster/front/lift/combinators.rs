//! Templates: core's definitions of the `Option`, `Result` and integer
//! methods that lifted code calls (SEMANTICS.md §19.7). The lift reads
//! `recv.m(args)`, for a receiver of kind `k` (`option`, `result`, `u64`,
//! ..), as the body of `k_m` below with the receiver and the arguments
//! bound by `let` in order (call by value), closure arguments inlined at
//! their calls, `panic!` read as an obligation (`unreachable!()`) and a
//! `&str` message argument dropped (it only shapes the panic payload).
//!
//! Each body transcribes core's definition (library/core/src/option.rs,
//! result.rs, num/uint_macros.rs). This file is plain Rust: the test
//! `lift_templates` compiles it natively and compares every template with
//! core's method on many inputs, so a transcription error fails a test
//! instead of changing a meaning. Rules for a template body: no `return`,
//! no `?`, no loops, no shadowing of its own locals, closures called only
//! as `f(x)`.
#![allow(dead_code)]

use core::cmp::Ordering;

// ---------------------------------------------------------------------------
// Option<T>
// ---------------------------------------------------------------------------

/// `Option::expect` (written with `let .. else`, so the rest of a lifted
/// body sees `self_ == Some(val)` as a fact).
pub fn option_expect<T>(self_: Option<T>, msg: &str) -> T {
    let Some(val) = self_ else { panic!("{}", msg) };
    val
}

/// `Option::and_then`.
pub fn option_and_then<T, U, F: FnOnce(T) -> Option<U>>(self_: Option<T>, f: F) -> Option<U> {
    match self_ {
        Some(x) => f(x),
        None => None,
    }
}

/// `Option::map`.
pub fn option_map<T, U, F: FnOnce(T) -> U>(self_: Option<T>, f: F) -> Option<U> {
    match self_ {
        Some(x) => Some(f(x)),
        None => None,
    }
}

/// `Option::map_or`.
pub fn option_map_or<T, U, F: FnOnce(T) -> U>(self_: Option<T>, default: U, f: F) -> U {
    match self_ {
        Some(t) => f(t),
        None => default,
    }
}

/// `Option::copied` (of an `Option<&T>`; lifted code reads `&T` as `T`,
/// so it is the identity there).
pub fn option_copied<T: Copy>(self_: Option<&T>) -> Option<T> {
    match self_ {
        Some(&v) => Some(v),
        None => None,
    }
}

/// `Option::ok_or`.
pub fn option_ok_or<T, E>(self_: Option<T>, err: E) -> Result<T, E> {
    match self_ {
        Some(v) => Ok(v),
        None => Err(err),
    }
}

/// `Option::filter`.
pub fn option_filter<T, P: FnOnce(&T) -> bool>(self_: Option<T>, predicate: P) -> Option<T> {
    match self_ {
        Some(x) => {
            if predicate(&x) {
                Some(x)
            } else {
                None
            }
        }
        None => None,
    }
}

/// `Option::or`.
pub fn option_or<T>(self_: Option<T>, optb: Option<T>) -> Option<T> {
    match self_ {
        Some(x) => Some(x),
        None => optb,
    }
}

/// `Option::is_some_and`.
pub fn option_is_some_and<T, F: FnOnce(T) -> bool>(self_: Option<T>, f: F) -> bool {
    match self_ {
        None => false,
        Some(x) => f(x),
    }
}

/// `Option::unwrap_or_else`.
pub fn option_unwrap_or_else<T, F: FnOnce() -> T>(self_: Option<T>, f: F) -> T {
    match self_ {
        Some(x) => x,
        None => f(),
    }
}

// ---------------------------------------------------------------------------
// Result<T, E>
// ---------------------------------------------------------------------------

/// `Result::expect` (a panic's payload, which formats the error, is
/// outside the model: the panic is an obligation).
pub fn result_expect<T, E: core::fmt::Debug>(self_: Result<T, E>, msg: &str) -> T {
    let Ok(t) = self_ else { panic!("{msg}") };
    t
}

/// `Result::unwrap`.
pub fn result_unwrap<T, E: core::fmt::Debug>(self_: Result<T, E>) -> T {
    let Ok(t) = self_ else { panic!("called `Result::unwrap()` on an `Err` value") };
    t
}

/// `Result::ok`.
pub fn result_ok<T, E>(self_: Result<T, E>) -> Option<T> {
    match self_ {
        Ok(x) => Some(x),
        Err(_) => None,
    }
}

/// `Result::is_ok`.
pub fn result_is_ok<T, E>(self_: Result<T, E>) -> bool {
    match self_ {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// `Result::and_then`.
pub fn result_and_then<T, U, E, F: FnOnce(T) -> Result<U, E>>(self_: Result<T, E>, op: F) -> Result<U, E> {
    match self_ {
        Ok(t) => op(t),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// unsigned integers
// ---------------------------------------------------------------------------

macro_rules! uint_templates {
    ($t:ty, $bits:literal, $checked_shl:ident, $checked_shr:ident, $trailing_ones:ident, $leading_ones:ident, $cmp:ident, $partial_cmp:ident) => {
        /// `checked_shl`: `None` for a shift of at least the bit width.
        pub fn $checked_shl(self_: $t, rhs: u32) -> Option<$t> {
            if rhs < $bits { Some(self_ << rhs) } else { None }
        }

        /// `checked_shr`.
        pub fn $checked_shr(self_: $t, rhs: u32) -> Option<$t> {
            if rhs < $bits { Some(self_ >> rhs) } else { None }
        }

        /// `trailing_ones`: the trailing zeros of the complement.
        pub fn $trailing_ones(self_: $t) -> u32 {
            (!self_).trailing_zeros()
        }

        /// `leading_ones`: the leading zeros of the complement.
        pub fn $leading_ones(self_: $t) -> u32 {
            (!self_).leading_zeros()
        }

        /// `Ord::cmp` (core: the three-way comparison intrinsic).
        pub fn $cmp(self_: &$t, other: &$t) -> Ordering {
            if *self_ < *other {
                Ordering::Less
            } else if *self_ == *other {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }

        /// `PartialOrd::partial_cmp` (a total order: always `Some`).
        pub fn $partial_cmp(self_: &$t, other: &$t) -> Option<Ordering> {
            if *self_ < *other {
                Some(Ordering::Less)
            } else if *self_ == *other {
                Some(Ordering::Equal)
            } else {
                Some(Ordering::Greater)
            }
        }
    };
}

uint_templates!(u8, 8, u8_checked_shl, u8_checked_shr, u8_trailing_ones, u8_leading_ones, u8_cmp, u8_partial_cmp);
uint_templates!(u16, 16, u16_checked_shl, u16_checked_shr, u16_trailing_ones, u16_leading_ones, u16_cmp, u16_partial_cmp);
uint_templates!(u32, 32, u32_checked_shl, u32_checked_shr, u32_trailing_ones, u32_leading_ones, u32_cmp, u32_partial_cmp);
uint_templates!(u64, 64, u64_checked_shl, u64_checked_shr, u64_trailing_ones, u64_leading_ones, u64_cmp, u64_partial_cmp);
uint_templates!(usize, 64, usize_checked_shl, usize_checked_shr, usize_trailing_ones, usize_leading_ones, usize_cmp, usize_partial_cmp);
