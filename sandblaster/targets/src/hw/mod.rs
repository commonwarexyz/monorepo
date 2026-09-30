//! The real intrinsics, wrapped on the model representation, and the
//! differential campaigns that compare them with the models (DESIGN.md §9.2
//! "Validation").
//!
//! Each architecture module (compiled only on its `target_arch`) provides:
//!
//! * a `#[target_feature]` wrapper per intrinsic with exactly the model's
//!   signature (vectors as lane arrays, immediates as `i32` dispatched through
//!   tables of monomorphized functions, one per immediate value — rustc
//!   requires stdarch immediates to be constants);
//! * `compress_*` — the SHA-256 compression built from the real intrinsics
//!   in the `sha2` crate's sequence (the kernel QMDB runs, §9.7);
//! * `detected_features()`, `run_model(name, cfg)`, `run_all(cfg)` and
//!   `run_compositions(cfg)`, used by the tests and the evidence binary.
//!
//! Vectors cross between the model representation and the stdarch types by
//! `transmute`, i.e. by their in-memory layout: on little-endian targets that
//! is lane 0 at the lowest address for NEON types and byte 0 = bits 7:0 for
//! `__m128i`, exactly the §9.2 representation. (Loads and stores are
//! additionally tested through the real `vld1q`/`vst1q`/`_mm_loadu`/
//! `_mm_storeu` intrinsics on memory.)
//!
//! This is the only module of the crate with `unsafe` code: pointer loads and
//! stores, `transmute`, and calls of `#[target_feature]` functions after the
//! feature was detected at run time.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64_wide;

/// The module for the architecture this crate was compiled for.
#[cfg(target_arch = "aarch64")]
pub use self::aarch64 as current;
/// The module for the architecture this crate was compiled for.
#[cfg(target_arch = "x86_64")]
pub use self::x86_64 as current;

/// Build a table of function pointers, one monomorphization per listed
/// immediate: `imm_table!(f, T; 0 1 2)` = `[f::<0> as T, f::<1> as T, f::<2> as T]`.
#[cfg_attr(not(target_arch = "aarch64"), allow(unused_macros))]
macro_rules! imm_table {
    ($f:ident, $ty:ty; $($n:literal)*) => {
        [$( $f::<$n> as $ty ),*]
    };
}

/// Build a 256-entry table (`imm8` immediates) of monomorphizations
/// `f::<0> .. f::<255>` at run time, generated as 16 × 16 assignments.
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_macros))]
macro_rules! imm8_table {
    ($f:ident, $ty:ty) => {{
        let mut table: [$ty; 256] = [$f::<0> as $ty; 256];
        imm8_table!(@hi table, $f, $ty; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
        table
    }};
    (@hi $t:ident, $f:ident, $ty:ty; $($h:literal)*) => {
        $( imm8_table!(@lo $t, $f, $ty, $h; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15); )*
    };
    (@lo $t:ident, $f:ident, $ty:ty, $h:literal; $($l:literal)*) => {
        $( $t[$h * 16 + $l] = $f::<{ $h * 16 + $l }> as $ty; )*
    };
}

#[allow(unused_imports)]
pub(crate) use {imm_table, imm8_table};

use crate::diff::Outcome;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Run `f` for every name on a pool of worker threads (one per available
/// core), returning the outcomes in input order. Campaigns are independent
/// and deterministic per model (each has its own seed), so parallelism does
/// not change any result.
pub fn run_parallel<F>(names: &[&str], f: F) -> Vec<Outcome>
where
    F: Fn(&str) -> Outcome + Sync,
{
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Outcome>>> = Mutex::new(vec![None; names.len()]);
    let workers = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(names.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(name) = names.get(i) else { break };
                    let o = f(name);
                    results
                        .lock()
                        .expect("no worker panicked while holding the lock")[i] = Some(o);
                }
            });
        }
    });
    results
        .into_inner()
        .expect("workers finished")
        .into_iter()
        .map(|o| o.expect("every name ran"))
        .collect()
}
