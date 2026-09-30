//! sandblaster facade (DESIGN.md §1.2).
//!
//! sandblaster is a proven subset of Rust with Bend-style laws, Verus-style
//! inline proofs and an always-on, kernel-validated optimizer. This crate is
//! what user crates depend on:
//!
//! * [`prelude`] — the annotation vocabulary of §4 and §15: the erasing
//!   attribute macros (`#[requires]`, `#[ensures]`, `#[decreases]`,
//!   `#[implements]`, `#[specialize]`, `#[law]`, `#[lemma]`, `#[spec]`,
//!   `#[rewrite]`, `#[induction]`, `#[refines]`, `#[example]`,
//!   `#[examples]`, `#[invariant]`, `#[view]`, `#[represents]`, `#[ghost]`,
//!   `#[section]`, `#[mirrors_impl]`, `#[fuel_sufficient]`,
//!   `#[trusted_extern]`) and the [`proof!`] statement macro. DSL
//!   sources import it with `use sandblaster::prelude::*;` (the one glob §3.1
//!   allows besides the `core::arch` modules). The `#[proof]` attribute of
//!   ghost proofs lives in [`ghost`] (it cannot share a module with `proof!`).
//! * [`arch`] — the trusted load/store helpers of §9.2 for aarch64 and
//!   x86_64, so hardware kernels written in the subset never touch raw
//!   pointers or `unsafe`.
//! * `build` (feature `"build"`) — `sandblaster::build::compile`, the `build.rs`
//!   entry point (§10.1), and `sandblaster::build::compile_module`, the entry
//!   point of module mode (a verified module inside an ordinary crate, §2.1).
//!
//! The annotations only matter to the sandblaster checker, which parses the
//! sources itself. When the DSL sources are compiled directly by `rustc` (the
//! baseline crate, §2) the macros erase every annotation; the shipped,
//! generated code has no runtime dependency on this crate (§1.2).
#![no_std]

#[cfg(test)]
extern crate std;

pub mod arch;
pub mod ghost;
pub mod prelude;

#[cfg(feature = "build")]
pub mod build;

#[cfg(test)]
mod erase_spec15;

/// Ghost proof statements inside exec code (DESIGN.md §4.3).
///
/// ```ignore
/// for k in 0u32..32 {
///     proof! { invariant(before <= k); }
///     // ...
/// }
/// ```
///
/// The body is a sequence of §4.4 script statements (`assert(..)`,
/// `invariant(..)`, `decreases(..)`, lemma applications, ...) that the
/// sandblaster checker runs in the proof context at that point. `rustc` never
/// sees them: the macro accepts any tokens and expands to nothing, so it may
/// appear anywhere a statement may.
#[macro_export]
macro_rules! proof {
    ($($body:tt)*) => {};
}
