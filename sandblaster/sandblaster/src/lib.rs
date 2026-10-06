//! sandblaster facade (DESIGN.md §1.2).
//!
//! sandblaster verifies Rust as written — laws reviewed by humans, proofs
//! written by agents, checked by a small kernel — so that very complex,
//! hand-optimized code can be proven against simple specifications. This
//! crate is what user crates depend on:
//!
//! * [`prelude`] — the annotation vocabulary of §4 and §15: the erasing
//!   attribute macros (`#[requires]`, `#[ensures]`, `#[decreases]`,
//!   `#[implements]`, `#[law]`, `#[lemma]`, `#[spec]`,
//!   `#[induction]`, `#[refines]`, `#[example]`,
//!   `#[examples]`, `#[invariant]`, `#[view]`, `#[represents]`, `#[ghost]`,
//!   `#[section]`, `#[mirrors_impl]`, `#[fuel_sufficient]`,
//!   `#[trusted_extern]`) and the [`proof!`] statement macro. DSL
//!   sources import it with `use sandblaster::prelude::*;` (the one glob §3.1
//!   allows). The `#[proof]` attribute of
//!   ghost proofs lives in [`ghost`] (it cannot share a module with `proof!`).
//! * `build` (feature `"build"`) — the `build.rs` entry points (§10.1, §2.1):
//!   `sandblaster::build::compile_lifted` (the host's own files verified in
//!   place) and `sandblaster::build::compile_module` (a verified lifted module
//!   inside an ordinary crate).
//!
//! The annotations only matter to the sandblaster checker, which parses the
//! sources itself. When the DSL sources are compiled directly by `rustc` (the
//! baseline crate, §2) the macros erase every annotation; the verified code
//! has no runtime dependency on this crate (§1.2).
#![no_std]

#[cfg(test)]
extern crate std;

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
