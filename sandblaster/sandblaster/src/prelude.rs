//! The sandblaster annotation vocabulary for exec code (DESIGN.md §3.1, §4).
//!
//! DSL sources start with `use sandblaster::prelude::*;`. This brings into
//! scope:
//!
//! | Name | Kind | Meaning (checker) | Baseline `rustc` build |
//! | --- | --- | --- | --- |
//! | `requires`, `ensures`, `decreases` | attribute | contracts, measure, stack-depth bound (§4.2, §3.7) | attribute erased |
//! | `implements` | attribute | hardware variant (§9.3) | attribute erased |
//! | `law`, `lemma`, `spec` | attribute | ghost items (§4.5); `#[spec]` also on `#[cfg(sandblaster)] #[spec] mod m;` (§15.1) | item erased |
//! | `induction` | attribute | proof by induction on a ghost item (§4.4) | attribute erased |
//! | `refines` | attribute | functional spec of an exec function (§15.2) | attribute erased |
//! | `example`, `examples` | attribute | known-answer examples and vector files (§15.7) | attribute erased |
//! | `invariant`, `view`, `represents` | attribute | invariants and meaning of types (§15.3) | attribute erased |
//! | `ghost` | parameter attribute | ghost parameter of an exec function (§15.3) | parameter removed by the function's annotation |
//! | `section` | attribute | merges computed sections (§15.5) | attribute erased |
//! | `mirrors_impl`, `fuel_sufficient` | attribute | spec-item lints (§15.1) | attribute erased |
//! | `trusted_extern` | attribute | runtime primitive with a contract (§15.8) | attribute erased |
//! | `reduces_to`, `definitional`, `corollary` | attribute | law rules: extraction form (§15.1 LR4, §15.13), intentional definition (LR6), corollary (LR7) | attribute erased |
//! | `assumption` | attribute | a named hardness assumption without logical content (§15.13) | attribute erased |
//! | `opaque` | attribute | a spec function opaque in proofs (§5.6) | attribute erased |
//! | `proof!` | statement macro | inline proof steps (§4.3) | expands to nothing |
//!
//! There is no `critical`: all of §15 is mandatory (§15.8).
//!
//! **The `#[proof]` attribute is not in the prelude.** Rust puts attribute
//! and bang macros in one namespace per module (two imports named `proof`
//! are error E0252, and an explicit or glob import of one hides the other),
//! and declarative attribute macros are unstable in rustc 1.98. Exec code
//! needs the `proof!` statement; `#[proof]` only appears in ghost modules
//! (`PROOF.rs`, behind `#[cfg(sandblaster)]`) that `rustc` never loads. For a
//! ghost file that should also build under `rustc`, import
//! [`crate::ghost`] instead (`use sandblaster::ghost::*;`), which exports every
//! ghost-item attribute including `#[proof]`. The sandblaster checker
//! recognizes all annotations by name, not by import.

pub use sandblaster_macros::{
    assumption, corollary, decreases, definitional, ensures, example, examples, fuel_sufficient,
    ghost, implements, induction, invariant, law, lemma, mirrors_impl, opaque, reduces_to, refines,
    represents, requires, section, spec, trusted_extern, view,
};

pub use crate::proof;
