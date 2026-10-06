//! sandblaster front end (DESIGN.md §3, §4, §6–§10). Untrusted except for the
//! elaboration semantics of the canonical dialect.
//!
//! Phase-1 pipeline ([`driver::check`]):
//!
//! 1. [`loader`] — module tree from the DSL root, `cfg` evaluation, ghost
//!    tracking (§2);
//! 2. [`resolve`] — items, namespaces, imports, privacy, the §3.3
//!    identifier-pattern hazard set;
//! 3. [`typeck`] — signatures, bidirectional surface typing (§3.6), patterns
//!    with explicit binding modes, exhaustiveness ([`exhaust`]), ghost
//!    propositions and scripts (§4), producing the typed [`hir`];
//! 4. [`validate`] — the global subset rules (boundary, recursion, ZST
//!    slices, `#![forbid(unsafe_code)]`, laws/proofs, variants).
//!
//! Verified pipeline ([`driver::build_crate`], phase 2):
//!
//! 5. [`elab`] — elaboration of the HIR to kernel definitions (the normative
//!    semantics, `SEMANTICS.md`), every obligation handed to a
//!    [`prover::Prover`] ([`elab::ProverChain`]: the development prover,
//!    then [`auto`]) and every definition checked by the kernel;
//! 6. [`lift`] and [`mir`] — existing Rust verified as written: the item
//!    skeleton from the source, the bodies from rustc's MIR, each function's
//!    theorem relating the literal and the structured reading;
//! 7. [`driver`] — the §15 gates, the lock, the report, the build-script
//!    logic and the reference evaluator (`sandblaster eval`).
//!
//! Supporting tables: [`builtins`] (§3.4 methods, operators, conversions),
//! [`intrinsics`] (the target intrinsic table, §9.2), [`target`] (target
//! description, feature implication closure, §9.3). Diagnostics: [`span`],
//! [`diag`] (§10.4).
#![forbid(unsafe_code)]

// Installs the process-wide allocation cap (resource safety; see the crate
// docs). Linked by every binary that uses the front end.
pub use sandblaster_memguard as memguard;

pub mod auto;
pub mod builtins;
pub mod conform;
pub mod const_eval;
pub mod deelab;
pub mod diag;
pub mod driver;
pub mod elab;
pub mod exhaust;
pub mod hir;
pub mod intrinsics;
pub mod json;
pub mod lift;
pub mod loader;
pub mod mir;
pub mod lock;
pub mod mutate;
pub mod prover;
pub mod refute;
pub mod resolve;
pub mod span;
pub mod specdiff;
pub mod surface;
pub mod target;
pub mod typeck;
pub mod validate;
pub mod visit;
