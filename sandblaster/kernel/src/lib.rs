//! The trusted kernel of sandblaster (DESIGN.md §5).
//!
//! `term`, `value` and `api` are frozen interfaces shared with the front end,
//! the automation and the optimizer. The other modules implement §5:
//!
//! | module | DESIGN.md |
//! | --- | --- |
//! | [`prim`] | §5.7 primitives: signatures, obligations, literal semantics, neutral simplifications |
//! | `eval` | §5.3/§5.6/§5.9 NbE evaluator, unfolding policy, array eta |
//! | `conv` | §5.9 memoized conversion with η and irrelevance |
//! | `quote` | §5.11 read-back (typed, shared, abstraction) |
//! | `check` | §5.2/§5.3 bidirectional checking and relevance |
//! | `inductive` | §5.4 inductive declarations |
//! | `recursion` | §5.6 definitions, structural/measure termination, commit |
//! | [`linarith`] | §5.8 linearization and certificate checking |
//! | `lincert` | §5.8 certificate search when a given certificate does not fit (untrusted: its result is re-checked) |
//! | [`bvnorm`] | §9.8 `BvRefl`: word normalizer (rules 1–7) and tripwire |
//! | [`axioms`] | §5.10 axiom schemas |
//! | `alpha` | §8.3 `alpha_eq_relevant`, `check_residual_equal` |
//! | [`syntax`] | §5.12 core text syntax (parser + printer) |
//! | `prelude` | §6 prelude definitions (`prelude/*.core`) |
//! | `section` | §15.1/§15.5 `Refs*` and `complete_p(R)` (`Env::refs_closure`, `Env::abstract_section`) |
//! | `closed` | §15.7 closed evaluation for examples (`Env::eval_closed`) |
//!
//! The kernel is recursive over terms and values; deep terms need a
//! correspondingly deep stack (run it on a thread with a large stack for big
//! symbolic executions).
#![forbid(unsafe_code)]

pub mod api;
pub mod axioms;
pub mod bvnorm;
pub mod linarith;
pub mod prim;
pub mod syntax;
pub mod term;
pub mod util;
pub mod value;

mod alpha;
mod check;
mod closed;
mod conv;
mod env;
mod eval;
mod inductive;
mod lincert;
mod prelude;
mod quote;
mod recursion;
mod section;

pub use check::measure_obligation_term;
pub use prelude::{FILES as PRELUDE_FILES, expand_templates};
