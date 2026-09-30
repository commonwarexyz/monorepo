//! Optimizer policy (DESIGN.md §8.2): every function gets exactly one
//! result; stuck evaluation and the cost model are ordinary
//! `Unspecialized(reason)` outcomes; optimizer failures are warnings with a
//! fallback to the proven unspecialized definition (errors under strict
//! mode); `#[specialize]` functions must specialize; the output is
//! deterministic.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use sandblaster_front::opt::{OptOptions, Outcome};

const SRC: &str = r#"
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Off,
    On(u8),
}

/// Stuck on a loop (the driver keeps loops for Σ2): an ordinary
/// `Unspecialized`.
pub fn gate(on: bool, xs: &[u32]) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..xs.len() {
        acc = acc.wrapping_add(xs[i]);
    }
    if on { acc.rotate_left(3) } else { acc }
}

/// Straight line: specialized.
pub fn mix(x: u32) -> u32 {
    x.rotate_left(5) ^ (x >> 2u32)
}

/// A residual the printer cannot express (an enum value): an optimizer
/// failure.
pub fn default_mode() -> Mode {
    Mode::On(3)
}
"#;

fn run(src: &str, o: OptOptions) -> driver::OptimizedEmit {
    let c = util::accepted(src);
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let built = driver::stage::verify_and_optimize(&c, &opts, &o, "r/mod.rs");
    assert!(built.v.proofs_ok, "{}", util::explain(&c, &built.v));
    built.emit.unwrap().unwrap()
}

fn outcome<'a>(em: &'a driver::OptimizedEmit, name: &str) -> &'a Outcome {
    &em.opt.fns.iter().find(|f| f.name == format!("crate::{name}")).unwrap_or_else(|| panic!("no report for {name}")).outcome
}

#[test]
fn outcomes_warnings_and_strict_mode() {
    let em = run(SRC, OptOptions::default());
    assert!(matches!(outcome(&em, "mix"), Outcome::Specialized { .. }));
    assert!(matches!(outcome(&em, "gate"), Outcome::Unspecialized { failure: false, reason } if reason.contains("stuck-free")), "{:?}", outcome(&em, "gate"));
    assert!(matches!(outcome(&em, "default_mode"), Outcome::Unspecialized { failure: true, .. }), "{:?}", outcome(&em, "default_mode"));
    // a failure is a warning, and the proven unspecialized definition is used
    assert!(em.opt.errors.is_empty());
    assert!(em.opt.warnings.iter().any(|w| w.contains("default_mode")), "{:?}", em.opt.warnings);
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    assert!(em.code.contains("fn default_mode()"));
    // strict mode turns it into an error
    let strict = run(SRC, OptOptions { strict: true, ..Default::default() });
    assert!(strict.opt.errors.iter().any(|e| e.contains("default_mode")), "{:?}", strict.opt.errors);
}

#[test]
fn specialize_attribute_requires_success() {
    let src = format!("{SRC}\n#[specialize]\npub fn must(xs: &[u32]) -> u32 {{ let mut acc: u32 = 0; for i in 0..xs.len() {{ acc = acc ^ xs[i]; }} acc }}\n");
    let em = run(&src, OptOptions::default());
    assert!(em.opt.errors.iter().any(|e| e.contains("must") && e.contains("#[specialize]")), "{:?}", em.opt.errors);
    // a #[specialize] function that does specialize is fine
    let src = format!("{SRC}\n#[specialize]\npub fn fine(x: u32) -> u32 {{ x ^ 1u32 }}\n");
    let em = run(&src, OptOptions::default());
    assert!(!em.opt.errors.iter().any(|e| e.contains("fine")), "{:?}", em.opt.errors);
}

#[test]
fn cost_model_budget_is_an_ordinary_outcome() {
    let em = run(SRC, OptOptions { node_budget: 3, ..Default::default() });
    assert!(matches!(outcome(&em, "mix"), Outcome::Unspecialized { failure: false, reason } if reason.contains("node budget")), "{:?}", outcome(&em, "mix"));
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
}

#[test]
fn output_is_deterministic() {
    let a = run(SRC, OptOptions::default()).code;
    let b = run(SRC, OptOptions::default()).code;
    assert_eq!(a, b);
}
