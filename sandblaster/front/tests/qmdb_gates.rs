//! QMDB on the crate path (DESIGN.md §15.8): the gates apply to it like to
//! every crate. Until the fully specified QMDB lands (the §15 S5 QMDB
//! package), the legacy root `sandblaster/fixtures/qmdb/sandblaster/mod.rs` must **fail** with
//! exactly the gate errors the S5 plan recorded for it (PLAN §1.1): its
//! proofs check, but its root exports modules (boundary), its sections are
//! not fully specified, its laws name exec functions (law rules), and its
//! specification surface cannot be locked (`laws::Acceptance` calls exec
//! functions). No verdict, no code.
//!
//! The integration step replaces this test with the passing build of the
//! fully specified root (single-threaded: it elaborates all of QMDB).

mod common;

use common::samples;
use sandblaster_front::driver::{self, LockUse};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

#[test]
fn the_legacy_qmdb_root_fails_the_gates() {
    let root = samples().join("../../../../sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let b = driver::build_crate(&c, LockUse::Enforce, "sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    assert!(b.v.proofs_ok, "the legacy proofs check:\n{}", b.v.diags.render(&c.sm));
    assert!(b.verdict.is_none() && b.emit.is_none(), "no verdict and no optimized code");
    let got: Vec<(&str, bool, usize)> = b.gates.results.iter().map(|r| (r.gate, r.ran, r.errors)).collect();
    let errors = |g: &str| b.gates.results.iter().find(|r| r.gate == g).map(|r| r.errors).unwrap_or(usize::MAX);
    // 5 root `pub mod`s and the generic boundary function `codec::exact`;
    // 44 sections, none fully specified; 22 LR1 + 2 LR2 + 1 LR6a law-rule
    // errors; `laws::Acceptance` reads an exec constant and calls exec
    // functions (spec closure); a surface that cannot be locked (2 errors)
    assert_eq!(errors("boundary"), 6, "{got:?}");
    assert_eq!(errors("sections"), 44, "{got:?}");
    assert_eq!(errors("law-rules"), 25, "{got:?}");
    assert_eq!(errors("examples"), 2, "{got:?}");
    assert_eq!(errors("lock"), 2, "{got:?}");
    // the expensive gate does not run on a crate that already failed
    assert!(b.gates.results.iter().any(|r| r.gate == "mutation" && !r.ran), "{got:?}");
    let rendered = b.render_failure(&c, "sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    assert!(rendered.contains("failed the §15 gates (boundary, examples, sections, law-rules, lock)"), "{rendered}");
}
