//! QMDB on the crate path (DESIGN.md §15.8): the gates apply to it like to
//! every crate. The root `sandblaster/fixtures/qmdb/sandblaster/mod.rs` is
//! the fully specified QMDB of §15 S5 (five laws over `spec::` items, the
//! refinements R1–R12): its proofs check and it passes the boundary,
//! examples, sections and law-rule gates. Its checked-in `SPEC.lock` was
//! written before the lock became the review surface (the lock format and
//! its root hash changed; a preview of the lock `sandblaster spec --accept`
//! would write has 235 items where the checked-in one has 332), so the lock
//! gate reports exactly one error — the lock is malformed for this
//! toolchain — the build issues no verdict and no code, and spec mutation
//! (which runs after every other gate passed) does not run.
//!
//! Re-accepting the lock is a review step for the fixture's owner
//! (`sandblaster spec --accept`); once it is accepted, this test becomes the
//! passing build of the root (single-threaded: it elaborates all of QMDB).
//! (Until 2026-09 this test expected the legacy root's 6 boundary, 44
//! section, 25 law-rule, 2 example and 2 lock errors; S5 replaced that
//! root.)

mod common;

use common::samples;
use sandblaster_front::driver::{self, LockUse};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

#[test]
fn the_qmdb_root_fails_only_its_stale_lock() {
    let root = samples().join("../../../../sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let b = driver::build_crate(&c, LockUse::Enforce, "sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    assert!(b.v.proofs_ok, "the proofs check:\n{}", b.v.diags.render(&c.sm));
    assert!(b.verdict.is_none() && b.emit.is_none(), "no verdict and no optimized code");
    let got: Vec<(&str, bool, usize)> = b.gates.results.iter().map(|r| (r.gate, r.ran, r.errors)).collect();
    let errors = |g: &str| b.gates.results.iter().find(|r| r.gate == g).map(|r| r.errors).unwrap_or(usize::MAX);
    // every gate but the lock passes
    for g in ["boundary", "examples", "sections", "law-rules"] {
        assert_eq!(errors(g), 0, "{g}: {got:?}");
    }
    // the lock of an older toolchain: one error, no verdict
    assert_eq!(errors("lock"), 1, "{got:?}");
    let diags = b.gates.diags.render(&c.sm);
    assert!(diags.contains("error[spec-lock]") && diags.contains("is malformed") && diags.contains("sandblaster spec --accept"), "{diags}");
    // the expensive gate does not run on a crate that already failed
    assert!(b.gates.results.iter().any(|r| r.gate == "mutation" && !r.ran), "{got:?}");
    let rendered = b.render_failure(&c, "sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    assert!(rendered.contains("failed the §15 gates (lock)"), "{rendered}");
}
