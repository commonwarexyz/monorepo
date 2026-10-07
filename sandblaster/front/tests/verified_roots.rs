//! The three verified roots — commonware-codec's varint
//! (`codec/sandblaster/varint`), commonware-storage's MMR
//! (`storage/sandblaster/mmr`) and Merkle proof verifier
//! (`storage/sandblaster/verifier`) — as the large examples of the
//! toolchain's suites. They replaced the QMDB fixture (a port in
//! sandblaster's own dialect, removed 2026-10-05), whose tests used it the
//! same way:
//!
//! * the boundary gate passes on every root, and a `pub mod` at a root is
//!   refused (was `boundary_rules::gate_on_todays_qmdb_root`);
//! * every root fits the stack budget, the verifier's depth-bounded
//!   non-tail recursion included (was
//!   `validator::qmdb_fits_the_stack_budget`);
//! * the MMR on the crate path: its proofs check (every law proven, every
//!   obligation proven and located) and it passes every §15 gate, the law
//!   rules (with the law table) and the lock included, and the theorem gate
//!   (was `qmdb_gates`, `elab_laws::qmdb_laws_are_proven`,
//!   `spec15_law_rules::qmdb_laws_pass_every_rule`,
//!   `elab_qmdb::obligation_records_carry_spans_kinds_and_provers`);
//! * a false law of a root is not proven, on the elaboration of what the
//!   law reaches (was `elab_laws::a_false_law_is_not_proven`);
//! * a root verifies on x86_64 (was
//!   `elab_qmdb::qmdb_on_x86_64_elaborates`).
//!
//! Each root's own build (`cargo test -p commonware-codec`,
//! `-p commonware-storage`) runs the whole verification — the lift
//! conformance check against rustc included — on every toolchain change.
//! The tests that elaborate a root take minutes each: run with
//! `--test-threads=1` under the default memory limit.

use std::path::{Path, PathBuf};

use sandblaster_front::diag::{Diagnostics, Severity};
use sandblaster_front::driver::{self, Checked, LockUse, ProverSet, VerifyOptions};
use sandblaster_front::elab::{self, DefStatus, ProverChain};
use sandblaster_front::loader::{self, FileProvider, RealFs};
use sandblaster_front::target::TargetInfo;
use sandblaster_front::validate;

const VARINT: &str = "codec/sandblaster/varint/mod.rs";
const MMR: &str = "storage/sandblaster/mmr/mod.rs";
const VERIFIER: &str = "storage/sandblaster/verifier/mod.rs";

/// Serializes the elaborations of whole roots (each holds a root's kernel
/// environment; side by side they would exceed the memory limit).
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn root(rel: &str) -> PathBuf {
    loader::normalize(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel))
}

/// The real file system with some files replaced (by their path relative
/// to the repository).
struct Overlay(Vec<(String, String)>);

impl Overlay {
    fn edit(&self, path: &Path) -> Option<&String> {
        let p = loader::normalize(path);
        self.0.iter().find(|(rel, _)| p.ends_with(rel)).map(|(_, t)| t)
    }
}

impl FileProvider for Overlay {
    fn read(&self, path: &Path) -> std::io::Result<String> {
        match self.edit(path) {
            Some(t) => Ok(t.clone()),
            None => RealFs.read(path),
        }
    }
    fn exists(&self, path: &Path) -> bool {
        self.edit(path).is_some() || RealFs.exists(path)
    }
    fn list_rs(&self, dir: &Path) -> std::io::Result<Vec<PathBuf>> {
        RealFs.list_rs(dir)
    }
}

/// `file` (relative to the repository) with `from` replaced by `to` once.
fn edited(file: &str, from: &str, to: &str) -> Overlay {
    let text = std::fs::read_to_string(root(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(text.matches(from).count(), 1, "{file}: `{from}` must occur once");
    Overlay(vec![(file.to_string(), text.replacen(from, to, 1))])
}

#[track_caller]
fn check_on(rel: &str, fs: &dyn FileProvider, target: &TargetInfo) -> Checked {
    let c = driver::check(&root(rel), fs, target);
    assert!(c.krate.is_some(), "{rel}:\n{}", c.render());
    c
}

#[track_caller]
fn check(rel: &str) -> Checked {
    let c = check_on(rel, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{rel}:\n{}", c.render());
    c
}

fn boundary_gate(c: &Checked) -> Vec<String> {
    let mut d = Diagnostics::new();
    validate::spec15_gate(c.krate.as_ref().expect("a crate"), &mut d);
    d.list.iter().map(|x| x.msg.clone()).collect()
}

/// Every root's boundary is its `pub use` list, and the §15.8 boundary
/// gate passes. Negative twin: the verifier with its `merkle` module made
/// `pub` at the root is refused by the gate.
#[test]
fn the_boundary_gate_passes_on_the_verified_roots_and_refuses_a_pub_mod() {
    for rel in [VARINT, MMR, VERIFIER] {
        let c = check(rel);
        assert_eq!(boundary_gate(&c), Vec::<String>::new(), "{rel}");
    }
    let fs = edited(VERIFIER, "\nmod merkle;\n", "\npub mod merkle;\n");
    let c = check_on(VERIFIER, &fs, &TargetInfo::aarch64_apple_darwin());
    let g = boundary_gate(&c);
    assert!(g.iter().any(|m| m.contains("`pub mod merkle` is not allowed at the DSL root")), "{g:?}\n{}", c.render());
}

/// Every root passes the front end's stack check (DESIGN.md §3.7), and the
/// verifier's non-tail recursion `Subtree::reconstruct_digest` (depth
/// bounded by its attachment, `decreases(self.height, max = 64)`) has an
/// estimate within the budget.
#[test]
fn the_verified_roots_fit_the_stack_budget() {
    for rel in [VARINT, MMR, VERIFIER] {
        let c = check(rel);
        assert!(!c.diags.list.iter().any(|d| d.kind == sandblaster_front::diag::DiagKind::Recursion), "{rel}:\n{}", c.render());
    }
    let c = check(VERIFIER);
    let k = c.krate.as_ref().unwrap();
    let id = k.find("crate::merkle::proof::Subtree::reconstruct_digest").expect("the verifier's recursion");
    let s = validate::stack_estimate(k, id);
    eprintln!("stack estimate of reconstruct_digest: {s:?} bytes (budget {})", validate::STACK_BUDGET);
    assert!(s.is_some_and(|s| s <= validate::STACK_BUDGET), "{s:?}");
}

/// The MMR on the crate path (`driver::build_crate`): its proofs check —
/// every law proven, no open claim, every obligation proven and located —
/// and every §15 gate passes (boundary, examples, sections, law rules with
/// every law's guarantee in the table, the lock, which matches), and every
/// lifted function has its MIR theorem. (The crate path issues no verdict
/// here: in-place modules are verified by `compile_lifted`, whose lift
/// conformance check compiles the host crate; the storage build runs it.)
#[test]
fn the_mmr_passes_every_gate_on_the_crate_path() {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = check(MMR);
    let b = driver::build_crate(&c, LockUse::Enforce, MMR);
    assert!(b.v.proofs_ok, "the proofs:\n{}", b.v.diags.render(&c.sm));
    let st = b.v.stats();
    assert_eq!(st.failed + st.todo, 0);
    assert!(!b.v.laws.is_empty() && b.v.laws.iter().all(|l| l.status == DefStatus::Checked && l.proof != "missing"), "{:?}", b.v.laws);
    for o in &b.v.obligations {
        assert!(!o.span.is_dummy(), "obligation {} of {} has no span", o.id, o.def);
        assert!(o.proven(), "{} unproven", o.def);
    }
    let kinds: std::collections::BTreeSet<&str> = b.v.obligations.iter().map(|o| elab::obl::kind_name(&o.kind)).collect();
    eprintln!("MMR: {} definitions, {} obligations, kinds {kinds:?}, {} laws, {:.1}s", b.v.defs.len(), st.total, b.v.laws.len(), b.v.elapsed.as_secs_f64());
    for kind in ["overflow", "law-goal"] {
        assert!(kinds.contains(kind), "no `{kind}` obligation in the MMR; kinds: {kinds:?}");
    }
    for g in ["boundary", "examples", "sections", "law-rules", "lock", "mir-theorems"] {
        let r = b.gates.results.iter().find(|r| r.gate == g).unwrap_or_else(|| panic!("gate {g} did not run: {:?}", b.gates.results));
        assert!(r.ran && r.errors == 0, "{g}: {r:?}\n{}", b.gates.diags.render(&c.sm));
    }
    assert!(!b.gates.diags.list.iter().any(|d| d.severity == Severity::Error), "{}", b.gates.diags.render(&c.sm));
    assert!(b.spec.matches(), "{}", b.spec.summary());
    let laws = &b.surface.as_ref().expect("the surface").laws;
    assert_eq!(laws.len(), b.v.laws.len(), "every law is in the table");
    assert!(laws.iter().all(|l| l.guarantee.as_deref().is_some_and(|g| !g.is_empty())), "{laws:?}");
    assert!(b.verdict.is_none() && b.gates.chain.iter().any(|x| x.contains("compile_lifted")), "{:?}", b.gates.chain);
}

/// A false law (`to_nearest_size` strictly below every size: it equals an
/// MMR size) is not proven, and the diagnostics name it; only what the law
/// reaches is elaborated (`elab::order::filter_closure`). Its positive
/// twin is the MMR's own law, proven in
/// [`the_mmr_passes_every_gate_on_the_crate_path`].
#[test]
fn a_false_law_of_the_mmr_is_not_proven() {
    const LAW: &str = "crate::laws::to_nearest_size_rounds_down";
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let fs = edited("storage/sandblaster/mmr/LAWS.rs", "PeakIterator::to_nearest_size(size).0 <= size.0);", "PeakIterator::to_nearest_size(size).0 < size.0);");
    let c = check_on(MMR, &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let items = elab::order::filter_closure(k, [k.find(LAW).expect("the law")]);
    let opts = elab::Options { items: Some(std::sync::Arc::new(items)), ..elab::Options::default() };
    let (status, errors) = elab::with_big_stack(|| {
        let out = elab::elaborate(k, &mut ProverChain::standard(), &opts);
        let status = out.laws.iter().find(|l| l.name == LAW).map(|l| l.status.clone());
        let errors: Vec<String> = out.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.render(&c.sm)).collect();
        (status, errors)
    });
    assert!(status.as_ref().is_some_and(|s| *s != DefStatus::Checked), "{status:?}");
    assert!(errors.iter().any(|e| e.contains("to_nearest_size_rounds_down")), "{}", errors.join("\n"));
}

/// The verifier's `reconstruct_digest` against its law `rebuild`, with no
/// case lemmas: at a node the search meets the code's halves
/// (`children()`), its `?` exits and its pushes with the law's
/// `left_half`/`right_half` through the recursive calls' induction
/// hypotheses — the prover gap that the verifier's `rebuild_case_node` and
/// four `node_*` lemmas worked around (`auto::rewrite`: alignment with the
/// equations' terms, and rewrites that keep the target in the facts'
/// terms first). Only what the function reaches is elaborated. Negative
/// twin: a law (and its step lemma) that hashes a node's halves the other
/// way round is not met by the code — its contract's obligations, and
/// only those, stay unproven — and nothing is rejected by the kernel.
#[test]
fn the_verifier_reconstruction_is_proven_without_case_lemmas() {
    const F: &str = "crate::merkle::proof::Subtree::reconstruct_digest";
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // the law and its step lemma (`rebuild_step`, still true of the swapped
    // law) swapped together: only the code's contract fails
    let swap = |file: &str, from: &str, to: &str| -> (String, String) {
        let text = std::fs::read_to_string(root(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(text.matches(from).count(), 1, "{file}: `{from}` must occur once");
        (file.to_string(), text.replacen(from, to, 1))
    };
    let swapped = Overlay(vec![
        swap(
            "storage/sandblaster/verifier/LAWS.rs",
            "crate::__lift::Result::Ok(sha256(node_message(s.pos.0, dl, dr))),",
            "crate::__lift::Result::Ok(sha256(node_message(s.pos.0, dr, dl))),",
        ),
        swap(
            "storage/sandblaster/verifier/PROOF.rs",
            "node_message(s.pos.0, dl, dr))),\n                    ),\n                }\n            }\n        }\n    }));\n    by_unfolding(crate::laws::rebuild);",
            "node_message(s.pos.0, dr, dl))),\n                    ),\n                }\n            }\n        }\n    }));\n    by_unfolding(crate::laws::rebuild);",
        ),
    ]);
    for (fs, holds) in [(&Overlay(Vec::new()), true), (&swapped, false)] {
        let c = check_on(VERIFIER, fs, &TargetInfo::aarch64_apple_darwin());
        assert!(c.ok(), "{}", c.render());
        let k = c.krate.as_ref().unwrap();
        let items = elab::order::filter_closure(k, [k.find(F).expect("the function")]);
        let opts = elab::Options { items: Some(std::sync::Arc::new(items)), ..elab::Options::default() };
        let (status, unproven, rendered) = elab::with_big_stack(|| {
            let out = elab::elaborate(k, &mut ProverChain::standard(), &opts);
            // the contract's obligations are the definition `F::ensures`
            let status = out.defs.iter().find(|d| d.name == format!("{F}::ensures")).map(|d| d.status.clone());
            let unproven: Vec<String> = out.obligations.iter().filter(|o| !o.proven()).map(|o| o.def.clone()).collect();
            (status, unproven, out.diags.render(&c.sm))
        });
        assert!(!rendered.contains("rejected by the kernel") && !rendered.contains("the kernel rejected"), "{rendered}");
        if holds {
            assert_eq!(status, Some(DefStatus::Checked), "{rendered}");
            assert!(unproven.is_empty(), "unproven: {unproven:?}\n{rendered}");
        } else {
            assert!(status.as_ref().is_some_and(|s| *s != DefStatus::Checked), "a swapped node hash was met: {status:?}");
            assert!(!unproven.is_empty() && unproven.iter().all(|d| d.starts_with(F)), "{unproven:?}");
        }
    }
}

/// The MMR verifies on x86_64 too: its proofs (exec code, laws, lemmas;
/// the lifted functions' contracts name the laws file, so the ghost items
/// are elaborated as well) check with every obligation proven. (No lock
/// accepts x86_64; the proofs, not the gates, are this test's subject.)
#[test]
fn the_mmr_verifies_on_x86_64() {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = check_on(MMR, &RealFs, &TargetInfo::x86_64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    assert!(v.failed_defs().is_empty(), "{}", v.diags.render(&c.sm));
    assert_eq!(v.stats().failed + v.stats().todo, 0, "{}", v.diags.render(&c.sm));
    assert!(v.proofs_ok, "{}", v.diags.render(&c.sm));
    assert!(v.defs.iter().any(|d| d.name.contains("to_nearest_size")), "the lifted functions are definitions");
}
