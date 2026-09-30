//! pe P3 (libraries, arithmetic, bit-vectors): the prover gaps behind the
//! QMDB proof's sequence, slice-view and arithmetic workaround lemmas, each
//! as the minimal repro that failed (docs `pe/INVENTORY.md`: C1, C2, C3, C4,
//! C5, C9), written the way an engineer writes it, and a negative twin that
//! must stay unproven (the closers still fail when the goal does not follow).
//!
//! * C1: the generic `Seq` library (`lemmas/seq_lib.core`) as conditional
//!   rewrite rules: `get` / `skip` / `take` / `++` / indexing;
//! * C2: slices against their views: slice patterns, `first`, `last`,
//!   `split_first`, `split_last`, `get(i)`, and the length link;
//! * C3: `x >> s` for a variable `s` is `x / pow2(s)`; `& 1`, `% 2` and a
//!   boolean equivalence of two comparisons (also through `bv()`);
//! * C4: the unique quotient of a division by a literal;
//! * C5: `pow2` successor and monotonicity for pairs of `pow2` atoms, one
//!   step of `popcount`;
//! * C9: arrays built by `copy_from_slice` into ranges read as appends;
//! * the generated lemma files still match their DSL source.

#[path = "spec15_util.rs"]
mod util;

use std::path::Path;

use util::*;

/// A probe crate: `exec` (exec functions next to a stub boundary function)
/// and `proof` (the PROOF.rs items).
fn run_probe(exec: &str, proof: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n".to_string();
    let exec = format!("use sandblaster::prelude::*;\n/// A stub boundary.\npub fn probe(x: u8) -> u8 {{ x }}\n{exec}");
    let proof = format!("use sandblaster::prelude::*;\n{proof}");
    run_files(&[("r/mod.rs", root.as_str()), ("r/exec.rs", exec.as_str()), ("r/PROOF.rs", proof.as_str())])
}

#[track_caller]
fn proves(exec: &str, proof: &str) -> Run {
    let r = run_probe(exec, proof);
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    assert!(r.verified && r.errors.is_empty(), "not verified:\n{}", r.explain());
    r
}

/// `lemma` stays unproven (an unproven obligation, never a kernel
/// rejection), and every other item proves.
#[track_caller]
fn refutes(exec: &str, proof: &str, lemma: &str) -> Run {
    let r = run_probe(exec, proof);
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    let name = format!("crate::proof::{lemma}");
    assert!(r.unproven.iter().any(|(d, _, _)| *d == name), "`{lemma}` was expected to stay unproven:\n{}", r.explain());
    assert!(r.failed_defs.iter().all(|(d, _)| *d == name), "only `{lemma}` should fail:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected by the kernel"), "a kernel rejection instead of an unproven obligation:\n{}", r.explain());
    r
}

// ---------------------------------------------------------------------------
// C1: the generic `Seq` library
// ---------------------------------------------------------------------------

#[test]
fn a_nonempty_sequence_has_a_first_element() {
    // x_exec2::seq_first
    proves("", "/// .\n#[lemma]\nfn seq_first(ys: Seq<u8>) {\n    requires(ys.len() > 0);\n    ensures(ys.get(0).is_some());\n    follows();\n}\n");
    refutes("", "/// .\n#[lemma]\nfn seq_first(ys: Seq<u8>) {\n    requires(ys.len() >= 0);\n    ensures(ys.get(0).is_some());\n    follows();\n}\n", "seq_first");
}

#[test]
fn an_element_is_get_unwrapped() {
    // a_kernel::idx_lemma
    proves("", "/// .\n#[lemma]\nfn idx_lemma(xs: Seq<u8>, i: Nat) {\n    requires(i < xs.len());\n    ensures(xs[i] == xs.get(i).unwrap_or(0u8));\n    follows();\n}\n");
    refutes("", "/// .\n#[lemma]\nfn idx_lemma(xs: Seq<u8>, i: Nat) {\n    requires(i + 1 < xs.len());\n    ensures(xs[i] == xs.get(i + 1).unwrap_or(0u8));\n    follows();\n}\n", "idx_lemma");
}

#[test]
fn get_through_skip_take_and_append() {
    let good = r#"
/// .
#[lemma]
fn through_skip(ys: Seq<u8>, k: Nat, i: Nat) {
    ensures(ys.skip(k).get(i) == ys.get(i + k));
    follows();
}

/// .
#[lemma]
fn through_append(a: Seq<u8>, b: Seq<u8>, i: Nat) {
    requires(a.len() <= i);
    ensures(seq![..a, ..b].get(i) == b.get(i - a.len()));
    follows();
}

/// .
#[lemma]
fn through_take(ys: Seq<u8>, n: Nat, i: Nat) {
    requires(i < n);
    ensures(ys.take(n).get(i) == ys.get(i));
    follows();
}

/// .
#[lemma]
fn skip_of_append(a: Seq<u8>, b: Seq<u8>) {
    ensures(seq![..a, ..b].skip(a.len() + 1) == b.skip(1));
    follows();
}
"#;
    proves("", good);
    refutes("", "/// .\n#[lemma]\nfn through_skip(ys: Seq<u8>, k: Nat, i: Nat) {\n    requires(k > 0);\n    ensures(ys.skip(k).get(i) == ys.get(i));\n    follows();\n}\n", "through_skip");
    refutes("", "/// .\n#[lemma]\nfn through_take(ys: Seq<u8>, n: Nat, i: Nat) {\n    requires(i <= n);\n    ensures(ys.take(n).get(i) == ys.get(i));\n    follows();\n}\n", "through_take");
}

// ---------------------------------------------------------------------------
// C2: slices against their views
// ---------------------------------------------------------------------------

const SLICE_EXEC: &str = r#"
/// The last element via `[init @ .., last]`.
pub fn last_of(xs: &[u8]) -> Option<u8> {
    match xs {
        [] => None,
        [_init @ .., last] => Some(*last),
    }
}

/// The first element via `[head, tail @ ..]`.
pub fn first_of(xs: &[u8]) -> Option<u8> {
    match xs {
        [] => None,
        [head, _tail @ ..] => Some(*head),
    }
}

/// `slice.get(i)`.
pub fn get_at(xs: &[u8], i: usize) -> Option<&u8> {
    xs.get(i)
}

/// `first()`.
pub fn first_m(xs: &[u8]) -> Option<u8> {
    match xs.first() {
        None => None,
        Some(h) => Some(*h),
    }
}

/// `split_first()`.
pub fn first_s(xs: &[u8]) -> Option<u8> {
    match xs.split_first() {
        None => None,
        Some((h, _t)) => Some(*h),
    }
}

/// `last()`.
pub fn last_m(xs: &[u8]) -> Option<u8> {
    match xs.last() {
        None => None,
        Some(h) => Some(*h),
    }
}

/// `split_last()`.
pub fn last_s(xs: &[u8]) -> Option<u8> {
    match xs.split_last() {
        None => None,
        Some((h, _init)) => Some(*h),
    }
}
"#;

/// A lemma `name` stating that `f(xs)` reads element `at` of the view `ys`.
fn view_lemma(name: &str, f: &str, at: &str) -> String {
    format!(
        "/// .\n#[lemma]\nfn {name}(xs: &[u8], ys: Seq<u8>) {{\n    requires(xs == ys && ys.len() > 0);\n    ensures(crate::exec::{f}(xs) == ys.get({at}));\n    unfold(crate::exec::{f});\n    follows();\n}}\n"
    )
}

#[test]
fn slice_patterns_read_the_view() {
    // x_exec::c1_first, c1_last, c2_get
    let mut p = view_lemma("c1_first", "first_of", "0");
    p.push_str(&view_lemma("c1_last", "last_of", "ys.len() - 1"));
    p.push_str("/// .\n#[lemma]\nfn c2_get(xs: &[u8], ys: Seq<u8>, i: usize) {\n    requires(xs == ys);\n    ensures(crate::exec::get_at(xs, i) == ys.get(i as Nat));\n    unfold(crate::exec::get_at);\n    follows();\n}\n");
    proves(SLICE_EXEC, &p);
    refutes(SLICE_EXEC, &view_lemma("c1_last", "last_of", "0"), "c1_last");
    refutes(SLICE_EXEC, "/// .\n#[lemma]\nfn c2_get(xs: &[u8], ys: Seq<u8>, i: usize) {\n    requires(xs == ys);\n    ensures(crate::exec::get_at(xs, i) == ys.get(i as Nat + 1));\n    unfold(crate::exec::get_at);\n    follows();\n}\n", "c2_get");
}

#[test]
fn slice_methods_read_the_view() {
    // x_exec2::first_m, first_s, last_m, last_s
    let mut p = view_lemma("first_m", "first_m", "0");
    p.push_str(&view_lemma("first_s", "first_s", "0"));
    p.push_str(&view_lemma("last_m", "last_m", "ys.len() - 1"));
    p.push_str(&view_lemma("last_s", "last_s", "ys.len() - 1"));
    proves(SLICE_EXEC, &p);
    refutes(SLICE_EXEC, &view_lemma("first_s", "first_s", "1"), "first_s");
    refutes(SLICE_EXEC, &view_lemma("last_s", "last_s", "0"), "last_s");
}

// ---------------------------------------------------------------------------
// C3: shifts, `& 1` and `% 2`
// ---------------------------------------------------------------------------

const BIT_EXEC: &str = r#"
/// The activity bit, with `& 1`.
#[requires(s < 8)]
pub fn bit_and(b: u8, s: u32) -> bool {
    (b >> s) & 1 != 0
}

/// The same with `% 2`.
#[requires(s < 8)]
pub fn bit_mod(b: u8, s: u32) -> bool {
    (b >> s) % 2 == 1
}
"#;

fn bit_lemma(name: &str, f: &str, rem: &str, closer: &str) -> String {
    format!(
        "/// .\n#[lemma]\nfn {name}(b: u8, s: u32) {{\n    requires(s < 8);\n    ensures(crate::exec::{f}(b, s) == ((b as Nat / pow2(s as Int)) % 2 == {rem}));\n    unfold(crate::exec::{f});\n    {closer}();\n}}\n"
    )
}

#[test]
fn a_shifted_bit_is_a_quotient_bit() {
    // x_exec::c3_bit_and (with `bv()`, as written), c3_bit_mod
    let mut p = bit_lemma("c3_bit_and", "bit_and", "1", "bv");
    p.push_str(&bit_lemma("c3_bit_mod", "bit_mod", "1", "follows"));
    p.push_str(&bit_lemma("c3_bit_and_arith", "bit_and", "1", "by_arithmetic"));
    proves(BIT_EXEC, &p);
    refutes(BIT_EXEC, &bit_lemma("c3_bit_and", "bit_and", "0", "bv"), "c3_bit_and");
    refutes(BIT_EXEC, &bit_lemma("c3_bit_mod", "bit_mod", "0", "follows"), "c3_bit_mod");
    refutes(BIT_EXEC, &bit_lemma("c3_bit_and", "bit_and", "0", "by_arithmetic"), "c3_bit_and");
}

#[test]
fn a_bit_tested_with_a_u64_shift_amount() {
    // QMDB's `active`: `(byte >> (bit % 8)) & 1 != 0` with a `u64` amount
    // (read through a truncating cast to `u32`) against the spec's
    // `(byte / pow2(bit % 8)) % 2 == 1`
    let lemma = |rem: &str| {
        format!(
            "/// .\n#[lemma]\nfn byte_bit(b: u8, s: u64) {{\n    requires(s < 8);\n    ensures(((b >> s) & 1 != 0) == ((b as Nat / pow2(s as Nat)) % 2 == {rem}));\n    bv();\n}}\n"
        )
    };
    proves("", &lemma("1"));
    refutes("", &lemma("0"), "byte_bit");
}

// ---------------------------------------------------------------------------
// C4: unique quotient
// ---------------------------------------------------------------------------

#[test]
fn a_remainder_below_the_divisor_is_unique() {
    // b_norm::c4_mod, and the quotient
    let good = r#"
/// .
#[lemma]
fn c4_mod(a: Nat, y: Nat) {
    requires(a < 128);
    ensures((a + 128 * y) % 128 == a);
    by_arithmetic();
}

/// .
#[lemma]
fn c4_div(a: Nat, y: Nat) {
    requires(a < 128);
    ensures((a + 128 * y) / 128 == y);
    by_arithmetic();
}

/// A hypothesis `x = 2h + b` gives the halves.
#[lemma]
fn c4_halves(x: Nat, h: Nat, b: Nat) {
    requires(b <= 1 && x == 2 * h + b);
    ensures(x / 2 == h && x % 2 == b);
    by_arithmetic();
}
"#;
    proves("", good);
    refutes("", "/// .\n#[lemma]\nfn c4_mod(a: Nat, y: Nat) {\n    requires(a <= 128);\n    ensures((a + 128 * y) % 128 == a);\n    by_arithmetic();\n}\n", "c4_mod");
    refutes("", "/// .\n#[lemma]\nfn c4_div(a: Nat, y: Nat) {\n    requires(a < 128);\n    ensures((a + 128 * y) / 128 == y + 1);\n    by_arithmetic();\n}\n", "c4_div");
}

// ---------------------------------------------------------------------------
// C5: pow2 / popcount
// ---------------------------------------------------------------------------

#[test]
fn pow2_steps_and_monotonicity() {
    // b_norm::c5_pow2_succ
    let good = r#"
/// .
#[lemma]
fn c5_pow2_succ(e: Nat) {
    ensures(pow2(e + 1) == 2 * pow2(e));
    by_arithmetic();
}

/// .
#[lemma]
fn c5_pow2_pred(e: Int) {
    requires(e >= 1);
    ensures(pow2(e) == 2 * pow2(e - 1));
    by_arithmetic();
}

/// .
#[lemma]
fn c5_pow2_mono(e: Int, f: Int) {
    requires(e <= f);
    ensures(pow2(e) <= pow2(f));
    by_arithmetic();
}

/// .
#[lemma]
fn c5_popcount_step(x: Nat) {
    ensures(popcount(x) == x % 2 + popcount(x / 2));
    by_arithmetic();
}
"#;
    proves("", good);
    refutes("", "/// .\n#[lemma]\nfn c5_pow2_succ(e: Nat) {\n    ensures(pow2(e + 1) == 2 * pow2(e) + 1);\n    by_arithmetic();\n}\n", "c5_pow2_succ");
    refutes("", "/// .\n#[lemma]\nfn c5_pow2_mono(e: Int, f: Int) {\n    requires(e <= f);\n    ensures(pow2(f) <= pow2(e));\n    by_arithmetic();\n}\n", "c5_pow2_mono");
}

// ---------------------------------------------------------------------------
// C9: arrays filled by `copy_from_slice`
// ---------------------------------------------------------------------------

#[test]
fn an_array_filled_by_ranges_is_the_append() {
    let exec = r#"
/// Two halves copied into one buffer.
pub fn join(a: &[u8; 4], b: &[u8; 4]) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(a);
    buf[4..].copy_from_slice(b);
    buf
}
"#;
    let lemma = |rhs: &str| {
        format!(
            "/// .\n#[lemma]\nfn join_is(a: [u8; 4], b: [u8; 4], xs: Seq<u8>, ys: Seq<u8>) {{\n    requires(a == xs && b == ys);\n    ensures(crate::exec::join(&a, &b) == {rhs});\n    unfold(crate::exec::join);\n    follows();\n}}\n"
        )
    };
    proves(exec, &lemma("seq![..xs, ..ys]"));
    refutes(exec, &lemma("seq![..ys, ..xs]"), "join_is");
}

// ---------------------------------------------------------------------------
// The generated lemma files
// ---------------------------------------------------------------------------

#[test]
fn p3_lemmas_match_their_source() {
    // `lemmas/seq_lib.core`, `lemmas/bits_pow2.core` and the second part of
    // `lemmas/nat.core` hold the kernel proofs of the DSL lemmas of
    // `samples/p3_lemmas` (the sequence lemmas generalized from the element
    // type `E` to `T`): the source still proves exactly their statements
    use sandblaster_front::driver;
    use sandblaster_front::loader::MemFs;
    use sandblaster_front::target::TargetInfo;
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/p3_lemmas");
    let names = ["mod.rs", "seq.rs", "view.rs", "option.rs", "nat.rs", "shift.rs"];
    let files: Vec<(String, String)> = names.iter().map(|f| (format!("r/{f}"), std::fs::read_to_string(dir.join(f)).unwrap())).collect();
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.clone().unwrap();
    let mismatches = sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(&k, &mut chain, &sandblaster_front::elab::Options::default());
        let mut bad = Vec::new();
        let mut count = 0;
        for d in &out.defs {
            let Some(rest) = d.name.strip_prefix("crate::") else { continue };
            let Some((module, lemma)) = rest.split_once("::") else { continue };
            let ns = match module {
                "seq" => "seq",
                "view" => "slice",
                "option" => "option",
                "nat" => "nat",
                "shift" => "bits",
                _ => continue,
            };
            if lemma == "E" || lemma == "F" || lemma.contains("::") {
                continue;
            }
            count += 1;
            let (Some(src), Some(lib)) = (out.env.lookup_global(&d.name), out.env.lookup_global(&format!("{ns}::{lemma}"))) else {
                bad.push(format!("{}: no library lemma `{ns}::{lemma}`", d.name));
                continue;
            };
            let e = format!("crate::{module}::E");
            let f = format!("crate::{module}::F");
            let st = |g| out.env.print_term(&[], &out.env.global_type(g).unwrap());
            let s = st(src);
            let mut params = String::new();
            if s.contains(&e) {
                params.push_str("(T : Type) ");
            }
            if s.contains(&f) {
                params.push_str("(U : Type) ");
            }
            let s = format!("{params}{}", s.replace(&e, "T").replace(&f, "U").replace(&format!("crate::{module}::"), &format!("{ns}::")));
            let l = st(lib);
            if d.status != sandblaster_front::elab::DefStatus::Checked || s != l {
                bad.push(format!("{}: checked={:?}\n  source: {s}\n  file:   {l}", d.name, d.status));
            }
        }
        if count < 30 {
            bad.push(format!("only {count} sample lemmas"));
        }
        bad
    });
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
