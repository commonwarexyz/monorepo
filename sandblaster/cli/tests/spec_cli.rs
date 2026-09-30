//! `sandblaster spec` (DESIGN.md §15.6): the spec sheet (the crate path:
//! exit 0 only with a crate verdict), `--accept [ITEM…]` (the only writer
//! of `SPEC.lock`, after every other gate passed), `--diff <rev-or-path>`
//! (a stage tool) and `--accept --equivalent-only`, on a crate directory on
//! disk.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandblaster")
}

fn tmp(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A fully specified crate: `clamp` and `dbl` refine `spec::capped` and
/// `spec::double`, and two laws state guarantees of the specification.
const ROOT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

mod m;

pub use m::{clamp, dbl};

#[cfg(sandblaster)]
#[spec]
#[path = "spec.rs"]
mod spec;

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const M: &str = r#"use sandblaster::prelude::*;

const LIMIT: u32 = 100;

/// `x`, capped at the limit.
#[refines(crate::spec::capped)]
pub fn clamp(x: u32) -> u32 {
    if x > LIMIT { LIMIT } else { x }
}

/// Twice `x`.
#[refines(crate::spec::double)]
pub fn dbl(x: u32) -> u64 {
    (x as u64) * 2
}
"#;

const SPEC: &str = r#"//! The reference of the two functions.

/// The cap.
pub const LIMIT: Nat = 100;

/// `x`, capped at [`LIMIT`].
#[example(capped(7) == 7)]
#[example(capped(100) == 100)]
#[example(capped(150) == 100)]
pub fn capped(x: Nat) -> Nat {
    x.min(LIMIT)
}

/// Twice `x`.
#[example(double(2) == 4)]
#[example(double(0) == 0)]
pub fn double(x: Nat) -> Nat {
    x + x
}
"#;

const LAWS: &str = r#"use sandblaster::prelude::*;
use crate::spec::capped;

/// Capping preserves order: a smaller input never gives a larger result.
#[law]
fn capping_is_monotone(x: Nat, y: Nat) {
    requires(x < 1000);
    requires(x <= y);
    ensures(capped(x) <= capped(y));
}

/// A value below the limit passes through unchanged.
#[law]
fn small_values_pass(x: Nat) {
    requires(x < 50);
    ensures(capped(x) == x);
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;
use crate::spec::capped;

#[proof]
fn capping_is_monotone(x: Nat, y: Nat) {
    follows();
}

#[proof]
fn small_values_pass(x: Nat) {
    follows();
}
"#;

/// A crate directory (DSL root `mod.rs`).
fn crate_dir(name: &str) -> PathBuf {
    let d = tmp(name);
    write(&d, "mod.rs", ROOT);
    write(&d, "m.rs", M);
    write(&d, "spec.rs", SPEC);
    write(&d, "LAWS.rs", LAWS);
    write(&d, "PROOF.rs", PROOF);
    d
}

fn write(d: &Path, f: &str, text: &str) {
    std::fs::write(d.join(f), text).unwrap();
}

fn edit(d: &Path, f: &str, from: &str, to: &str) {
    let t = std::fs::read_to_string(d.join(f)).unwrap();
    assert!(t.contains(from), "edit site not found: {from}");
    write(d, f, &t.replacen(from, to, 1));
}

fn run(args: &[&str], dir: &Path) -> (Output, String, String) {
    let mut c = Command::new(bin());
    c.arg(args[0]).arg(dir).args(&args[1..]);
    let out = c.output().unwrap();
    let so = String::from_utf8_lossy(&out.stdout).to_string();
    let se = String::from_utf8_lossy(&out.stderr).to_string();
    (out, so, se)
}

#[test]
fn the_sheet_then_accept_then_a_named_change() {
    let d = crate_dir("spec-cli-flow");
    // no lock: the sheet is printed, the missing lock reported, exit 1
    let (o, so, se) = run(&["spec"], &d);
    assert_eq!(o.status.code(), Some(1), "{so}{se}");
    assert!(so.contains("SPECIFICATION SHEET") && so.contains("What a green build means"), "{so}");
    assert!(so.contains("law:crate::laws::capping_is_monotone") && so.contains("requires ((x < (1000: Nat)) == true)"), "{so}");
    assert!(so.contains("kernel type: (x : Int) (y : Int) -> "), "the kernel statement: {so}");
    assert!(so.contains("SPEC.lock: missing"), "{so}");
    assert!(se.contains("error[spec-lock]: no SPEC.lock at"), "{se}");
    assert!(!d.join("SPEC.lock").exists(), "`spec` writes nothing");
    // without a lock there is no verdict: `emit` prints nothing and never
    // writes the lock
    let (o, code, _) = run(&["emit"], &d);
    assert_eq!(o.status.code(), Some(1));
    assert!(code.is_empty());
    assert!(!d.join("SPEC.lock").exists());
    // accept: the lock is written, and then matches
    let (o, so, se) = run(&["spec", "--accept"], &d);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("accepted (added): law:crate::laws::capping_is_monotone") && so.contains("SPEC.lock: matches"), "{so}");
    let lock = std::fs::read_to_string(d.join("SPEC.lock")).unwrap();
    assert!(lock.starts_with("# SPEC.lock") && lock.contains("\nitem law:crate::laws::capping_is_monotone\n"), "{lock}");
    let root = lock.lines().find_map(|l| l.strip_prefix("root ")).unwrap().to_string();
    let (o, so, _) = run(&["spec"], &d);
    assert!(o.status.success(), "{so}");
    assert!(so.contains("SPEC.lock: matches (") && so.contains(&format!("root {root})")), "{so}");
    // the emitted crate exports the lock's root
    let (o, code, se) = run(&["emit"], &d);
    assert!(o.status.success(), "{se}");
    let bytes: Vec<String> = (0..32).map(|i| format!("0x{}u8", &root[2 * i..2 * i + 2])).collect();
    assert!(code.contains(&format!("pub const SANDBLASTER_SPEC_ROOT: [u8; 32] = [{}];", bytes.join(", "))), "{}", &code[code.len().saturating_sub(500)..]);
    // an implementation change needs no review
    edit(&d, "m.rs", "if x > LIMIT { LIMIT } else { x }", "if x >= LIMIT { LIMIT } else { x }");
    let (o, so, _) = run(&["spec"], &d);
    assert!(o.status.success(), "{so}");
    // a changed law is named, with its classification
    edit(&d, "LAWS.rs", "requires(x < 1000);", "requires(x < 2000);");
    let (o, so, se) = run(&["spec"], &d);
    assert_eq!(o.status.code(), Some(1));
    assert!(se.contains("error[spec-lock]: SPEC.lock: `law:crate::laws::capping_is_monotone` changed (strengthened)"), "{se}");
    assert!(so.contains("[changed: strengthened]"), "{so}");
    // accepting it makes the lock match again
    let (o, so, se) = run(&["spec", "--accept", "law:crate::laws::capping_is_monotone"], &d);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("accepted (changed): law:crate::laws::capping_is_monotone"), "{so}");
    let (o, so, _) = run(&["spec"], &d);
    assert!(o.status.success(), "{so}");
    // an unknown item is refused
    let (o, _, se) = run(&["spec", "--accept", "law:crate::laws::nope"], &d);
    assert_eq!(o.status.code(), Some(1));
    assert!(se.contains("is neither a surface item nor an entry of the lock"), "{se}");
}

/// `--accept` writes nothing for a crate that fails another gate: a known
/// answer that does not hold.
#[test]
fn accept_refuses_a_crate_that_fails_a_gate() {
    let d = crate_dir("spec-cli-refuse");
    edit(&d, "spec.rs", "#[example(capped(150) == 100)]", "#[example(capped(150) == 150)]");
    let (o, so, se) = run(&["spec", "--accept"], &d);
    assert_eq!(o.status.code(), Some(1), "{so}{se}");
    assert!(se.contains("is false") && se.contains("not writing"), "{se}");
    assert!(!d.join("SPEC.lock").exists());
}

#[test]
fn diff_against_another_directory_classifies_requires_changes() {
    let old = crate_dir("spec-cli-diff-old");
    let new = crate_dir("spec-cli-diff-new");
    edit(&new, "LAWS.rs", "requires(x < 50);", "requires(x < 50);\n    requires(x > 3);");
    let (o, so, se) = run(&["spec", "--diff", old.to_str().unwrap()], &new);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("law:crate::laws::small_values_pass: changed (weakened)"), "{so}");
    // and the section of `clamp` (its hypotheses changed; S3)
    assert!(so.contains("2 change(s): 1 weakened, 1 unrelated") || so.contains("1 weakened"), "{so}");
    let (o, so, se) = run(&["spec", "--diff", new.to_str().unwrap()], &old);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("law:crate::laws::small_values_pass: changed (strengthened)"), "{so}");
}

#[test]
fn diff_against_a_git_revision() {
    let d = crate_dir("spec-cli-diff-git");
    let git = |args: &[&str]| Command::new("git").arg("-C").arg(&d).args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]).args(args).output();
    match git(&["init", "-q"]) {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("git is not available: skipped");
            return;
        }
    }
    assert!(git(&["add", "."]).unwrap().status.success());
    assert!(git(&["commit", "-q", "-m", "base"]).unwrap().status.success());
    edit(&d, "LAWS.rs", "requires(x < 50);", "requires(x < 50);\n    requires(x > 3);");
    let (o, so, se) = run(&["spec", "--diff", "HEAD"], &d);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("spec diff: `HEAD`") && so.contains("law:crate::laws::small_values_pass: changed (weakened)"), "{so}");
}

#[test]
fn equivalent_only_accepts_only_kernel_proven_equivalents() {
    let d = crate_dir("spec-cli-equiv");
    let (o, so, se) = run(&["spec", "--accept"], &d);
    assert!(o.status.success(), "{so}{se}");
    edit(&d, "LAWS.rs", "requires(x < 1000);", "requires(x <= 999);");
    edit(&d, "LAWS.rs", "requires(x < 50);", "requires(x < 50);\n    requires(x > 3);");
    let (o, so, se) = run(&["spec", "--accept", "--equivalent-only"], &d);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("accepted (changed): law:crate::laws::capping_is_monotone"), "{so}");
    assert!(so.contains("not accepted: law:crate::laws::small_values_pass: changed (weakened)"), "{so}");
    let (o, so, se) = run(&["spec"], &d);
    assert_eq!(o.status.code(), Some(1), "{so}");
    let errors: Vec<&str> = se.lines().filter(|l| l.contains("error[spec-lock]")).collect();
    assert!(errors.iter().any(|l| l.contains("`law:crate::laws::small_values_pass` changed (weakened)")) && !errors.iter().any(|l| l.contains("capping_is_monotone")), "{se}");
    // --equivalent-only needs an existing lock
    let e = crate_dir("spec-cli-equiv-nolock");
    let (o, _, se) = run(&["spec", "--accept", "--equivalent-only"], &e);
    assert_eq!(o.status.code(), Some(1));
    assert!(se.contains("--equivalent-only re-accepts"), "{se}");
}

#[test]
fn spec_options_belong_to_spec() {
    let d = crate_dir("spec-cli-usage");
    let (o, _, _) = run(&["check", "--accept"], &d);
    assert_eq!(o.status.code(), Some(2));
    let (o, _, _) = run(&["spec", "--equivalent-only"], &d);
    assert_eq!(o.status.code(), Some(2));
    let (o, _, _) = run(&["spec", "--accept", "--diff", "HEAD"], &d);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn diff_against_a_git_revision_reads_vector_files_outside_the_root() {
    // the QMDB layout: the DSL root in `q/sandblaster/`, the vectors in
    // `q/vectors/`, named `../vectors/..` from the root; the old revision is
    // read from git as a whole tree, not only the root directory
    let repo = tmp("spec-cli-diff-git-vectors");
    let git = |args: &[&str]| Command::new("git").arg("-C").arg(&repo).args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]).args(args).output();
    match git(&["init", "-q"]) {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("git is not available: skipped");
            return;
        }
    }
    let root = repo.join("q/sandblaster");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(repo.join("q/vectors")).unwrap();
    let with_vectors = format!("{SPEC}\n/// The known answers of `double`.\n#[examples(file = \"../vectors/dbl.rsp\", format = \"cavp\", provenance = independent)]\npub fn dbl_kat(x: Nat, y: Nat) -> bool {{ double(x) == y }}\n");
    write(&root, "mod.rs", ROOT);
    write(&root, "m.rs", M);
    write(&root, "spec.rs", &with_vectors);
    write(&root, "LAWS.rs", LAWS);
    write(&root, "PROOF.rs", PROOF);
    write(&repo.join("q/vectors"), "dbl.rsp", "X = 1\nY = 2\n\nX = 7\nY = 14\n");
    assert!(git(&["add", "."]).unwrap().status.success());
    assert!(git(&["commit", "-q", "-m", "base"]).unwrap().status.success());
    // the working tree changes a law and the vector file
    edit(&root, "LAWS.rs", "requires(x < 50);", "requires(x < 50);\n    requires(x > 3);");
    write(&repo.join("q/vectors"), "dbl.rsp", "X = 1\nY = 2\n\nX = 8\nY = 16\n");
    let (o, so, se) = run(&["spec", "--diff", "HEAD"], &root);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("law:crate::laws::small_values_pass: changed (weakened)"), "{so}");
    assert!(so.contains("vector-file:crate::spec::dbl_kat#0: changed"), "the old revision's vector file comes from git: {so}");
}

/// `--preview <file>` writes the lock `--accept` would write — to that
/// file, never to a lock — and reports the item counts; it refuses a lock
/// file name and `--accept`.
#[test]
fn preview_writes_the_lock_accept_would_write_and_never_a_lock() {
    let d = crate_dir("spec-cli-preview");
    let out = d.join("preview.txt");
    let (o, so, se) = run(&["spec", "--preview", out.to_str().unwrap()], &d);
    assert!(o.status.success(), "{so}{se}");
    assert!(so.contains("item(s) (the lock now: missing or malformed)") && so.contains("proof internal(s) not locked") && so.contains("(not the lock)"), "{so}");
    assert!(!d.join("SPEC.lock").exists(), "a preview never writes the lock");
    let preview = std::fs::read_to_string(&out).unwrap();
    let (o, so, se) = run(&["spec", "--accept"], &d);
    assert!(o.status.success(), "{so}{se}");
    assert_eq!(std::fs::read_to_string(d.join("SPEC.lock")).unwrap(), preview, "the preview is the lock --accept writes");
    // with a lock: nothing to add, change or remove
    let (o, so, _) = run(&["spec", "--preview", out.to_str().unwrap()], &d);
    assert!(o.status.success() && so.contains("0 added, 0 changed, 0 removed, 0 restated"), "{so}");
    // negative twins: a lock file name, and together with --accept
    let lock = d.join("SPEC.lock");
    let before = std::fs::read_to_string(&lock).unwrap();
    edit(&d, "LAWS.rs", "requires(x < 1000);", "requires(x < 2000);");
    let (o, _, se) = run(&["spec", "--preview", lock.to_str().unwrap()], &d);
    assert_eq!(o.status.code(), Some(2), "{se}");
    assert!(se.contains("never writes a lock file"), "{se}");
    let (o, _, se) = run(&["spec", "--preview", d.join("SPEC.other.lock").to_str().unwrap()], &d);
    assert_eq!(o.status.code(), Some(2), "{se}");
    assert_eq!(std::fs::read_to_string(&lock).unwrap(), before);
    let (o, _, _) = run(&["spec", "--accept", "--preview", out.to_str().unwrap()], &d);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(std::fs::read_to_string(&lock).unwrap(), before, "no lock was written");
    // the changed law shows in the preview's counts
    let (o, so, _) = run(&["spec", "--preview", out.to_str().unwrap()], &d);
    assert!(o.status.success() && so.contains(" changed, ") && !so.contains(" 0 changed, "), "{so}");
}
