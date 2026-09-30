//! RED TEAM — proof-gate integrity (lens: PROOF-GATE INTEGRITY).
//!
//! Goal of these probes: make `sandblaster::build::compile` (via
//! `driver::build_verified`) accept a crate that ships unverified code or a
//! false/vacuous law, without the build failing, or emit a verification
//! report that overstates what was proven.
//!
//! The two findings (RG-1 vacuous laws, RG-2 stack overflow) are regression
//! tests now; the remaining `#[ignore]`d probes only print emitted code.
//!
//! Each probe drives `build_verified` with an in-memory file system, exactly
//! as `sandblaster/sandblaster/src/build.rs` drives it with the real one. `outcome.ok`
//! is what decides whether the crate compiles; `sandblaster-report.json` is what
//! an auditor reads.

use std::collections::HashMap;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";
const LIB: &str = "include!(concat!(env!(\"OUT_DIR\"), \"/sandblaster.rs\"));";

use sandblaster_front::driver::{build_verified, BuildOutcome};
use sandblaster_front::loader::MemFs;

fn env() -> HashMap<String, String> {
    [
        ("CARGO_MANIFEST_DIR", "/crate"),
        ("OUT_DIR", "/out"),
        ("CARGO_CFG_TARGET_ARCH", "aarch64"),
        ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// Builds a crate whose DSL files are given relative to `sandblaster/`
/// (`files[0]` is `mod.rs`). `src/lib.rs` is the mandated include line.
fn build(files: &[(&str, &str)]) -> BuildOutcome {
    let mut all: Vec<(String, String)> = vec![("/crate/src/lib.rs".into(), LIB.into())];
    for (p, c) in files {
        all.push((format!("/crate/sandblaster/{p}"), (*c).to_string()));
    }
    let fs = MemFs::from_files(all.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let e = env();
    build_verified("sandblaster/mod.rs", &|k| e.get(k).cloned(), &fs)
}

#[allow(dead_code)]
fn code<'o>(o: &'o BuildOutcome) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.ends_with("sandblaster.rs")).map(|(_, c)| c.as_str())
}
fn report<'o>(o: &'o BuildOutcome) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.ends_with("sandblaster-report.json")).map(|(_, c)| c.as_str())
}

// ===========================================================================
// FINDING 1 (RG-1) — a *vacuously true* law with a false-looking conclusion
// was certified "checked" and the whole build was "VERIFIED + OPTIMIZED",
// even though the shipped function does the opposite of what the law
// appears to say. The gate now refutes contradictory hypotheses (bounded
// prover attempt, kernel-checked) and fails the build with "vacuous law".
// ===========================================================================
fn vacuous_law_crate(requires: &str) -> BuildOutcome {
    // A BROKEN verifier that accepts everything.
    let root = format!(
        "{HEADER}\
         #[cfg(sandblaster)] #[path = \"laws.rs\"] mod laws;\n\
         #[cfg(sandblaster)] #[path = \"proof.rs\"] mod proof;\n\
         /// Membership verifier.\n\
         pub fn verify(_root: &[u8], _key: &[u8], _value: &[u8], _proof: &[u8]) -> bool {{ true }}\n"
    );
    // A law that *reads* like the core soundness guarantee, but whose
    // `requires` is a hidden contradiction, so it is vacuously true.
    let laws = format!(
        "use sandblaster::prelude::*;\nuse super::verify;\n\
        /// SOUNDNESS: a forged proof (empty) is never accepted.\n\
        #[law]\n\
        fn verify_rejects_forged_proof(root: &[u8], key: &[u8], value: &[u8]) {{\n\
            {requires}\n\
            ensures(verify(root, key, value, &[]) == false);\n\
        }}\n"
    );
    let proof = "use sandblaster::prelude::*;\n\
        #[proof]\n\
        fn verify_rejects_forged_proof(root: &[u8], key: &[u8], value: &[u8]) {}\n";
    build(&[("mod.rs", &root), ("laws.rs", &laws), ("proof.rs", proof)])
}

#[test]
fn finding1_vacuous_law_masquerades_as_soundness() {
    // Two innocuous-looking bounds that cannot both hold.
    let o = vacuous_law_crate("requires(root.len() < 3);\n requires(root.len() > 5);");
    eprintln!("stderr:\n{}", o.stderr);
    assert!(!o.ok, "a vacuous law must fail the build");
    assert!(o.stderr.contains("vacuous law"), "{}", o.stderr);
    assert!(code(&o).is_none(), "nothing is emitted");
    let r = report(&o).expect("the report of the failed build");
    assert!(r.contains("\"status\": \"NOT VERIFIED\"") && !r.contains("VERIFIED +") && !r.contains("VERIFIED (phase"), "the report must not claim verification:\n{r}");
    assert!(r.contains("vacuous: its hypotheses are contradictory"), "{r}");
    // the law's statement is in the report for auditors
    assert!(r.contains("requires(root.len() < 3) requires(root.len() > 5) ensures(verify(root, key, value, &[]) == false)"), "{r}");
    // the minimal variant
    let o = vacuous_law_crate("requires(1u32 == 2u32);");
    assert!(!o.ok && o.stderr.contains("vacuous law"), "{}", o.stderr);
    // contradictory facts about one atom (the function is not unfolded)
    let o = vacuous_law_crate("requires(verify(root, key, value, value) == true);\n requires(verify(root, key, value, value) == false);");
    assert!(!o.ok && o.stderr.contains("vacuous law"), "{}", o.stderr);
    // a satisfiable hypothesis is not flagged (the law is false: rejected as unproven)
    let o = vacuous_law_crate("requires(root.len() < 3);");
    assert!(!o.ok && !o.stderr.contains("vacuous law") && o.stderr.contains("unproven obligation"), "{}", o.stderr);
}

// ===========================================================================
// CONTROL — a genuinely false law (satisfiable `requires`) MUST fail, proving
// the finding above is specifically about vacuity, not a broken prover.
// ===========================================================================
#[test]
fn control_genuinely_false_law_is_rejected() {
    let root = format!(
        "{HEADER}\
         #[cfg(sandblaster)] #[path = \"laws.rs\"] mod laws;\n\
         #[cfg(sandblaster)] #[path = \"proof.rs\"] mod proof;\n\
         pub fn verify(_root: &[u8], _key: &[u8], _value: &[u8], _proof: &[u8]) -> bool {{ true }}\n"
    );
    let laws = "use sandblaster::prelude::*;\nuse super::verify;\n\
        #[law]\n\
        fn verify_rejects_forged_proof(root: &[u8], key: &[u8], value: &[u8]) {\n\
            ensures(verify(root, key, value, &[]) == false);\n\
        }\n";
    let proof = "use sandblaster::prelude::*;\n\
        #[proof]\n\
        fn verify_rejects_forged_proof(root: &[u8], key: &[u8], value: &[u8]) {}\n";
    let o = build(&[("mod.rs", &root), ("laws.rs", laws), ("proof.rs", proof)]);
    eprintln!("stderr:\n{}", o.stderr);
    eprintln!("ok = {}", o.ok);
    assert!(!o.ok, "a genuinely false law must be rejected");
}

// ===========================================================================
// PROBE — review-1.md line 39 [critical]: or-pattern + guard divergence.
// rustc tries the guard once per matching alternative, left to right. Inspect
// the emitted desugaring for a=Some(1),b=Some(9) semantics.
// ===========================================================================
#[test]
#[ignore = "inspect emitted or-pattern/guard desugaring; run with --ignored"]
fn inspect_guard_orpat() {
    let body = "pub fn pick(a: Option<u32>, b: Option<u32>) -> u32 {\n\
        match (a, b) {\n\
            (Some(x), _) | (_, Some(x)) if x > 5 => x,\n\
            _ => 0,\n\
        }\n\
    }\n";
    let root = format!("{HEADER}{body}");
    let o = build(&[("mod.rs", &root)]);
    eprintln!("ok = {}", o.ok);
    eprintln!("stderr:\n{}", o.stderr);
    if let Some(c) = code(&o) {
        eprintln!("=== emitted ===\n{}", c);
    }
}

// ===========================================================================
// FINDING 2 (RG-2) — deep non-tail recursion (DESIGN §3.7 allowed max=65536
// with no frame-size accounting; review-1.md line 73): a verified program
// aborted with a stack overflow on ordinary input from its total boundary.
// Stack safety is now an obligation (`validate::check_stack`).
// ===========================================================================
fn deep_recursion_crate(max: u32, clamp: u32) -> BuildOutcome {
    let body = format!(
        "pub fn deep(n: u32) -> u64 {{\n\
        helper(if n > {clamp}u32 {{ {clamp}u32 }} else {{ n }})\n\
    }}\n\
    #[decreases(n, max = {max})]\n\
    fn helper(n: u32) -> u64 {{\n\
        let buf: [u64; 128] = [7u64; 128];\n\
        if n == 0u32 {{\n\
            0u64\n\
        }} else {{\n\
            buf[(n as usize) % 128].wrapping_add(helper(n - 1u32))\n\
        }}\n\
    }}\n"
    );
    let root = format!("{HEADER}{body}");
    build(&[("mod.rs", &root)])
}

#[test]
fn finding2_deep_recursion_is_rejected() {
    // the red team's program (max = 65536, clamp 60000)
    let o = deep_recursion_crate(65536, 60000);
    assert!(!o.ok, "must be rejected");
    assert!(o.stderr.contains("exceeds 4096"), "{}", o.stderr);
    // under the depth cap, the ~1 KiB frame still breaks the stack budget
    let o = deep_recursion_crate(4096, 4000);
    assert!(!o.ok, "must be rejected");
    assert!(o.stderr.contains("may overflow the stack"), "{}", o.stderr);
    assert!(code(&o).is_none());
}

// ===========================================================================
// PROBE — review-1.md line 87: an empty `for` loop's post-condition must NOT
// leak `off <= len` (false when off > len) to justify a later checked sub.
// ===========================================================================
#[test]
fn probe_loop_post_leak() {
    let body = "pub fn f(s: &[u8], off: usize) -> u64 {\n\
        let mut acc: u64 = 0;\n\
        for _i in off..s.len() {\n\
            acc = acc.wrapping_add(1);\n\
        }\n\
        let d = s.len() - off;\n\
        acc.wrapping_add(d as u64)\n\
    }\n";
    let root = format!("{HEADER}{body}");
    let o = build(&[("mod.rs", &root)]);
    eprintln!("ok = {}", o.ok);
    eprintln!("stderr:\n{}", o.stderr);
    if let Some(c) = code(&o) { eprintln!("=== emitted ===\n{}", c); }
    // `off <= s.len()` must not leak out of an empty loop
    assert!(!o.ok, "the unproven subtraction must fail the build");
}
