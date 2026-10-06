//! RED TEAM — proof-gate integrity (lens: PROOF-GATE INTEGRITY).
//!
//! Goal of these probes: make the crate path (`driver::build_crate`, the
//! pipeline of every build entry point) issue a verdict for a crate with
//! unverified code or a false/vacuous law, or emit a verification report
//! that overstates what was proven.
//!
//! The two findings (RG-1 vacuous laws, RG-2 stack overflow) are regression
//! tests now; the remaining `#[ignore]`d probes only print diagnostics.
//!
//! Each probe checks an in-memory crate and runs the crate path on it.
//! `ok` (a verdict) is what decides whether a build passes;
//! `sandblaster-report.json` is what an auditor reads.

use std::path::Path;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

use sandblaster_front::driver::{self, LockUse};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

/// What the crate path made of a probe.
struct Outcome {
    /// A verdict.
    ok: bool,
    /// The diagnostics and the failure's closing line.
    stderr: String,
    report: Option<String>,
}

/// Runs the crate path on a crate whose DSL files are given relative to
/// `sandblaster/` (`files[0]` is `mod.rs`).
fn build(files: &[(&str, &str)]) -> Outcome {
    let all: Vec<(String, String)> = files.iter().map(|(p, c)| (format!("/crate/sandblaster/{p}"), (*c).to_string())).collect();
    let fs = MemFs::from_files(all.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let root = "/crate/sandblaster/mod.rs";
    let c = driver::check(Path::new(root), &fs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        return Outcome { ok: false, stderr: c.render(), report: None };
    }
    let b = driver::build_crate(&c, LockUse::Enforce, root);
    Outcome { ok: b.verdict.is_some(), stderr: b.render_failure(&c, root), report: Some(b.report.clone()) }
}

fn report(o: &Outcome) -> Option<&str> {
    o.report.as_deref()
}

// ===========================================================================
// FINDING 1 (RG-1) — a *vacuously true* law with a false-looking conclusion
// was certified "checked" and the whole build was "VERIFIED + OPTIMIZED",
// even though the shipped function does the opposite of what the law
// appears to say. The gate now refutes contradictory hypotheses (bounded
// prover attempt, kernel-checked) and fails the build with "vacuous law".
// ===========================================================================
fn vacuous_law_crate(requires: &str) -> Outcome {
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
    let r = report(&o).expect("the report of the failed build");
    assert!(r.contains("\"status\": \"NOT VERIFIED\"") && !r.contains("\"status\": \"VERIFIED"), "the report must not claim verification:\n{r}");
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
}

// ===========================================================================
// FINDING 2 (RG-2) — deep non-tail recursion (DESIGN §3.7 allowed max=65536
// with no frame-size accounting; review-1.md line 73): a verified program
// aborted with a stack overflow on ordinary input from its total boundary.
// Stack safety is now an obligation (`validate::check_stack`).
// ===========================================================================
fn deep_recursion_crate(max: u32, clamp: u32) -> Outcome {
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
    // `off <= s.len()` must not leak out of an empty loop
    assert!(!o.ok, "the unproven subtraction must fail the build");
}
