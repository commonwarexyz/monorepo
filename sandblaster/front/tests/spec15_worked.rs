//! The §15 S1 worked example (`tests/samples/spec15_sha256`): a SHA-256
//! compression function written for speed refines a FIPS 180-4 reference
//! (proof: `bv()` in PROOF.rs), a big-endian reader refines a positional
//! `Seq`/`Nat` reference through the view coercion (proof: a word lemma
//! and arithmetic in PROOF.rs), and the
//! specification is validated by known-answer examples and a CAVP-format
//! vector file computed by an independent implementation — the features of
//! S1 composing in one crate.

#[path = "spec15_util.rs"]
mod util;
#[path = "gated_util.rs"]
mod gated;

use std::path::Path;

use sandblaster_front::elab::examples::ExampleMethod;
use util::*;

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/spec15_sha256/mod.rs")
}

fn sample() -> Run {
    run_dir(&root())
}

/// The sample with `from` replaced by `to` (once, required) in `file`.
fn mutated(file: &str, from: &str, to: &str) -> Run {
    run_dir_edited(&root(), &|p, c| {
        if p == file {
            assert!(c.contains(from), "`{from}` not in {file}");
            c.replacen(from, to, 1)
        } else {
            c.to_string()
        }
    })
}

#[test]
fn the_worked_example_verifies() {
    let r = sample();
    assert!(r.front_ok, "{}", r.rendered);
    assert!(r.verified && r.errors.is_empty(), "{}", r.explain());
    // both boundary functions refine their references, determined by
    // injective views: they are established
    for f in ["crate::sha::compress", "crate::codec::read_u32_be"] {
        let x = r.refinement(f);
        assert!(x.checked && x.up_to.is_none(), "{f}: {}", r.explain());
        assert!(r.established.iter().any(|g| g == f), "{f} established: {:?}", r.established);
    }
    assert_eq!(r.refinement("crate::sha::compress").proof, "crate::proof::compress");
    assert_eq!(r.refinement("crate::codec::read_u32_be").proof, "crate::proof::read_u32_be");
    // the known answers and the twelve independent vector records, all
    // decided by the kernel
    let hash_examples: Vec<&Ex> = r.examples.iter().filter(|e| e.item == "crate::spec::sha256::hash1").collect();
    assert_eq!(hash_examples.len(), 3);
    let vectors: Vec<&Ex> = r.examples.iter().filter(|e| e.item == "crate::spec::sha256::cavp" && e.file).collect();
    assert_eq!(vectors.len(), 12, "{}", r.explain());
    assert!(vectors.iter().all(|e| e.checked && e.counts && e.method.is_some()));
    assert!(r.examples.iter().all(|e| e.checked), "{}", r.explain());
    let _ = ExampleMethod::Conversion;
    // coverage: both outcomes of `hash1` and of `read_u32_be` have examples;
    // every spec function of the crate is exercised
    for c in &r.coverage {
        assert!(c.exercised, "{} is not exercised: {:?}", c.spec, r.coverage);
        assert!(c.needed.iter().all(|o| c.seen.contains(o)), "{}: outcomes {:?} of {:?}", c.spec, c.seen, c.needed);
    }
    // nothing outside the S1 surface was recorded for the spec-closure gate
    assert!(r.closure.is_empty(), "{:?}", r.closure);
}

/// The sample on the crate path: every §15 gate passes and the verdict is
/// deterministic; the spec-mutation tool (`sandblaster mutate`, no longer a
/// gate) kills every non-equivalent spec mutant with the known answers
/// (FIPS examples, the independent `compress` answer, the CAVP records),
/// and a second run decides every mutant the same way and the build emits
/// the same file.
#[test]
#[ignore = "slow: the spec-mutation tool on the SHA-256 sample (1526 mutants, about a minute on 4 threads) runs twice; the DESIGN.md §15.7 measurement"]
fn the_worked_example_passes_every_gate_deterministically() {
    use sandblaster_front::driver::{self, LockUse};
    use sandblaster_front::loader::MemFs;
    use sandblaster_front::target::TargetInfo;
    let dir = root().parent().unwrap().to_path_buf();
    let mut files: Vec<(String, String)> = Vec::new();
    fn walk(d: &Path, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.file_name().is_some_and(|n| n != "SPEC.lock") {
                out.push((p.display().to_string(), std::fs::read_to_string(&p).unwrap()));
            }
        }
    }
    walk(&dir, &mut files);
    let target = TargetInfo::aarch64_apple_darwin();
    let root_s = root().display().to_string();
    let files = gated::with_accepted_lock(&files, &root_s, &target).unwrap_or_else(|e| panic!("the sample fails a gate:\n{e}"));
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let run = || {
        let c = driver::check(&root(), &fs, &target);
        let b = driver::build_crate(&c, LockUse::Enforce, "spec15_sha256/mod.rs");
        let v = b.verdict.as_ref().unwrap_or_else(|| panic!("no verdict:\n{}", b.render_failure(&c, "spec15_sha256/mod.rs")));
        let t = driver::stage::mutate(&c);
        let m = t.report.as_ref().expect("the crate verifies");
        assert!(m.complete, "{:?}", m.incomplete_reasons);
        assert!(!t.findings.has_errors(), "{}", t.findings.render(&c.sm));
        let verdicts: Vec<(String, String)> = m.mutants.iter().map(|(x, o)| (format!("{} {}", x.path, x.desc), o.verdict.word().to_string())).collect();
        (v.code_sha256(), verdicts, m.elapsed)
    };
    let (h1, v1, t1) = run();
    let (h2, v2, t2) = run();
    assert_eq!(h1, h2, "the emitted file");
    assert_eq!(v1, v2, "every mutant is decided the same way");
    eprintln!("spec-mutation tool: {} mutants, {:.0} s and {:.0} s", v1.len(), t1.as_secs_f64(), t2.as_secs_f64());
}

// ---------------------------------------------------------------------
// red team: wrong implementations and wrong specifications do not build
// ---------------------------------------------------------------------

#[test]
fn a_wrong_round_constant_in_the_implementation_fails_the_refinement() {
    // K[19] off by one (the classic transcription error)
    let r = mutated("sha.rs", "0x240ca1ccu32", "0x240ca1cdu32");
    assert!(!r.verified, "{}", r.explain());
    assert!(!r.refinement("crate::sha::compress").checked);
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::sha::compress::refines" && k == "refines"), "{}", r.explain());
}

#[test]
fn a_wrong_round_constant_in_the_specification_fails_its_examples() {
    let r = mutated("spec/sha256.rs", "0x240ca1ccu32", "0x240ca1cdu32");
    assert!(!r.verified, "{}", r.explain());
    // the known answers and the independent vectors catch it; the
    // implementation no longer refines the (now wrong) specification either
    assert!(r.examples.iter().filter(|e| e.item == "crate::spec::sha256::cavp").any(|e| !e.checked), "{}", r.explain());
    assert!(r.has_error(sandblaster_front::diag::DiagKind::Example, "is false"), "{}", r.explain());
}

#[test]
fn a_specification_calling_the_implementation_does_not_build() {
    let r = mutated("spec/sha256.rs", "let v = rounds(64, 0, h, words(block));", "let v = crate::sha::compress(h, &block);");
    assert!(!r.verified, "{}", r.explain());
    assert!(r.has_error(sandblaster_front::diag::DiagKind::SpecDependsOnImpl, "the specification `crate::spec::sha256::compress` of `#[refines]` on `crate::sha::compress` depends on `crate::sha::compress` itself"), "{}", r.explain());
}

#[test]
fn an_off_by_one_in_the_reader_fails_the_refinement() {
    let r = mutated("codec.rs", "&xs[4..]", "&xs[3..]");
    assert!(!r.verified, "{}", r.explain());
    assert!(!r.refinement("crate::codec::read_u32_be").checked, "{}", r.explain());
}
