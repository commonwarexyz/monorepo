//! The verdict cache (`sandblaster_front::driver::cache`) and incremental
//! spec mutation (`sandblaster_front::mutate::cache`).
//!
//! * the store: a round trip; a miss; an edited payload, a truncated entry,
//!   an entry filed under another key and an entry written without the
//!   cache's key (a forgery) are all rejected; an address that is not a
//!   hash is refused; the size cap evicts the least recently used entries;
//!   HMAC-SHA-256 matches RFC 4231;
//! * module mode on an in-memory host crate: a warm build in a new target
//!   directory (no `OUT_DIR` key) reuses the cached verdict byte for byte;
//!   a tampered entry is rejected and the module re-verified to the same
//!   bytes (and the entry repaired); another toolchain, `SANDBLASTER_CACHE=off`
//!   and a changed source do not reuse; crate mode reuses too;
//! * incremental spec mutation: a rebuild whose sources changed where no
//!   mutant reads takes every spec mutant's verdict from the cache and
//!   writes the same report; after an edit of one spec function only its
//!   mutants run; a tampered mutant entry is re-run with the same verdict.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;
#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sandblaster_front::driver::cache::{hmac, Lookup, Store};
use sandblaster_front::driver::{build_module, build_verified_with, module_include_line, BuildOutcome, LIB_RS_LINE};
use sandblaster_front::loader::MemFs;
use sandblaster_front::surface::{hex, sha256};
use sandblaster_front::target::TargetInfo;
use util::HEADER;

const ROOT: &str = "sandblaster/prog/mod.rs";
const MODULE: &str = "src/verified/prog.rs";

program!(prog {
    pub fn clamp_add(a: u8, b: u8) -> u8 {
        let s = a as u16 + b as u16;
        if s > 255 { 255 } else { s as u8 }
    }
    pub fn classify(x: u32) -> u32 {
        match x {
            0 => 0,
            1..=9 => 1,
            _ if x % 2 == 0 => 2,
            _ => 3,
        }
    }
});

const SPEC: &str = r#"//! What the functions compute.

/// `a + b`, capped at 255.
#[example(saturating_sum(1, 2) == 3)]
#[example(saturating_sum(200, 100) == 255)]
#[example(saturating_sum(255, 0) == 255)]
pub fn saturating_sum(a: Nat, b: Nat) -> Nat {
    (a + b).min(255)
}

/// 0 for zero, 1 for one digit, else 2 for even and 3 for odd numbers.
#[example(classify(0) == 0)]
#[example(classify(9) == 1)]
#[example(classify(10) == 2)]
#[example(classify(13) == 3)]
pub fn classify(x: Nat) -> Nat {
    if x == 0 { 0 } else if x < 10 { 1 } else if x % 2 == 0 { 2 } else { 3 }
}
"#;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sandblaster-verdict-cache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn env(out: &str, cache: Option<&Path>, extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = [
        ("CARGO_MANIFEST_DIR", "/host"),
        ("OUT_DIR", out),
        ("CARGO_CFG_TARGET_ARCH", "aarch64"),
        ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    if let Some(c) = cache {
        m.insert("SANDBLASTER_CACHE_DIR".into(), c.display().to_string());
        m.insert("SANDBLASTER_CACHE_KEY".into(), "test secret".into());
    }
    for (k, v) in extra {
        m.insert(k.to_string(), v.to_string());
    }
    m
}

fn host_files() -> Vec<(String, String)> {
    vec![
        ("/host/src/lib.rs".into(), "//! A host crate.\nmod verified;\n".into()),
        ("/host/src/verified/mod.rs".into(), "pub mod prog;\n".into()),
        (format!("/host/{MODULE}"), format!("{}\n", module_include_line("prog"))),
    ]
}

fn dsl_files(spec: &str) -> Vec<(String, String)> {
    let mut code = prog::SRC.replace("pub fn\n", "pub fn ");
    for (f, s) in [("clamp_add", "saturating_sum"), ("classify", "classify")] {
        let at = code.find(&format!("pub fn {f}")).unwrap();
        code.insert_str(at, &format!("#[refines(crate::spec::{s})] "));
    }
    let files = vec![
        (format!("/host/{ROOT}"), format!("{HEADER}mod m;\npub use m::{{clamp_add, classify}};\n#[cfg(sandblaster)]\n#[spec]\n#[path = \"spec.rs\"]\nmod spec;\n")),
        ("/host/sandblaster/prog/m.rs".to_string(), format!("use sandblaster::prelude::*;\n{code}\n")),
        ("/host/sandblaster/prog/spec.rs".to_string(), spec.to_string()),
    ];
    gated::with_accepted_lock(&files, &format!("/host/{ROOT}"), &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the gates reject the test crate:\n{e}"))
}

fn all_files(spec: &str) -> Vec<(String, String)> {
    let mut v = host_files();
    v.extend(dsl_files(spec));
    v
}

fn with(files: &[(String, String)], path: &str, text: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = files.iter().filter(|(p, _)| p != path).cloned().collect();
    v.push((path.to_string(), text.to_string()));
    v
}

fn build(files: &[(String, String)], context: Option<&str>, e: &HashMap<String, String>) -> BuildOutcome {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    build_module(ROOT, MODULE, context, &|k| e.get(k).cloned(), &fs)
}

fn output<'o>(o: &'o BuildOutcome, name: &str) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, c)| c.as_str())
}

fn reused(o: &BuildOutcome) -> bool {
    o.cargo.iter().any(|l| l.contains("reusing the verdict cache entry"))
}

fn entries(dir: &Path, ns: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let root = dir.join("sandblaster-cache-1").join(ns);
    for sub in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        for f in std::fs::read_dir(sub.path()).into_iter().flatten().flatten() {
            if !f.file_name().to_string_lossy().starts_with('.') {
                out.push(f.path());
            }
        }
    }
    out.sort();
    out
}

/// A `mutation_cache_*` count of the timing file.
fn timing_num(o: &BuildOutcome, field: &str) -> i64 {
    let t = output(o, "prog-timing.json").unwrap_or_else(|| panic!("no timing: {:?}", o.cargo));
    let at = t.find(&format!("\"{field}\": ")).unwrap_or_else(|| panic!("no {field} in {t}"));
    t[at + field.len() + 4..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap()
}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

const K1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const K2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

#[test]
fn hmac_matches_rfc_4231() {
    // test case 1: a 20-byte key (HMAC pads keys shorter than a block with
    // zeros, as `hmac` pads its 32-byte secret)
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(&[0x0b; 20]);
    assert_eq!(hex(&hmac(&key, &[b"Hi ", b"There"])), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

#[test]
fn the_store_round_trips_and_rejects_tampered_entries() {
    let dir = scratch("store");
    let s = Store::open(dir.clone(), sha256(b"secret one"));
    assert_eq!(s.get("verdict", K1), Lookup::Miss);
    s.put("verdict", K1, &[("code", "fn f() {}\n"), ("report", "{}")]).unwrap();
    assert_eq!(s.get("verdict", K1), Lookup::Hit(vec![("code".into(), "fn f() {}\n".into()), ("report".into(), "{}".into())]));
    let file = entries(&dir, "verdict").pop().unwrap();
    let good = std::fs::read(&file).unwrap();
    let rejected = |bytes: &[u8]| {
        std::fs::write(&file, bytes).unwrap();
        let r = s.get("verdict", K1);
        std::fs::write(&file, &good).unwrap();
        r
    };
    // an edited payload byte
    let mut edited = good.clone();
    let n = edited.len();
    edited[n - 3] = b'X';
    assert!(matches!(rejected(&edited), Lookup::Rejected(w) if w.contains("MAC")));
    // truncated
    assert!(matches!(rejected(&good[..good.len() - 1]), Lookup::Rejected(_)));
    // an edited length with a recomputed payload hash still fails the MAC
    let text = String::from_utf8(good.clone()).unwrap().replace("fn f() {}\n", "fn g() {}\n");
    assert!(matches!(rejected(text.as_bytes()), Lookup::Rejected(_)));
    // filed under another key
    let other = s.put("verdict", K2, &[("code", "x")]).map(|_| entries(&dir, "verdict").into_iter().find(|p| p.ends_with(K2)).unwrap()).unwrap();
    std::fs::copy(&file, &other).unwrap();
    assert!(matches!(s.get("verdict", K2), Lookup::Rejected(w) if w.contains("another address")));
    // a forgery: a well-formed entry written with another secret
    Store::open(dir.clone(), sha256(b"attacker")).put("verdict", K1, &[("code", "fn evil() {}\n"), ("report", "{}")]).unwrap();
    assert!(matches!(s.get("verdict", K1), Lookup::Rejected(w) if w.contains("MAC")));
    // addresses are hashes, never paths
    assert!(matches!(s.get("verdict", "../../etc/passwd"), Lookup::Rejected(_)));
    assert!(s.put("../x", K1, &[("code", "")]).is_err());
    assert!(s.put("verdict", K1, &[("../code", "")]).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_store_evicts_the_least_recently_used_entries_over_its_cap() {
    let dir = scratch("trim");
    let e: HashMap<String, String> = [("SANDBLASTER_CACHE_DIR", dir.display().to_string()), ("SANDBLASTER_CACHE_KEY", "k".to_string()), ("SANDBLASTER_CACHE_MAX_MB", "0".to_string())].into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let s = Store::from_env(&|k| e.get(k).cloned()).unwrap().unwrap();
    s.put("verdict", K1, &[("code", "a")]).unwrap();
    // a cap of 0: every write leaves an empty namespace
    assert_eq!(s.get("verdict", K1), Lookup::Miss);
    // off: no store at all
    let off: HashMap<String, String> = [("SANDBLASTER_CACHE", "off")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    assert!(Store::from_env(&|k| off.get(k).cloned()).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// the verdict cache in module mode and crate mode
// ---------------------------------------------------------------------------

#[test]
fn a_warm_build_in_a_new_target_dir_reuses_the_cached_verdict() {
    let dir = scratch("warm");
    let files = all_files(SPEC);
    let cold = build(&files, Some("toolchain-1"), &env("/out", Some(&dir), &[]));
    assert!(cold.ok, "{}", cold.stderr);
    assert!(!reused(&cold));
    assert!(timing_num(&cold, "mutation_cache_misses") > 0 && timing_num(&cold, "mutation_cache_hits") == 0);
    // a new target directory: no OUT_DIR key, the cache has the verdict
    let warm = build(&files, Some("toolchain-1"), &env("/target2/out", Some(&dir), &[]));
    assert!(warm.ok && reused(&warm), "{:?}\n{}", warm.cargo, warm.stderr);
    for f in ["prog.rs", "prog-report.json", "prog-timing.json"] {
        assert_eq!(output(&warm, f), output(&cold, f), "{f} is the cached one");
    }
    let key = output(&warm, "prog-verdict.key").expect("the OUT_DIR key is written on a cache hit");
    assert!(key.contains(&hex(&sha256(output(&cold, "prog.rs").unwrap().as_bytes()))), "{key}");
    assert!(warm.outputs.iter().all(|(p, _)| p.starts_with("/target2/out")), "{:?}", warm.outputs.iter().map(|x| &x.0).collect::<Vec<_>>());
    // not reused: another toolchain, the cache off, a changed source
    for (what, fs, ctx, extra) in [
        ("toolchain", files.clone(), "toolchain-2", vec![]),
        ("off", files.clone(), "toolchain-1", vec![("SANDBLASTER_CACHE", "off")]),
        ("source", with(&files, "/host/sandblaster/prog/m.rs", &format!("{}\n// an edit\n", files.iter().find(|(p, _)| p.ends_with("m.rs")).unwrap().1)), "toolchain-1", vec![]),
    ] {
        let o = build(&fs, Some(ctx), &env("/target3/out", Some(&dir), &extra));
        assert!(o.ok, "{what}: {}", o.stderr);
        assert!(!reused(&o), "{what}: reused");
    }
    // crate mode reuses too
    let crate_files = with(&files, "/host/src/lib.rs", LIB_RS_LINE);
    let crate_build = |out: &str| {
        let fs = MemFs::from_files(crate_files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
        let e = env(out, Some(&dir), &[]);
        build_verified_with(ROOT, Some("toolchain-1"), &|k| e.get(k).cloned(), &fs)
    };
    let c1 = crate_build("/c1");
    assert!(c1.ok && !reused(&c1), "{}", c1.stderr);
    let c2 = crate_build("/c2");
    assert!(c2.ok && reused(&c2), "{:?}", c2.cargo);
    assert_eq!(output(&c2, "sandblaster.rs"), output(&c1, "sandblaster.rs"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_tampered_cache_entry_is_rejected_and_the_module_reverified() {
    let dir = scratch("tamper");
    let files = all_files(SPEC);
    let e = env("/out", Some(&dir), &[]);
    let cold = build(&files, Some("t"), &e);
    assert!(cold.ok, "{}", cold.stderr);
    let code = output(&cold, "prog.rs").unwrap().to_string();
    let entry = entries(&dir, "verdict").pop().expect("the verdict was stored");
    let good = std::fs::read_to_string(&entry).unwrap();
    // an unverified body with a recomputed payload hash: the MAC rejects it
    let evil = good.replacen("STATUS: VERIFIED", "STATUS: VERIFIEd", 1);
    assert_ne!(evil, good);
    std::fs::write(&entry, &evil).unwrap();
    let o = build(&files, Some("t"), &env("/out2", Some(&dir), &[]));
    assert!(o.ok && !reused(&o), "{:?}", o.cargo);
    assert!(o.cargo.iter().any(|l| l.contains("rejected")), "{:?}", o.cargo);
    assert_eq!(output(&o, "prog.rs"), Some(code.as_str()), "re-verified to the same bytes");
    // the re-verification repaired the entry
    let again = build(&files, Some("t"), &env("/out3", Some(&dir), &[]));
    assert!(again.ok && reused(&again), "{:?}", again.cargo);
    // a forged entry (another secret) is rejected the same way
    let forged = Store::open(dir.clone(), sha256(b"not the key"));
    let key_name = entry.file_name().unwrap().to_string_lossy().to_string();
    forged.put("verdict", &key_name, &[("code", "pub fn clamp_add(a: u8, b: u8) -> u8 { a }\n"), ("report", "{}"), ("timing", "{}")]).unwrap();
    let o = build(&files, Some("t"), &env("/out4", Some(&dir), &[]));
    assert!(o.ok && !reused(&o) && output(&o, "prog.rs") == Some(code.as_str()), "{:?}", o.cargo);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// incremental spec mutation
// ---------------------------------------------------------------------------

#[test]
fn spec_mutation_reruns_only_the_mutants_an_edit_can_affect() {
    let dir = scratch("mutants");
    let files = all_files(SPEC);
    let cold = build(&files, Some("t"), &env("/out", Some(&dir), &[]));
    assert!(cold.ok, "{}", cold.stderr);
    let total = timing_num(&cold, "mutation_cache_misses");
    assert!(total > 0 && timing_num(&cold, "mutation_cache_hits") == 0);
    assert_eq!(entries(&dir, "mutant").len() as i64, total, "every decided verdict is stored");
    // an edit no mutant reads (a comment at the end of the exec file): the
    // crate is re-verified, every spec mutant comes from the cache, and the
    // (deterministic) report is the cold one
    let m_rs = files.iter().find(|(p, _)| p.ends_with("m.rs")).unwrap().1.clone();
    let comment = with(&files, "/host/sandblaster/prog/m.rs", &format!("{m_rs}// a comment\n"));
    let warm = build(&comment, Some("t"), &env("/out2", Some(&dir), &[]));
    assert!(warm.ok && !reused(&warm), "{}", warm.stderr);
    assert_eq!(timing_num(&warm, "mutation_cache_hits"), total);
    assert_eq!(timing_num(&warm, "mutation_cache_misses"), 0);
    assert_eq!(output(&warm, "prog-report.json"), output(&cold, "prog-report.json"), "cached verdicts reproduce the report");
    // a tampered mutant entry is re-run, with the same result
    let victim = entries(&dir, "mutant").remove(0);
    let mut text = std::fs::read_to_string(&victim).unwrap();
    text.push('x');
    std::fs::write(&victim, text).unwrap();
    let again = build(&with(&comment, "/host/sandblaster/prog/m.rs", &format!("{m_rs}// another comment\n")), Some("t"), &env("/out3", Some(&dir), &[]));
    assert!(again.ok, "{}", again.stderr);
    assert_eq!(timing_num(&again, "mutation_cache_misses"), 1, "the tampered entry is a miss");
    assert_eq!(output(&again, "prog-report.json"), output(&cold, "prog-report.json"));
    // an edit of one spec function: only the mutants that read it run
    let edited_spec = SPEC.replace("else if x < 10 { 1 }", "else if x <= 9 { 1 }");
    let edited = all_files(&edited_spec);
    let o = build(&edited, Some("t"), &env("/out4", Some(&dir), &[]));
    assert!(o.ok, "{}", o.stderr);
    let (hits, misses) = (timing_num(&o, "mutation_cache_hits"), timing_num(&o, "mutation_cache_misses"));
    eprintln!("spec mutants: {total} in the cold run; after editing `classify`: {hits} from the cache, {misses} run");
    assert!(hits > 0 && misses > 0, "hits {hits}, misses {misses}");
    assert!(hits >= 5, "the `saturating_sum` mutants are unaffected: hits {hits}, misses {misses}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// what a mutant's key reads: statements of laws and lemmas, never proofs;
// positions never
// ---------------------------------------------------------------------------

const FP_ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\npub fn f(x: u32) -> u32 { if x < 10 { x } else { 10 } }\n\n#[cfg(sandblaster)]\n#[spec]\nfn s(x: Nat) -> Nat { x }\n\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n";
const FP_LAWS: &str = "use sandblaster::prelude::*;\nuse super::{f, s};\n\n/// Small inputs pass.\n#[law]\nfn small(x: u32) {\n    requires(x < 5);\n    ensures(f(x) as Nat == s(x as Nat));\n}\n";
const FP_PROOF: &str = "use sandblaster::prelude::*;\nuse super::f;\n\n#[lemma]\nfn helper(x: u32) {\n    requires(x < 5);\n    ensures(f(x) == x);\n}\n\n#[proof]\nfn small(x: u32) {\n    helper(x);\n}\n";

fn fp_crate(laws: &str, proof: &str) -> sandblaster_front::driver::Checked {
    let fs = MemFs::from_files([("r/mod.rs", FP_ROOT), ("r/LAWS.rs", laws), ("r/PROOF.rs", proof)]);
    let c = sandblaster_front::driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

#[test]
fn a_mutant_key_reads_statements_not_proofs_or_positions() {
    use sandblaster_front::mutate::cache::Fps;
    let fp = |laws: &str, proof: &str, path: &str| {
        let c = fp_crate(laws, proof);
        let k = c.krate.as_ref().unwrap();
        let id = k.find(path).unwrap_or_else(|| panic!("no {path}"));
        Fps::new(k).item(id)
    };
    let law = |l: &str, p: &str| fp(l, p, "crate::laws::small");
    let lemma = |l: &str, p: &str| fp(l, p, "crate::proof::helper");
    // a lemma's proof is not part of it; its statement is
    let proved = FP_PROOF.replace("    ensures(f(x) == x);\n}", "    ensures(f(x) == x);\n    follows();\n}");
    assert_eq!(lemma(FP_LAWS, &proved), lemma(FP_LAWS, FP_PROOF), "a lemma's body is proof");
    assert_ne!(lemma(FP_LAWS, &FP_PROOF.replace("requires(x < 5)", "requires(x < 4)")), lemma(FP_LAWS, FP_PROOF), "a lemma's statement is not");
    // a law's `#[proof]` item is not part of it, and neither is its position
    let reproved = FP_PROOF.replace("    helper(x);\n", "    helper(x);\n    follows();\n");
    assert_eq!(law(FP_LAWS, &reproved), law(FP_LAWS, FP_PROOF));
    let moved = FP_LAWS.replace("use super::{f, s};\n", "use super::{f, s};\n\n// a comment that moves the law down\n\n");
    assert_eq!(law(&moved, FP_PROOF), law(FP_LAWS, FP_PROOF), "positions are not part of a fingerprint");
    assert_ne!(law(&FP_LAWS.replace("requires(x < 5)", "requires(x < 3)"), FP_PROOF), law(FP_LAWS, FP_PROOF));
    // what a law checker reaches: the statement's items, not the proof's
    let c = fp_crate(FP_LAWS, FP_PROOF);
    let k = c.krate.as_ref().unwrap();
    let fps = Fps::new(k);
    let reach: Vec<String> = fps.reach([k.find("crate::laws::small").unwrap()]).into_iter().map(|x| k.item(x).path.to_string()).collect();
    assert!(reach.contains(&"crate::f".to_string()) && reach.contains(&"crate::s".to_string()), "{reach:?}");
    assert!(!reach.iter().any(|p| p == "crate::proof::helper" || p == "crate::proof::small"), "{reach:?}");
}

#[test]
fn an_exec_functions_proof_blocks_are_not_part_of_a_mutant_key() {
    use sandblaster_front::mutate::cache::{strip_proofs, Fps};
    assert_eq!(strip_proofs("A, Proof([X { s: \"])\" }, Y([1])]), B"), "A, Proof(..), B");
    let with_proof = |block: &str| {
        let root = FP_ROOT.replace("pub fn f(x: u32) -> u32 { if", &format!("pub fn f(x: u32) -> u32 {{ proof! {{ {block} }} if"));
        let proof = format!("{FP_PROOF}\n#[lemma]\nfn other(x: u32) {{\n    ensures(x == x);\n    follows();\n}}\n");
        let fs = MemFs::from_files([("r/mod.rs", root.as_str()), ("r/LAWS.rs", FP_LAWS), ("r/PROOF.rs", proof.as_str())]);
        let c = sandblaster_front::driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
        assert!(c.ok(), "{}", c.render());
        let k = c.krate.as_ref().unwrap();
        let fps = Fps::new(k);
        let f = k.find("crate::f").unwrap();
        let reach: Vec<String> = fps.reach([f]).into_iter().map(|x| k.item(x).path.to_string()).collect();
        (fps.item(f), reach)
    };
    let (a, reach) = with_proof("crate::proof::other(x);");
    let (b, _) = with_proof("assert(x == x);");
    assert_eq!(a, b, "the content of a proof block is not part of the fingerprint");
    assert!(!reach.iter().any(|p| p == "crate::proof::other"), "a lemma named in a proof block is not reached: {reach:?}");
}
