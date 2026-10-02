//! Fairness guard (audit of 2026-10-02, J1/J5): no hand-written
//! alternative stands in for optimizer output on the monorepo's code.
//!
//! A `#[rewrite]` lemma `f(x̄) == g(x̄)` with `g` in a `#[lift(opt)]` module
//! makes user code a replacement of `f` (the MMR's `opt.rs` did this for
//! `PeakIterator::to_nearest_size`, the only source of a 36–44× figure that
//! docs credited to the optimizer). The mechanism stays, as a reported
//! developer feature, but on the monorepo's DSL roots every use must be
//! listed in `sandblaster/tools/gates/user-rewrites.toml` with an owner, a
//! justification and `benchmark_excluded = true`, and benchmark targets can
//! never be listed (`FORBIDDEN`).
//!
//! * `no_dsl_root_has_an_unlisted_user_alternative`: scans every DSL root —
//!   each `<crate>/sandblaster/` directory of the monorepo and
//!   `sandblaster/fixtures/` — for `#[rewrite]` attributes and `#[lift(opt …)]`
//!   modules (parsed with `syn`; comments do not count). The toolchain's toy
//!   fixtures under `sandblaster/front/tests/` are not DSL roots.
//! * `the_scan_flags_its_twin` (the negative twin): a scratch tree with a
//!   `#[rewrite]` lemma in the MMR's proof, a `#[lift(opt)]` module in a
//!   codec root, an allowlist entry for a forbidden path and one without
//!   `benchmark_excluded` is refused; a toy fixture, a commented-out
//!   attribute and a valid entry are not.

use std::path::{Path, PathBuf};

/// Paths (prefixes, repo-relative) that can never be allowlisted: the
/// benchmark targets and their DSL roots.
const FORBIDDEN: &[&str] = &[
    "storage/src/merkle/",
    "storage/sandblaster/mmr/",
    "storage/sandblaster/verifier/",
    "codec/src/varint.rs",
    "codec/sandblaster/varint/",
    "cryptography/src/sha256/",
    "cryptography/src/bls12381/",
    "cryptography/src/ed25519/",
    "cryptography/src/reed_solomon/",
    "coding/src/reed_solomon.rs",
    "sandblaster/fixtures/qmdb/",
];

#[derive(Clone, Debug, Default)]
struct Allow {
    path: String,
    owner: String,
    justification: String,
    benchmark_excluded: bool,
}

/// Reads the `[[allow]]` tables of the allowlist (string and boolean
/// values; `#` comments).
fn parse_allow(text: &str) -> Result<Vec<Allow>, String> {
    let mut out: Vec<Allow> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[allow]]" {
            out.push(Allow::default());
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { return Err(format!("line {}: `{line}`", n + 1)) };
        let (k, v) = (k.trim(), v.trim());
        let cur = out.last_mut().ok_or(format!("line {}: a key outside `[[allow]]`", n + 1))?;
        let s = || v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).map(|x| x.to_string()).ok_or(format!("line {}: `{k}` is not a string", n + 1));
        match k {
            "path" => cur.path = s()?,
            "owner" => cur.owner = s()?,
            "justification" => cur.justification = s()?,
            "benchmark_excluded" => cur.benchmark_excluded = v == "true",
            _ => return Err(format!("line {}: unknown key `{k}`", n + 1)),
        }
    }
    Ok(out)
}

/// Why each allowlist entry is refused (empty: all valid).
fn check_allow(entries: &[Allow]) -> Vec<String> {
    let mut bad = Vec::new();
    for e in entries {
        if let Some(f) = FORBIDDEN.iter().find(|f| e.path.starts_with(*f)) {
            bad.push(format!("`{}`: a benchmark target ({f}) can never have a user alternative", e.path));
        }
        if !e.benchmark_excluded {
            bad.push(format!("`{}`: `benchmark_excluded = true` is required", e.path));
        }
        if e.owner.trim().is_empty() || e.justification.trim().is_empty() {
            bad.push(format!("`{}`: an owner and a justification are required", e.path));
        }
    }
    bad
}

/// The user-alternative attributes of one source: (line, what).
fn user_alternatives(src: &str) -> Result<Vec<(usize, String)>, String> {
    struct V(Vec<(usize, String)>);
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
            let path = a.path();
            let last = path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
            let line = a.pound_token.span.start().line;
            if last == "rewrite" {
                self.0.push((line, "a `#[rewrite]` lemma".into()));
            }
            if last == "lift"
                && let syn::Meta::List(l) = &a.meta
            {
                let toks: Vec<String> = l.tokens.clone().into_iter().map(|t| t.to_string()).collect();
                if toks.iter().any(|t| t == "opt") {
                    self.0.push((line, "a `#[lift(opt)]` module".into()));
                }
            }
            syn::visit::visit_attribute(self, a);
        }
    }
    let f = syn::parse_file(src).map_err(|e| format!("not parsed: {e}"))?;
    let mut v = V(Vec::new());
    syn::visit::Visit::visit_file(&mut v, &f);
    Ok(v.0)
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut es: Vec<PathBuf> = rd.map(|e| e.unwrap().path()).collect();
    es.sort();
    for p in es {
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The DSL roots of a monorepo checkout: `<crate>/sandblaster/` for every
/// top-level directory but the toolchain's own, and `sandblaster/fixtures/`.
fn dsl_roots(repo: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut tops: Vec<PathBuf> = std::fs::read_dir(repo).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()).collect();
    tops.sort();
    for t in tops {
        let name = t.file_name().unwrap().to_string_lossy().to_string();
        if name == "sandblaster" || name == "target" || name.starts_with('.') {
            continue;
        }
        let d = t.join("sandblaster");
        if d.is_dir() {
            out.push(d);
        }
    }
    out.push(repo.join("sandblaster/fixtures"));
    out
}

/// Findings of the scan of `repo` against `allow` (repo-relative paths).
fn scan(repo: &Path, allow: &[Allow]) -> Vec<String> {
    let mut bad = check_allow(allow);
    for root in dsl_roots(repo) {
        let mut files = Vec::new();
        rs_files(&root, &mut files);
        for f in files {
            let rel = f.strip_prefix(repo).unwrap().display().to_string();
            if rel.starts_with("sandblaster/front/tests/") {
                continue;
            }
            let src = std::fs::read_to_string(&f).unwrap();
            // (a cheap filter first: most files name neither attribute)
            if !src.contains("rewrite") && !src.contains("lift") {
                continue;
            }
            let found = match user_alternatives(&src) {
                Ok(v) => v,
                // a file syn cannot read counts if it names an attribute at all
                Err(e) => {
                    if src.lines().any(|l| {
                        let t = l.trim_start();
                        !t.starts_with("//") && (t.contains("#[rewrite") || (t.contains("#[lift(") && t.contains("opt")))
                    }) {
                        vec![(0, format!("an attribute in a file syn cannot parse ({e})"))]
                    } else {
                        Vec::new()
                    }
                }
            };
            if found.is_empty() {
                continue;
            }
            let listed = allow.iter().any(|a| a.path == rel);
            if !listed {
                for (line, what) in found {
                    bad.push(format!("{rel}:{line}: {what}, not listed in sandblaster/tools/gates/user-rewrites.toml"));
                }
            }
        }
    }
    bad
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn no_dsl_root_has_an_unlisted_user_alternative() {
    let repo = repo();
    let text = std::fs::read_to_string(repo.join("sandblaster/tools/gates/user-rewrites.toml")).expect("the allowlist");
    let allow = parse_allow(&text).unwrap();
    let roots = dsl_roots(&repo);
    for need in ["codec/sandblaster", "storage/sandblaster", "sandblaster/fixtures"] {
        assert!(roots.iter().any(|r| r.ends_with(need)), "the scan covers {need}: {roots:?}");
    }
    let bad = scan(&repo, &allow);
    assert!(bad.is_empty(), "user alternatives on the monorepo's code (fairness rule, J1/J5):\n{}", bad.join("\n"));
}

/// The negative twin (see the module docs).
#[test]
fn the_scan_flags_its_twin() {
    let tmp = std::env::temp_dir().join(format!("fairness-rewrites-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let put = |p: &str, s: &str| {
        let f = tmp.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, s).unwrap();
    };
    put("storage/sandblaster/mmr/PROOF.rs", "#[lemma]\n#[rewrite]\nfn fast(x: u64) {\n    ensures(f(x) == g(x));\n}\n");
    put("codec/sandblaster/varint/mod.rs", "#[lift(opt, mir = \"varint.sbmir\")]\nmod opt;\n");
    put("math/sandblaster/m/mod.rs", "// #[rewrite] is only mentioned here\n/// and `#[lift(opt)]` in a doc\npub fn x() {}\n");
    put("p2p/sandblaster/q/PROOF.rs", "#[lemma]\n#[sandblaster::rewrite]\nfn listed(x: u64) {\n    ensures(f(x) == g(x));\n}\n");
    put("sandblaster/front/tests/mir_fixtures/toy/opt.rs", "#[lift(opt)]\nmod opt;\n");
    put("sandblaster/fixtures/qmdb/sandblaster/PROOF.rs", "#[rewrite]\nfn h() {}\n");
    let valid = Allow { path: "p2p/sandblaster/q/PROOF.rs".into(), owner: "a reviewer".into(), justification: "no pass derives it; not benchmarked".into(), benchmark_excluded: true };
    let bad = scan(&tmp, std::slice::from_ref(&valid));
    let has = |needle: &str| bad.iter().any(|b| b.contains(needle));
    assert!(has("storage/sandblaster/mmr/PROOF.rs:2: a `#[rewrite]` lemma"), "{bad:?}");
    assert!(has("codec/sandblaster/varint/mod.rs:1: a `#[lift(opt)]` module"), "{bad:?}");
    assert!(has("sandblaster/fixtures/qmdb/sandblaster/PROOF.rs"), "{bad:?}");
    assert!(!has("math/sandblaster"), "comments do not count: {bad:?}");
    assert!(!has("mir_fixtures"), "toy fixtures are not DSL roots: {bad:?}");
    assert!(!has("p2p/sandblaster"), "a listed, valid entry passes: {bad:?}");
    assert_eq!(bad.len(), 3, "{bad:?}");
    // allowlist entries: a benchmark target, and one without the exclusion
    let target = Allow { path: "storage/sandblaster/mmr/PROOF.rs".into(), ..valid.clone() };
    let unexcluded = Allow { benchmark_excluded: false, ..valid.clone() };
    let refused = check_allow(&[target, unexcluded]);
    assert!(refused.iter().any(|r| r.contains("can never have a user alternative")) && refused.iter().any(|r| r.contains("benchmark_excluded")), "{refused:?}");
    // the file format
    let parsed = parse_allow("# c\n[[allow]]\npath = \"a/b.rs\"\nowner = \"o\"\njustification = \"j\"\nbenchmark_excluded = true\n").unwrap();
    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].benchmark_excluded && parsed[0].path == "a/b.rs");
    let _ = std::fs::remove_dir_all(&tmp);
}
