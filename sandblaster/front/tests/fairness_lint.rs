//! Fairness guard (audit of 2026-10-02): the optimizer never names its
//! benchmark targets. "Make sure your optimization layer doesn't factor in
//! the benchmark targets": a rule, threshold or table keyed on a target's
//! name is the plainest way to do that, so this lint fails on any string
//! literal or identifier in optimizer code that names one.
//!
//! **Scanned:** `front/src/opt/**`, `front/src/driver/lowered.rs`,
//! `front/src/lower.rs`, `rulegen/src/**` and `targets/src/**`, with
//! comments (line, block and doc) and `#[cfg(test)]` modules stripped.
//!
//! **Denylist:** `merkle`, `mmr`, `qmdb`, `shape_go`, `varint`, `leb128`,
//! `uint64_go`, `PeakIterator`, `to_nearest_size`, `is_valid_size`,
//! `reconstruct`, `commonware` (in any identifier or word, any case),
//! `hash_<digits>`, and the identifiers `Position` and `Location`.
//! Hardware intrinsic names (`vsha256hq_u32`, `_mm_sha256rnds2_epu32`, …) do
//! not match it: they name instructions, not programs.
//!
//! **Allowlist** ([`ALLOW`]): each entry names a file, a token and why it is
//! not an optimizer input; an entry that matches nothing fails (no stale
//! permissions). Today: the measurement keys of the target evidence
//! (validation rows the tests compare the model's decisions with) and the
//! names of the host-kit suites.
//!
//! **Validation rows are not inputs** (J12): no string literal of the
//! optimizer proper (`front/src/opt/**`, `lowered.rs`, `lower.rs`) starts
//! with a validation-row prefix (`sha.`, `varint.`, `crossover.`,
//! `threads.`, `memory.`, `simd.`): the cost model reads `cycle_ns` and
//! `op.*` only.
//!
//! `the_lint_flags_its_twin` is the negative twin: a synthetic source with
//! a target's name in code is flagged, the same names in comments, doc
//! comments and a `#[cfg(test)]` module are not.

use std::path::{Path, PathBuf};

/// Denylisted substrings (lower case; matched in lower-cased tokens).
const DENY: [&str; 12] = ["merkle", "mmr", "qmdb", "shape_go", "varint", "leb128", "uint64_go", "peakiterator", "to_nearest_size", "is_valid_size", "reconstruct", "commonware"];

/// Denylisted identifiers (exact, case-sensitive: the MMR's index types).
const DENY_EXACT: [&str; 2] = ["Position", "Location"];

/// Validation-row prefixes the optimizer proper must not read.
const ROW_PREFIXES: [&str; 6] = ["sha.", "varint.", "crossover.", "threads.", "memory.", "simd."];

/// (file, token, why): permitted denylist matches.
const ALLOW: &[(&str, &str, &str)] = &[
    ("targets/src/evidence/tuning.rs", "varint", "the `varint.*` measurement keys a tuning file must record: validation rows the tests compare the cost model's decisions with (no optimizer code reads them; checked below)"),
    ("targets/src/evidence/tuning.rs", "merkle_level_pairs", "the `crossover.merkle_level_pairs` measurement key: a validation row, read by no optimizer code"),
    ("targets/src/evidence.rs", "qmdb", "`SET_SUITES`: the names of the host-kit suites a feature-only variant set must pass on a CPU (`tests/host_sets.rs`), evidence of correctness, not an optimizer input"),
];

/// `src` with comments blanked out (string and char literals kept; line
/// structure kept).
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    while i < b.len() {
        let c = b[i];
        if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if c == '/' && b.get(i + 1) == Some(&'*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
            continue;
        }
        // raw strings r"..", r#".."#
        let ident_before = i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_');
        if c == 'r' && !ident_before && matches!(b.get(i + 1), Some('"') | Some('#')) {
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                let close: String = std::iter::once('"').chain(std::iter::repeat_n('#', hashes)).collect();
                let rest: String = b[j + 1..].iter().collect();
                let end = rest.find(&close).map(|e| j + 1 + rest[..e].chars().count() + close.chars().count()).unwrap_or(b.len());
                out.extend(&b[i..end]);
                i = end;
                continue;
            }
        }
        if c == '"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != '"' {
                j += if b[j] == '\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(b.len());
            out.extend(&b[i..end]);
            i = end;
            continue;
        }
        if c == '\'' {
            // a char literal ('x', '\n', '\u{..}'); a lifetime otherwise
            let end = if b.get(i + 1) == Some(&'\\') {
                (i + 2..b.len().min(i + 12)).find(|&j| b[j] == '\'').map(|j| j + 1)
            } else if b.get(i + 2) == Some(&'\'') {
                Some(i + 3)
            } else {
                None
            };
            if let Some(end) = end {
                out.extend(&b[i..end]);
                i = end;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `src` (comments already stripped) with every `#[cfg(test)]` module
/// (`#[cfg(test)] [pub[(crate)]] mod name { … }`) blanked out.
fn strip_cfg_test(src: &str) -> String {
    let mut s: Vec<char> = src.chars().collect();
    let pat: Vec<char> = "#[cfg(test)]".chars().collect();
    let skip_ws = |s: &[char], mut j: usize| {
        while j < s.len() && s[j].is_whitespace() {
            j += 1;
        }
        j
    };
    let word = |s: &[char], j: usize, w: &str| -> Option<usize> {
        let w: Vec<char> = w.chars().collect();
        (s.len() >= j + w.len() && s[j..j + w.len()] == w[..]).then_some(j + w.len())
    };
    let mut i = 0;
    while i + pat.len() <= s.len() {
        if s[i..i + pat.len()] != pat[..] {
            i += 1;
            continue;
        }
        let mut j = skip_ws(&s, i + pat.len());
        if let Some(k) = word(&s, j, "pub(crate)").or_else(|| word(&s, j, "pub ")) {
            j = skip_ws(&s, k);
        }
        let Some(k) = word(&s, j, "mod ") else {
            i += 1;
            continue;
        };
        j = skip_ws(&s, k);
        while j < s.len() && (s[j].is_alphanumeric() || s[j] == '_') {
            j += 1;
        }
        j = skip_ws(&s, j);
        if s.get(j) != Some(&'{') {
            i += 1;
            continue;
        }
        let (mut depth, mut in_str) = (0i32, false);
        while j < s.len() {
            match s[j] {
                '\\' if in_str => j += 1,
                '"' => in_str = !in_str,
                '{' if !in_str => depth += 1,
                '}' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let end = (j + 1).min(s.len());
        for c in &mut s[i..end] {
            if *c != '\n' {
                *c = ' ';
            }
        }
        i = end;
    }
    s.into_iter().collect()
}

/// A denylisted name in `tok`, if any.
fn denied(tok: &str) -> Option<String> {
    let lower = tok.to_ascii_lowercase();
    if let Some(d) = DENY.iter().find(|d| lower.contains(*d)) {
        return Some((*d).to_string());
    }
    if let Some(n) = lower.strip_prefix("hash_")
        && !n.is_empty()
        && n.chars().all(|c| c.is_ascii_digit())
    {
        return Some("hash_<digits>".into());
    }
    DENY_EXACT.iter().find(|d| tok == **d).map(|d| d.to_string())
}

/// The words of a piece of text (identifiers, and the identifier-like runs
/// inside string literals), with their line numbers.
fn words(text: &str) -> Vec<(usize, String, bool)> {
    let mut out = Vec::new();
    for (ln, line) in text.lines().enumerate() {
        let mut in_str = false;
        let mut cur = String::new();
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if c.is_alphanumeric() || c == '_' {
                cur.push(c);
                continue;
            }
            if !cur.is_empty() {
                out.push((ln + 1, std::mem::take(&mut cur), in_str));
            }
            if c == '\\' && in_str {
                chars.next();
            } else if c == '"' {
                in_str = !in_str;
            }
        }
        if !cur.is_empty() {
            out.push((ln + 1, cur, in_str));
        }
    }
    out
}

/// The string literals of a piece of text (comments stripped), with lines.
fn string_literals(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (ln, line) in text.lines().enumerate() {
        let mut it = line.char_indices().peekable();
        while let Some((i, c)) = it.next() {
            if c != '"' {
                continue;
            }
            let mut s = String::new();
            let mut closed = false;
            while let Some((_, d)) = it.next() {
                match d {
                    '\\' => {
                        it.next();
                    }
                    '"' => {
                        closed = true;
                        break;
                    }
                    _ => s.push(d),
                }
            }
            let _ = i;
            if closed {
                out.push((ln + 1, s));
            }
        }
    }
    out
}

/// One finding: (file, line, token, rule).
type Finding = (String, usize, String, String);

/// The lint of one source text (`file` as named in [`ALLOW`]); `allowed`
/// collects the allowlist entries used.
fn lint_text(file: &str, src: &str, rows: bool, used: &mut Vec<usize>) -> Vec<Finding> {
    let text = strip_cfg_test(&strip_comments(src));
    let mut out = Vec::new();
    for (ln, w, _) in words(&text) {
        if let Some(d) = denied(&w) {
            if let Some(k) = ALLOW.iter().position(|(f, t, _)| *f == file && w.to_ascii_lowercase().contains(&t.to_ascii_lowercase())) {
                if !used.contains(&k) {
                    used.push(k);
                }
                continue;
            }
            out.push((file.to_string(), ln, w, format!("names a benchmark target (`{d}`)")));
        }
    }
    if rows {
        for (ln, s) in string_literals(&text) {
            if let Some(p) = ROW_PREFIXES.iter().find(|p| s.starts_with(*p)) {
                out.push((file.to_string(), ln, s.clone(), format!("reads a validation row (`{p}*`)")));
            }
        }
    }
    out
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut es: Vec<PathBuf> = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).map(|e| e.unwrap().path()).collect();
    es.sort();
    for p in es {
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The scanned files (path relative to `sandblaster/`, and whether the
/// validation-row rule applies).
fn scanned() -> Vec<(String, PathBuf, bool)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = Vec::new();
    for (dir, rows) in [("front/src/opt", true), ("rulegen/src", false), ("targets/src", false)] {
        let mut fs = Vec::new();
        rs_files(&root.join(dir), &mut fs);
        for f in fs {
            let rel = f.strip_prefix(&root).unwrap().display().to_string();
            out.push((rel, f, rows));
        }
    }
    for f in ["front/src/driver/lowered.rs", "front/src/lower.rs"] {
        out.push((f.to_string(), root.join(f), true));
    }
    out
}

#[test]
fn optimizer_code_names_no_benchmark_target() {
    let files = scanned();
    assert!(files.len() > 40, "the lint scans the optimizer: {} files", files.len());
    let mut used = Vec::new();
    let mut findings = Vec::new();
    for (rel, path, rows) in &files {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        findings.extend(lint_text(rel, &src, *rows, &mut used));
    }
    let report: Vec<String> = findings.iter().map(|(f, l, t, r)| format!("{f}:{l}: `{t}` {r}")).collect();
    assert!(report.is_empty(), "optimizer code names benchmark targets (fairness rule; see this file's docs):\n{}", report.join("\n"));
    let stale: Vec<String> = (0..ALLOW.len()).filter(|k| !used.contains(k)).map(|k| format!("{} `{}`", ALLOW[k].0, ALLOW[k].1)).collect();
    assert!(stale.is_empty(), "allowlist entries that match nothing (remove them): {stale:?}");
}

/// The negative twin (see the module docs).
#[test]
fn the_lint_flags_its_twin() {
    let src = r##"//! Mentions of merkle and qmdb in docs are fine.
/// PeakIterator::to_nearest_size in a doc comment is fine.
fn generic(x: u64) -> u64 {
    /* a block comment naming shape_go /* nested varint */ is fine */
    let s = "a generic message";
    let c = 'm';
    x + s.len() as u64 + c as u64
}

#[cfg(test)]
mod tests {
    fn t() {
        let _ = "crate::merkle::shape_go";
        let _ = leb128_go;
    }
}

fn special(f: &str, at: Position) -> bool {
    f == "crate::merkle::shape_go" || f.starts_with("commonware_storage") || f == "hash_64"
}

fn tuned(t: &Tuning) -> u64 {
    t.get(r#"varint.swar_ns.1B"#) + t.get("sha.x16.ns_per_msg")
}
"##;
    let mut used = Vec::new();
    let got = lint_text("front/src/opt/twin.rs", src, true, &mut used);
    let lines: Vec<usize> = got.iter().map(|f| f.1).collect();
    let toks: Vec<&str> = got.iter().map(|f| f.2.as_str()).collect();
    // the code lines are flagged …
    assert!(lines.iter().all(|l| [18, 19, 23].contains(l)), "only code is flagged: {got:?}");
    for t in ["Position", "merkle", "shape_go", "commonware_storage", "hash_64", "varint", "sha.x16.ns_per_msg"] {
        assert!(toks.contains(&t), "`{t}` is flagged: {got:?}");
    }
    // … the comments, doc comments and the test module are not
    assert!(!lines.iter().any(|l| *l < 18), "{got:?}");
    // the allowlist is per file: the same key elsewhere is flagged
    let mut used = Vec::new();
    let g2 = lint_text("front/src/opt/cost/model.rs", "fn f() -> &'static str { \"varint\" }\n", true, &mut used);
    assert_eq!(g2.len(), 1, "{g2:?}");
    let g3 = lint_text("targets/src/evidence/tuning.rs", "fn f() -> &'static str { \"varint\" }\n", false, &mut used);
    assert!(g3.is_empty() && !used.is_empty(), "{g3:?}");
}
