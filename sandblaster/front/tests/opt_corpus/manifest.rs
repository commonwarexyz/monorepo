//! A reader for `corpus.toml` (the subset it uses: `[[program]]` tables of
//! `key = value` lines, dotted keys with one quoted segment, strings, numbers,
//! booleans and arrays). Shared by `tests/opt_explore.rs` and
//! `tests/opt_reject.rs` through `#[path]`. The file is also valid TOML
//! (`python3 -c "import tomllib; tomllib.load(open(PATH, 'rb'))"`).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One `[[program]]` table: plain keys, and the `today.<function>` map.
#[derive(Clone, Debug, Default)]
pub struct Program {
    pub fields: BTreeMap<String, String>,
    pub today: BTreeMap<String, String>,
    pub functions: Vec<String>,
}

impl Program {
    pub fn get(&self, k: &str) -> &str {
        self.fields.get(k).map(|s| s.as_str()).unwrap_or_else(|| panic!("corpus.toml: missing `{k}` in {:?}", self.fields.get("id")))
    }
    pub fn id(&self) -> &str {
        self.get("id")
    }
    pub fn control(&self) -> bool {
        self.get("control") == "true"
    }
}

pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/opt_corpus")
}

/// A TOML basic string starting at `s[0] == '"'`: (value, rest).
fn string(s: &str) -> (String, &str) {
    let mut out = String::new();
    let mut it = s[1..].char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '"' => return (out, &s[i + 2..]),
            '\\' => match it.next() {
                Some((_, 'n')) => out.push('\n'),
                Some((_, 't')) => out.push('\t'),
                Some((_, c)) => out.push(c),
                None => break,
            },
            c => out.push(c),
        }
    }
    panic!("corpus.toml: unterminated string: {s}")
}

/// A value: strings unquoted, arrays of strings as `\u{1f}`-separated
/// items, anything else verbatim.
fn value(v: &str) -> String {
    let v = v.trim();
    if v.starts_with('"') {
        return string(v).0;
    }
    if v.starts_with("[\"") {
        let mut items = Vec::new();
        let mut rest = &v[1..];
        loop {
            rest = rest.trim_start_matches([' ', ',']);
            if rest.starts_with('"') {
                let (s, r) = string(rest);
                items.push(s);
                rest = r;
            } else {
                break;
            }
        }
        return items.join("\u{1f}");
    }
    v.to_string()
}

pub fn load() -> Vec<Program> {
    let text = std::fs::read_to_string(corpus_dir().join("corpus.toml")).expect("read corpus.toml");
    let mut out: Vec<Program> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l == "[[program]]" {
            out.push(Program::default());
            continue;
        }
        let (k, v) = l.split_once(" = ").unwrap_or_else(|| panic!("corpus.toml: bad line `{l}`"));
        let p = out.last_mut().expect("a key before the first [[program]]");
        if let Some(rest) = k.strip_prefix("today.") {
            let (f, _) = string(rest);
            p.today.insert(f, value(v));
        } else if k.starts_with("baseline.") {
            // numbers for the native harness; not needed here
        } else if k == "functions" {
            p.functions = value(v).split('\u{1f}').map(|s| s.to_string()).collect();
        } else {
            p.fields.insert(k.to_string(), value(v));
        }
    }
    out
}
