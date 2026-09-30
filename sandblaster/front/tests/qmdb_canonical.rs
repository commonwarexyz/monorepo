//! Differential test on the real program: the canonical output of the QMDB
//! port (`sandblaster/fixtures/qmdb/sandblaster`, exec part of its N = 1 instance root `n1.rs`: the
//! fixtures and the Bend corpus are N = 1 proofs) is compiled with rustc (overflow checks
//! and debug assertions on) and run on every fixture and on the port's Bend 2
//! oracle corpus of mutated fixtures (`sandblaster/fixtures/qmdb/baseline/tests/data/
//! bend_verify.json`); `verify` must return the expected result everywhere.
//!
//! The ghost modules (`LAWS.rs`, `PROOF.rs`) are left out of this build: they
//! are never printed, and their phase-1 status is reported by `sandblaster
//! check`. The test is skipped when the port is absent.

mod common;

use std::path::Path;

use common::*;

#[test]
fn qmdb_canonical_output_verifies_fixtures_and_bend_corpus() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let src = repo.join("sandblaster/fixtures/qmdb/sandblaster");
    let fixtures = repo.join("sandblaster/fixtures/qmdb/fixtures");
    let fixture_rs = repo.join("sandblaster/fixtures/qmdb/baseline/src/fixture.rs");
    let corpus = repo.join("sandblaster/fixtures/qmdb/baseline/tests/data/bend_verify.json");
    if !src.join("n1.rs").is_file() || !fixture_rs.is_file() || !fixtures.is_dir() {
        eprintln!("qmdb port not present; skipping");
        return;
    }
    // copy the exec sources without the ghost module declarations
    let t = tmp("qmdb-canonical");
    let dsl = t.join("dsl");
    std::fs::create_dir_all(&dsl).unwrap();
    for e in std::fs::read_dir(&src).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") {
            std::fs::copy(&p, dsl.join(p.file_name().unwrap())).unwrap();
        }
    }
    let root = std::fs::read_to_string(dsl.join("n1.rs")).unwrap();
    let mut out = String::new();
    let mut skip_next = false;
    for line in root.lines() {
        let t = line.trim();
        if t == "#[cfg(sandblaster)]" {
            skip_next = true;
            continue;
        }
        if skip_next && (t.starts_with("#[path") || t.starts_with("mod ")) {
            skip_next = !t.starts_with("mod ");
            continue;
        }
        skip_next = false;
        out.push_str(line);
        out.push('\n');
    }
    std::fs::write(dsl.join("n1.rs"), out).unwrap();
    let c = check_dir(&dsl.join("n1.rs"));
    if !c.ok() {
        panic!("the exec part of the QMDB port does not pass the front end:\n{}", c.render());
    }
    let code = sandblaster_front::driver::stage::emit(&c, "sandblaster/fixtures/qmdb/sandblaster/n1.rs").unwrap();
    std::fs::write(t.join("sandblaster.rs"), &code).unwrap();
    let main = format!(
        r#"include!({gen:?});
#[allow(dead_code)]
#[path = {fx:?}]
mod fixture;
use fixture::{{Json, bytes_from_hex, parse_json}};
fn number(case: &Json, key: &str) -> u64 {{
    match case.get(key) {{
        Some(Json::Number(text)) => text.parse().unwrap(),
        Some(Json::String(units)) => String::from_utf16(units).unwrap().parse().unwrap(),
        other => panic!("{{key}}: {{other:?}}"),
    }}
}}
fn main() {{
    let files = fixture::fixture_files(std::path::Path::new({dir:?})).unwrap();
    let fixtures: Vec<fixture::Fixture> = files.iter().map(|f| fixture::load_fixture(f.to_str().unwrap(), None).unwrap()).collect();
    let mut accepted = 0;
    for fx in &fixtures {{
        let b = fx.bytes();
        let got = verify(&b.root, &b.key, &b.value, &b.proof);
        assert_eq!(got, fx.expected, "{{}}", fx.name_lossy());
        accepted += usize::from(got);
    }}
    let mut cases_run = 0;
    if let Ok(text) = std::fs::read_to_string({corpus:?}) {{
        let corpus = parse_json(&text).unwrap();
        let Some(Json::Array(cases)) = corpus.get("cases") else {{ panic!("no cases") }};
        let hex = |case: &Json, key: &str| -> Vec<u8> {{
            let Some(Json::String(units)) = case.get(key) else {{ panic!("{{key}}") }};
            bytes_from_hex(&String::from_utf16(units).unwrap()).unwrap()
        }};
        for (i, case) in cases.iter().enumerate() {{
            let fixture = &fixtures[number(case, "fixture") as usize];
            let value = fixture.bytes().value;
            let (root, key, proof) = (hex(case, "root"), hex(case, "key"), hex(case, "proof"));
            let Some(&Json::Bool(expected)) = case.get("expected") else {{ panic!("expected") }};
            assert_eq!(verify(&root, &key, &value, &proof), expected, "bend case {{i}}");
            cases_run += 1;
        }}
    }}
    println!("fixtures {{}} accepted {{}} bend-cases {{}}", fixtures.len(), accepted, cases_run);
}}
"#,
        gen = t.join("sandblaster.rs"),
        fx = fixture_rs,
        dir = fixtures,
        corpus = corpus,
    );
    std::fs::write(t.join("main.rs"), main).unwrap();
    let out = rustc_run(&t.join("main.rs"), &t.join("qmdb_canonical"), &[]);
    eprintln!("{out}");
    assert!(out.starts_with("fixtures "), "{out}");
    let n: usize = out.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert!(n >= 30, "{out}");
}
