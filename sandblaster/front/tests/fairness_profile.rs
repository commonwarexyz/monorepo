//! Fairness guard (audit of 2026-10-02, J8): the optimizer's profile is
//! never recorded on the inputs a benchmark times (train ≠ test).
//!
//! QMDB's `PROFILE.json` used to hold `shape_go` samples recorded on the
//! very fixtures (`fixtures`, `fixtures-n32`) that the benchmark then timed.
//! The fixtures are now split by a rule fixed before any measurement
//! (`sandblaster/fixtures/qmdb/splits/`: sorted by name, every first
//! fixture to the profile half, every second to the timed half; frozen by
//! G6), the profile is recorded on the profile halves, and
//! `Profile::check_timed` refuses a timed input that lies in a profile
//! corpus.
//!
//! * `the_splits_partition_the_fixtures`: each corpus is exactly the union
//!   of its two halves, the halves are disjoint, and they follow the rule;
//! * `the_qmdb_profile_is_disjoint_from_the_timed_inputs`: every entry of the
//!   committed `PROFILE.json` names its corpora, and none of them contains
//!   a timed fixture;
//! * `overlapping_profiles_are_refused` (the negative twin): a profile over
//!   a whole corpus directory, or over a timed half, is refused.

use std::path::{Path, PathBuf};

use sandblaster_front::opt::cost::profile::{Entry, Profile, corpus_files};

fn qmdb() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/qmdb")
}

/// The fixture files of a corpus directory, by the loader's rule (`*.json`
/// named with a leading digit), sorted.
fn fixtures(dir: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(qmdb().join(dir))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json") && p.file_name().unwrap().to_string_lossy().starts_with(|c: char| c.is_ascii_digit()))
        .collect();
    v.sort();
    v
}

fn canon(ps: Vec<PathBuf>) -> Vec<PathBuf> {
    ps.into_iter().map(|p| std::fs::canonicalize(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).collect()
}

fn half(name: &str) -> Vec<PathBuf> {
    canon(corpus_files(&qmdb().join("splits").join(name)).unwrap())
}

#[test]
fn the_splits_partition_the_fixtures() {
    for (dir, tag) in [("fixtures", "n1"), ("fixtures-n32", "n32")] {
        let all = canon(fixtures(dir));
        let (p, t) = (half(&format!("{tag}-profile.txt")), half(&format!("{tag}-timed.txt")));
        assert!(!p.is_empty() && !t.is_empty(), "{tag}: both halves are non-empty");
        assert!(p.iter().all(|x| !t.contains(x)), "{tag}: the halves are disjoint");
        let mut union: Vec<PathBuf> = p.iter().chain(&t).cloned().collect();
        union.sort();
        assert_eq!(union, all, "{tag}: the halves cover the corpus exactly");
        // the rule: sorted by name, alternating, the first to the profile
        let want_p: Vec<PathBuf> = all.iter().step_by(2).cloned().collect();
        let want_t: Vec<PathBuf> = all.iter().skip(1).step_by(2).cloned().collect();
        assert_eq!((p, t), (want_p, want_t), "{tag}: the split follows its rule");
    }
}

#[test]
fn the_qmdb_profile_is_disjoint_from_the_timed_inputs() {
    let text = std::fs::read_to_string(qmdb().join("PROFILE.json")).unwrap();
    let p = Profile::parse(&text).unwrap();
    assert!(!p.entries.is_empty());
    for e in &p.entries {
        assert!(!e.corpora.is_empty(), "{}: a profile entry declares its corpora", e.root);
        assert!(e.corpora.iter().all(|c| c.starts_with("splits/") && c.ends_with("-profile.txt")), "{}: recorded on a profile half, got {:?}", e.root, e.corpora);
    }
    let timed: Vec<PathBuf> = half("n1-timed.txt").into_iter().chain(half("n32-timed.txt")).collect();
    p.check_timed(&qmdb(), &timed).unwrap();
}

/// The negative twin (see the module docs).
#[test]
fn overlapping_profiles_are_refused() {
    let entry = |corpus: &str| Profile { entries: vec![Entry { root: "sandblaster/mod.rs".into(), entry: "verifier::verify".into(), corpora: vec![corpus.into()], fixtures: 1, loops: Default::default() }] };
    let timed = half("n32-timed.txt");
    // the pre-audit profile: the whole corpus the benchmark times
    let e = entry("fixtures-n32").check_timed(&qmdb(), &timed).unwrap_err();
    assert!(e.contains("245 timed input(s) are profile inputs"), "{e}");
    // a profile recorded on the timed half
    assert!(entry("splits/n32-timed.txt").check_timed(&qmdb(), &timed).is_err());
    // one timed file is enough
    assert!(entry("splits/n32-profile.txt").check_timed(&qmdb(), &half("n32-profile.txt")[..1]).is_err());
    // the profile half is fine
    entry("splits/n32-profile.txt").check_timed(&qmdb(), &timed).unwrap();
}
