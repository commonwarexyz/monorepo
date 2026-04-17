//! Table-driven replay fixture suites.
//!
//! There are two suites, deliberately separated so that the word "OK" in
//! a test result means what it says:
//!
//! 1. **Strict** — `src/simplex/replay/fixtures/strict/*.json`. Fixtures
//!    whose embedded [`Snapshot`] must match the replay output **bit for
//!    bit**. These are the long-term contract: a fixture passes iff the
//!    driver reproduces exactly what is recorded. Fresh traces captured
//!    at engine ingress belong here.
//!
//! 2. **Legacy** — `src/simplex/replay/fixtures/legacy/*.json`. Fixtures
//!    migrated from the pre-replay fuzz harness via
//!    `cargo run -p commonware-consensus-fuzz --bin convert_trace`. The
//!    legacy harness recorded observational signer data at an arbitrary
//!    quiesce point; past each node's last-finalized view this data is
//!    timing-noisy in both directions (the old harness sometimes misses
//!    self-votes our driver catches; sometimes records self-votes our
//!    driver cannot reproduce). The legacy suite therefore compares only
//!    the stable-finalized window. This relaxation is honest about the
//!    legacy format's limits — it is *not* a tolerance for real replay
//!    drift, and it applies only to this suite.
//!
//! Producers of new fixtures should aim for the strict suite. A legacy
//! fixture that starts passing strict equality can simply be moved.

use super::{replay, Snapshot, Trace};
use std::{fs, path::PathBuf};

fn suite_dir(suite: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/simplex/replay/fixtures")
        .join(suite)
}

fn collect_fixtures(suite: &str) -> Vec<PathBuf> {
    let dir = suite_dir(suite);
    let mut out = Vec::new();
    if !dir.exists() {
        return out;
    }
    for entry in fs::read_dir(&dir).expect("read fixtures dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn load_and_replay(path: &PathBuf) -> (Snapshot, Snapshot) {
    let json = fs::read_to_string(path).expect("read fixture");
    let trace = Trace::from_json(&json).expect("parse fixture");
    let expected = trace.expected.clone();
    let actual = replay(&trace);
    (expected, actual)
}

/// Strict suite: `actual == expected` exactly.
#[test]
fn replay_strict_fixtures() {
    let fixtures = collect_fixtures("strict");
    if fixtures.is_empty() {
        eprintln!(
            "note: no fixtures in {} yet — strict suite will populate \
             once traces are recorded at engine ingress.",
            suite_dir("strict").display()
        );
        return;
    }

    let mut failures = Vec::new();
    for path in &fixtures {
        let (expected, actual) = load_and_replay(path);
        if actual != expected {
            failures.push(diff_snapshots(path, &expected, &actual));
        } else {
            eprintln!("OK (strict) {}", path.display());
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} of {} strict fixtures failed:\n{}",
            failures.len(),
            fixtures.len(),
            failures.join("\n---\n")
        );
    }
}

/// Legacy suite: compares only the stable-finalized window on both sides.
/// See the module doc comment for why.
#[test]
fn replay_legacy_fixtures() {
    let fixtures = collect_fixtures("legacy");
    assert!(
        !fixtures.is_empty(),
        "no fixtures in {}",
        suite_dir("legacy").display()
    );

    let mut failures = Vec::new();
    for path in &fixtures {
        let (mut expected, mut actual) = load_and_replay(path);
        trim_past_horizon(&mut expected);
        trim_past_horizon(&mut actual);
        if actual != expected {
            failures.push(diff_snapshots(path, &expected, &actual));
        } else {
            eprintln!("OK (legacy) {}", path.display());
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} of {} legacy fixtures failed:\n{}",
            failures.len(),
            fixtures.len(),
            failures.join("\n---\n")
        );
    }
}

/// Trim observational signer data past each node's stable finalized
/// horizon. Applied to both `expected` and `actual` before comparison.
/// Used only by the legacy suite.
fn trim_past_horizon(snapshot: &mut Snapshot) {
    for node in snapshot.nodes.values_mut() {
        let horizon = node.last_finalized;
        node.notarize_signers.retain(|v, _| *v <= horizon);
        node.nullify_signers.retain(|v, _| *v <= horizon);
        node.finalize_signers.retain(|v, _| *v <= horizon);
    }
}

fn diff_snapshots(path: &PathBuf, expected: &Snapshot, actual: &Snapshot) -> String {
    use std::fmt::Write as _;
    let mut out = format!("snapshot mismatch for {path:?}\n");
    for (p, exp) in &expected.nodes {
        let act = match actual.nodes.get(p) {
            Some(a) => a,
            None => {
                let _ = writeln!(out, "  node {p:?}: missing in actual");
                continue;
            }
        };
        if exp.notarizations != act.notarizations {
            let _ = writeln!(
                out,
                "  node {p:?}: notarizations differ\n    expected: {:?}\n    actual:   {:?}",
                exp.notarizations.keys().collect::<Vec<_>>(),
                act.notarizations.keys().collect::<Vec<_>>()
            );
        }
        if exp.nullifications != act.nullifications {
            let _ = writeln!(
                out,
                "  node {p:?}: nullifications differ\n    expected: {:?}\n    actual:   {:?}",
                exp.nullifications.keys().collect::<Vec<_>>(),
                act.nullifications.keys().collect::<Vec<_>>()
            );
        }
        if exp.finalizations != act.finalizations {
            let _ = writeln!(
                out,
                "  node {p:?}: finalizations differ\n    expected: {:?}\n    actual:   {:?}",
                exp.finalizations.keys().collect::<Vec<_>>(),
                act.finalizations.keys().collect::<Vec<_>>()
            );
        }
        if exp.certified != act.certified {
            let _ = writeln!(
                out,
                "  node {p:?}: certified differ\n    expected: {:?}\n    actual:   {:?}",
                exp.certified, act.certified
            );
        }
        if exp.last_finalized != act.last_finalized {
            let _ = writeln!(
                out,
                "  node {p:?}: last_finalized exp={:?} got={:?}",
                exp.last_finalized, act.last_finalized
            );
        }
        for (kind, e, a) in [
            ("notarize", &exp.notarize_signers, &act.notarize_signers),
            ("nullify", &exp.nullify_signers, &act.nullify_signers),
            ("finalize", &exp.finalize_signers, &act.finalize_signers),
        ] {
            if e != a {
                for view in e.keys().chain(a.keys()).collect::<std::collections::BTreeSet<_>>() {
                    let empty = std::collections::BTreeSet::new();
                    let es = e.get(view).unwrap_or(&empty);
                    let as_ = a.get(view).unwrap_or(&empty);
                    if es != as_ {
                        let _ = writeln!(
                            out,
                            "  node {p:?} view {view:?} {kind}_signers:\n    expected: {:?}\n    actual:   {:?}",
                            es, as_
                        );
                    }
                }
            }
        }
    }
    for p in actual.nodes.keys() {
        if !expected.nodes.contains_key(p) {
            let _ = writeln!(out, "  node {p:?}: unexpected in actual");
        }
    }
    out
}
