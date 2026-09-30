//! The evidence records are build inputs (`build.rs`): changing **only** an
//! evidence file re-runs the build scripts that consult it at build time, so
//! a cached verified build can never keep dispatch decisions made against an
//! older record (DESIGN.md §9.2 fail closed; the host kit's dispatch test
//! build relied on a stale cache before this).
//!
//! The optimizer reads the records at run time (`evidence::validation`,
//! `std::fs`), inside QMDB's build script, through the chain
//! `qmdb` build script → `sandblaster` → `sandblaster-front` → this crate. The
//! test copies this crate (sources, core texts, evidence, `build.rs`) into a
//! scratch workspace next to a fixture of the same shape — `mid`, a library
//! depending on the copy, and `probe`, whose build script asks `mid` for a
//! verdict and appends it to a log — then:
//!
//! 1. builds `probe` (the build script runs once);
//! 2. builds again unchanged (it must not run again: the fixture is cached);
//! 3. edits only the copy's `evidence/x86_64.json` (a model hash made stale)
//!    and builds: the build script must run again and see the new verdict.
//!
//! It runs a nested `cargo build` of this dependency-free crate (offline,
//! `-j 2`, its own target directory under `CARGO_TARGET_TMPDIR`).

use sandblaster_targets::json::{self, Json};
use std::path::{Path, PathBuf};
use std::process::Command;

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let (src, dst) = (e.path(), to.join(e.file_name()));
        if e.file_type().unwrap().is_dir() {
            copy_dir(&src, &dst);
        } else {
            std::fs::copy(&src, &dst).unwrap();
        }
    }
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// The model whose verdict the fixture reports.
const MODEL: &str = "_mm_shuffle_epi8";

fn build(root: &Path) {
    let out = Command::new(env!("CARGO"))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args(["build", "--offline", "-j", "2", "-p", "probe"])
        .output()
        .expect("run cargo");
    assert!(out.status.success(), "nested cargo build failed:\n{}", String::from_utf8_lossy(&out.stderr));
}

fn log(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join("verdicts.log")).unwrap_or_default().lines().map(str::to_string).collect()
}

#[test]
fn changing_only_the_evidence_reruns_dependent_build_scripts() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("evidence-rebuild");
    let _ = std::fs::remove_dir_all(&root);
    let t = root.join("sandblaster-targets");
    for d in ["src", "core", "evidence"] {
        copy_dir(&src.join(d), &t.join(d));
    }
    std::fs::copy(src.join("build.rs"), t.join("build.rs")).unwrap();
    write(
        &t.join("Cargo.toml"),
        "[package]\nname = \"sandblaster-targets\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\nautobins = false\n\n[features]\ndefault = []\nkernel = []\n",
    );
    write(&root.join("Cargo.toml"), "[workspace]\nresolver = \"3\"\nmembers = [\"sandblaster-targets\", \"mid\", \"probe\"]\n");
    write(
        &root.join("mid/Cargo.toml"),
        "[package]\nname = \"mid\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nsandblaster-targets = { path = \"../sandblaster-targets\" }\n",
    );
    write(
        &root.join("mid/src/lib.rs"),
        &format!(
            "pub fn verdict() -> String {{ format!(\"{{:?}}\", sandblaster_targets::evidence::validation(sandblaster_targets::registry::Arch::X86_64, {MODEL:?})) }}\n"
        ),
    );
    write(
        &root.join("probe/Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[build-dependencies]\nmid = { path = \"../mid\" }\n",
    );
    write(&root.join("probe/src/lib.rs"), "");
    // Like QMDB's build script: it declares its own inputs, so only those (and
    // rebuilt dependencies) re-run it.
    write(
        &root.join("probe/build.rs"),
        &format!(
            "use std::io::Write;\nfn main() {{\n    println!(\"cargo::rerun-if-changed=build.rs\");\n    let v = mid::verdict();\n    let mut f = std::fs::OpenOptions::new().create(true).append(true).open({:?}).unwrap();\n    writeln!(f, \"{{v}}\").unwrap();\n}}\n",
            root.join("verdicts.log")
        ),
    );

    build(&root);
    let first = log(&root);
    assert_eq!(first.len(), 1, "{first:?}");
    assert!(!first[0].contains("stale record"), "the copied record is current: {}", first[0]);

    build(&root);
    assert_eq!(log(&root), first, "an unchanged rebuild must not re-run the build script");

    // Edit only the evidence: make the model's recorded hash stale.
    let path = t.join("evidence/x86_64.json");
    let mut doc = json::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let Json::Obj(members) = &mut doc else { panic!("not an object") };
    let (_, Json::Arr(models)) = members.iter_mut().find(|(k, _)| k == "models").unwrap() else { panic!("no models") };
    let model = models.iter_mut().find(|m| m.get("name").and_then(Json::as_str) == Some(MODEL)).unwrap();
    let Json::Obj(fields) = model else { panic!("model is not an object") };
    fields.iter_mut().find(|(k, _)| k == "source_hash").unwrap().1 = Json::str("sha256:00");
    std::fs::write(&path, doc.to_pretty()).unwrap();

    build(&root);
    let after = log(&root);
    assert_eq!(after.len(), 2, "changing only the evidence file must re-run the dependent build script: {after:?}");
    assert!(after[1].contains("stale record") && after[1] != after[0], "{after:?}");
}
