//! Delivery checks derived from SPEC.md section 10.

mod dkg {
    use std::{fs, path::PathBuf, process::Command};

    const TARGETS: [&str; 6] = [
        "dkg_bootstrap",
        "dkg_bootstrap_restarts",
        "dkg_reshare",
        "dkg_reshare_restarts",
        "dkg_probe",
        "dkg_state_sync",
    ];

    fn fuzz_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn thin_body(text: &str, target: &str) -> bool {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let Some((_, entry)) = compact.split_once("fuzz_target!(|input:") else {
            return false;
        };
        let Some((input_type, body)) = entry.split_once("|{") else {
            return false;
        };
        input_type.ends_with("FuzzInput") && body == format!("fuzz_{target}(input);}});}}")
    }

    #[test]
    fn at_047_all_six_entries_are_thin_and_typed() {
        for target in TARGETS {
            let source = fs::read_to_string(fuzz_dir().join(format!("fuzz_targets/{target}.rs")))
                .expect("registered target exists");
            assert!(thin_body(&source, target), "{target}: extra target logic");
            let with_oracle = source.replace(
                &format!("fuzz_{target}(input);"),
                &format!("assert!(false); fuzz_{target}(input);"),
            );
            assert!(!thin_body(&with_oracle, target));
        }
    }

    fn registered(manifest: &str, target: &str) -> bool {
        manifest.split("[[bin]]").skip(1).any(|entry| {
            let compact: String = entry.chars().filter(|c| !c.is_whitespace()).collect();
            compact.contains(&format!("name=\"{target}\""))
                && compact.contains(&format!("path=\"fuzz_targets/{target}.rs\""))
                && ["test=false", "doc=false", "bench=false"]
                    .iter()
                    .all(|key| compact.contains(key))
        })
    }

    #[test]
    fn at_050_manifest_contains_each_target() {
        let manifest = fs::read_to_string(fuzz_dir().join("Cargo.toml")).unwrap();
        for target in TARGETS {
            assert!(registered(&manifest, target), "missing {target}");
            let omitted = manifest.replace(&format!("name = \"{target}\""), "name = \"omitted\"");
            assert!(!registered(&omitted, target));
        }
    }

    fn in_scope(path: &str) -> bool {
        path.starts_with("glue/fuzz/") || path == "Cargo.lock"
    }

    #[test]
    fn at_034_at_046_production_trees_unchanged() {
        let result = Command::new("git")
            .current_dir(fuzz_dir())
            .args([
                "status",
                "--porcelain",
                "--",
                "../src",
                "../../cryptography/src",
                "../../consensus/src",
            ])
            .output()
            .expect("git status runs");
        assert!(result.status.success());
        assert!(
            result.stdout.is_empty(),
            "I11: production tree changed: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert!(in_scope("glue/fuzz/src/dkg/dkg_acceptance.rs"));
        assert!(!in_scope("glue/src/dkg/reshare/actor/mod.rs"));
    }
}

#[test]
#[ignore = "copies the workspace into scratchpad and runs a compiler negative control"]
fn dkg_at_048_report_field_removal_is_a_compile_error() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let work = root.join(format!(
        "scratchpad/dkg-r30-compile-negative-{}",
        std::process::id()
    ));
    std::fs::create_dir(&work).expect("fresh throwaway copy");
    let listed = std::process::Command::new("git")
        .current_dir(root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let names = String::from_utf8(listed.stdout).unwrap();
    for name in names.split('\0').filter(|name| !name.is_empty()) {
        if name.starts_with("scratchpad/") || name.starts_with("target/") {
            continue;
        }
        let source = root.join(name);
        if !source.is_file() {
            continue;
        }
        let destination = work.join(name);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(source, destination).unwrap();
    }
    // Rename the returned field and its implementation uses, keeping the trait's
    // method and all DKG acceptance files intact. Only the API is removed.
    let dkg = work.join("glue/fuzz/src/dkg");
    for path in std::fs::read_dir(&dkg).unwrap() {
        let path = path.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if path.extension().is_none_or(|extension| extension != "rs") || name.contains("acceptance")
        {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        let mut replaced = String::new();
        let mut rest = source.as_str();
        while let Some(at) = rest.find("judged") {
            replaced.push_str(&rest[..at]);
            let after = &rest[at + "judged".len()..];
            let before_ident = rest[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            let after_ident = after
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            if !before_ident && !after_ident && !after.trim_start().starts_with('(') {
                replaced.push_str("removed_report");
            } else {
                replaced.push_str("judged");
            }
            rest = after;
        }
        replaced.push_str(rest);
        std::fs::write(path, replaced).unwrap();
    }
    let output = std::process::Command::new("cargo")
        .arg("+stable")
        .current_dir(&work)
        .args([
            "check",
            "-p",
            "commonware-glue-fuzz",
            "--tests",
            "--message-format=json",
        ])
        .env(
            "CARGO_TARGET_DIR",
            root.join("scratchpad/dkg-r30-compile-negative-target"),
        )
        .output()
        .unwrap();
    std::fs::write(work.join("compiler.stdout.jsonl"), &output.stdout).unwrap();
    std::fs::write(work.join("compiler.stderr.log"), &output.stderr).unwrap();
    eprintln!("AT-048 compiler evidence: {}", work.display());
    assert!(
        !output.status.success(),
        "removed report field must not compile"
    );
    let diagnostics = String::from_utf8(output.stdout).unwrap();
    let errors: Vec<_> = diagnostics
        .lines()
        .filter(|line| line.contains("\"level\":\"error\""))
        .collect();
    assert!(!errors.is_empty());
    for error in errors {
        assert!(
            error.contains("dkg_acceptance.rs")
                && error.contains("E0609")
                && error.contains("judged"),
            "unexpected compile error: {error}"
        );
    }
}
