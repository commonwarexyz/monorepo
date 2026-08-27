//! End-to-end tests for the formatter command-line interface.

use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Output, Stdio},
};

const UNFORMATTED: &str = "fn run() { select! {value=receive()=>value} }\n";

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_commonware-fmt"))
}

fn run(arguments: &[&str]) -> Output {
    command()
        .args(arguments)
        .output()
        .expect("formatter process should run")
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary path should be UTF-8")
}

#[test]
fn stdin_writes_only_formatted_source() {
    let mut child = command()
        .arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("formatter process should start");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(UNFORMATTED.as_bytes())
        .expect("source should be written");

    let output = child
        .wait_with_output()
        .expect("formatter process should finish");
    let expected = commonware_fmt::file::format(UNFORMATTED)
        .expect("source should format")
        .into_string();

    assert!(output.status.success());
    assert_eq!(output.stdout, expected.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn check_and_fix_use_expected_streams_and_statuses() {
    let temp = tempfile::tempdir().expect("temporary directory should be created");
    let path = temp.path().join("input.rs");
    fs::write(&path, UNFORMATTED).expect("source should be written");

    let check = run(&["--check", path_text(&path)]);
    assert!(!check.status.success());
    assert!(check.stdout.is_empty());
    assert_eq!(
        String::from_utf8(check.stderr).expect("diagnostic should be UTF-8"),
        format!("{}\n", path.display())
    );
    assert_eq!(
        fs::read_to_string(&path).expect("source should be read"),
        UNFORMATTED
    );

    let fix = run(&[path_text(&path)]);
    assert!(fix.status.success());
    assert!(fix.stdout.is_empty());
    assert!(fix.stderr.is_empty());
    assert_ne!(
        fs::read_to_string(&path).expect("source should be read"),
        UNFORMATTED
    );

    let clean = run(&["--check", path_text(&path)]);
    assert!(clean.status.success());
    assert!(clean.stdout.is_empty());
    assert!(clean.stderr.is_empty());
}
