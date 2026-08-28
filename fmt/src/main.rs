//! Command-line interface for formatting Commonware macro invocations.

use clap::Parser;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};
use tempfile::NamedTempFile;

#[derive(Parser)]
#[command(name = "commonware-fmt")]
#[command(about = "Format Commonware macro invocations")]
struct Args {
    /// Check whether files are formatted without writing them.
    #[arg(long)]
    check: bool,

    /// Read one Rust source file from stdin and write it to stdout.
    #[arg(long, conflicts_with_all = ["check", "files"])]
    stdin: bool,

    /// Rust source files to format.
    #[arg(
        value_name = "FILE",
        required_unless_present = "stdin",
        conflicts_with = "stdin"
    )]
    files: Vec<PathBuf>,
}

#[derive(Default)]
struct Outcome {
    changed: Vec<PathBuf>,
    errors: Vec<String>,
}

struct Input {
    display: PathBuf,
    resolved: PathBuf,
}

impl Outcome {
    const fn failed(&self, check: bool) -> bool {
        !self.errors.is_empty() || (check && !self.changed.is_empty())
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.stdin {
        return match run_stdin() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let outcome = run_files(&args.files, args.check);
    if args.check {
        for path in &outcome.changed {
            eprintln!("{}", path.display());
        }
    }
    for error in &outcome.errors {
        eprintln!("error: {error}");
    }
    if outcome.failed(args.check) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run_stdin() -> Result<(), String> {
    let mut source = String::new();
    io::stdin()
        .lock()
        .read_to_string(&mut source)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let output = commonware_fmt::file::format(&source)
        .map_err(|error| format!("failed to format stdin: {error}"))?;
    write_output(io::stdout().lock(), output.text())
}

fn write_output(mut writer: impl io::Write, output: &str) -> Result<(), String> {
    writer
        .write_all(output.as_bytes())
        .map_err(|error| format!("failed to write stdout: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))
}

fn run_files(paths: &[PathBuf], check: bool) -> Outcome {
    let mut outcome = Outcome::default();
    let inputs = collect_files(paths, &mut outcome.errors);
    for input in inputs {
        let source = match fs::read_to_string(&input.resolved) {
            Ok(source) => source,
            Err(error) => {
                outcome.errors.push(format!(
                    "failed to read `{}`: {error}",
                    input.display.display()
                ));
                continue;
            }
        };
        let output = match commonware_fmt::file::format(&source) {
            Ok(output) => output,
            Err(error) => {
                outcome.errors.push(format!(
                    "failed to format `{}`: {error}",
                    input.display.display()
                ));
                continue;
            }
        };
        if output.text() == source {
            continue;
        }
        if check {
            outcome.changed.push(input.display);
            continue;
        }
        if let Err(error) = replace(&input.resolved, output.text()) {
            outcome.errors.push(format!(
                "failed to write `{}`: {error}",
                input.display.display()
            ));
            continue;
        }
        outcome.changed.push(input.display);
    }
    outcome
}

fn replace(path: &Path, source: &str) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(path)?;
    if has_multiple_hard_links(&metadata) {
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        file.write_all(source.as_bytes())?;
        file.set_len(source.len() as u64)?;
        return file.flush();
    }

    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(source.as_bytes())?;
    temporary.flush()?;
    temporary
        .as_file()
        .set_permissions(metadata.permissions())?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(unix)]
fn has_multiple_hard_links(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.nlink() > 1
}

#[cfg(not(unix))]
fn has_multiple_hard_links(_metadata: &fs::Metadata) -> bool {
    false
}

fn collect_files(paths: &[PathBuf], errors: &mut Vec<String>) -> Vec<Input> {
    let mut files = BTreeMap::new();
    for path in paths {
        if path.extension() != Some(OsStr::new("rs")) {
            errors.push(format!("`{}` is not a Rust source file", path.display()));
            continue;
        }
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                errors.push(format!("`{}` is not a regular file", path.display()));
                continue;
            }
            Err(error) => {
                errors.push(format!("failed to inspect `{}`: {error}", path.display()));
                continue;
            }
        }
        let resolved = match fs::canonicalize(path) {
            Ok(resolved) => resolved,
            Err(error) => {
                errors.push(format!("failed to resolve `{}`: {error}", path.display()));
                continue;
            }
        };
        files
            .entry(resolved.clone())
            .and_modify(|input: &mut Input| {
                if path < &input.display {
                    input.display = path.clone();
                }
            })
            .or_insert_with(|| Input {
                display: path.clone(),
                resolved,
            });
    }
    files.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FlushError;

    impl io::Write for FlushError {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    struct TempDir(tempfile::TempDir);

    impl TempDir {
        fn new() -> Self {
            Self(tempfile::tempdir().expect("temporary directory should be created"))
        }

        fn join(&self, path: impl AsRef<Path>) -> PathBuf {
            self.0.path().join(path)
        }
    }

    fn unformatted() -> &'static str {
        "fn run() { select! {value=receive()=>value} }\n"
    }

    #[test]
    fn stdin_conflicts_with_check_and_files() {
        assert!(Args::try_parse_from(["commonware-fmt"]).is_err());
        assert!(Args::try_parse_from(["commonware-fmt", "--stdin", "--check"]).is_err());
        assert!(Args::try_parse_from(["commonware-fmt", "--stdin", "input.rs"]).is_err());
    }

    #[test]
    fn reports_buffered_stdout_errors() {
        let error = write_output(FlushError, "output").unwrap_err();

        assert_eq!(error, "failed to flush stdout: flush failed");
    }

    #[test]
    fn collects_files_deterministically_and_deduplicates_them() {
        let temp = TempDir::new();
        fs::write(temp.join("a.rs"), "").expect("Rust file should be written");
        fs::write(temp.join("b.rs"), "").expect("Rust file should be written");

        let mut errors = Vec::new();
        let files = collect_files(
            &[temp.join("b.rs"), temp.join("a.rs"), temp.join("b.rs")],
            &mut errors,
        );
        let display: Vec<_> = files.into_iter().map(|file| file.display).collect();

        assert!(errors.is_empty());
        assert_eq!(display, vec![temp.join("a.rs"), temp.join("b.rs")]);
    }

    #[test]
    fn reports_non_rust_missing_and_directory_inputs() {
        let temp = TempDir::new();
        fs::write(temp.join("readme.md"), "text").expect("file should be written");
        fs::create_dir(temp.join("directory.rs")).expect("directory should be created");

        let mut errors = Vec::new();
        let files = collect_files(
            &[
                temp.join("readme.md"),
                temp.join("missing.rs"),
                temp.join("directory.rs"),
            ],
            &mut errors,
        );

        assert!(files.is_empty());
        assert_eq!(errors.len(), 3);
        assert!(errors[0].contains("not a Rust source file"));
        assert!(errors[1].contains("failed to inspect"));
        assert!(errors[2].contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn resolves_and_deduplicates_symlinked_files() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new();
        let target = temp.join("target.rs");
        let link = temp.join("link.rs");
        fs::write(&target, unformatted()).expect("Rust file should be written");
        symlink(&target, &link).expect("symlink should be created");

        let mut errors = Vec::new();
        let files = collect_files(&[temp.join("target.rs"), link.clone()], &mut errors);

        assert!(errors.is_empty());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].display, link);
        assert_eq!(
            files[0].resolved,
            fs::canonicalize(temp.join("target.rs")).unwrap()
        );

        let outcome = run_files(std::slice::from_ref(&link), false);
        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.changed, vec![link.clone()]);
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        assert_ne!(fs::read_to_string(target).unwrap(), unformatted());
    }

    #[cfg(unix)]
    #[test]
    fn preserves_hard_link_aliases_when_replacing_files() {
        use std::os::unix::fs::MetadataExt as _;

        let temp = TempDir::new();
        let target = temp.join("target.rs");
        let alias = temp.join("alias.rs");
        fs::write(&target, unformatted()).expect("Rust file should be written");
        fs::hard_link(&target, &alias).expect("hard link should be created");
        let original_inode = fs::metadata(&target).unwrap().ino();

        let outcome = run_files(std::slice::from_ref(&target), false);

        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.changed, vec![target.clone()]);
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            fs::read_to_string(&alias).unwrap()
        );
        assert_ne!(fs::read_to_string(&target).unwrap(), unformatted());
        assert_eq!(fs::metadata(&target).unwrap().ino(), original_inode);
        assert_eq!(fs::metadata(&alias).unwrap().ino(), original_inode);
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 2);
    }

    #[test]
    fn check_mode_lists_changes_without_writing() {
        let temp = TempDir::new();
        let path = temp.join("input.rs");
        fs::write(&path, unformatted()).expect("source should be written");

        let outcome = run_files(std::slice::from_ref(&path), true);

        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.changed, vec![path.clone()]);
        assert_eq!(
            fs::read_to_string(path).expect("source should be read"),
            unformatted()
        );
    }

    #[test]
    fn fix_mode_writes_complete_formatted_files() {
        let temp = TempDir::new();
        let path = temp.join("input.rs");
        fs::write(&path, unformatted()).expect("source should be written");

        let first = run_files(std::slice::from_ref(&path), false);
        let second = run_files(std::slice::from_ref(&path), false);

        assert!(first.errors.is_empty());
        assert_eq!(first.changed, vec![path]);
        assert!(second.errors.is_empty());
        assert!(second.changed.is_empty());
    }

    #[test]
    fn later_files_are_processed_after_a_formatting_error() {
        let temp = TempDir::new();
        let invalid = temp.join("a-invalid.rs");
        let valid = temp.join("b-valid.rs");
        fs::write(&invalid, "fn invalid(\n").expect("invalid source should be written");
        fs::write(&valid, unformatted()).expect("valid source should be written");

        let outcome = run_files(&[invalid, valid.clone()], false);

        assert_eq!(outcome.errors.len(), 1);
        assert!(outcome.errors[0].contains("a-invalid.rs"));
        assert_eq!(outcome.changed, vec![valid.clone()]);
        assert_ne!(
            fs::read_to_string(valid).expect("source should be read"),
            unformatted()
        );
    }
}
