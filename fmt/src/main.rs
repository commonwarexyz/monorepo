//! Command-line interface for formatting Commonware macro invocations.

use clap::Parser;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{self, Read as _, Write as _},
    path::{Component, Path, PathBuf},
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
    #[arg(long, conflicts_with_all = ["check", "paths"])]
    stdin: bool,

    /// Rust files or directories to format.
    #[arg(value_name = "PATH", conflicts_with = "stdin")]
    paths: Vec<PathBuf>,
}

#[derive(Default)]
struct Outcome {
    changed: Vec<PathBuf>,
    errors: Vec<String>,
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

    let outcome = run_files(&args.paths, args.check);
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
    io::stdout()
        .lock()
        .write_all(output.text().as_bytes())
        .map_err(|error| format!("failed to write stdout: {error}"))
}

fn run_files(paths: &[PathBuf], check: bool) -> Outcome {
    let mut outcome = Outcome::default();
    let files = discover(paths, &mut outcome.errors);
    for path in files {
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                outcome
                    .errors
                    .push(format!("failed to read `{}`: {error}", path.display()));
                continue;
            }
        };
        let output = match commonware_fmt::file::format(&source) {
            Ok(output) => output,
            Err(error) => {
                outcome
                    .errors
                    .push(format!("failed to format `{}`: {error}", path.display()));
                continue;
            }
        };
        if output.text() == source {
            continue;
        }
        if check {
            outcome.changed.push(path);
            continue;
        }
        if let Err(error) = replace(&path, output.text()) {
            outcome
                .errors
                .push(format!("failed to write `{}`: {error}", path.display()));
            continue;
        }
        outcome.changed.push(path);
    }
    outcome
}

fn replace(path: &Path, source: &str) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let permissions = fs::metadata(path)?.permissions();
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(source.as_bytes())?;
    temporary.flush()?;
    temporary.as_file().set_permissions(permissions)?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn discover(paths: &[PathBuf], errors: &mut Vec<String>) -> Vec<PathBuf> {
    let roots = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };
    let mut files = BTreeMap::new();
    for root in roots {
        match contains_symlink(&root) {
            Ok(true) => errors.push(format!(
                "refusing to follow symlink in `{}`",
                root.display()
            )),
            Ok(false) => collect(&root, true, &mut files, errors),
            Err(error) => errors.push(format!("failed to inspect `{}`: {error}", root.display())),
        }
    }
    let mut files: Vec<_> = files.into_values().collect();
    files.sort_unstable();
    files
}

fn collect(
    path: &Path,
    explicit: bool,
    files: &mut BTreeMap<PathBuf, PathBuf>,
    errors: &mut Vec<String>,
) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(format!("failed to inspect `{}`: {error}", path.display()));
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        if explicit {
            errors.push(format!("refusing to follow symlink `{}`", path.display()));
        }
        return;
    }
    if metadata.is_file() {
        collect_file(path, explicit, files, errors);
        return;
    }
    if !metadata.is_dir() {
        if explicit {
            errors.push(format!(
                "`{}` is not a regular file or directory",
                path.display()
            ));
        }
        return;
    }
    if in_target(path) {
        return;
    }

    let directory = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!(
                "failed to read directory `{}`: {error}",
                path.display()
            ));
            return;
        }
    };
    let mut entries = Vec::new();
    for entry in directory {
        match entry {
            Ok(entry) => entries.push(entry.path()),
            Err(error) => errors.push(format!(
                "failed to read an entry in `{}`: {error}",
                path.display()
            )),
        }
    }
    entries.sort_unstable();
    for entry in entries {
        collect(&entry, false, files, errors);
    }
}

fn collect_file(
    path: &Path,
    explicit: bool,
    files: &mut BTreeMap<PathBuf, PathBuf>,
    errors: &mut Vec<String>,
) {
    if in_target(path) {
        return;
    }
    if path.extension() != Some(OsStr::new("rs")) {
        if explicit {
            errors.push(format!("`{}` is not a Rust source file", path.display()));
        }
        return;
    }
    let canonical = match fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(error) => {
            errors.push(format!("failed to resolve `{}`: {error}", path.display()));
            return;
        }
    };
    if in_target(&canonical) {
        return;
    }
    files
        .entry(canonical)
        .and_modify(|current| {
            if path < current.as_path() {
                *current = path.to_owned();
            }
        })
        .or_insert_with(|| path.to_owned());
}

fn contains_symlink(path: &Path) -> io::Result<bool> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if fs::symlink_metadata(&prefix)?.file_type().is_symlink() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn in_target(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::Normal(name) if name == "target"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn stdin_conflicts_with_check_and_paths() {
        assert!(Args::try_parse_from(["commonware-fmt", "--stdin", "--check"]).is_err());
        assert!(Args::try_parse_from(["commonware-fmt", "--stdin", "input.rs"]).is_err());
    }

    #[test]
    fn discovers_rust_files_deterministically_and_skips_target() {
        let temp = TempDir::new();
        fs::create_dir(temp.join("nested")).expect("nested directory should be created");
        fs::create_dir(temp.join("target")).expect("target directory should be created");
        fs::write(temp.join("b.rs"), "").expect("Rust file should be written");
        fs::write(temp.join("nested/a.rs"), "").expect("Rust file should be written");
        fs::write(temp.join("nested/readme.md"), "").expect("other file should be written");
        fs::write(temp.join("target/ignored.rs"), "").expect("target file should be written");

        let mut errors = Vec::new();
        let files = discover(&[temp.0.path().to_owned(), temp.join("b.rs")], &mut errors);

        assert!(errors.is_empty());
        assert_eq!(files, vec![temp.join("b.rs"), temp.join("nested/a.rs")]);
    }

    #[test]
    fn reports_invalid_explicit_paths() {
        let temp = TempDir::new();
        fs::write(temp.join("readme.md"), "text").expect("file should be written");

        let mut errors = Vec::new();
        let files = discover(
            &[temp.join("readme.md"), temp.join("missing.rs")],
            &mut errors,
        );

        assert!(files.is_empty());
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("not a Rust source file"));
        assert!(errors[1].contains("failed to inspect"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_explicit_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new();
        let target = temp.join("target.rs");
        let link = temp.join("link.rs");
        fs::write(&target, "").expect("Rust file should be written");
        symlink(target, &link).expect("symlink should be created");

        let mut errors = Vec::new();
        let files = discover(std::slice::from_ref(&link), &mut errors);

        assert!(files.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("refusing to follow symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_ancestors_and_ignores_discovered_dangling_links() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new();
        let target = temp.join("target");
        let link = temp.join("alias");
        fs::create_dir(&target).expect("target directory should be created");
        fs::write(target.join("input.rs"), "").expect("Rust file should be written");
        symlink(&target, &link).expect("directory symlink should be created");
        symlink(temp.join("missing"), temp.join("dangling"))
            .expect("dangling symlink should be created");

        let mut errors = Vec::new();
        let files = discover(
            &[link.join("input.rs"), temp.0.path().to_owned()],
            &mut errors,
        );

        assert!(files.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("refusing to follow symlink in"));
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
        let root = temp.0.path().to_owned();
        let invalid = temp.join("a-invalid.rs");
        let valid = temp.join("b-valid.rs");
        fs::write(&invalid, "fn invalid(\n").expect("invalid source should be written");
        fs::write(&valid, unformatted()).expect("valid source should be written");

        let outcome = run_files(std::slice::from_ref(&root), false);

        assert_eq!(outcome.errors.len(), 1);
        assert!(outcome.errors[0].contains("a-invalid.rs"));
        assert_eq!(outcome.changed, vec![valid.clone()]);
        assert_ne!(
            fs::read_to_string(valid).expect("source should be read"),
            unformatted()
        );
    }
}
