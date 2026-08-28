//! Stock rustfmt adapter for ordinary Rust fragments.

use crate::pretty::{MultilineLiterals, ProtectedFragment};
use std::{
    ffi::OsString,
    io::Write as _,
    path::PathBuf,
    process::{Command, Stdio},
};
use thiserror::Error;

const INDENT: usize = 4;

/// Configuration for the rustfmt subprocess used to format fragments.
#[derive(Clone, Debug)]
pub struct Formatter {
    program: OsString,
    toolchain: Option<OsString>,
    edition: String,
    config_path: Option<PathBuf>,
}

impl Default for Formatter {
    fn default() -> Self {
        Self {
            program: OsString::from("rustfmt"),
            toolchain: None,
            edition: String::from("2024"),
            config_path: None,
        }
    }
}

impl Formatter {
    /// Creates a formatter that invokes `program`.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            ..Self::default()
        }
    }

    /// Selects a rustup-style toolchain argument such as `+nightly`.
    pub fn with_toolchain(mut self, toolchain: impl Into<OsString>) -> Self {
        self.toolchain = Some(toolchain.into());
        self
    }

    /// Selects the Rust edition used for synthetic wrappers.
    pub fn with_edition(mut self, edition: impl Into<String>) -> Self {
        self.edition = edition.into();
        self
    }

    /// Selects the path from which rustfmt resolves its configuration.
    pub fn with_config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_path = Some(path.into());
        self
    }

    pub(crate) fn items(
        &self,
        source: &str,
        indentation: usize,
    ) -> Result<ProtectedFragment, Error> {
        self.format_protected(source, indentation, WrapperKind::Items)
    }

    pub(crate) fn statements(
        &self,
        source: &str,
        indentation: usize,
    ) -> Result<ProtectedFragment, Error> {
        self.format_protected(source, indentation, WrapperKind::Statements)
    }

    fn format_protected(
        &self,
        source: &str,
        indentation: usize,
        kind: WrapperKind,
    ) -> Result<ProtectedFragment, Error> {
        let source = normalize_source(source);
        if let Some(literals) = MultilineLiterals::prepare(&source) {
            let formatted = self.format_raw(literals.text(), indentation, kind)?;
            return literals
                .restore(ProtectedFragment::formatted(formatted))
                .ok_or(Error::LiteralRestoration);
        }
        self.format_raw(&source, indentation, kind)
            .map(ProtectedFragment::formatted)
    }

    fn format_raw(
        &self,
        source: &str,
        indentation: usize,
        kind: WrapperKind,
    ) -> Result<String, Error> {
        if !indentation.is_multiple_of(INDENT)
            || (kind == WrapperKind::Statements && indentation < INDENT)
        {
            return Err(Error::UnsupportedIndentation(indentation));
        }
        let prefix = crate::marker::unique_prefix(source, "rustfmt");
        let start = format!("{prefix}start");
        let end = format!("{prefix}end");
        let wrapper = wrapper(source, indentation, kind, &prefix, &start, &end);
        let formatted = self.run(&wrapper)?;
        extract(&formatted, indentation, &start, &end)
    }

    fn run(&self, source: &str) -> Result<String, Error> {
        let mut command = Command::new(&self.program);
        if let Some(toolchain) = &self.toolchain {
            command.arg(toolchain);
        }
        command
            .args(["--quiet", "--emit", "stdout", "--edition"])
            .arg(&self.edition);
        if let Some(path) = &self.config_path {
            command.arg("--config-path").arg(path);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| Error::Spawn {
                program: self.program.clone(),
                source,
            })?;
        child
            .stdin
            .take()
            .ok_or(Error::Stdin)?
            .write_all(source.as_bytes())
            .map_err(Error::Write)?;
        let output = child.wait_with_output().map_err(Error::Wait)?;
        let stderr = String::from_utf8(output.stderr).map_err(Error::StderrUtf8)?;
        if !output.status.success() {
            return Err(Error::Exit {
                code: output.status.code(),
                stderr,
            });
        }
        if !stderr.is_empty() {
            return Err(Error::Warning(stderr));
        }
        String::from_utf8(output.stdout).map_err(Error::StdoutUtf8)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WrapperKind {
    Items,
    Statements,
}

fn wrapper(
    source: &str,
    indentation: usize,
    kind: WrapperKind,
    prefix: &str,
    start: &str,
    end: &str,
) -> String {
    let module_depth = match kind {
        WrapperKind::Items => indentation / INDENT,
        WrapperKind::Statements => indentation / INDENT - 1,
    };
    let mut output = String::new();
    for depth in 0..module_depth {
        output.push_str("mod ");
        output.push_str(prefix);
        output.push_str("module_");
        output.push_str(&depth.to_string());
        output.push_str(" {\n");
    }
    if kind == WrapperKind::Statements {
        output.push_str("fn ");
        output.push_str(prefix);
        output.push_str("function() {\n");
    }
    output.push_str("// ");
    output.push_str(start);
    output.push('\n');
    let source = indent_source(source, indentation);
    output.push_str(&source);
    if !source.ends_with('\n') {
        output.push('\n');
    }
    output.push_str("// ");
    output.push_str(end);
    output.push('\n');
    if kind == WrapperKind::Statements {
        output.push_str("}\n");
    }
    for _ in 0..module_depth {
        output.push_str("}\n");
    }
    output
}

fn normalize_source(source: &str) -> String {
    let source = source.trim_matches(['\n', '\r']);
    let indentation = source
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| {
            let bytes = line.as_bytes();
            &line[..bytes
                .iter()
                .take_while(|byte| matches!(byte, b' ' | b'\t'))
                .count()]
        })
        .unwrap_or("");
    let mut output = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        let content = if line.trim().is_empty() {
            line
        } else {
            line.strip_prefix(indentation).unwrap_or(line)
        };
        output.push_str(content);
    }
    output
}

fn indent_source(source: &str, indentation: usize) -> String {
    let prefix = " ".repeat(indentation);
    let mut output = String::with_capacity(source.len() + prefix.len());
    for (index, line) in source.split_inclusive('\n').enumerate() {
        if index != 0 || !line.is_empty() {
            output.push_str(&prefix);
        }
        output.push_str(line);
    }
    output
}

fn extract(formatted: &str, indentation: usize, start: &str, end: &str) -> Result<String, Error> {
    let start_offset = unique_offset(formatted, start)?;
    let end_offset = unique_offset(formatted, end)?;
    if start_offset >= end_offset {
        return Err(Error::MarkerMismatch);
    }
    let start_line = line_range(formatted, start_offset);
    let end_line = line_range(formatted, end_offset);
    let start_text = formatted
        .get(start_line.clone())
        .ok_or(Error::MarkerMismatch)?;
    let end_text = formatted
        .get(end_line.clone())
        .ok_or(Error::MarkerMismatch)?;
    let start_prefix = start_text
        .split_once("//")
        .map(|(prefix, _)| prefix)
        .ok_or(Error::MarkerMismatch)?;
    let end_prefix = end_text
        .split_once("//")
        .map(|(prefix, _)| prefix)
        .ok_or(Error::MarkerMismatch)?;
    if start_prefix != end_prefix || visual_width(start_prefix) != indentation {
        return Err(Error::UnexpectedIndentation);
    }
    let body_start = start_line.end;
    let body_end = end_line.start;
    let body = formatted
        .get(body_start..body_end)
        .ok_or(Error::MarkerMismatch)?;
    dedent(body, start_prefix)
}

fn unique_offset(source: &str, marker: &str) -> Result<usize, Error> {
    let mut offsets = source.match_indices(marker).map(|(offset, _)| offset);
    let offset = offsets.next().ok_or(Error::MarkerMismatch)?;
    if offsets.next().is_some() {
        return Err(Error::MarkerMismatch);
    }
    Ok(offset)
}

fn line_range(source: &str, offset: usize) -> std::ops::Range<usize> {
    let start = source[..offset]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let end = source[offset..]
        .find('\n')
        .map_or(source.len(), |newline| offset + newline + 1);
    start..end
}

fn visual_width(source: &str) -> usize {
    source.bytes().fold(0, |column, byte| match byte {
        b'\t' => (column / INDENT + 1) * INDENT,
        _ => column + 1,
    })
}

fn dedent(source: &str, prefix: &str) -> Result<String, Error> {
    let mut output = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        if content.trim().is_empty() {
            output.push('\n');
            continue;
        }
        let content = content
            .strip_prefix(prefix)
            .ok_or(Error::UnexpectedIndentation)?;
        output.push_str(content);
        if line.ends_with('\n') {
            output.push('\n');
        }
    }
    if output.ends_with('\n') {
        output.pop();
    }
    Ok(output)
}

/// An error produced while formatting a Rust fragment with rustfmt.
#[derive(Debug, Error)]
pub enum Error {
    /// The rustfmt process could not be started.
    #[error("failed to start `{}`: {source}", program.to_string_lossy())]
    Spawn {
        program: OsString,
        #[source]
        source: std::io::Error,
    },
    /// The rustfmt process did not expose its configured standard input.
    #[error("rustfmt standard input was unavailable")]
    Stdin,
    /// A synthetic wrapper could not be written to rustfmt.
    #[error("failed to write rustfmt input: {0}")]
    Write(#[source] std::io::Error),
    /// The rustfmt process could not be awaited.
    #[error("failed to wait for rustfmt: {0}")]
    Wait(#[source] std::io::Error),
    /// Rustfmt rejected a synthetic wrapper.
    #[error("rustfmt exited with code {code:?}: {stderr}")]
    Exit { code: Option<i32>, stderr: String },
    /// Rustfmt wrote a warning while formatting a synthetic wrapper.
    #[error("rustfmt emitted a warning: {0}")]
    Warning(String),
    /// Rustfmt standard output was not UTF-8.
    #[error("rustfmt output was not UTF-8: {0}")]
    StdoutUtf8(#[source] std::string::FromUtf8Error),
    /// Rustfmt standard error was not UTF-8.
    #[error("rustfmt diagnostics were not UTF-8: {0}")]
    StderrUtf8(#[source] std::string::FromUtf8Error),
    /// The requested fragment indentation could not be represented safely.
    #[error("unsupported fragment indentation {0}")]
    UnsupportedIndentation(usize),
    /// Rustfmt moved or duplicated a synthetic wrapper marker.
    #[error("rustfmt wrapper marker mismatch")]
    MarkerMismatch,
    /// Rustfmt did not retain the requested destination indentation.
    #[error("rustfmt wrapper had unexpected destination indentation")]
    UnexpectedIndentation,
    /// A protected multiline literal could not be restored exactly.
    #[error("failed to restore protected multiline literal")]
    LiteralRestoration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_items_at_the_requested_indentation() {
        let source = "/// Keep docs.\npub struct Example { pub value: usize }\n\n// Keep separation.\nimpl Example { pub fn value(&self)->usize{self.value} }";
        let formatted = Formatter::default().items(source, 12).unwrap();

        assert!(formatted.text().contains("/// Keep docs."));
        assert!(formatted.text().contains("\n\n// Keep separation.\n"));
        assert!(formatted.text().contains("pub value: usize,"));
    }

    #[test]
    fn formats_statements_at_the_requested_indentation() {
        let source = "first();\n\n// Keep phase.\nsecond(1,2);\nvalue";
        let formatted = Formatter::default().statements(source, 8).unwrap();

        assert_eq!(
            formatted.text(),
            "first();\n\n// Keep phase.\nsecond(1, 2);\nvalue"
        );
    }

    #[test]
    fn destination_indentation_changes_width_decisions() {
        let source = "let value = build_something(first_argument, second_argument, third_argument, fourth_arg);";
        let shallow = Formatter::default().statements(source, 4).unwrap();
        let deep = Formatter::default().statements(source, 12).unwrap();

        assert_eq!(shallow.text(), source);
        assert_eq!(
            deep.text(),
            "let value =\n    build_something(first_argument, second_argument, third_argument, fourth_arg);"
        );
    }

    #[test]
    fn preserves_multiline_literal_bytes() {
        let source = "let value = r#\"first\n  second\"#;\nvalue";
        let formatted = Formatter::default().statements(source, 8).unwrap();

        assert!(formatted.text().contains("r#\"first\n  second\"#"));
    }

    #[test]
    fn rejects_unrepresentable_indentation() {
        let Err(error) = Formatter::default().items("struct Example;", 6) else {
            panic!("indentation should be rejected");
        };

        assert!(matches!(error, Error::UnsupportedIndentation(6)));
    }
}
