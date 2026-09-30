//! Source files and spans (DESIGN.md §10.4).
//!
//! Every diagnostic and every HIR node carries a [`Span`]:
//! `Span { file: FileId, lo: (line, col), hi: (line, col) }` where `line` is
//! **1-based** and `col` is the **0-based** character column (the
//! `proc_macro2::LineColumn` convention). Rendering prints `col + 1`.
//!
//! The [`SourceMap`] owns the text of every file the loader read, so
//! diagnostics can print source snippets and the build driver can print
//! `cargo::rerun-if-changed` lines for every file read.
//!
//! Spans are produced from `syn`/`proc_macro2` spans: each file is parsed with
//! its own `syn::parse_file` call, so `proc_macro2::Span::start()` yields
//! positions relative to that file. [`Span::from_pm2`] attaches the file id.

use std::path::{Path, PathBuf};

/// Index of a file in the [`SourceMap`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Default)]
pub struct FileId(pub u32);

/// A source range. `lo`/`hi` are `(line, col)` with 1-based lines and 0-based
/// character columns; `hi` is exclusive. A span with `line == 0` is a dummy
/// span (generated code without a source position).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Span {
    pub file: FileId,
    pub lo: (u32, u32),
    pub hi: (u32, u32),
}

impl Span {
    /// A span without a source position.
    pub const DUMMY: Span = Span { file: FileId(0), lo: (0, 0), hi: (0, 0) };

    /// Converts a `proc_macro2` span of a token parsed from `file`.
    pub fn from_pm2(file: FileId, s: proc_macro2::Span) -> Span {
        let a = s.start();
        let b = s.end();
        Span { file, lo: (a.line as u32, a.column as u32), hi: (b.line as u32, b.column as u32) }
    }

    /// Whether this is [`Span::DUMMY`]-like (no position).
    pub fn is_dummy(&self) -> bool {
        self.lo.0 == 0
    }

    /// The smallest span covering both (same file assumed; `self` wins otherwise).
    pub fn to(self, other: Span) -> Span {
        if self.is_dummy() {
            return other;
        }
        if other.is_dummy() || other.file != self.file {
            return self;
        }
        Span { file: self.file, lo: self.lo.min(other.lo), hi: self.hi.max(other.hi) }
    }
}

/// One loaded source file.
#[derive(Clone, Debug)]
pub struct SourceFile {
    /// Path as given to the loader (absolute for real files, virtual otherwise).
    pub path: PathBuf,
    /// Full text.
    pub text: String,
    /// Byte offsets of line starts.
    line_starts: Vec<usize>,
}

impl SourceFile {
    fn new(path: PathBuf, text: String) -> SourceFile {
        let mut line_starts = vec![0];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        SourceFile { path, text, line_starts }
    }

    /// Text of 1-based line `line` (without the newline), if it exists.
    pub fn line(&self, line: u32) -> Option<&str> {
        let i = (line as usize).checked_sub(1)?;
        let start = *self.line_starts.get(i)?;
        let end = self.line_starts.get(i + 1).copied().unwrap_or(self.text.len());
        Some(self.text[start..end].trim_end_matches(['\n', '\r']))
    }

    /// Source text covered by a span of this file (best effort).
    pub fn snippet(&self, span: Span) -> Option<String> {
        if span.is_dummy() {
            return None;
        }
        let byte = |(line, col): (u32, u32)| -> Option<usize> {
            let l = self.line(line)?;
            let start = self.line_starts[(line - 1) as usize];
            let off: usize = l.chars().take(col as usize).map(char::len_utf8).sum();
            Some(start + off)
        };
        let a = byte(span.lo)?;
        let b = byte(span.hi)?;
        (a <= b).then(|| self.text[a..b].to_string())
    }
}

/// All files read by one front-end run.
#[derive(Clone, Debug, Default)]
pub struct SourceMap {
    files: Vec<SourceFile>,
}

impl SourceMap {
    pub fn new() -> SourceMap {
        SourceMap::default()
    }

    /// Adds a file and returns its id.
    pub fn add(&mut self, path: PathBuf, text: String) -> FileId {
        let id = FileId(self.files.len() as u32);
        self.files.push(SourceFile::new(path, text));
        id
    }

    pub fn get(&self, id: FileId) -> Option<&SourceFile> {
        self.files.get(id.0 as usize)
    }

    pub fn path(&self, id: FileId) -> &Path {
        self.get(id).map(|f| f.path.as_path()).unwrap_or(Path::new("<unknown>"))
    }

    /// Every file, in load order.
    pub fn files(&self) -> impl Iterator<Item = (FileId, &SourceFile)> {
        self.files.iter().enumerate().map(|(i, f)| (FileId(i as u32), f))
    }

    /// Source text of a span (best effort).
    pub fn snippet(&self, span: Span) -> Option<String> {
        self.get(span.file)?.snippet(span)
    }
}
