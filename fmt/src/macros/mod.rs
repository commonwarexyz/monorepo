//! Formatters for supported Commonware macro bodies.

mod nested;
mod select;

pub use select::{select, select_loop};
use syn::{MacroDelimiter, Path};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacroKind {
    Select,
    SelectLoop,
}

pub(crate) fn macro_kind(path: &Path, delimiter: &MacroDelimiter) -> Option<MacroKind> {
    if !matches!(delimiter, MacroDelimiter::Brace(_)) || path.leading_colon.is_some() {
        return None;
    }
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [name] if name == "select" => Some(MacroKind::Select),
        [name] if name == "select_loop" => Some(MacroKind::SelectLoop),
        [prefix, name] if prefix == "commonware_macros" && name == "select" => {
            Some(MacroKind::Select)
        }
        [prefix, name] if prefix == "commonware_macros" && name == "select_loop" => {
            Some(MacroKind::SelectLoop)
        }
        _ => None,
    }
}

/// Line ending emitted by a macro shell writer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LineEnding {
    /// Line feed.
    #[default]
    Lf,
    /// Carriage return followed by line feed.
    Crlf,
}

impl LineEnding {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::Crlf => "\r\n",
        }
    }
}

/// Placement options for a formatted macro body.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Options {
    /// Number of spaces before the containing macro invocation.
    pub indentation: usize,
    /// Line ending to emit.
    pub line_ending: LineEnding,
}

/// An error produced while formatting a supported macro body.
#[derive(Debug, Error)]
pub enum Error {
    /// The original macro body did not match its production grammar.
    #[error("failed to parse macro body: {0}")]
    Parse(#[source] syn::Error),
    /// The parsed macro body violated a shared semantic constraint.
    #[error("invalid macro body: {0}")]
    Validate(#[source] syn::Error),
    /// An embedded Rust fragment could not be formatted safely.
    #[error("failed to format embedded Rust: {0}")]
    Pretty(#[from] crate::pretty::Error),
    /// A parsed field could not be mapped back to its exact source text.
    #[error("failed to locate macro field source: {0}")]
    Source(#[from] crate::source::Error),
    /// The rendered body no longer matched the production grammar.
    #[error("formatted macro body did not parse: {0}")]
    Output(#[source] syn::Error),
    /// Nested supported macros exceeded the recursion bound.
    #[error("nested supported macros exceeded the recursion limit")]
    RecursionLimit,
    /// A nested marker could not be restored exactly once in source order.
    #[error("nested macro marker mismatch")]
    MarkerMismatch,
    /// A supported nested macro did not retain brace delimiters.
    #[error("nested supported macro did not have valid brace delimiters")]
    MarkerDelimiter,
}
