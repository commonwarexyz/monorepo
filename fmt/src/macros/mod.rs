//! Formatters for supported Commonware macro bodies.

mod select;

pub use select::{select, select_loop};
use thiserror::Error;

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
}
