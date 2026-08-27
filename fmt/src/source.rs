//! Checked conversion between source coordinates and byte ranges.

use proc_macro2::{LineColumn, Span};
use std::ops::Range;
use thiserror::Error;

/// An error produced while mapping source coordinates.
#[derive(Debug, Error)]
pub enum Error {
    /// A coordinate used line zero or a line beyond the source.
    #[error("line {line} is outside the source, which has {line_count} lines")]
    InvalidLine {
        /// Requested one-based line.
        line: usize,
        /// Number of addressable source lines.
        line_count: usize,
    },
    /// A character column extended beyond its source line.
    #[error("column {column} is outside line {line}, which has {column_count} characters")]
    InvalidColumn {
        /// Requested one-based line.
        line: usize,
        /// Requested zero-based character column.
        column: usize,
        /// Number of characters on the line.
        column_count: usize,
    },
    /// A range ended before it started.
    #[error("source range starts at byte {start} but ends at byte {end}")]
    ReversedRange {
        /// Start byte.
        start: usize,
        /// End byte.
        end: usize,
    },
    /// A range extended beyond the source.
    #[error("source range {start}..{end} exceeds source length {source_len}")]
    OutOfBounds {
        /// Start byte.
        start: usize,
        /// End byte.
        end: usize,
        /// Source length in bytes.
        source_len: usize,
    },
    /// A range endpoint split a UTF-8 code point.
    #[error("byte {offset} is not a UTF-8 character boundary")]
    InvalidBoundary {
        /// Invalid byte offset.
        offset: usize,
    },
}

/// A checked line and column index over a UTF-8 source string.
pub struct SourceMap<'a> {
    source: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> SourceMap<'a> {
    /// Builds an index over `source`.
    pub fn new(source: &'a str) -> Self {
        let mut line_starts = Vec::with_capacity(source.lines().count().saturating_add(1));
        line_starts.push(0);
        line_starts.extend(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );
        Self {
            source,
            line_starts,
        }
    }

    /// Converts a one-based line and character column to a byte offset.
    pub fn byte_offset(&self, location: LineColumn) -> Result<usize, Error> {
        let Some(index) = location.line.checked_sub(1) else {
            return Err(Error::InvalidLine {
                line: location.line,
                line_count: self.line_starts.len(),
            });
        };
        let Some(&line_start) = self.line_starts.get(index) else {
            return Err(Error::InvalidLine {
                line: location.line,
                line_count: self.line_starts.len(),
            });
        };
        let mut line_end = self
            .line_starts
            .get(index + 1)
            .copied()
            .unwrap_or(self.source.len());
        if line_end > line_start && self.source.as_bytes().get(line_end - 1) == Some(&b'\n') {
            line_end -= 1;
            if line_end > line_start && self.source.as_bytes().get(line_end - 1) == Some(&b'\r') {
                line_end -= 1;
            }
        }

        let line = &self.source[line_start..line_end];
        let column_count = line.chars().count();
        if location.column > column_count {
            return Err(Error::InvalidColumn {
                line: location.line,
                column: location.column,
                column_count,
            });
        }
        if location.column == column_count {
            return Ok(line_end);
        }
        let byte = line
            .char_indices()
            .nth(location.column)
            .map(|(byte, _)| byte)
            .ok_or(Error::InvalidColumn {
                line: location.line,
                column: location.column,
                column_count,
            })?;
        Ok(line_start + byte)
    }

    /// Converts a span to a checked byte range in this source.
    pub fn span_range(&self, span: Span) -> Result<Range<usize>, Error> {
        let start = self.byte_offset(span.start())?;
        let end = self.byte_offset(span.end())?;
        self.validate_range(start..end)?;
        Ok(start..end)
    }

    /// Returns a checked source slice.
    pub fn slice(&self, range: Range<usize>) -> Result<&'a str, Error> {
        self.validate_range(range.clone())?;
        Ok(&self.source[range])
    }

    fn validate_range(&self, range: Range<usize>) -> Result<(), Error> {
        if range.start > range.end {
            return Err(Error::ReversedRange {
                start: range.start,
                end: range.end,
            });
        }
        if range.end > self.source.len() {
            return Err(Error::OutOfBounds {
                start: range.start,
                end: range.end,
                source_len: self.source.len(),
            });
        }
        for offset in [range.start, range.end] {
            if !self.source.is_char_boundary(offset) {
                return Err(Error::InvalidBoundary { offset });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::spanned::Spanned;

    #[test]
    fn maps_ascii_lines_and_eof() {
        let source = SourceMap::new("abc\ndef\n");

        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 3 })
                .expect("coordinate should map"),
            3
        );
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 2, column: 1 })
                .expect("coordinate should map"),
            5
        );
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 3, column: 0 })
                .expect("coordinate should map"),
            8
        );
    }

    #[test]
    fn maps_unicode_character_columns() {
        let source = SourceMap::new("aé中");

        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 1 })
                .expect("coordinate should map"),
            1
        );
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 2 })
                .expect("coordinate should map"),
            3
        );
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 3 })
                .expect("coordinate should map"),
            6
        );
    }

    #[test]
    fn excludes_crlf_from_character_columns() {
        let source = SourceMap::new("abc\r\ndef");

        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 3 })
                .expect("coordinate should map"),
            3
        );
        assert!(matches!(
            source.byte_offset(LineColumn { line: 1, column: 4 }),
            Err(Error::InvalidColumn { .. })
        ));
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 2, column: 0 })
                .expect("coordinate should map"),
            5
        );
    }

    #[test]
    fn rejects_invalid_coordinates_and_ranges() {
        let source = SourceMap::new("é");

        assert!(matches!(
            source.byte_offset(LineColumn { line: 0, column: 0 }),
            Err(Error::InvalidLine { .. })
        ));
        assert!(matches!(
            source.byte_offset(LineColumn { line: 1, column: 2 }),
            Err(Error::InvalidColumn { .. })
        ));
        let reversed_start = 2;
        let reversed_end = 1;
        assert!(matches!(
            source.slice(reversed_start..reversed_end),
            Err(Error::ReversedRange { .. })
        ));
        assert!(matches!(source.slice(0..3), Err(Error::OutOfBounds { .. })));
        assert!(matches!(
            source.slice(1..2),
            Err(Error::InvalidBoundary { .. })
        ));
    }

    #[test]
    fn maps_parsed_span() {
        let text = "value + 1";
        let expression: syn::Expr = syn::parse_str(text).expect("expression should parse");
        let source = SourceMap::new(text);
        let range = source
            .span_range(expression.span())
            .expect("expression span should map");

        assert_eq!(source.slice(range).expect("range should slice"), text);
    }

    #[test]
    fn maps_empty_source_origin() {
        let source = SourceMap::new("");
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 0 })
                .expect("origin should map"),
            0
        );
    }
}
