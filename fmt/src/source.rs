//! Checked conversion between source coordinates and byte ranges.
//!
//! `proc_macro2` spans use one-based lines and zero-based UTF-8 character
//! columns. This module maps those coordinates back to byte offsets while
//! accounting for a leading byte order mark, CRLF endings, and multibyte code
//! points.

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
///
/// Line terminators and a leading byte order mark are not addressable columns.
pub struct SourceMap<'a> {
    source: &'a str,
    lines: Vec<Line>,
}

/// Byte bounds and optional character-to-byte offsets for one logical line.
struct Line {
    start: usize,
    end: usize,
    non_ascii_columns: Option<Vec<usize>>,
}

impl Line {
    /// Returns the number of addressable UTF-8 character columns.
    fn column_count(&self) -> usize {
        self.non_ascii_columns
            .as_ref()
            .map_or(self.end - self.start, |columns| columns.len() - 1)
    }

    /// Converts a validated character column to an absolute byte offset.
    fn byte_offset(&self, column: usize) -> usize {
        self.start
            + self
                .non_ascii_columns
                .as_ref()
                .map_or(column, |columns| columns[column])
    }
}

impl<'a> SourceMap<'a> {
    /// Builds an index over `source`.
    ///
    /// Empty source still has an addressable origin at line 1, column 0.
    pub fn new(source: &'a str) -> Self {
        let mut line_starts = Vec::new();
        // proc_macro2 reports the first token after a UTF-8 byte order mark at
        // column zero, so the first logical line begins after the mark.
        line_starts.push(if source.starts_with('\u{feff}') { 3 } else { 0 });
        line_starts.extend(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );
        let lines = line_starts
            .iter()
            .enumerate()
            .map(|(index, &start)| {
                let mut end = line_starts.get(index + 1).copied().unwrap_or(source.len());
                // Span columns exclude both bytes of CRLF and the single byte
                // of LF, while the next logical line still starts after them.
                if end > start && source.as_bytes().get(end - 1) == Some(&b'\n') {
                    end -= 1;
                    if end > start && source.as_bytes().get(end - 1) == Some(&b'\r') {
                        end -= 1;
                    }
                }
                let text = &source[start..end];
                // ASCII columns equal byte offsets. Non-ASCII lines pay for an
                // index that maps proc_macro2 character columns exactly.
                let non_ascii_columns = (!text.is_ascii()).then(|| {
                    text.char_indices()
                        .map(|(offset, _)| offset)
                        .chain(std::iter::once(text.len()))
                        .collect()
                });
                Line {
                    start,
                    end,
                    non_ascii_columns,
                }
            })
            .collect();
        Self { source, lines }
    }

    /// Builds a line error using the map's addressable line count.
    const fn invalid_line(&self, line: usize) -> Error {
        Error::InvalidLine {
            line,
            line_count: self.lines.len(),
        }
    }

    /// Converts a one-based line and zero-based character column to a byte offset.
    pub fn byte_offset(&self, location: LineColumn) -> Result<usize, Error> {
        let Some(index) = location.line.checked_sub(1) else {
            return Err(self.invalid_line(location.line));
        };
        let Some(line) = self.lines.get(index) else {
            return Err(self.invalid_line(location.line));
        };
        let column_count = line.column_count();
        if location.column > column_count {
            return Err(Error::InvalidColumn {
                line: location.line,
                column: location.column,
                column_count,
            });
        }
        Ok(line.byte_offset(location.column))
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

    /// Validates ordering, bounds, and UTF-8 boundaries for a byte range.
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
    fn maps_first_line_after_a_byte_order_mark() {
        let source = SourceMap::new("\u{feff}abc\ndef");

        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 0 })
                .expect("coordinate should map"),
            3
        );
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 1, column: 3 })
                .expect("coordinate should map"),
            6
        );
        assert_eq!(
            source
                .byte_offset(LineColumn { line: 2, column: 0 })
                .expect("coordinate should map"),
            7
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
