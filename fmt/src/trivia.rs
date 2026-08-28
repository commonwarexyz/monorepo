//! Conservative recovery of comments owned by custom macro shells.
//!
//! Shell formatters may relocate whitespace and plain `//` comments between parsed
//! entries. Any token or comment with a different form rejects recovery so the
//! caller can preserve the original shell.

use std::ops::Range;

/// An ordinary line comment recovered from a macro shell boundary.
pub(crate) struct ShellComment {
    /// The complete comment text without its line ending.
    pub(crate) text: String,
    /// Whether non-whitespace source precedes the comment on its physical line.
    pub(crate) trailing: bool,
}

/// Extracts whitespace-separated ordinary line comments from `range`.
///
/// Returns `None` when the range contains a token, block comment, or doc comment.
/// Callers use that result to fall back to preserving the surrounding source.
/// The range must be within `source` and its endpoints must be UTF-8 boundaries.
pub(crate) fn shell_comments(source: &str, range: Range<usize>) -> Option<Vec<ShellComment>> {
    let mut comments = Vec::new();
    let mut offset = range.start;
    while offset < range.end {
        let remaining = &source[offset..range.end];
        let character = remaining.chars().next()?;
        if character.is_whitespace() {
            offset += character.len_utf8();
            continue;
        }
        if !remaining.starts_with("//")
            || remaining.starts_with("///")
            || remaining.starts_with("//!")
        {
            // Doc-style prefixes may carry syntax-level ownership and cannot be
            // safely moved as shell trivia.
            return None;
        }

        let comment_start = offset;
        let newline = source[comment_start..range.end]
            .find('\n')
            .map(|relative| comment_start + relative)
            .unwrap_or(range.end);
        // Keep the logical comment independent of the source's line-ending style.
        let comment_end =
            if newline > comment_start && source.as_bytes().get(newline - 1) == Some(&b'\r') {
                newline - 1
            } else {
                newline
            };
        let line_start = source[..comment_start]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        comments.push(ShellComment {
            text: source[comment_start..comment_end].to_owned(),
            // Inspect the complete physical line because the boundary often starts
            // immediately after the branch token that owns a trailing comment.
            trailing: source[line_start..comment_start]
                .chars()
                .any(|character| !character.is_whitespace()),
        });
        offset = newline.saturating_add(usize::from(newline < range.end));
    }
    Some(comments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_structural_and_trailing_comments() {
        let structural = "\n// first\n";
        let comments = shell_comments(structural, 0..structural.len())
            .expect("structural comment should parse");
        assert_eq!(comments.len(), 1);
        assert!(!comments[0].trailing);

        let trailing = "value, // second\n";
        let comments = shell_comments(trailing, "value,".len()..trailing.len())
            .expect("trailing comment should parse");
        assert_eq!(comments.len(), 1);
        assert!(comments[0].trailing);
    }

    #[test]
    fn rejects_non_comment_shell_tokens() {
        assert!(shell_comments("value", 0..5).is_none());
        assert!(shell_comments("/// docs", 0..8).is_none());
    }
}
