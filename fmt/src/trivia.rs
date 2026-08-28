//! Conservative recovery of comments owned by custom macro shells.

use std::ops::Range;

pub(crate) struct ShellComment {
    pub(crate) text: String,
    pub(crate) trailing: bool,
}

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
            return None;
        }

        let comment_start = offset;
        let newline = source[comment_start..range.end]
            .find('\n')
            .map(|relative| comment_start + relative)
            .unwrap_or(range.end);
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
