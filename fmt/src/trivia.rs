//! Conservative token-anchored recovery of ordinary line comments.

use crate::source::SourceMap;
use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::ops::Range;

const MAX_OPTIONAL_ALIGNMENT_CELLS: usize = 16_384;

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKey {
    Open(char),
    Close(char),
    Ident(String),
    Punct(char),
    Literal(String),
    Doc(String),
}

#[derive(Clone)]
struct Token {
    key: TokenKey,
    range: Range<usize>,
    line_leading: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Comment {
    text: String,
    trailing: bool,
    left: Option<usize>,
    right: Option<usize>,
}

pub(crate) struct LineComments {
    tokens: Vec<Token>,
    comments: Vec<Comment>,
    allow_source_docs: bool,
}

pub(crate) struct ShellComment {
    pub(crate) text: String,
    pub(crate) trailing: bool,
}

pub(crate) fn shell_comments(source: &str, range: Range<usize>) -> Option<Vec<ShellComment>> {
    let mut comments = Vec::new();
    parse_gap(source, range, None, None, false, &mut comments)?;
    Some(
        comments
            .into_iter()
            .map(|comment| ShellComment {
                text: comment.text,
                trailing: comment.trailing,
            })
            .collect(),
    )
}

impl LineComments {
    pub(crate) fn prepare(source: &str) -> Option<Self> {
        Self::prepare_with_policy(source, false)
    }

    pub(crate) fn prepare_allowing_docs(source: &str) -> Option<Self> {
        Self::prepare_with_policy(source, true)
    }

    fn prepare_with_policy(source: &str, allow_source_docs: bool) -> Option<Self> {
        let stream = source.parse::<TokenStream>().ok()?;
        let source_map = SourceMap::new(source);
        let mut tokens = Vec::new();
        let mut literal_ranges = Vec::new();
        flatten(
            stream,
            source,
            &source_map,
            &mut tokens,
            &mut literal_ranges,
        )?;
        let doc_ranges = source_doc_ranges(source, &literal_ranges);
        if allow_source_docs {
            tokens.retain(|token| {
                matches!(token.key, TokenKey::Doc(_))
                    || !doc_ranges
                        .iter()
                        .any(|doc| token.range.start < doc.end && doc.start < token.range.end)
            });
        }
        if literal_ranges.iter().any(|range| {
            if allow_source_docs && doc_ranges.contains(range) {
                return false;
            }
            source_map
                .slice(range.clone())
                .is_ok_and(|literal| literal.contains('\n') || literal.contains('\r'))
        }) || (!allow_source_docs && has_source_spelled_doc_comment(source, &literal_ranges))
        {
            return None;
        }
        if tokens
            .windows(2)
            .any(|pair| pair[0].range.end > pair[1].range.start)
        {
            return None;
        }

        let mut comments = Vec::new();
        let mut cursor = 0;
        for (right, token) in tokens.iter().enumerate() {
            parse_gap(
                source,
                cursor..token.range.start,
                right.checked_sub(1),
                Some(right),
                allow_source_docs,
                &mut comments,
            )?;
            cursor = token.range.end;
        }
        parse_gap(
            source,
            cursor..source.len(),
            tokens.len().checked_sub(1),
            None,
            allow_source_docs,
            &mut comments,
        )?;
        if comments.is_empty() {
            return None;
        }
        Some(Self {
            tokens,
            comments,
            allow_source_docs,
        })
    }

    pub(crate) fn restore(&self, formatted: &str) -> Option<String> {
        let formatted_plan = token_plan(formatted, self.allow_source_docs)?;
        let mapping = token_mapping(&self.tokens, &formatted_plan)?;
        let mut replacements = Vec::new();
        let mut expected_comments = Vec::with_capacity(self.comments.len());
        let mut index = 0;
        while index < self.comments.len() {
            let left = self.comments[index].left;
            let right = self.comments[index].right;
            let start = index;
            while index < self.comments.len()
                && self.comments[index].left == left
                && self.comments[index].right == right
            {
                index += 1;
            }

            let mapped_left = nearest_mapped_left(&mapping, left);
            let mapped_right = nearest_mapped_right(&mapping, right);
            if mapped_left
                .zip(mapped_right)
                .is_some_and(|(left, right)| left >= right)
            {
                return None;
            }
            let insertion_left = mapped_right.map_or_else(
                || formatted_plan.len().checked_sub(1),
                |right| right.checked_sub(1),
            );
            if mapped_left
                .zip(insertion_left)
                .is_some_and(|(left, insertion)| left > insertion)
            {
                return None;
            }
            let range = insertion_left.map_or(0, |left| formatted_plan[left].range.end)
                ..mapped_right.map_or(formatted.len(), |right| formatted_plan[right].range.start);
            let comments = &self.comments[start..index];
            let replacement = render_gap(
                formatted,
                &formatted_plan,
                insertion_left,
                mapped_right,
                comments,
            )?;
            replacements.push((range, replacement));
            expected_comments.extend(comments.iter().map(|comment| Comment {
                text: comment.text.clone(),
                trailing: comment.trailing,
                left: insertion_left,
                right: mapped_right,
            }));
        }
        if replacements
            .windows(2)
            .any(|pair| pair[0].0.end > pair[1].0.start)
        {
            return None;
        }

        let mut output = formatted.to_owned();
        for (range, replacement) in replacements.into_iter().rev() {
            output.replace_range(range, &replacement);
        }
        let mut restored = Self::prepare_with_policy(&output, self.allow_source_docs)?;
        let restored_mapping = token_mapping(&self.tokens, &restored.tokens)?;
        let required_closes = line_leading_comment_closes(&self.tokens, &self.comments)?;
        restore_line_leading_closing_delimiters(
            &mut output,
            &restored.tokens,
            &restored_mapping,
            &required_closes,
        )?;
        restored = Self::prepare_with_policy(&output, self.allow_source_docs)?;
        let restored_mapping = token_mapping(&self.tokens, &restored.tokens)?;
        if restored.comments != expected_comments
            || restored
                .tokens
                .iter()
                .map(|token| &token.key)
                .ne(formatted_plan.iter().map(|token| &token.key))
            || !preserves_line_leading_closing_delimiters(
                &restored.tokens,
                &restored_mapping,
                &required_closes,
            )
        {
            return None;
        }
        Some(output)
    }
}

fn token_plan(source: &str, allow_source_docs: bool) -> Option<Vec<Token>> {
    let stream = source.parse::<TokenStream>().ok()?;
    let source_map = SourceMap::new(source);
    let mut tokens = Vec::new();
    let mut literal_ranges = Vec::new();
    flatten(
        stream,
        source,
        &source_map,
        &mut tokens,
        &mut literal_ranges,
    )?;
    if allow_source_docs {
        let doc_ranges = source_doc_ranges(source, &literal_ranges);
        tokens.retain(|token| {
            matches!(token.key, TokenKey::Doc(_))
                || !doc_ranges
                    .iter()
                    .any(|doc| token.range.start < doc.end && doc.start < token.range.end)
        });
    }
    Some(tokens)
}

fn flatten(
    stream: TokenStream,
    source_text: &str,
    source: &SourceMap<'_>,
    tokens: &mut Vec<Token>,
    literal_ranges: &mut Vec<Range<usize>>,
) -> Option<()> {
    for token in stream {
        match token {
            TokenTree::Group(group) => {
                if group.delimiter() == Delimiter::None {
                    flatten(group.stream(), source_text, source, tokens, literal_ranges)?;
                    continue;
                }
                let (open, close) = delimiter_keys(group.delimiter())?;
                let open_range = source.span_range(group.span_open()).ok()?;
                tokens.push(Token {
                    key: TokenKey::Open(open),
                    line_leading: line_leading_whitespace(source_text, open_range.start).is_some(),
                    range: open_range,
                });
                flatten(group.stream(), source_text, source, tokens, literal_ranges)?;
                let close_range = source.span_range(group.span_close()).ok()?;
                tokens.push(Token {
                    key: TokenKey::Close(close),
                    line_leading: line_leading_whitespace(source_text, close_range.start).is_some(),
                    range: close_range,
                });
            }
            TokenTree::Ident(ident) => {
                let range = source.span_range(ident.span()).ok()?;
                tokens.push(Token {
                    key: TokenKey::Ident(ident.to_string()),
                    line_leading: line_leading_whitespace(source_text, range.start).is_some(),
                    range,
                });
            }
            TokenTree::Punct(punct) => {
                let range = source.span_range(punct.span()).ok()?;
                tokens.push(Token {
                    key: TokenKey::Punct(punct.as_char()),
                    line_leading: line_leading_whitespace(source_text, range.start).is_some(),
                    range,
                });
            }
            TokenTree::Literal(literal) => {
                let range = source.span_range(literal.span()).ok()?;
                let text = source.slice(range.clone()).ok()?;
                tokens.push(Token {
                    key: if text.starts_with("///")
                        || text.starts_with("//!")
                        || text.starts_with("/**")
                        || text.starts_with("/*!")
                    {
                        TokenKey::Doc(literal.to_string())
                    } else {
                        TokenKey::Literal(text.to_owned())
                    },
                    line_leading: line_leading_whitespace(source_text, range.start).is_some(),
                    range: range.clone(),
                });
                literal_ranges.push(range);
            }
        }
    }
    Some(())
}

fn preserves_line_leading_closing_delimiters(
    restored: &[Token],
    mapping: &[Option<usize>],
    required: &[bool],
) -> bool {
    required.iter().enumerate().all(|(index, required)| {
        !required || mapping[index].is_some_and(|mapped| restored[mapped].line_leading)
    })
}

fn line_leading_comment_closes(tokens: &[Token], comments: &[Comment]) -> Option<Vec<bool>> {
    let opening = matching_opening_indices(tokens)?;
    let mut closing = vec![None; tokens.len()];
    for (close, open) in opening.iter().enumerate() {
        if let Some(open) = open {
            closing[*open] = Some(close);
        }
    }
    let mut comment_positions = comments
        .iter()
        .map(|comment| comment.right.unwrap_or(tokens.len()))
        .collect::<Vec<_>>();
    comment_positions.sort_unstable();

    let mut required = vec![false; tokens.len()];
    let mut stack = Vec::new();
    let mut comment_index = 0;
    for (boundary, token) in tokens.iter().enumerate() {
        while comment_positions.get(comment_index) == Some(&boundary) {
            if let Some((_, Some(close))) = stack.last() {
                required[*close] = true;
            }
            comment_index += 1;
        }
        match token.key {
            TokenKey::Open(_) => {
                let close = closing[boundary]?;
                let nearest = if tokens[close].line_leading {
                    Some(close)
                } else {
                    stack.last().and_then(|(_, nearest)| *nearest)
                };
                stack.push((close, nearest));
            }
            TokenKey::Close(_) => {
                if stack.pop().is_none_or(|(close, _)| close != boundary) {
                    return None;
                }
            }
            TokenKey::Ident(_) | TokenKey::Punct(_) | TokenKey::Literal(_) | TokenKey::Doc(_) => {}
        }
    }
    while comment_positions.get(comment_index) == Some(&tokens.len()) {
        if let Some((_, Some(close))) = stack.last() {
            required[*close] = true;
        }
        comment_index += 1;
    }
    if comment_index != comment_positions.len() || !stack.is_empty() {
        return None;
    }
    Some(required)
}

fn restore_line_leading_closing_delimiters(
    source: &mut String,
    restored: &[Token],
    mapping: &[Option<usize>],
    required: &[bool],
) -> Option<()> {
    let opening = matching_opening_indices(restored)?;
    let mut replacements = Vec::new();
    for (index, required) in required.iter().enumerate() {
        if !required {
            continue;
        }
        let restored_index = mapping[index]?;
        if restored[restored_index].line_leading {
            continue;
        }
        let open_index = opening[restored_index]?;
        let indentation = line_indentation(source, restored[open_index].range.start).to_owned();
        let close_start = restored[restored_index].range.start;
        let whitespace_start = source[..close_start]
            .char_indices()
            .rev()
            .take_while(|(_, character)| matches!(character, ' ' | '\t'))
            .last()
            .map_or(close_start, |(offset, _)| offset);
        replacements.push((whitespace_start..close_start, format!("\n{indentation}")));
    }
    for (range, replacement) in replacements.into_iter().rev() {
        source.replace_range(range, &replacement);
    }
    Some(())
}

fn matching_opening_indices(tokens: &[Token]) -> Option<Vec<Option<usize>>> {
    let mut opening = Vec::new();
    let mut stack = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token.key {
            TokenKey::Open(delimiter) => stack.push((delimiter, index)),
            TokenKey::Close(delimiter) => {
                let (open, open_index) = stack.pop()?;
                if !delimiters_match(open, delimiter) {
                    return None;
                }
                opening.resize(index + 1, None);
                opening[index] = Some(open_index);
            }
            TokenKey::Ident(_) | TokenKey::Punct(_) | TokenKey::Literal(_) | TokenKey::Doc(_) => {}
        }
    }
    if !stack.is_empty() {
        return None;
    }
    opening.resize(tokens.len(), None);
    Some(opening)
}

const fn delimiter_keys(delimiter: Delimiter) -> Option<(char, char)> {
    match delimiter {
        Delimiter::Parenthesis => Some(('(', ')')),
        Delimiter::Brace => Some(('{', '}')),
        Delimiter::Bracket => Some(('[', ']')),
        Delimiter::None => None,
    }
}

fn parse_gap(
    source: &str,
    range: Range<usize>,
    left: Option<usize>,
    right: Option<usize>,
    allow_source_docs: bool,
    comments: &mut Vec<Comment>,
) -> Option<()> {
    let mut offset = range.start;
    while offset < range.end {
        let remaining = &source[offset..range.end];
        let character = remaining.chars().next()?;
        if character.is_whitespace() {
            offset += character.len_utf8();
            continue;
        }
        if allow_source_docs && (remaining.starts_with("///") || remaining.starts_with("//!")) {
            let newline = remaining
                .find('\n')
                .map(|relative| offset + relative)
                .unwrap_or(range.end);
            offset = newline.saturating_add(usize::from(newline < range.end));
            continue;
        }
        if allow_source_docs && (remaining.starts_with("/**") || remaining.starts_with("/*!")) {
            let end = remaining.find("*/")? + offset + 2;
            if end > range.end {
                return None;
            }
            offset = end;
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
        let trailing = source[line_start..comment_start]
            .chars()
            .any(|character| !character.is_whitespace());
        comments.push(Comment {
            text: source[comment_start..comment_end].to_owned(),
            trailing,
            left,
            right,
        });
        offset = newline.saturating_add(usize::from(newline < range.end));
    }
    Some(())
}

fn token_mapping(original: &[Token], formatted: &[Token]) -> Option<Vec<Option<usize>>> {
    let mut mapping = vec![None; original.len()];
    let original_required = original
        .iter()
        .enumerate()
        .filter(|(_, token)| !is_removable_original_token(&token.key))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let formatted_required = formatted
        .iter()
        .enumerate()
        .filter(|(_, token)| !is_inserted_formatted_token(&token.key))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if original_required.len() != formatted_required.len() {
        return None;
    }

    let mut original_start = 0;
    let mut formatted_start = 0;
    for (&original_index, &formatted_index) in original_required.iter().zip(&formatted_required) {
        if original[original_index].key != formatted[formatted_index].key {
            return None;
        }
        map_optional_tokens(
            original,
            original_start..original_index,
            formatted,
            formatted_start..formatted_index,
            &mut mapping,
        )?;
        mapping[original_index] = Some(formatted_index);
        original_start = original_index + 1;
        formatted_start = formatted_index + 1;
    }
    map_optional_tokens(
        original,
        original_start..original.len(),
        formatted,
        formatted_start..formatted.len(),
        &mut mapping,
    )?;
    Some(mapping)
}

fn map_optional_tokens(
    original: &[Token],
    original_range: Range<usize>,
    formatted: &[Token],
    formatted_range: Range<usize>,
    mapping: &mut [Option<usize>],
) -> Option<()> {
    let original = &original[original_range.clone()];
    let formatted = &formatted[formatted_range.clone()];
    let columns = formatted.len() + 1;
    let cells = (original.len() + 1).checked_mul(columns)?;
    if cells > MAX_OPTIONAL_ALIGNMENT_CELLS {
        return None;
    }
    let mut common = vec![0; cells];
    for original_index in (0..original.len()).rev() {
        for formatted_index in (0..formatted.len()).rev() {
            let index = original_index * columns + formatted_index;
            common[index] = if original[original_index].key == formatted[formatted_index].key {
                common[(original_index + 1) * columns + formatted_index + 1] + 1
            } else {
                common[(original_index + 1) * columns + formatted_index]
                    .max(common[original_index * columns + formatted_index + 1])
            };
        }
    }

    let mut original_index = 0;
    let mut formatted_index = 0;
    while original_index < original.len() && formatted_index < formatted.len() {
        if original[original_index].key == formatted[formatted_index].key {
            mapping[original_range.start + original_index] =
                Some(formatted_range.start + formatted_index);
            original_index += 1;
            formatted_index += 1;
        } else if common[(original_index + 1) * columns + formatted_index]
            >= common[original_index * columns + formatted_index + 1]
        {
            original_index += 1;
        } else {
            formatted_index += 1;
        }
    }
    Some(())
}

const fn is_removable_original_token(key: &TokenKey) -> bool {
    matches!(
        key,
        TokenKey::Punct(',' | ';') | TokenKey::Open(_) | TokenKey::Close(_)
    )
}

const fn is_inserted_formatted_token(key: &TokenKey) -> bool {
    matches!(
        key,
        TokenKey::Punct(',' | ';') | TokenKey::Open(_) | TokenKey::Close(_)
    )
}

fn nearest_mapped_left(mapping: &[Option<usize>], left: Option<usize>) -> Option<usize> {
    mapping[..left?.saturating_add(1)]
        .iter()
        .rev()
        .find_map(|mapped| *mapped)
}

fn nearest_mapped_right(mapping: &[Option<usize>], right: Option<usize>) -> Option<usize> {
    mapping[right?..].iter().find_map(|mapped| *mapped)
}

fn render_gap(
    formatted: &str,
    tokens: &[Token],
    left: Option<usize>,
    right: Option<usize>,
    comments: &[Comment],
) -> Option<String> {
    let comment_indentation = comment_indentation(formatted, tokens, left, right);
    let right_indentation = right.map(|right| {
        line_leading_whitespace(formatted, tokens[right].range.start).map_or_else(
            || {
                if matches!(tokens[right].key, TokenKey::Close(_)) {
                    enclosing_indentation(formatted, tokens, right)
                } else {
                    comment_indentation.clone()
                }
            },
            str::to_owned,
        )
    });
    let mut output = String::new();
    for (index, comment) in comments.iter().enumerate() {
        if comment.trailing {
            if index != 0 || !output.is_empty() {
                return None;
            }
            output.push(' ');
            output.push_str(&comment.text);
            output.push('\n');
        } else {
            if !output.ends_with('\n') && (left.is_some() || !output.is_empty()) {
                output.push('\n');
            }
            output.push_str(&comment_indentation);
            output.push_str(&comment.text);
            output.push('\n');
        }
    }
    if let Some(indentation) = right_indentation {
        output.push_str(&indentation);
    }
    Some(output)
}

fn comment_indentation(
    source: &str,
    tokens: &[Token],
    left: Option<usize>,
    right: Option<usize>,
) -> String {
    if let Some(right) = right
        && !matches!(tokens[right].key, TokenKey::Close(_))
        && let Some(indentation) = line_leading_whitespace(source, tokens[right].range.start)
    {
        return indentation.to_owned();
    }
    if let Some(left) = left
        && !matches!(tokens[left].key, TokenKey::Open(_))
        && let Some(indentation) = line_leading_whitespace(source, tokens[left].range.start)
    {
        return indentation.to_owned();
    }

    let position = right.unwrap_or(tokens.len());
    let indentation = enclosing_indentation(source, tokens, position);
    if has_enclosing_delimiter(tokens, position) {
        format!("{indentation}    ")
    } else {
        indentation
    }
}

fn enclosing_indentation(source: &str, tokens: &[Token], position: usize) -> String {
    let mut delimiters = Vec::new();
    for token in &tokens[..position] {
        match token.key {
            TokenKey::Open(open) => delimiters.push((open, token.range.start)),
            TokenKey::Close(close) => {
                if delimiters
                    .last()
                    .is_some_and(|(open, _)| delimiters_match(*open, close))
                {
                    delimiters.pop();
                }
            }
            TokenKey::Ident(_) | TokenKey::Punct(_) | TokenKey::Literal(_) | TokenKey::Doc(_) => {}
        }
    }
    delimiters.last().map_or_else(String::new, |(_, offset)| {
        line_indentation(source, *offset).to_owned()
    })
}

fn has_enclosing_delimiter(tokens: &[Token], position: usize) -> bool {
    let mut delimiters = Vec::new();
    for token in &tokens[..position] {
        match token.key {
            TokenKey::Open(open) => delimiters.push(open),
            TokenKey::Close(close) => {
                if delimiters
                    .last()
                    .is_some_and(|open| delimiters_match(*open, close))
                {
                    delimiters.pop();
                }
            }
            TokenKey::Ident(_) | TokenKey::Punct(_) | TokenKey::Literal(_) | TokenKey::Doc(_) => {}
        }
    }
    !delimiters.is_empty()
}

const fn delimiters_match(open: char, close: char) -> bool {
    matches!((open, close), ('(', ')') | ('{', '}') | ('[', ']'))
}

fn line_leading_whitespace(source: &str, offset: usize) -> Option<&str> {
    let line_start = source[..offset]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let prefix = &source[line_start..offset];
    prefix.chars().all(char::is_whitespace).then_some(prefix)
}

fn line_indentation(source: &str, offset: usize) -> &str {
    let line_start = source[..offset]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = &source[line_start..offset];
    let end = line
        .char_indices()
        .find_map(|(index, character)| (!character.is_whitespace()).then_some(index))
        .unwrap_or(line.len());
    &line[..end]
}

fn has_source_spelled_doc_comment(source: &str, literal_ranges: &[Range<usize>]) -> bool {
    let mut literal_ranges = literal_ranges.to_vec();
    literal_ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut literals = literal_ranges.iter().peekable();
    let mut offset = 0;
    while offset < source.len() {
        while literals.peek().is_some_and(|literal| literal.end <= offset) {
            literals.next();
        }
        let remaining = &source[offset..];
        if remaining.starts_with("///")
            || remaining.starts_with("//!")
            || remaining.starts_with("/**")
            || remaining.starts_with("/*!")
        {
            return true;
        }
        if let Some(literal) = literals.peek()
            && literal.start <= offset
        {
            offset = literal.end;
            literals.next();
            continue;
        }
        offset += source[offset..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

fn source_doc_ranges(source: &str, literal_ranges: &[Range<usize>]) -> Vec<Range<usize>> {
    literal_ranges
        .iter()
        .filter(|range| {
            source.get((*range).clone()).is_some_and(|text| {
                text.starts_with("///")
                    || text.starts_with("//!")
                    || text.starts_with("/**")
                    || text.starts_with("/*!")
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_line_comment_beside_source_doc_comment() {
        let source = "// keep item comment\n/// Run one selection.\nfn run(){marker! {}}";
        let comments = LineComments::prepare_allowing_docs(source)
            .expect("ordinary comment should be recoverable beside docs");
        let formatted = "/// Run one selection.\nfn run() {\n    marker! {}\n}";
        let restored = comments
            .restore(formatted)
            .expect("ordinary comment should restore beside docs");

        assert_eq!(restored.matches("// keep item comment").count(), 1);
        assert_eq!(restored.matches("/// Run one selection.").count(), 1);
    }

    #[test]
    fn bounds_optional_token_alignment() {
        let source = format!(
            "{}value // keep exactly\n{}",
            "(".repeat(200),
            ")".repeat(200)
        );
        let comments = LineComments::prepare(&source).expect("line comment should be detected");

        assert!(comments.restore(&source).is_none());
    }
}
