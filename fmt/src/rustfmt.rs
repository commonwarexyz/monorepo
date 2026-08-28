//! Stock rustfmt adapter for ordinary Rust fragments.

use crate::fragment::{MultilineLiterals, ProtectedFragment};
use proc_macro2::Span;
use std::{
    ffi::OsString,
    io::Write as _,
    path::PathBuf,
    process::{Command, Stdio},
};
use syn::{Expr, Item, Meta, parse::Parse as _, spanned::Spanned as _};
use thiserror::Error;

const INDENT: usize = 4;

struct BlankLines {
    marked: String,
    marker_prefix: String,
    count: usize,
}

impl BlankLines {
    fn prepare(source: &str) -> Option<Self> {
        if !crate::fragment::source_has_internal_blank_line(source) {
            return None;
        }
        let lines = source.split_inclusive('\n').collect::<Vec<_>>();
        let first_content = lines.iter().position(|line| !line.trim().is_empty())?;
        let last_content = lines.iter().rposition(|line| !line.trim().is_empty())?;
        let marker_prefix = crate::marker::unique_prefix(source, "rustfmt_blank");
        let mut marked = String::with_capacity(source.len());
        let mut count = 0;
        for (index, line) in lines.into_iter().enumerate() {
            if first_content < index && index < last_content && line.trim().is_empty() {
                marked.push_str("// ");
                marked.push_str(&marker_prefix);
                marked.push_str(&count.to_string());
                if line.ends_with("\r\n") {
                    marked.push_str("\r\n");
                } else if line.ends_with('\n') {
                    marked.push('\n');
                }
                count += 1;
            } else {
                marked.push_str(line);
            }
        }
        Some(Self {
            marked,
            marker_prefix,
            count,
        })
    }

    fn text(&self) -> &str {
        &self.marked
    }

    fn restore(self, formatted: &str) -> Option<String> {
        let marker_start = format!("// {}", self.marker_prefix);
        let mut next = 0;
        let mut output = String::with_capacity(formatted.len());
        for line in formatted.split_inclusive('\n') {
            let line_ending = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            let content = line.strip_suffix(line_ending).unwrap_or(line);
            let trimmed = content.trim();
            if let Some(index) = trimmed
                .strip_prefix(&marker_start)
                .and_then(|index| index.parse::<usize>().ok())
            {
                if index != next || index >= self.count {
                    return None;
                }
                next += 1;
                output.push_str(line_ending);
            } else {
                if content.contains(&self.marker_prefix) {
                    return None;
                }
                output.push_str(line);
            }
        }
        (next == self.count && !output.contains(&self.marker_prefix)).then_some(output)
    }
}

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

    pub(crate) fn expression(
        &self,
        source: &str,
        indentation: usize,
    ) -> Result<ProtectedFragment, Error> {
        let formatted = self.format_protected(source, indentation, WrapperKind::Expression)?;
        if syn::parse_str::<Expr>(formatted.text()).is_ok() {
            return Ok(formatted);
        }
        let mut text = formatted.into_string();
        if text.ends_with(';') {
            text.pop();
        }
        syn::parse_str::<Expr>(&text).map_err(Error::Reparse)?;
        Ok(ProtectedFragment::formatted(text))
    }

    pub(crate) fn block_expression(
        &self,
        source: &str,
        indentation: usize,
    ) -> Result<ProtectedFragment, Error> {
        if !source.contains(['\n', '\r']) {
            return self.expression(source, indentation);
        }
        self.format_with_protection(source, |source| {
            self.format_multiline_block_raw(source, indentation)
        })
    }

    pub(crate) fn pattern(
        &self,
        source: &str,
        indentation: usize,
    ) -> Result<ProtectedFragment, Error> {
        self.format_with_protection(source, |source| {
            self.format_pattern_raw(source, indentation)
        })
    }

    pub(crate) fn match_arm_body(
        &self,
        source: &str,
        indentation: usize,
    ) -> Result<ProtectedFragment, Error> {
        self.format_with_protection(source, |source| {
            self.format_match_arm_body_raw(source, indentation)
        })
    }

    pub(crate) fn meta(&self, source: &str, column: usize) -> Result<ProtectedFragment, Error> {
        self.format_with_protection(source, |source| self.format_meta_raw(source, column))
    }

    fn format_protected(
        &self,
        source: &str,
        indentation: usize,
        kind: WrapperKind,
    ) -> Result<ProtectedFragment, Error> {
        self.format_with_protection(source, |source| self.format_raw(source, indentation, kind))
    }

    fn format_with_protection(
        &self,
        source: &str,
        format: impl FnOnce(&str) -> Result<String, Error>,
    ) -> Result<ProtectedFragment, Error> {
        if let Some(literals) = MultilineLiterals::prepare(source) {
            let normalized = normalize_source(literals.text());
            let formatted = format_with_blank_lines(&normalized, format)?;
            return literals.restore(formatted).ok_or(Error::LiteralRestoration);
        }
        let source = normalize_source(source);
        format_with_blank_lines(&source, format)
    }

    fn format_raw(
        &self,
        source: &str,
        indentation: usize,
        kind: WrapperKind,
    ) -> Result<String, Error> {
        if !indentation.is_multiple_of(INDENT)
            || (matches!(kind, WrapperKind::Statements | WrapperKind::Expression)
                && indentation < INDENT)
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

    fn format_pattern_raw(&self, source: &str, indentation: usize) -> Result<String, Error> {
        if indentation < INDENT || !indentation.is_multiple_of(INDENT) {
            return Err(Error::UnsupportedIndentation(indentation));
        }
        let prefix = crate::marker::unique_prefix(source, "rustfmt_pattern");
        let module_depth = indentation / INDENT - 1;
        let wrapper = pattern_wrapper(source, indentation, module_depth, &prefix);
        let formatted = self.run(&wrapper)?;
        let file = syn::parse_file(&formatted).map_err(Error::Reparse)?;
        let item = nested_item(&file.items, module_depth, &prefix)?;
        let Item::Const(item) = item else {
            return Err(Error::WrapperShape);
        };
        let Expr::Match(expression) = item.expr.as_ref() else {
            return Err(Error::WrapperShape);
        };
        let [arm] = expression.arms.as_slice() else {
            return Err(Error::WrapperShape);
        };
        extract_span(&formatted, arm.pat.span(), Some(indentation), indentation)
    }

    fn format_meta_raw(&self, source: &str, column: usize) -> Result<String, Error> {
        let (attribute_indentation, attribute_name) = meta_wrapper_placement(column)?;
        let prefix = crate::marker::unique_prefix(source, "rustfmt_meta");
        let module_depth = attribute_indentation / INDENT;
        let wrapper = meta_wrapper(source, column, module_depth, &attribute_name, &prefix);
        let formatted = self.run(&wrapper)?;
        let file = syn::parse_file(&formatted).map_err(Error::Reparse)?;
        let item = nested_item(&file.items, module_depth, &prefix)?;
        let Item::Const(item) = item else {
            return Err(Error::WrapperShape);
        };
        let [attribute] = item.attrs.as_slice() else {
            return Err(Error::WrapperShape);
        };
        if !attribute.path().is_ident(&attribute_name) {
            return Err(Error::WrapperShape);
        }
        let meta = attribute
            .parse_args_with(Meta::parse)
            .map_err(Error::Reparse)?;
        extract_span(&formatted, meta.span(), Some(column), attribute_indentation)
    }

    fn format_match_arm_body_raw(&self, source: &str, indentation: usize) -> Result<String, Error> {
        if indentation < INDENT || !indentation.is_multiple_of(INDENT) {
            return Err(Error::UnsupportedIndentation(indentation));
        }
        let prefix = crate::marker::unique_prefix(source, "rustfmt_match_arm");
        let module_depth = if indentation == INDENT {
            0
        } else {
            indentation / INDENT - 2
        };
        let wrapper = match_arm_wrapper(source, indentation, module_depth, &prefix);
        let formatted = self.run(&wrapper)?;
        let file = syn::parse_file(&formatted).map_err(Error::Reparse)?;
        let item = nested_item(&file.items, module_depth, &prefix)?;
        let expression = if indentation == INDENT {
            let Item::Const(item) = item else {
                return Err(Error::WrapperShape);
            };
            let Expr::Match(expression) = item.expr.as_ref() else {
                return Err(Error::WrapperShape);
            };
            expression
        } else {
            let Item::Fn(item) = item else {
                return Err(Error::WrapperShape);
            };
            if item.sig.ident != format!("{prefix}item") {
                return Err(Error::WrapperShape);
            }
            let [syn::Stmt::Expr(Expr::Match(expression), _)] = item.block.stmts.as_slice() else {
                return Err(Error::WrapperShape);
            };
            expression
        };
        let [arm] = expression.arms.as_slice() else {
            return Err(Error::WrapperShape);
        };
        extract_span(&formatted, arm.body.span(), None, indentation)
    }

    fn format_multiline_block_raw(
        &self,
        source: &str,
        indentation: usize,
    ) -> Result<String, Error> {
        if indentation < INDENT || !indentation.is_multiple_of(INDENT) {
            return Err(Error::UnsupportedIndentation(indentation));
        }
        let prefix = crate::marker::unique_prefix(source, "rustfmt_block");
        let module_depth = indentation / INDENT - 1;
        let wrapper = multiline_block_wrapper(source, indentation, module_depth, &prefix);
        let formatted = self.run(&wrapper)?;
        let file = syn::parse_file(&formatted).map_err(Error::Reparse)?;
        let item = nested_item(&file.items, module_depth, &prefix)?;
        let Item::Fn(item) = item else {
            return Err(Error::WrapperShape);
        };
        if item.sig.ident != format!("{prefix}item") {
            return Err(Error::WrapperShape);
        }
        let [syn::Stmt::Expr(expression, Some(_))] = item.block.stmts.as_slice() else {
            return Err(Error::WrapperShape);
        };
        if !matches!(expression, Expr::Block(_)) {
            return Err(Error::WrapperShape);
        }
        extract_span(&formatted, expression.span(), None, indentation)
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

fn format_with_blank_lines(
    source: &str,
    format: impl FnOnce(&str) -> Result<String, Error>,
) -> Result<ProtectedFragment, Error> {
    let Some(blank_lines) = BlankLines::prepare(source) else {
        return format(source).map(ProtectedFragment::formatted);
    };
    let formatted = format(blank_lines.text())?;
    Ok(blank_lines.restore(&formatted).map_or_else(
        || ProtectedFragment::preserved(source),
        ProtectedFragment::formatted,
    ))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WrapperKind {
    Items,
    Statements,
    Expression,
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
        WrapperKind::Statements | WrapperKind::Expression => indentation / INDENT - 1,
    };
    let mut output = String::new();
    for depth in 0..module_depth {
        output.push_str("mod ");
        output.push_str(prefix);
        output.push_str("module_");
        output.push_str(&depth.to_string());
        output.push_str(" {\n");
    }
    if matches!(kind, WrapperKind::Statements | WrapperKind::Expression) {
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
    if matches!(kind, WrapperKind::Statements | WrapperKind::Expression) {
        output.push_str("}\n");
    }
    for _ in 0..module_depth {
        output.push_str("}\n");
    }
    output
}

fn pattern_wrapper(source: &str, indentation: usize, module_depth: usize, prefix: &str) -> String {
    let mut output = module_prefix(module_depth, prefix);
    output.push_str(&" ".repeat(indentation - INDENT));
    output.push_str("const _: () = match () {\n");
    output.push_str(&indent_source(source, indentation));
    output.push_str(" => (),\n");
    output.push_str(&" ".repeat(indentation - INDENT));
    output.push_str("};\n");
    close_modules(&mut output, module_depth);
    output
}

fn match_arm_wrapper(
    source: &str,
    indentation: usize,
    module_depth: usize,
    prefix: &str,
) -> String {
    let mut output = module_prefix(module_depth, prefix);
    if indentation >= INDENT * 2 {
        output.push_str(&" ".repeat(indentation - INDENT * 2));
        output.push_str("fn ");
        output.push_str(prefix);
        output.push_str("item() {\n");
        output.push_str(&" ".repeat(indentation - INDENT));
        output.push_str("match () {\n");
        output.push_str(&" ".repeat(indentation));
        output.push_str("_ => ");
        output.push_str(&indent_inline_source(source, indentation));
        output.push_str(",\n");
        output.push_str(&" ".repeat(indentation - INDENT));
        output.push_str("};\n");
        output.push_str(&" ".repeat(indentation - INDENT * 2));
        output.push_str("}\n");
        close_modules(&mut output, module_depth);
        return output;
    }
    output.push_str(&" ".repeat(indentation - INDENT));
    output.push_str("const _: () = match () {\n");
    output.push_str(&" ".repeat(indentation));
    output.push_str("_ => ");
    output.push_str(&indent_inline_source(source, indentation));
    output.push_str(",\n");
    output.push_str(&" ".repeat(indentation - INDENT));
    output.push_str("};\n");
    close_modules(&mut output, module_depth);
    output
}

fn multiline_block_wrapper(
    source: &str,
    indentation: usize,
    module_depth: usize,
    prefix: &str,
) -> String {
    let mut output = module_prefix(module_depth, prefix);
    output.push_str(&" ".repeat(indentation - INDENT));
    output.push_str("fn ");
    output.push_str(prefix);
    output.push_str("item() {\n");
    output.push_str(&indent_source(source, indentation));
    output.push_str(";\n");
    output.push_str(&" ".repeat(indentation - INDENT));
    output.push_str("}\n");
    close_modules(&mut output, module_depth);
    output
}

fn meta_wrapper(
    source: &str,
    column: usize,
    module_depth: usize,
    attribute_name: &str,
    prefix: &str,
) -> String {
    let indentation = module_depth * INDENT;
    let mut output = module_prefix(module_depth, prefix);
    output.push_str(&" ".repeat(indentation));
    output.push_str("#[");
    output.push_str(attribute_name);
    output.push('(');
    output.push_str(&indent_inline_source(source, column));
    output.push_str(")]\n");
    output.push_str(&" ".repeat(indentation));
    output.push_str("const ");
    output.push_str(prefix);
    output.push_str("item: () = ();\n");
    close_modules(&mut output, module_depth);
    output
}

fn meta_wrapper_placement(column: usize) -> Result<(usize, String), Error> {
    for name_length in 1..=INDENT {
        let prefix_width = name_length + 3;
        if column >= prefix_width && (column - prefix_width).is_multiple_of(INDENT) {
            return Ok((column - prefix_width, "a".repeat(name_length)));
        }
    }
    Err(Error::UnsupportedColumn(column))
}

fn module_prefix(module_depth: usize, prefix: &str) -> String {
    let mut output = String::new();
    for depth in 0..module_depth {
        output.push_str(&" ".repeat(depth * INDENT));
        output.push_str("mod ");
        output.push_str(prefix);
        output.push_str("module_");
        output.push_str(&depth.to_string());
        output.push_str(" {\n");
    }
    output
}

fn close_modules(output: &mut String, module_depth: usize) {
    for depth in (0..module_depth).rev() {
        output.push_str(&" ".repeat(depth * INDENT));
        output.push_str("}\n");
    }
}

fn nested_item<'a>(
    items: &'a [Item],
    module_depth: usize,
    prefix: &str,
) -> Result<&'a Item, Error> {
    let mut items = items;
    for depth in 0..module_depth {
        let [Item::Mod(module)] = items else {
            return Err(Error::WrapperShape);
        };
        if module.ident != format!("{prefix}module_{depth}") {
            return Err(Error::WrapperShape);
        }
        let Some((_, nested)) = &module.content else {
            return Err(Error::WrapperShape);
        };
        items = nested;
    }
    let [item] = items else {
        return Err(Error::WrapperShape);
    };
    Ok(item)
}

fn indent_inline_source(source: &str, column: usize) -> String {
    let prefix = " ".repeat(column);
    let mut output = String::with_capacity(source.len() + prefix.len());
    for (index, line) in source.split_inclusive('\n').enumerate() {
        if index != 0 {
            output.push_str(&prefix);
        }
        output.push_str(line);
    }
    output
}

fn extract_span(
    formatted: &str,
    span: Span,
    column: Option<usize>,
    indentation: usize,
) -> Result<String, Error> {
    let source_map = crate::source::SourceMap::new(formatted);
    let range = source_map.span_range(span)?;
    let line_start = formatted[..range.start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line_prefix = formatted
        .get(line_start..range.start)
        .ok_or(Error::WrapperShape)?;
    if column.is_some_and(|column| visual_width(line_prefix) != column) {
        return Err(Error::UnexpectedIndentation);
    }
    let prefix_length = line_prefix
        .bytes()
        .take_while(|byte| byte.is_ascii_whitespace())
        .count();
    let prefix = line_prefix
        .get(..prefix_length)
        .ok_or(Error::WrapperShape)?;
    if visual_width(prefix) != indentation {
        return Err(Error::UnexpectedIndentation);
    }
    let fragment = source_map.slice(range)?;
    let mut output = String::with_capacity(fragment.len());
    for (index, line) in fragment.split_inclusive('\n').enumerate() {
        if index == 0 {
            output.push_str(line);
            continue;
        }
        let content = line
            .strip_prefix(prefix)
            .ok_or(Error::UnexpectedIndentation)?;
        output.push_str(content);
    }
    Ok(output)
}

fn normalize_source(source: &str) -> String {
    let source = source.trim_matches(['\n', '\r']);
    let lines = source.split_inclusive('\n').collect::<Vec<_>>();
    let Some(first_content) = lines.iter().position(|line| !line.trim().is_empty()) else {
        return source.to_owned();
    };
    let first_indentation = leading_whitespace(lines[first_content]);
    let first_is_inline = first_indentation.is_empty();
    let indentation = if first_indentation.is_empty() {
        lines
            .iter()
            .skip(first_content + 1)
            .filter(|line| !line.trim().is_empty())
            .map(|line| leading_whitespace(line))
            .min_by_key(|prefix| prefix.len())
            .unwrap_or("")
    } else {
        first_indentation
    };
    let mut output = String::with_capacity(source.len());
    for (index, line) in lines.iter().copied().enumerate() {
        let content = if line.trim().is_empty() || index == first_content && first_is_inline {
            line
        } else {
            line.strip_prefix(indentation).unwrap_or(line)
        };
        output.push_str(content);
    }
    output
}

fn leading_whitespace(line: &str) -> &str {
    &line[..line
        .as_bytes()
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count()]
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
    /// The requested inline column could not be represented safely.
    #[error("unsupported fragment column {0}")]
    UnsupportedColumn(usize),
    /// Formatted wrapper output was not valid Rust.
    #[error("failed to parse formatted rustfmt wrapper: {0}")]
    Reparse(#[source] syn::Error),
    /// The formatted wrapper did not retain its synthetic syntax shape.
    #[error("formatted rustfmt wrapper had an unexpected shape")]
    WrapperShape,
    /// A formatted source span could not be mapped back to bytes.
    #[error("failed to locate formatted rustfmt fragment: {0}")]
    Source(#[from] crate::source::Error),
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
    use syn::parse::Parser as _;

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
    fn formats_expression_at_destination_indentation() {
        let source = "build_something(first_argument, second_argument, third_argument, fourth_arg)";
        let shallow = Formatter::default().expression(source, 4).unwrap();
        let deep = Formatter::default().expression(source, 28).unwrap();

        assert_eq!(shallow.text(), source);
        assert!(deep.text().contains('\n'), "{}", deep.text());
        syn::parse_str::<Expr>(deep.text()).expect("formatted expression should parse");
    }

    #[test]
    fn removes_wrapper_semicolon_from_control_flow_expression() {
        let formatted = Formatter::default()
            .expression("return descriptive_result", 8)
            .unwrap();

        assert_eq!(formatted.text(), "return descriptive_result");
    }

    #[test]
    fn formats_pattern_at_destination_indentation() {
        let source = "Message::Data { first, second, third, fourth, fifth }";
        let formatted = Formatter::default().pattern(source, 12).unwrap();

        assert!(formatted.text().contains("Message::Data"));
        assert!(formatted.text().contains('\n'), "{}", formatted.text());
        syn::Pat::parse_single
            .parse_str(formatted.text())
            .expect("formatted pattern should parse");
    }

    #[test]
    fn formats_match_arm_body_in_match_context() {
        let source = "value.map(|value| value.with_first_component().with_second_component().with_third_component())";
        let formatted = Formatter::default().match_arm_body(source, 8).unwrap();

        assert!(formatted.text().contains("value.map(|value|"));
        assert!(formatted.text().contains('\n'), "{}", formatted.text());
        syn::parse_str::<Expr>(formatted.text()).expect("formatted body should parse");
    }

    #[test]
    fn match_arm_wrapper_retains_deep_destination_indentation() {
        let source = "match value {\n    _ => {\n        if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {\n            async {\n                verifications\n                    .drive(self.processor.notify_finalized(\n                        self.context.as_present(),\n                        block.as_ref(),\n                    ))\n                    .await;\n                acknowledgement.acknowledge();\n            }\n            .instrument(process)\n            .await;\n        } else {}\n    }\n}";
        let formatted = Formatter::default().match_arm_body(source, 12).unwrap();

        assert!(
            formatted.text().contains("match value {"),
            "{}",
            formatted.text()
        );
        syn::parse_str::<Expr>(formatted.text()).expect("formatted body should parse");
    }

    #[test]
    fn removes_absolute_indentation_from_inline_multiline_expression() {
        let source = "async {\n                    work().await;\n                }";
        let once = Formatter::default().match_arm_body(source, 16).unwrap();
        let twice = Formatter::default()
            .match_arm_body(once.text(), 16)
            .unwrap();

        assert_eq!(
            once.text(),
            "{\n    async {\n        work().await;\n    }\n}"
        );
        assert_eq!(once.text(), twice.text());
    }

    #[test]
    fn keeps_preserved_macro_continuation_at_a_fixed_indentation() {
        let source = "span.in_scope(|| {\n                    debug!(epoch = %context.epoch(), view = %context.view(), \"proposal rejected: state sync in progress\");\n                    response.send_lossy(None);\n                })";
        let once = Formatter::default().match_arm_body(source, 12).unwrap();
        let twice = Formatter::default()
            .match_arm_body(once.text(), 12)
            .unwrap();

        assert_eq!(once.text(), twice.text());
        assert!(
            once.text()
                .contains("\n    debug!(epoch = %context.epoch()"),
            "{}",
            once.text()
        );
    }

    #[test]
    fn formats_meta_at_destination_column() {
        let source =
            "all(feature=\"first\",feature=\"second\",feature=\"third\",feature=\"fourth\")";
        let formatted = Formatter::default().meta(source, 17).unwrap();

        assert!(formatted.text().starts_with("all("));
        assert!(formatted.text().contains("feature = \"first\""));
        syn::parse_str::<Meta>(formatted.text()).expect("formatted meta should parse");
    }

    #[test]
    fn preserves_multiline_literal_bytes() {
        let source = "let value = r#\"first\n  second\"#;\nvalue";
        let formatted = Formatter::default().statements(source, 8).unwrap();

        assert!(formatted.text().contains("r#\"first\n  second\"#"));
    }

    #[test]
    fn preserves_expression_blank_line_topology() {
        let source = "match value {\n    Some(value) => {\n        first(value);\n\n        // __commonware_fmt_rustfmt_blank_user\n        second(value);\n\n        finish(value)\n    }\n    None => fallback(),\n}";
        let once = Formatter::default().expression(source, 4).unwrap();
        let twice = Formatter::default().expression(once.text(), 4).unwrap();

        assert_eq!(
            once.text()
                .lines()
                .filter(|line| line.trim().is_empty())
                .count(),
            2
        );
        assert_eq!(
            once.text()
                .matches("// __commonware_fmt_rustfmt_blank_user")
                .count(),
            1
        );
        assert_eq!(once.text(), twice.text());
    }

    #[test]
    fn does_not_mark_blank_lines_inside_multiline_literals() {
        let literal = "r#\"first\n\n    third\"#";
        let source = format!("consume({literal})");
        let formatted = Formatter::default().expression(&source, 8).unwrap();

        assert_eq!(formatted.text().matches(literal).count(), 1);
    }

    #[test]
    fn rejects_unrepresentable_indentation() {
        let Err(error) = Formatter::default().items("struct Example;", 6) else {
            panic!("indentation should be rejected");
        };

        assert!(matches!(error, Error::UnsupportedIndentation(6)));
    }
}
