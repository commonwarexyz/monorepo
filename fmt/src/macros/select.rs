//! Formatters for `select!` and `select_loop!` bodies.

use super::{Error, MacroKind, Options, nested};
use crate::{
    pretty::{self, Disposition, ProtectedFragment},
    source::SourceMap,
    trivia::{self, ShellComment},
    writer::{MAX_OVERFLOW_WIDTH, Writer},
};
use commonware_macros_grammar::{
    SelectBranch, SelectInput, SelectLoopBranch, SelectLoopInput, SelectLoopLifecycle,
};
use proc_macro2::Span;
use std::ops::Range;
use syn::{Expr, spanned::Spanned};

const MAX_UNWRAPPED_MULTILINE_BODY_LINES: usize = 16;

struct BranchLayout {
    pattern: String,
    future: String,
    divergence: Option<String>,
    body: String,
    body_is_block: bool,
    wrapped_body: Option<String>,
}

struct LifecycleLayout {
    keyword: String,
    expression: String,
    expression_is_block: bool,
}

struct ShellTrivia {
    boundaries: Vec<Vec<ShellComment>>,
}

struct SelectLoopPrefix {
    context: String,
    on_start: Option<LifecycleLayout>,
    shell_trivia: ShellTrivia,
}

#[derive(Clone, Copy)]
struct FormatContext<'map, 'source> {
    source: &'source str,
    source_map: &'map SourceMap<'source>,
    options: Options,
    depth: usize,
}

/// Formats the delimiter contents of a `select!` invocation.
pub fn select(source: &str, options: Options) -> Result<ProtectedFragment, Error> {
    super::format_at_depth(MacroKind::Select, source, options, 0)
}

pub(super) fn select_at_depth(
    source: &str,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let input = syn::parse_str::<SelectInput>(source).map_err(Error::Parse)?;
    let source_map = SourceMap::new(source);
    if pretty::source_has_internal_blank_line(source) {
        return preserve_select(source, &source_map, &input, options, depth);
    }
    let Some(shell_trivia) = select_shell_trivia(source, &source_map, &input)? else {
        return preserve_select(source, &source_map, &input, options, depth);
    };
    let context = FormatContext {
        source,
        source_map: &source_map,
        options,
        depth,
    };
    let mut branches = Vec::with_capacity(input.branches.len());
    for branch in &input.branches {
        let Some(branch) = format_select_branch(context, branch)? else {
            return preserve_select(source, &source_map, &input, options, depth);
        };
        branches.push(branch);
    }

    let output = render(options, |writer| {
        write_boundary(writer, false, &shell_trivia.boundaries[0]);
        for (index, branch) in branches.iter().enumerate() {
            write_branch(writer, branch, &shell_trivia.boundaries[index + 1]);
            write_boundary(writer, true, &shell_trivia.boundaries[index + 1]);
        }
    });
    syn::parse_str::<SelectInput>(&output).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(output))
}

/// Formats the delimiter contents of a `select_loop!` invocation.
pub fn select_loop(source: &str, options: Options) -> Result<ProtectedFragment, Error> {
    super::format_at_depth(MacroKind::SelectLoop, source, options, 0)
}

pub(super) fn select_loop_at_depth(
    source: &str,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let input = syn::parse_str::<SelectLoopInput>(source).map_err(Error::Parse)?;
    input.validate().map_err(Error::Validate)?;
    let source_map = SourceMap::new(source);
    if pretty::source_has_internal_blank_line(source) {
        return preserve_select_loop(source, &source_map, &input, options, depth);
    }
    let Some(shell_trivia) = select_loop_shell_trivia(source, &source_map, &input)? else {
        return preserve_select_loop(source, &source_map, &input, options, depth);
    };
    let Some(context) = format_expression(source, &source_map, &input.context, depth)? else {
        return preserve_select_loop(source, &source_map, &input, options, depth);
    };
    let on_start = match &input.on_start {
        Some(lifecycle) => {
            let Some(lifecycle) = format_lifecycle(source, &source_map, lifecycle, depth)? else {
                return preserve_select_loop(source, &source_map, &input, options, depth);
            };
            Some(lifecycle)
        }
        None => None,
    };

    render_select_loop(
        source,
        options,
        &input,
        &source_map,
        SelectLoopPrefix {
            context,
            on_start,
            shell_trivia,
        },
        depth,
    )
}

fn render_select_loop(
    source: &str,
    options: Options,
    input: &SelectLoopInput,
    source_map: &SourceMap<'_>,
    prefix: SelectLoopPrefix,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let context = FormatContext {
        source,
        source_map,
        options,
        depth,
    };
    let Some(on_stopped) = format_lifecycle(source, source_map, &input.on_stopped, depth)? else {
        return preserve_select_loop(source, source_map, input, options, depth);
    };
    let mut branches = Vec::with_capacity(input.branches.len());
    for branch in &input.branches {
        let Some(branch) = format_select_loop_branch(context, branch)? else {
            return preserve_select_loop(source, source_map, input, options, depth);
        };
        branches.push(branch);
    }
    let on_end = match &input.on_end {
        Some(lifecycle) => {
            let Some(lifecycle) = format_lifecycle(source, source_map, lifecycle, depth)? else {
                return preserve_select_loop(source, source_map, input, options, depth);
            };
            Some(lifecycle)
        }
        None => None,
    };

    let output = render(options, |writer| {
        let mut boundary = 0;
        write_boundary(writer, false, &prefix.shell_trivia.boundaries[boundary]);
        write_expression_entry(writer, None, &prefix.context, false);
        boundary += 1;
        write_boundary(writer, true, &prefix.shell_trivia.boundaries[boundary]);
        if let Some(on_start) = &prefix.on_start {
            write_expression_entry(
                writer,
                Some(&on_start.keyword),
                &on_start.expression,
                on_start.expression_is_block,
            );
            boundary += 1;
            write_boundary(writer, true, &prefix.shell_trivia.boundaries[boundary]);
        }
        write_expression_entry(
            writer,
            Some(&on_stopped.keyword),
            &on_stopped.expression,
            on_stopped.expression_is_block,
        );
        boundary += 1;
        write_boundary(writer, true, &prefix.shell_trivia.boundaries[boundary]);
        for branch in &branches {
            write_branch(
                writer,
                branch,
                &prefix.shell_trivia.boundaries[boundary + 1],
            );
            boundary += 1;
            write_boundary(writer, true, &prefix.shell_trivia.boundaries[boundary]);
        }
        if let Some(on_end) = &on_end {
            write_expression_entry(
                writer,
                Some(&on_end.keyword),
                &on_end.expression,
                on_end.expression_is_block,
            );
            boundary += 1;
            write_boundary(writer, true, &prefix.shell_trivia.boundaries[boundary]);
        }
        debug_assert_eq!(boundary + 1, prefix.shell_trivia.boundaries.len());
    });
    let reparsed = syn::parse_str::<SelectLoopInput>(&output).map_err(Error::Output)?;
    reparsed.validate().map_err(Error::Validate)?;
    Ok(ProtectedFragment::formatted(output))
}

fn format_select_branch(
    context: FormatContext<'_, '_>,
    branch: &SelectBranch,
) -> Result<Option<BranchLayout>, Error> {
    format_branch(context, &branch.pattern, &branch.future, None, &branch.body)
}

fn format_select_loop_branch(
    context: FormatContext<'_, '_>,
    branch: &SelectLoopBranch,
) -> Result<Option<BranchLayout>, Error> {
    format_branch(
        context,
        &branch.pattern,
        &branch.future,
        branch
            .else_clause
            .as_ref()
            .map(|else_clause| &else_clause.expression),
        &branch.body,
    )
}

fn format_branch(
    context: FormatContext<'_, '_>,
    pattern: &syn::Pat,
    future: &Expr,
    divergence: Option<&Expr>,
    body_expression: &Expr,
) -> Result<Option<BranchLayout>, Error> {
    let FormatContext {
        source,
        source_map,
        options,
        depth,
    } = context;
    let body_is_block = matches!(body_expression, Expr::Block(_));
    let pattern_source = spanned_source(source_map, pattern)?;
    let future_source = spanned_source(source_map, future)?;
    let body_range = source_map.span_range(body_expression.span())?;
    let body_source = source_map.slice(body_range.clone())?;
    let pattern = pretty::pattern(pattern, pattern_source)?;
    let future = nested::expression(future, future_source, source, source_map, depth)?;
    let mut body = nested::expression(body_expression, body_source, source, source_map, depth)?;
    if exceeds_destination_width(body.text(), options.indentation + 4)
        && let Some(dedented) =
            source_layout_at_destination(context, body_expression, body_source, body_range.start)?
    {
        body = ProtectedFragment::formatted(dedented);
    }
    let body_needs_wrapper =
        !body_is_block && body.text().lines().count() > MAX_UNWRAPPED_MULTILINE_BODY_LINES;
    let wrapped_body = if !body_needs_wrapper || body.disposition() != Disposition::Formatted {
        None
    } else {
        Some(wrap_value_body(body.text()))
    };
    let divergence = divergence
        .map(|expression| {
            let expression_source = spanned_source(source_map, expression)?;
            nested::expression(expression, expression_source, source, source_map, depth)
        })
        .transpose()?;
    if [&pattern, &future, &body].into_iter().any(is_immovable)
        || divergence.as_ref().is_some_and(is_immovable)
    {
        return Ok(None);
    }

    Ok(Some(BranchLayout {
        pattern: pattern.into_string(),
        future: future.into_string(),
        divergence: divergence.map(ProtectedFragment::into_string),
        body: body.into_string(),
        body_is_block,
        wrapped_body,
    }))
}

fn source_layout_at_destination(
    context: FormatContext<'_, '_>,
    expression: &Expr,
    fragment_source: &str,
    fragment_start: usize,
) -> Result<Option<String>, Error> {
    let FormatContext {
        source,
        source_map,
        options,
        depth,
    } = context;
    if fragment_source.contains("/*") || pretty::source_has_multiline_literal(fragment_source) {
        return Ok(None);
    }
    let preserved = nested::preserve_expression(
        expression,
        fragment_source,
        fragment_start,
        source,
        source_map,
        options,
        depth,
    )?;
    let Some(dedented) = dedent_source_fragment(preserved.text()) else {
        return Ok(None);
    };
    if exceeds_destination_width(&dedented, options.indentation + 4)
        || syn::parse_str::<Expr>(&dedented).is_err()
    {
        return Ok(None);
    }
    Ok(Some(dedented))
}

fn exceeds_destination_width(fragment: &str, indentation: usize) -> bool {
    fragment
        .lines()
        .any(|line| indentation + line.chars().count() > MAX_OVERFLOW_WIDTH)
}

fn dedent_source_fragment(source: &str) -> Option<String> {
    let lines = source.split('\n').collect::<Vec<_>>();
    let indentation = lines
        .iter()
        .skip(1)
        .filter_map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            (!line.trim().is_empty()).then(|| line.bytes().take_while(|byte| *byte == b' ').count())
        })
        .min()
        .unwrap_or(0);
    let mut output = String::with_capacity(source.len());
    for (index, line) in lines.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        if index == 0 || line.trim().is_empty() {
            output.push_str(line);
        } else {
            output.push_str(line.get(indentation..)?);
        }
    }
    Some(output)
}

fn wrap_value_body(body: &str) -> String {
    let mut output = String::from("{\n");
    for line in body.lines() {
        output.push_str("    ");
        output.push_str(line);
        output.push('\n');
    }
    output.push('}');
    output
}

fn format_lifecycle(
    source: &str,
    source_map: &SourceMap<'_>,
    lifecycle: &SelectLoopLifecycle,
    depth: usize,
) -> Result<Option<LifecycleLayout>, Error> {
    let expression_is_block = matches!(lifecycle.expression, Expr::Block(_));
    let expression_source = spanned_source(source_map, &lifecycle.expression)?;
    let expression = if expression_is_block {
        nested::block_expression(
            &lifecycle.expression,
            expression_source,
            source,
            source_map,
            depth,
        )?
    } else {
        nested::expression(
            &lifecycle.expression,
            expression_source,
            source,
            source_map,
            depth,
        )?
    };
    if is_immovable(&expression) {
        return Ok(None);
    }
    Ok(Some(LifecycleLayout {
        keyword: lifecycle.keyword.to_string(),
        expression: expression.into_string(),
        expression_is_block,
    }))
}

fn format_expression(
    source: &str,
    source_map: &SourceMap<'_>,
    expression: &Expr,
    depth: usize,
) -> Result<Option<String>, Error> {
    let expression_source = spanned_source(source_map, expression)?;
    let expression = nested::expression(expression, expression_source, source, source_map, depth)?;
    if is_immovable(&expression) {
        return Ok(None);
    }
    Ok(Some(expression.into_string()))
}

fn spanned_source<'a>(source_map: &SourceMap<'a>, value: &impl Spanned) -> Result<&'a str, Error> {
    let range = source_map.span_range(value.span())?;
    source_map.slice(range).map_err(Error::from)
}

fn is_immovable(fragment: &ProtectedFragment) -> bool {
    fragment.disposition() != Disposition::Formatted
        && (fragment.text().contains('\n') || fragment.text().contains('\r'))
}

fn preserve_select(
    source: &str,
    source_map: &SourceMap<'_>,
    input: &SelectInput,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let expressions = input
        .branches
        .iter()
        .flat_map(|branch| [&branch.future, &branch.body])
        .collect::<Vec<_>>();
    nested::preserve_with_nested(source, source_map, &expressions, options, depth)
}

fn preserve_select_loop(
    source: &str,
    source_map: &SourceMap<'_>,
    input: &SelectLoopInput,
    options: Options,
    depth: usize,
) -> Result<ProtectedFragment, Error> {
    let mut expressions = vec![&input.context, &input.on_stopped.expression];
    if let Some(on_start) = &input.on_start {
        expressions.push(&on_start.expression);
    }
    for branch in &input.branches {
        expressions.push(&branch.future);
        if let Some(else_clause) = &branch.else_clause {
            expressions.push(&else_clause.expression);
        }
        expressions.push(&branch.body);
    }
    if let Some(on_end) = &input.on_end {
        expressions.push(&on_end.expression);
    }
    nested::preserve_with_nested(source, source_map, &expressions, options, depth)
}

fn select_shell_trivia(
    source: &str,
    source_map: &SourceMap<'_>,
    input: &SelectInput,
) -> Result<Option<ShellTrivia>, Error> {
    let mut spans = Vec::new();
    let mut entries = Vec::new();
    for branch in &input.branches {
        spans.extend([
            branch.pattern.span(),
            branch.eq_token.span(),
            branch.future.span(),
            branch.fat_arrow_token.span(),
            branch.body.span(),
        ]);
        spans.extend(branch.comma_token.as_ref().map(Spanned::span));
        let end = branch
            .comma_token
            .as_ref()
            .map_or_else(|| branch.body.span(), Spanned::span);
        entries.push(entry_range(source_map, branch.pattern.span(), end)?);
    }
    shell_trivia(source, source_map, spans, entries)
}

fn select_loop_shell_trivia(
    source: &str,
    source_map: &SourceMap<'_>,
    input: &SelectLoopInput,
) -> Result<Option<ShellTrivia>, Error> {
    let mut spans = vec![input.context.span(), input.context_comma_token.span()];
    let mut entries = vec![entry_range(
        source_map,
        input.context.span(),
        input.context_comma_token.span(),
    )?];
    if let Some(on_start) = &input.on_start {
        push_lifecycle_spans(&mut spans, on_start);
        entries.push(lifecycle_range(source_map, on_start)?);
    }
    push_lifecycle_spans(&mut spans, &input.on_stopped);
    entries.push(lifecycle_range(source_map, &input.on_stopped)?);
    for branch in &input.branches {
        spans.extend([
            branch.pattern.span(),
            branch.eq_token.span(),
            branch.future.span(),
        ]);
        if let Some(else_clause) = &branch.else_clause {
            spans.extend([else_clause.else_token.span(), else_clause.expression.span()]);
        }
        spans.extend([branch.fat_arrow_token.span(), branch.body.span()]);
        spans.extend(branch.comma_token.as_ref().map(Spanned::span));
        let end = branch
            .comma_token
            .as_ref()
            .map_or_else(|| branch.body.span(), Spanned::span);
        entries.push(entry_range(source_map, branch.pattern.span(), end)?);
    }
    if let Some(on_end) = &input.on_end {
        push_lifecycle_spans(&mut spans, on_end);
        entries.push(lifecycle_range(source_map, on_end)?);
    }
    shell_trivia(source, source_map, spans, entries)
}

fn push_lifecycle_spans(spans: &mut Vec<Span>, lifecycle: &SelectLoopLifecycle) {
    spans.extend([
        lifecycle.keyword.span(),
        lifecycle.fat_arrow_token.span(),
        lifecycle.expression.span(),
    ]);
    spans.extend(lifecycle.comma_token.as_ref().map(Spanned::span));
}

fn lifecycle_range(
    source_map: &SourceMap<'_>,
    lifecycle: &SelectLoopLifecycle,
) -> Result<Range<usize>, Error> {
    let end = lifecycle
        .comma_token
        .as_ref()
        .map_or_else(|| lifecycle.expression.span(), Spanned::span);
    entry_range(source_map, lifecycle.keyword.span(), end)
}

fn entry_range(source_map: &SourceMap<'_>, start: Span, end: Span) -> Result<Range<usize>, Error> {
    let start = source_map.span_range(start)?.start;
    let end = source_map.span_range(end)?.end;
    Ok(start..end)
}

fn shell_trivia(
    source: &str,
    source_map: &SourceMap<'_>,
    spans: Vec<Span>,
    entries: Vec<Range<usize>>,
) -> Result<Option<ShellTrivia>, Error> {
    let mut ranges = spans
        .into_iter()
        .map(|span| source_map.span_range(span))
        .collect::<Result<Vec<Range<usize>>, _>>()?;
    ranges.sort_unstable_by_key(|range| (range.start, range.end));

    if entries.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Ok(None);
    }
    let mut boundaries = Vec::with_capacity(entries.len() + 1);
    if entries.is_empty() {
        boundaries.extend(std::iter::once(0..source.len()));
    } else {
        boundaries.push(0..entries[0].start);
        boundaries.extend(entries.windows(2).map(|pair| pair[0].end..pair[1].start));
        boundaries.push(entries.last().expect("entries are not empty").end..source.len());
    }

    let mut cursor = 0;
    for range in ranges {
        let gap = cursor..range.start;
        if gap.start < gap.end
            && !source[gap.clone()].chars().all(char::is_whitespace)
            && !boundaries
                .iter()
                .any(|boundary| boundary.start <= gap.start && gap.end <= boundary.end)
        {
            return Ok(None);
        }
        cursor = cursor.max(range.end);
    }
    let gap = cursor..source.len();
    if gap.start < gap.end
        && !source[gap.clone()].chars().all(char::is_whitespace)
        && !boundaries
            .iter()
            .any(|boundary| boundary.start <= gap.start && gap.end <= boundary.end)
    {
        return Ok(None);
    }

    let mut parsed = Vec::with_capacity(boundaries.len());
    for boundary in boundaries {
        let Some(comments) = trivia::shell_comments(source, boundary) else {
            return Ok(None);
        };
        parsed.push(comments);
    }
    Ok(Some(ShellTrivia { boundaries: parsed }))
}

fn write_boundary(writer: &mut Writer<'_>, has_previous: bool, comments: &[ShellComment]) {
    if comments.is_empty() {
        if has_previous {
            writer.newline();
        }
        return;
    }

    let mut previous_line_open = has_previous;
    for comment in comments {
        if comment.trailing && previous_line_open {
            writer.push(" ");
            writer.push(&comment.text);
            writer.newline();
        } else {
            if previous_line_open {
                writer.newline();
            }
            writer.push(&comment.text);
            writer.newline();
        }
        previous_line_open = false;
    }
}

fn render(options: Options, write: impl FnOnce(&mut Writer<'_>)) -> String {
    let mut writer = Writer::new(options.indentation, options.line_ending.as_str());
    writer.newline();
    writer.indented(write);
    writer.pad_to_indentation();
    writer.finish()
}

fn write_branch(
    writer: &mut Writer<'_>,
    branch: &BranchLayout,
    following_comments: &[ShellComment],
) {
    let trailing_comment = following_comments
        .first()
        .filter(|comment| comment.trailing)
        .map(|comment| comment.text.as_str());
    let inline = inline_branch(branch);
    if !inline.contains('\n') && fits_with_trailing_comment(writer, &inline, trailing_comment) {
        writer.push(&inline);
        return;
    }

    write_branch_head(writer, branch, trailing_comment);
    if branch.body_is_block {
        write_block_body(writer, &branch.body, trailing_comment);
        return;
    }

    let inline_body = format!(" => {},", branch.body);
    if !branch.body.contains('\n')
        && fits_with_trailing_comment_overflow(writer, &inline_body, trailing_comment)
    {
        writer.push(&inline_body);
        return;
    }

    if let Some(wrapped_body) = &branch.wrapped_body {
        write_block_body(writer, wrapped_body, trailing_comment);
    } else if !branch.body.contains('\n')
        || !writer.fits(&format!(
            " => {}",
            branch.body.lines().next().unwrap_or(&branch.body)
        ))
        || !fits_on_final_line(writer, &branch.body, trailing_comment)
    {
        write_block_body(writer, &wrap_value_body(&branch.body), trailing_comment);
    } else {
        write_unwrapped_body(writer, &branch.body);
    }
}

fn inline_branch(branch: &BranchLayout) -> String {
    let mut output = format!("{} = {}", branch.pattern, branch.future);
    if let Some(divergence) = &branch.divergence {
        output.push_str(" else ");
        output.push_str(divergence);
    }
    output.push_str(" => ");
    output.push_str(&branch.body);
    output.push(',');
    output
}

fn write_branch_head(
    writer: &mut Writer<'_>,
    branch: &BranchLayout,
    trailing_comment: Option<&str>,
) {
    writer.push(&branch.pattern);
    writer.push(" =");
    write_continuation(
        writer,
        &branch.future,
        &branch_head_reserve(writer, branch, trailing_comment),
    );

    if let Some(divergence) = &branch.divergence {
        let first_line = divergence.lines().next().unwrap_or(divergence);
        if writer.fits(&format!(" else {first_line}")) {
            writer.push(" else ");
            writer.push(divergence);
        } else if first_line == "{" {
            if writer.fits_with_overflow(" else {") {
                writer.push(" else ");
            } else {
                writer.newline();
                writer.push("else ");
            }
            writer.push(divergence);
        } else {
            if writer.fits(" else") {
                writer.push(" else");
            } else {
                writer.newline();
                writer.push("else");
            }
            writer.newline();
            writer.indented(|writer| writer.push(divergence));
        }
    }
}

fn branch_head_reserve(
    writer: &Writer<'_>,
    branch: &BranchLayout,
    trailing_comment: Option<&str>,
) -> String {
    let mut reserve = String::new();
    if let Some(divergence) = &branch.divergence {
        if divergence.contains('\n') {
            return reserve;
        }
        reserve.push_str(" else ");
        reserve.push_str(divergence);
    }

    if branch.body_is_block {
        reserve.push_str(" => {");
    } else if !branch.body.contains('\n') {
        let mut direct_body = format!("=> {},", branch.body);
        if let Some(comment) = trailing_comment {
            direct_body.push(' ');
            direct_body.push_str(comment);
        }
        if writer.fits_on_new_line(&direct_body) {
            reserve.push(' ');
            reserve.push_str(&direct_body);
        } else {
            reserve.push_str(" => {");
        }
    } else if branch.wrapped_body.is_some() {
        reserve.push_str(" => {");
    } else {
        reserve.push_str(" => ");
        reserve.push_str(branch.body.lines().next().unwrap_or(&branch.body));
    }
    reserve
}

fn write_continuation(writer: &mut Writer<'_>, fragment: &str, reserve: &str) {
    let first_line = fragment.lines().next().unwrap_or(fragment);
    if writer.fits(&format!(" {first_line}{reserve}")) {
        writer.push(" ");
        writer.push(fragment);
    } else {
        writer.newline();
        writer.indented(|writer| writer.push(fragment));
    }
}

fn write_block_body(writer: &mut Writer<'_>, body: &str, trailing_comment: Option<&str>) {
    let first_line = body.lines().next().unwrap_or(body);
    let prefix = format!(" => {first_line}");
    let first_line_fits = if body.contains('\n') {
        writer.fits(&prefix)
    } else {
        fits_with_trailing_comment(writer, &format!(" => {body},"), trailing_comment)
    };
    if first_line_fits || first_line == "{" && writer.fits_with_overflow(" => {") {
        writer.push(" => ");
    } else if let Some(inner) = body
        .strip_prefix("{ ")
        .and_then(|body| body.strip_suffix(" }"))
    {
        if writer.fits_with_overflow(" => {") {
            writer.push(" => {");
        } else {
            writer.newline();
            writer.push("=> {");
        }
        writer.newline();
        writer.indented(|writer| writer.push(inner));
        writer.newline();
        writer.push("},");
        return;
    } else {
        writer.newline();
        writer.push("=> ");
    }
    writer.push(body);
    writer.push(",");
}

fn write_unwrapped_body(writer: &mut Writer<'_>, body: &str) {
    let first_line = body.lines().next().unwrap_or(body);
    if writer.fits(&format!(" => {first_line}")) {
        writer.push(" => ");
    } else {
        writer.newline();
        writer.push("=> ");
    }
    writer.push(body);
    writer.push(",");
}

fn write_expression_entry(
    writer: &mut Writer<'_>,
    keyword: Option<&str>,
    expression: &str,
    expression_is_block: bool,
) {
    if expression_is_block && let Some(keyword) = keyword {
        writer.push(keyword);
        write_block_body(writer, expression, None);
        return;
    }

    let prefix = keyword.map_or_else(String::new, |keyword| format!("{keyword} => "));
    let inline = format!("{prefix}{expression},");
    if !expression.contains('\n') && writer.fits(&inline) {
        writer.push(&inline);
        return;
    }

    if let Some(keyword) = keyword {
        writer.push(keyword);
        writer.push(" =>");
        writer.newline();
        writer.indented(|writer| {
            writer.push(expression);
            writer.push(",");
        });
    } else {
        writer.push(expression);
        writer.push(",");
    }
}

fn fits_with_trailing_comment(
    writer: &Writer<'_>,
    text: &str,
    trailing_comment: Option<&str>,
) -> bool {
    trailing_comment.map_or_else(
        || writer.fits(text),
        |comment| writer.fits(&format!("{text} {comment}")),
    )
}

fn fits_with_trailing_comment_overflow(
    writer: &Writer<'_>,
    text: &str,
    trailing_comment: Option<&str>,
) -> bool {
    trailing_comment.map_or_else(
        || writer.fits_with_overflow(text),
        |comment| writer.fits_with_overflow(&format!("{text} {comment}")),
    )
}

fn fits_on_final_line(writer: &Writer<'_>, body: &str, trailing_comment: Option<&str>) -> bool {
    let mut final_line = format!("{},", body.lines().last().unwrap_or(body));
    if let Some(comment) = trailing_comment {
        final_line.push(' ');
        final_line.push_str(comment);
    }
    writer.fits_on_new_line(&final_line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::LineEnding;

    const OPTIONS: Options = Options {
        indentation: 0,
        line_ending: LineEnding::Lf,
    };

    fn assert_bounded_width(output: &str) {
        assert!(
            output
                .lines()
                .all(|line| line.chars().count() <= MAX_OVERFLOW_WIDTH),
            "{output}"
        );
    }

    #[test]
    fn formats_short_select_branches() {
        let source = "first=receive_one()=>first,second = receive_two() => second";
        let formatted = select(source, OPTIONS).expect("select should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(
            formatted.text(),
            "\n    first = receive_one() => first,\n    second = receive_two() => second,\n"
        );
    }

    #[test]
    fn keeps_formatted_multiline_body_unwrapped() {
        let source = "value = receive() => value.map(|value| value.with_first_component().with_second_component().with_third_component())";
        let formatted = select(source, OPTIONS).expect("select should format");

        assert!(
            formatted.text().contains("=> value\n"),
            "{}",
            formatted.text()
        );
        assert!(!formatted.text().contains("=> {\n"), "{}", formatted.text());
        syn::parse_str::<SelectInput>(formatted.text()).expect("formatted select should parse");
    }

    #[test]
    fn wraps_over_width_branch_head_after_equals() {
        let options = Options {
            indentation: 8,
            line_ending: LineEnding::Lf,
        };
        let source = "an_extremely_descriptive_pattern_name_that_uses_most_of_the_available_width = another_descriptive_future_name().await => value";
        let once = select(source, options)
            .expect("select should format")
            .into_string();
        let twice = select(&once, options)
            .expect("select should format twice")
            .into_string();

        assert!(once.contains(
            "available_width =\n                another_descriptive_future_name().await"
        ));
        assert_eq!(once, twice);
    }

    #[test]
    fn keeps_short_body_after_multiline_future() {
        let source = "result = async { let value = receive().await; value } => result";
        let once = select(source, OPTIONS)
            .expect("select should format")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("select should format twice")
            .into_string();

        assert!(once.contains("} => result,"), "{once}");
        assert!(!once.contains("=> { result }"), "{once}");
        assert_eq!(once, twice);
    }

    #[test]
    fn keeps_trivial_body_unwrapped_after_long_branch_head() {
        let options = Options {
            indentation: 20,
            line_ending: LineEnding::Lf,
        };
        let source = "result = receive_an_unexpectedly_descriptive_message_from_the_network().await => request.expect(\"request should remain available\")";
        let formatted = select(source, options).expect("select should format");

        assert!(
            formatted
                .text()
                .contains("=> request.expect(\"request should remain available\"),"),
            "{}",
            formatted.text()
        );
        assert!(!formatted.text().contains("=> {\n"), "{}", formatted.text());
    }

    #[test]
    fn keeps_arrow_attached_to_a_short_multiline_body() {
        let options = Options {
            indentation: 16,
            line_ending: LineEnding::Lf,
        };
        let source = "result = receive_an_unexpectedly_descriptive_message_from_the_network().await => match result { Ok(value) => value, Err(error) => return handle(error) }";
        let formatted = select(source, options).expect("select should format");

        assert!(
            formatted.text().contains("=> match result {"),
            "{}",
            formatted.text()
        );
        assert!(
            !formatted
                .text()
                .lines()
                .any(|line| line.trim_start().starts_with("=>")),
            "{}",
            formatted.text()
        );
    }

    #[test]
    fn keeps_divergence_block_attached_to_else() {
        let options = Options {
            indentation: 20,
            line_ending: LineEnding::Lf,
        };
        let source = "Some(value) = receive_an_unexpectedly_descriptive_message_from_the_network().await else { cleanup(); break; } => value";
        let formatted = select_loop(&format!("context,on_stopped=>stop(),{source}"), options)
            .expect("select loop should format");

        assert!(formatted.text().contains("else {"), "{}", formatted.text());
        assert!(!formatted.text().contains("else\n"), "{}", formatted.text());
    }

    #[test]
    fn accounts_for_trailing_shell_comment_width() {
        let options = Options {
            indentation: 20,
            line_ending: LineEnding::Lf,
        };
        let source = "result = receive_a_reasonably_descriptive_message().await => result, // keep this trailing branch context without overflowing the line";
        let formatted = select(source, options).expect("select should format comment");

        assert_bounded_width(formatted.text());
        assert_eq!(formatted.text().matches("// keep this trailing").count(), 1);
    }

    #[test]
    fn retains_source_breaks_when_destination_indentation_would_overflow() {
        let options = Options {
            indentation: 16,
            line_ending: LineEnding::Lf,
        };
        let source = "result = subscription => {\n                    result.expect(\n                        \"notarized reconstruction state should accept the leader shard\",\n                    );\n                }";
        let formatted = select(source, options).expect("select should retain bounded call layout");

        assert!(
            formatted.text().contains("result.expect(\n"),
            "{}",
            formatted.text()
        );
        assert_bounded_width(formatted.text());
    }

    #[test]
    fn preserves_unknown_macro_tokens_in_body() {
        let source = "span=receive()=>info_span!(parent: &span, \"name\")";
        let once = select(source, OPTIONS)
            .expect("select should format")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("select should format twice")
            .into_string();

        assert!(
            once.contains("info_span!(parent: &span, \"name\")"),
            "{once}"
        );
        assert_eq!(once, twice);
    }

    #[test]
    fn preserves_layout_around_multiline_opaque_macro() {
        let source = "value = receive() => option.unwrap_or_else(|| {\n    panic!(\n        \"missing value: {value:?}\"\n    )\n})";
        let formatted = select(source, OPTIONS).expect("select should be preserved");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn wraps_over_width_divergence_after_else() {
        let source = "Some(value) = an_extremely_descriptive_future_name_that_uses_most_of_the_available_width().await else return an_extremely_descriptive_collection_name_that_uses_most_of_the_available_width => value";
        let once = select_loop(&format!("context,on_stopped=>shutdown(),{source}"), OPTIONS)
            .expect("select loop should format")
            .into_string();
        let twice = select_loop(&once, OPTIONS)
            .expect("select loop should format twice")
            .into_string();

        assert!(
            once.contains(".await else\n        return an_extremely_descriptive_collection_name"),
            "{once}"
        );
        assert_eq!(once, twice);
    }

    #[test]
    fn formats_select_loop_entries_and_divergence() {
        let source = "context,on_start=>start(),on_stopped=>stop(),Some(value)=receive() else break=>value,on_end=>finish()";
        let formatted = select_loop(source, OPTIONS).expect("select loop should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(formatted.text().contains("on_start => start(),\n"));
        assert!(
            formatted
                .text()
                .contains("Some(value) = receive() else break => value,\n")
        );
        assert!(formatted.text().contains("on_end => finish(),\n"));
    }

    #[test]
    fn keeps_lifecycle_block_attached_to_keyword() {
        let source = "context,on_start=>{if !start_sync::<E,A,S,V>(&context,&mut state).await{return;}},on_stopped=>{},";
        let once = select_loop(source, OPTIONS)
            .expect("select loop should format")
            .into_string();
        let twice = select_loop(&once, OPTIONS)
            .expect("select loop should format twice")
            .into_string();

        assert!(once.contains("on_start => {\n"), "{once}");
        assert!(once.contains("start_sync::<E, A, S, V>("), "{once}");
        assert_eq!(once, twice);
    }

    #[test]
    fn formats_select_loop_match_body() {
        let source = "context,on_stopped=>{},msg=receive()=>match msg {Some(value)=>values.push(value),None=>break},";
        let formatted = select_loop(source, OPTIONS).expect("select loop should format");

        assert!(formatted.text().contains("=> match msg {"));
        syn::parse_str::<SelectLoopInput>(formatted.text())
            .expect("formatted select loop should parse");
    }

    #[test]
    fn wraps_large_multiline_match_body() {
        let arms = (0..20)
            .map(|value| format!("{value}=>handle_{value}(),"))
            .collect::<String>();
        let source = format!("value=receive()=>match value {{{arms}_=>fallback()}}");
        let formatted = select(&source, OPTIONS).expect("select should format");

        assert!(formatted.text().contains("=> {\n        match value {"));
        syn::parse_str::<SelectInput>(formatted.text()).expect("formatted select should parse");
    }

    #[test]
    fn expands_single_line_block_to_keep_arrow_attached() {
        let options = Options {
            indentation: 24,
            line_ending: LineEnding::Lf,
        };
        let source = "receiver=receiver=>{panic!(\"receiver exited with an unexpectedly descriptive failure: {receiver:?}\")}";
        let formatted = select(source, options).expect("select should format");

        assert!(
            formatted.text().contains("receiver = receiver => {\n"),
            "{}",
            formatted.text()
        );
    }

    #[test]
    fn wraps_long_body_to_keep_arrow_attached() {
        let options = Options {
            indentation: 12,
            line_ending: LineEnding::Lf,
        };
        let source = "result=&mut first=>panic!(\"the selected operation returned an unexpectedly descriptive failure\")";
        let formatted = select(source, options).expect("select should format");

        assert!(
            formatted.text().contains("result = &mut first => {\n"),
            "{}",
            formatted.text()
        );
        assert!(
            !formatted
                .text()
                .lines()
                .any(|line| line.trim_start().starts_with("=>")),
            "{}",
            formatted.text()
        );
    }

    #[test]
    fn keeps_arrow_on_multiline_future_with_bounded_overflow() {
        let options = Options {
            indentation: 8,
            line_ending: LineEnding::Lf,
        };
        let source = "artifact=self.syncer.update_targets(Anchor::from(block.as_ref()),A::sync_targets(block.as_ref()))=>artifact";
        let formatted = select(source, options).expect("select should format");

        assert!(
            formatted.text().contains(")) => {\n"),
            "{}",
            formatted.text()
        );
        assert!(
            !formatted
                .text()
                .lines()
                .any(|line| line.trim_start().starts_with("=>")),
            "{}",
            formatted.text()
        );
    }

    #[test]
    fn formats_select_loop_custom_divergence_block() {
        let source = "context,on_stopped=>{},Some(value)=receive() else { closed = true; break; }=>values.push(value),";
        let once = select_loop(source, OPTIONS)
            .expect("select loop should format")
            .into_string();
        let twice = select_loop(&once, OPTIONS)
            .expect("select loop should format twice")
            .into_string();

        assert!(once.contains("else {\n"));
        assert_eq!(once, twice);
    }

    #[test]
    fn formats_select_loop_without_optional_entries_or_branches() {
        let source = "context,on_stopped=>shutdown(),";
        let formatted = select_loop(source, OPTIONS).expect("select loop should format");

        assert_eq!(
            formatted.text(),
            "\n    context,\n    on_stopped => shutdown(),\n"
        );
    }

    #[test]
    fn rejects_refutable_select_loop_pattern_without_else() {
        let source = "context,on_stopped=>stop(),Some(value)=receive()=>value";
        assert!(matches!(
            select_loop(source, OPTIONS),
            Err(Error::Validate(_))
        ));
    }

    #[test]
    fn formats_structural_line_comment() {
        let source = "\n    // Keep this branch.\n    value = receive() => value,\n";
        let formatted = select(source, OPTIONS).expect("select should format");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(
            formatted.text(),
            "\n    // Keep this branch.\n    value = receive() => value,\n"
        );
    }

    #[test]
    fn formats_structural_comments_in_select_loop() {
        let source = "context,on_stopped=>{},\n// first line\n// second line\nvalue=receive()=>{\n// field comment\nvalue\n},";
        let once = select_loop(source, OPTIONS)
            .expect("select loop should format comments")
            .into_string();
        let twice = select_loop(&once, OPTIONS)
            .expect("select loop should format twice")
            .into_string();

        assert!(
            once.contains("    // first line\n    // second line\n"),
            "{once}"
        );
        assert!(once.contains("        // field comment\n"), "{once}");
        assert_eq!(once, twice);
    }

    #[test]
    fn keeps_trailing_comment_after_branch_comma() {
        let source =
            "first=receive_first()=>first, // keep trailing\nsecond=receive_second()=>second";
        let once = select(source, OPTIONS)
            .expect("select should format trailing comment")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("select should format twice")
            .into_string();

        assert!(once.contains("first = receive_first() => first, // keep trailing\n"));
        assert_eq!(once, twice);
    }

    #[test]
    fn formats_nested_select_inside_commented_shell() {
        let source = "\n    // Keep the outer shell.\n    outer = receive_outer() => select! {inner=receive_inner()=>inner},\n";
        let once = select(source, OPTIONS).expect("nested select should format commented shell");
        assert_eq!(once.disposition(), Disposition::Formatted);
        let once = once.into_string();
        let twice = select(&once, OPTIONS)
            .expect("nested select should format twice")
            .into_string();

        assert!(once.contains("// Keep the outer shell."));
        assert!(once.contains("inner = receive_inner() => inner,"), "{once}");
        assert_eq!(once, twice);
    }

    #[test]
    fn uses_parent_indentation_for_first_line_nested_macro() {
        let options = Options {
            indentation: 8,
            line_ending: LineEnding::Lf,
        };
        let source =
            "/* keep seam */ outer=receive_outer()=>select! {inner=receive_inner()=>inner}";
        let formatted = select(source, options).expect("nested select should format safely");

        assert!(
            formatted
                .text()
                .contains("select! {\n            inner = receive_inner() => inner,\n        }")
        );
    }

    #[test]
    fn formats_shell_around_single_line_protected_fragment() {
        let source = "value=receive()=>call(/* keep exactly */ value)";
        let formatted = select(source, OPTIONS).expect("select should format safely");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(
            formatted.text(),
            "\n    value = receive() => call(/* keep exactly */ value),\n"
        );
    }

    #[test]
    fn formats_select_loop_around_single_line_protected_lifecycle() {
        let source = "context,on_stopped=>shutdown(/* keep exactly */),value=receive()=>value";
        let formatted = select_loop(source, OPTIONS).expect("select loop should format safely");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert!(
            formatted
                .text()
                .contains("on_stopped => shutdown(/* keep exactly */),\n")
        );
    }

    #[test]
    fn preserves_comment_at_structural_seam() {
        let source = "value = receive() /* keep seam */ => value";
        let formatted = select(source, OPTIONS).expect("select should be preserved");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn preserves_blank_line_between_branches() {
        let source = "first = receive_first() => first,\n\nsecond = receive_second() => second,";
        let formatted = select(source, OPTIONS).expect("select should be protected");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn preserves_blank_line_between_select_loop_entries() {
        let source = "context,\non_stopped => {},\n\nvalue = receive() => value,";
        let formatted = select_loop(source, OPTIONS).expect("select loop should be protected");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
    }

    #[test]
    fn formats_multiline_literal_in_select_without_changing_token() {
        let literal = "r#\"first\n    second\"#";
        let source = format!("value=receive()=>consume({literal})");
        let formatted = select(&source, OPTIONS).expect("select should format");
        let twice = select(formatted.text(), OPTIONS).expect("select should format twice");

        assert_eq!(formatted.disposition(), Disposition::Formatted);
        assert_eq!(formatted.text().matches(literal).count(), 1);
        assert!(formatted.text().contains("value = receive() => consume("));
        assert_eq!(formatted.text(), twice.text());
    }

    #[test]
    fn select_reaches_fixed_point() {
        let source = "first=receive_one()=>first,second = receive_two() => second";
        let once = select(source, OPTIONS)
            .expect("select should format")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("select should format twice")
            .into_string();

        assert_eq!(once, twice);
    }

    #[test]
    fn recursively_formats_nested_select() {
        let source = "outer=receive_outer()=>select! {inner=receive_inner()=>inner}";
        let once = select(source, OPTIONS)
            .expect("nested select should format")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("nested select should format twice")
            .into_string();

        assert!(
            once.contains("select! {\n        inner = receive_inner() => inner,\n    }"),
            "{once}"
        );
        assert_eq!(once, twice);
    }

    #[test]
    fn formats_outer_comments_around_nested_select() {
        let source = "outer=receive_outer()=>{\n// before nested\nlet value=select! {\n// inside nested\ninner=receive_inner()=>inner\n};\n// after nested\nvalue\n}";
        let once = select(source, OPTIONS)
            .expect("nested select and comments should format")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("nested select and comments should format twice")
            .into_string();

        assert_eq!(once.matches("// before nested").count(), 1);
        assert_eq!(once.matches("// inside nested").count(), 1);
        assert_eq!(once.matches("// after nested").count(), 1);
        assert!(once.contains("inner = receive_inner() => inner,"), "{once}");
        assert_eq!(once, twice);
    }

    #[test]
    fn recursively_formats_nested_select_loop() {
        let source = "outer=receive_outer()=>select_loop! {context,on_stopped=>shutdown(),inner=receive_inner()=>inner}";
        let once = select(source, OPTIONS)
            .expect("nested select loop should format")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("nested select loop should format twice")
            .into_string();

        assert!(once.contains("select_loop! {\n        context,"), "{once}");
        assert_eq!(once, twice);
    }

    #[test]
    fn recursively_formats_sibling_nested_selects_with_marker_collision() {
        let source = "outer=receive_outer()=>{let __commonware_fmt_nested_0_0=0;let first=select! {value=receive_first()=>value};let second=select! {value=receive_second()=>value};(first,second,__commonware_fmt_nested_0_0)}";
        let once = select(source, OPTIONS)
            .expect("sibling selects should format")
            .into_string();
        let twice = select(&once, OPTIONS)
            .expect("sibling selects should format twice")
            .into_string();

        assert_eq!(once.matches("value = receive_").count(), 2);
        assert_eq!(once, twice);
    }

    #[test]
    fn accepts_every_legacy_marker_prefix_without_nested_macros() {
        let arguments = (0..1_000)
            .map(|nonce| format!("\"__commonware_fmt_nested_{nonce}_\""))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!("outer=receive_outer()=>consume({arguments})");

        select(&source, OPTIONS).expect("legacy marker text should not block formatting");
    }

    #[test]
    fn bounds_nested_select_recursion() {
        let mut body = "value".to_owned();
        for depth in 0..34 {
            body = format!("select! {{value_{depth}=receive_{depth}()=>{body}}}");
        }
        let source = format!("outer=receive_outer()=>{body}");

        assert!(matches!(
            select(&source, OPTIONS),
            Err(Error::RecursionLimit)
        ));
    }

    #[test]
    fn bounds_preserved_nested_select_recursion() {
        let mut body = "value".to_owned();
        for depth in 0..34 {
            body = format!(
                "select! {{\n// keep shell {depth}\nvalue_{depth}=receive_{depth}()=>{body}\n}}"
            );
        }
        let source = format!("/* keep outer shell */ outer=receive_outer()=>{body}");

        assert!(matches!(
            select(&source, OPTIONS),
            Err(Error::RecursionLimit)
        ));
    }

    #[test]
    fn emits_requested_indentation_and_line_ending() {
        let options = Options {
            indentation: 8,
            line_ending: LineEnding::Crlf,
        };
        let formatted = select("value=receive()=>value", options).expect("select should format");

        assert_eq!(
            formatted.text(),
            "\r\n            value = receive() => value,\r\n        "
        );
    }
}
