//! Formatters for `select!` and `select_loop!` bodies.

use super::{Error, Options};
use crate::{
    pretty::{self, Disposition, ProtectedFragment},
    source::SourceMap,
    writer::Writer,
};
use commonware_macros_grammar::{
    SelectBranch, SelectInput, SelectLoopBranch, SelectLoopInput, SelectLoopLifecycle,
};
use proc_macro2::Span;
use std::ops::Range;
use syn::{Expr, spanned::Spanned};

struct BranchLayout {
    pattern: String,
    future: String,
    divergence: Option<String>,
    body: String,
    body_is_block: bool,
}

struct LifecycleLayout {
    keyword: String,
    expression: String,
}

/// Formats the delimiter contents of a `select!` invocation.
pub fn select(source: &str, options: Options) -> Result<ProtectedFragment, Error> {
    let input = syn::parse_str::<SelectInput>(source).map_err(Error::Parse)?;
    let source_map = SourceMap::new(source);
    if select_has_structural_trivia(source, &source_map, &input)? {
        return Ok(ProtectedFragment::preserved(source));
    }
    let mut branches = Vec::with_capacity(input.branches.len());
    for branch in &input.branches {
        let Some(branch) = format_select_branch(&source_map, branch)? else {
            return Ok(ProtectedFragment::preserved(source));
        };
        branches.push(branch);
    }

    let output = render(options, |writer| {
        for branch in &branches {
            write_branch(writer, branch);
            writer.newline();
        }
    });
    syn::parse_str::<SelectInput>(&output).map_err(Error::Output)?;
    Ok(ProtectedFragment::formatted(output))
}

/// Formats the delimiter contents of a `select_loop!` invocation.
pub fn select_loop(source: &str, options: Options) -> Result<ProtectedFragment, Error> {
    let input = syn::parse_str::<SelectLoopInput>(source).map_err(Error::Parse)?;
    input.validate().map_err(Error::Validate)?;
    let source_map = SourceMap::new(source);
    if select_loop_has_structural_trivia(source, &source_map, &input)? {
        return Ok(ProtectedFragment::preserved(source));
    }
    let Some(context) = format_expression(&source_map, &input.context)? else {
        return Ok(ProtectedFragment::preserved(source));
    };
    let on_start = match &input.on_start {
        Some(lifecycle) => {
            let Some(lifecycle) = format_lifecycle(&source_map, lifecycle)? else {
                return Ok(ProtectedFragment::preserved(source));
            };
            Some(lifecycle)
        }
        None => None,
    };

    render_select_loop(source, options, &input, &source_map, context, on_start)
}

fn render_select_loop(
    source: &str,
    options: Options,
    input: &SelectLoopInput,
    source_map: &SourceMap<'_>,
    context: String,
    on_start: Option<LifecycleLayout>,
) -> Result<ProtectedFragment, Error> {
    let Some(on_stopped) = format_lifecycle(source_map, &input.on_stopped)? else {
        return Ok(ProtectedFragment::preserved(source));
    };
    let mut branches = Vec::with_capacity(input.branches.len());
    for branch in &input.branches {
        let Some(branch) = format_select_loop_branch(source_map, branch)? else {
            return Ok(ProtectedFragment::preserved(source));
        };
        branches.push(branch);
    }
    let on_end = match &input.on_end {
        Some(lifecycle) => {
            let Some(lifecycle) = format_lifecycle(source_map, lifecycle)? else {
                return Ok(ProtectedFragment::preserved(source));
            };
            Some(lifecycle)
        }
        None => None,
    };

    let output = render(options, |writer| {
        write_expression_entry(writer, None, &context);
        writer.newline();
        if let Some(on_start) = &on_start {
            write_expression_entry(writer, Some(&on_start.keyword), &on_start.expression);
            writer.newline();
        }
        write_expression_entry(writer, Some(&on_stopped.keyword), &on_stopped.expression);
        writer.newline();
        for branch in &branches {
            write_branch(writer, branch);
            writer.newline();
        }
        if let Some(on_end) = &on_end {
            write_expression_entry(writer, Some(&on_end.keyword), &on_end.expression);
            writer.newline();
        }
    });
    let reparsed = syn::parse_str::<SelectLoopInput>(&output).map_err(Error::Output)?;
    reparsed.validate().map_err(Error::Validate)?;
    Ok(ProtectedFragment::formatted(output))
}

fn format_select_branch(
    source_map: &SourceMap<'_>,
    branch: &SelectBranch,
) -> Result<Option<BranchLayout>, Error> {
    format_branch(
        source_map,
        &branch.pattern,
        &branch.future,
        None,
        &branch.body,
    )
}

fn format_select_loop_branch(
    source_map: &SourceMap<'_>,
    branch: &SelectLoopBranch,
) -> Result<Option<BranchLayout>, Error> {
    format_branch(
        source_map,
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
    source_map: &SourceMap<'_>,
    pattern: &syn::Pat,
    future: &Expr,
    divergence: Option<&Expr>,
    body: &Expr,
) -> Result<Option<BranchLayout>, Error> {
    let body_is_block = matches!(body, Expr::Block(_));
    let pattern_source = spanned_source(source_map, pattern)?;
    let future_source = spanned_source(source_map, future)?;
    let body_source = spanned_source(source_map, body)?;
    let pattern = pretty::pattern(pattern, pattern_source)?;
    let future = pretty::expression(future, future_source)?;
    let body = pretty::expression(body, body_source)?;
    let divergence = divergence
        .map(|expression| {
            let expression_source = spanned_source(source_map, expression)?;
            pretty::expression(expression, expression_source).map_err(Error::from)
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
    }))
}

fn format_lifecycle(
    source_map: &SourceMap<'_>,
    lifecycle: &SelectLoopLifecycle,
) -> Result<Option<LifecycleLayout>, Error> {
    let Some(expression) = format_expression(source_map, &lifecycle.expression)? else {
        return Ok(None);
    };
    Ok(Some(LifecycleLayout {
        keyword: lifecycle.keyword.to_string(),
        expression,
    }))
}

fn format_expression(
    source_map: &SourceMap<'_>,
    expression: &Expr,
) -> Result<Option<String>, Error> {
    let expression_source = spanned_source(source_map, expression)?;
    let expression = pretty::expression(expression, expression_source)?;
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
    fragment.disposition() == Disposition::PreservedForTrivia
        && (fragment.text().contains('\n') || fragment.text().contains('\r'))
}

fn select_has_structural_trivia(
    source: &str,
    source_map: &SourceMap<'_>,
    input: &SelectInput,
) -> Result<bool, Error> {
    let mut spans = Vec::new();
    for branch in &input.branches {
        spans.extend([
            branch.pattern.span(),
            branch.eq_token.span(),
            branch.future.span(),
            branch.fat_arrow_token.span(),
            branch.body.span(),
        ]);
        spans.extend(branch.comma_token.as_ref().map(Spanned::span));
    }
    has_unowned_source(source, source_map, spans)
}

fn select_loop_has_structural_trivia(
    source: &str,
    source_map: &SourceMap<'_>,
    input: &SelectLoopInput,
) -> Result<bool, Error> {
    let mut spans = vec![input.context.span(), input.context_comma_token.span()];
    if let Some(on_start) = &input.on_start {
        push_lifecycle_spans(&mut spans, on_start);
    }
    push_lifecycle_spans(&mut spans, &input.on_stopped);
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
    }
    if let Some(on_end) = &input.on_end {
        push_lifecycle_spans(&mut spans, on_end);
    }
    has_unowned_source(source, source_map, spans)
}

fn push_lifecycle_spans(spans: &mut Vec<Span>, lifecycle: &SelectLoopLifecycle) {
    spans.extend([
        lifecycle.keyword.span(),
        lifecycle.fat_arrow_token.span(),
        lifecycle.expression.span(),
    ]);
    spans.extend(lifecycle.comma_token.as_ref().map(Spanned::span));
}

fn has_unowned_source(
    source: &str,
    source_map: &SourceMap<'_>,
    spans: Vec<Span>,
) -> Result<bool, Error> {
    let mut ranges = spans
        .into_iter()
        .map(|span| source_map.span_range(span))
        .collect::<Result<Vec<Range<usize>>, _>>()?;
    ranges.sort_unstable_by_key(|range| (range.start, range.end));

    let mut cursor = 0;
    for range in ranges {
        if range.start > cursor && !source[cursor..range.start].chars().all(char::is_whitespace) {
            return Ok(true);
        }
        cursor = cursor.max(range.end);
    }
    Ok(source[cursor..]
        .chars()
        .any(|character| !character.is_whitespace()))
}

fn render(options: Options, write: impl FnOnce(&mut Writer<'_>)) -> String {
    let mut writer = Writer::new(options.indentation, options.line_ending.as_str());
    writer.newline();
    writer.indented(write);
    writer.pad_to_indentation();
    writer.finish()
}

fn write_branch(writer: &mut Writer<'_>, branch: &BranchLayout) {
    let inline = inline_branch(branch);
    if !inline.contains('\n') && writer.fits(&inline) {
        writer.push(&inline);
        return;
    }

    write_branch_head(writer, branch);
    if branch.body_is_block {
        write_block_body(writer, &branch.body);
    } else {
        write_value_body(writer, &branch.body);
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

fn write_branch_head(writer: &mut Writer<'_>, branch: &BranchLayout) {
    writer.push(&branch.pattern);
    writer.push(" =");
    write_continuation(writer, &branch.future);

    if let Some(divergence) = &branch.divergence {
        let first_line = divergence.lines().next().unwrap_or(divergence);
        if writer.fits(&format!(" else {first_line}")) {
            writer.push(" else ");
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

fn write_continuation(writer: &mut Writer<'_>, fragment: &str) {
    let first_line = fragment.lines().next().unwrap_or(fragment);
    if writer.fits(&format!(" {first_line}")) {
        writer.push(" ");
        writer.push(fragment);
    } else {
        writer.newline();
        writer.indented(|writer| writer.push(fragment));
    }
}

fn write_block_body(writer: &mut Writer<'_>, body: &str) {
    let first_line = body.lines().next().unwrap_or(body);
    let prefix = format!(" => {first_line}");
    if writer.fits(&prefix) {
        writer.push(" => ");
    } else {
        writer.newline();
        writer.push("=> ");
    }
    writer.push(body);
    writer.push(",");
}

fn write_value_body(writer: &mut Writer<'_>, body: &str) {
    let inline = format!(" => {body},");
    if !body.contains('\n') && writer.fits(&inline) {
        writer.push(&inline);
        return;
    }

    let mut started_new_line = false;
    if !body.contains('\n') {
        let compact_block = format!("=> {{ {body} }},");
        writer.newline();
        started_new_line = true;
        if writer.fits(&compact_block) {
            writer.push(&compact_block);
            return;
        }
    }

    if !started_new_line && writer.fits(" => {") {
        writer.push(" => {");
    } else {
        if !started_new_line {
            writer.newline();
        }
        writer.push("=> {");
    }
    writer.newline();
    writer.indented(|writer| {
        writer.push(body);
        writer.newline();
    });
    writer.push("},");
}

fn write_expression_entry(writer: &mut Writer<'_>, keyword: Option<&str>, expression: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::LineEnding;

    const OPTIONS: Options = Options {
        indentation: 0,
        line_ending: LineEnding::Lf,
    };

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
    fn wraps_long_non_block_body() {
        let source = "value = receive() => value.map(|value| value.with_first_component().with_second_component().with_third_component())";
        let formatted = select(source, OPTIONS).expect("select should format");

        assert!(formatted.text().contains("=> {\n"));
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
    fn formats_select_loop_match_body() {
        let source = "context,on_stopped=>{},msg=receive()=>match msg {Some(value)=>values.push(value),None=>break},";
        let formatted = select_loop(source, OPTIONS).expect("select loop should format");

        assert!(formatted.text().contains("=> {\n        match msg {"));
        syn::parse_str::<SelectLoopInput>(formatted.text())
            .expect("formatted select loop should parse");
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
    fn preserves_comment_bearing_select() {
        let source = "\n    // Keep this branch.\n    value = receive() => value,\n";
        let formatted = select(source, OPTIONS).expect("select should be preserved");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
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
    fn preserves_multiline_literal_in_select() {
        let source = "value = receive() => r#\"first\n    second\"#";
        let formatted = select(source, OPTIONS).expect("select should be preserved");

        assert_eq!(formatted.disposition(), Disposition::PreservedForTrivia);
        assert_eq!(formatted.text(), source);
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
