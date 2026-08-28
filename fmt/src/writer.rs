//! Small indentation-aware writer for custom macro shells.
//!
//! Indentation is emitted lazily for non-empty lines, which avoids introducing
//! trailing whitespace while a layout is assembled. Embedded LF separators are
//! rewritten with the destination file's configured line ending.

/// Number of columns in one shell indentation level.
const INDENT: usize = 4;
/// Preferred maximum column for custom shell layout.
pub(crate) const MAX_WIDTH: usize = 89;
/// Maximum column allowed for compact forms that tolerate limited overflow.
pub(crate) const MAX_OVERFLOW_WIDTH: usize = 100;

/// Accumulates a macro shell while tracking indentation and the current column.
///
/// Column accounting counts Unicode scalar values rather than terminal display
/// width. Generated shell syntax is ASCII, while source fragments retain their
/// original characters.
pub(crate) struct Writer<'a> {
    output: String,
    line_ending: &'a str,
    indentation: usize,
    column: usize,
    at_line_start: bool,
}

impl<'a> Writer<'a> {
    /// Creates a writer positioned at the logical start of a new line.
    ///
    /// The configured indentation is deferred until content is written.
    pub(crate) const fn new(indentation: usize, line_ending: &'a str) -> Self {
        Self {
            output: String::new(),
            line_ending,
            indentation,
            column: 0,
            at_line_start: true,
        }
    }

    /// Creates a writer positioned on an existing line at `indentation`.
    ///
    /// No leading spaces are emitted. Lines created later use the same configured
    /// indentation.
    pub(crate) const fn new_inline(indentation: usize, line_ending: &'a str) -> Self {
        Self {
            output: String::new(),
            line_ending,
            indentation,
            column: indentation,
            at_line_start: false,
        }
    }

    /// Appends text and indents each non-empty line that begins at a line boundary.
    pub(crate) fn push(&mut self, text: &str) {
        // Formatted fragments use LF as their logical separator. Route every break
        // through `newline` so rendered shells retain the destination convention.
        for (index, line) in text.split('\n').enumerate() {
            if index != 0 {
                self.newline();
            }
            if !line.is_empty() {
                // Empty segments stay indentation-free unless the caller explicitly
                // requests padding for a following delimiter.
                self.ensure_indentation();
                self.output.push_str(line);
                self.column += line.chars().count();
            }
        }
    }

    /// Appends the configured line ending and moves to a pending line start.
    pub(crate) fn newline(&mut self) {
        self.output.push_str(self.line_ending);
        self.column = 0;
        self.at_line_start = true;
    }

    /// Adds one indentation level for the duration of `write`.
    ///
    /// Increasing indentation affects content written at a line start. It does not
    /// insert spaces into a line that is already open.
    pub(crate) fn indented(&mut self, write: impl FnOnce(&mut Self)) {
        self.indentation += INDENT;
        write(self);
        self.indentation -= INDENT;
    }

    /// Returns whether single-line `additional` text fits the preferred width.
    pub(crate) fn fits(&self, additional: &str) -> bool {
        self.current_column() + additional.chars().count() <= MAX_WIDTH
    }

    /// Returns whether single-line text fits the limited-overflow width.
    pub(crate) fn fits_with_overflow(&self, additional: &str) -> bool {
        self.current_column() + additional.chars().count() <= MAX_OVERFLOW_WIDTH
    }

    /// Returns whether single-line `text` fits from the configured indentation.
    pub(crate) fn fits_on_new_line(&self, text: &str) -> bool {
        self.indentation + text.chars().count() <= MAX_WIDTH
    }

    /// Materializes pending indentation without appending other content.
    ///
    /// Shell renderers use this before returning control to an outer delimiter that
    /// is not part of the writer's output.
    pub(crate) fn pad_to_indentation(&mut self) {
        self.ensure_indentation();
    }

    /// Returns the accumulated shell text.
    pub(crate) fn finish(self) -> String {
        self.output
    }

    /// Returns the column where newly appended single-line text would begin.
    const fn current_column(&self) -> usize {
        // Pending indentation is part of width even though it has not been emitted.
        if self.at_line_start {
            self.indentation
        } else {
            self.column
        }
    }

    /// Emits indentation if the writer is at the start of a line.
    fn ensure_indentation(&mut self) {
        if !self.at_line_start {
            return;
        }
        self.output
            .extend(std::iter::repeat_n(' ', self.indentation));
        self.column = self.indentation;
        self.at_line_start = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indents_multiline_text() {
        let mut writer = Writer::new(0, "\n");
        writer.newline();
        writer.indented(|writer| writer.push("first\n    second"));
        writer.newline();
        writer.pad_to_indentation();

        assert_eq!(writer.finish(), "\n    first\n        second\n");
    }

    #[test]
    fn preserves_requested_line_ending() {
        let mut writer = Writer::new(0, "\r\n");
        writer.push("first\nsecond");

        assert_eq!(writer.finish(), "first\r\nsecond");
    }

    #[test]
    fn accounts_for_pending_indentation_when_fitting() {
        let writer = Writer::new(88, "\n");
        assert!(writer.fits("x"));
        assert!(!writer.fits("xy"));
        assert!(writer.fits_with_overflow("123456789012"));
        assert!(!writer.fits_with_overflow("1234567890123"));
    }

    #[test]
    fn checks_fit_from_configured_indentation() {
        let writer = Writer::new_inline(80, "\n");

        assert!(writer.fits_on_new_line("123456789"));
        assert!(!writer.fits_on_new_line("1234567890"));
    }

    #[test]
    fn starts_inline_then_uses_configured_indentation() {
        let mut writer = Writer::new_inline(4, "\n");
        writer.push("first");
        writer.newline();
        writer.push("second");

        assert_eq!(writer.finish(), "first\n    second");
    }
}
