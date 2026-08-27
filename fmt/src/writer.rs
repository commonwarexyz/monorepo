//! Small indentation-aware writer for custom macro shells.

const INDENT: usize = 4;
pub(crate) const MAX_WIDTH: usize = 89;

pub(crate) struct Writer<'a> {
    output: String,
    line_ending: &'a str,
    indentation: usize,
    column: usize,
    at_line_start: bool,
}

impl<'a> Writer<'a> {
    pub(crate) const fn new(indentation: usize, line_ending: &'a str) -> Self {
        Self {
            output: String::new(),
            line_ending,
            indentation,
            column: 0,
            at_line_start: true,
        }
    }

    pub(crate) const fn new_inline(indentation: usize, line_ending: &'a str) -> Self {
        Self {
            output: String::new(),
            line_ending,
            indentation,
            column: indentation,
            at_line_start: false,
        }
    }

    pub(crate) fn push(&mut self, text: &str) {
        for (index, line) in text.split('\n').enumerate() {
            if index != 0 {
                self.newline();
            }
            if !line.is_empty() {
                self.ensure_indentation();
                self.output.push_str(line);
                self.column += line.chars().count();
            }
        }
    }

    pub(crate) fn newline(&mut self) {
        self.output.push_str(self.line_ending);
        self.column = 0;
        self.at_line_start = true;
    }

    pub(crate) fn indented(&mut self, write: impl FnOnce(&mut Self)) {
        self.indentation += INDENT;
        write(self);
        self.indentation -= INDENT;
    }

    pub(crate) fn fits(&self, additional: &str) -> bool {
        self.current_column() + additional.chars().count() <= MAX_WIDTH
    }

    pub(crate) fn pad_to_indentation(&mut self) {
        self.ensure_indentation();
    }

    pub(crate) fn finish(self) -> String {
        self.output
    }

    const fn current_column(&self) -> usize {
        if self.at_line_start {
            self.indentation
        } else {
            self.column
        }
    }

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
