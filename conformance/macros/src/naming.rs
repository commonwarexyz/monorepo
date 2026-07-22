/// Convert a type to a valid snake_case function name suffix.
///
/// Inserts underscores at PascalCase boundaries and replaces punctuation
/// with underscores. Consecutive separators are collapsed.
pub(crate) fn type_to_ident(type_name: &str) -> String {
    let mut result = String::with_capacity(type_name.len());
    let mut previous_was_separator = true;

    for character in type_name.chars() {
        match character {
            'A'..='Z' => {
                if !previous_was_separator && !result.is_empty() {
                    result.push('_');
                }
                result.push(character.to_ascii_lowercase());
                previous_was_separator = false;
            }
            'a'..='z' | '0'..='9' => {
                result.push(character);
                previous_was_separator = false;
            }
            _ => {
                if !previous_was_separator && !result.is_empty() {
                    result.push('_');
                }
                previous_was_separator = true;
            }
        }
    }

    result.trim_end_matches('_').to_string()
}
