//! Parse cfg_if! blocks to extract module declarations.
//!
//! This module handles the common pattern of declaring modules inside cfg_if! blocks:
//! ```rust,ignore
//! cfg_if::cfg_if! {
//!     if #[cfg(feature = "std")] {
//!         pub mod journal;
//!     }
//! }
//! ```

use std::collections::HashSet;

/// Extract only public module names from cfg_if! blocks.
/// Returns a set of module names that are declared as `pub mod`.
pub fn extract_public_modules_from_cfg_if(content: &str) -> HashSet<String> {
    let mut modules = HashSet::new();

    // Find cfg_if! blocks using simple string matching
    for cfg_if_match in find_cfg_if_blocks(content) {
        parse_cfg_if_block_public_only(&cfg_if_match, &mut modules);
    }

    modules
}

/// Find all cfg_if! blocks in the content.
fn find_cfg_if_blocks(content: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut chars = content.char_indices();

    while let Some((pos, _)) = chars.next() {
        // Look for "cfg_if::cfg_if!" or just "cfg_if!"
        let rest = &content[pos..];
        if rest.starts_with("cfg_if::cfg_if!") || rest.starts_with("cfg_if!") {
            let start = pos;
            // Find the opening brace
            let brace_offset = match rest.find('{') {
                Some(offset) => offset,
                None => continue,
            };
            let brace_pos = pos + brace_offset;

            // Find the matching closing brace
            if let Some(end) = find_matching_brace(&content[brace_pos..]) {
                let block = content[start..brace_pos + end + 1].to_string();
                blocks.push(block);
                // Skip past this block
                for _ in 0..(brace_pos + end - pos) {
                    chars.next();
                }
            }
        }
    }

    blocks
}

/// Find the position of the matching closing brace.
fn find_matching_brace(content: &str) -> Option<usize> {
    let mut depth = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, c) in content.chars().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }

    None
}

/// Parse a cfg_if! block to extract only public module declarations.
fn parse_cfg_if_block_public_only(block: &str, modules: &mut HashSet<String>) {
    // Look for module declarations like: pub mod name;
    for line in block.lines() {
        let line = line.trim();
        if let Some(mod_name) = parse_public_mod_declaration(line) {
            modules.insert(mod_name);
        }
    }
}

/// Parse a public module declaration line like "pub mod name;".
/// Only returns modules declared with `pub mod`, not `mod` or `pub(crate) mod`.
fn parse_public_mod_declaration(line: &str) -> Option<String> {
    let line = line.trim();

    // Only match fully public modules: "pub mod "
    // Must NOT match "pub(crate) mod " or "pub(super) mod "
    if line.starts_with("pub mod ") {
        let rest = &line[8..]; // "pub mod ".len() == 8
                               // Extract module name (up to ; or {)
        let end = rest.find(|c| c == ';' || c == '{').unwrap_or(rest.len());
        let name = rest[..end].trim().to_string();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_public_mod_declaration() {
        // Public modules should be matched
        assert_eq!(
            parse_public_mod_declaration("pub mod journal;"),
            Some("journal".to_string())
        );
        assert_eq!(
            parse_public_mod_declaration("pub mod inline {"),
            Some("inline".to_string())
        );

        // Non-public should NOT be matched
        assert_eq!(parse_public_mod_declaration("mod helpers;"), None);
        assert_eq!(
            parse_public_mod_declaration("pub(crate) mod internal;"),
            None
        );
        assert_eq!(
            parse_public_mod_declaration("pub(super) mod internal;"),
            None
        );
        assert_eq!(parse_public_mod_declaration("let x = 1;"), None);
    }

    #[test]
    fn test_extract_public_modules_from_cfg_if() {
        let content = r#"
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod journal;
        mod private_mod;
        pub(crate) mod internal;
        pub mod cache;
    }
}
"#;
        let modules = extract_public_modules_from_cfg_if(content);
        // Only public modules should be extracted
        assert!(modules.contains("journal"));
        assert!(modules.contains("cache"));
        // Private and pub(crate) should NOT be included
        assert!(!modules.contains("private_mod"));
        assert!(!modules.contains("internal"));
    }
}
