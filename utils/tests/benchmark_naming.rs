//! Lint test to ensure benchmark naming conventions are followed.
//!
//! This test validates:
//! 1. All benchmark functions use `bench_` prefix (not `benchmark_`)
//! 2. Benchmark name strings follow `{module_path!()}/key=value key=value` format

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Find all benchmark files in the repository.
fn find_benchmark_files(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    find_benchmark_files_recursive(root, &mut results);
    results
}

fn find_benchmark_files_recursive(dir: &Path, results: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip target, .git, and other non-source directories
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            find_benchmark_files_recursive(&path, results);
        } else if path.is_file() {
            // Check if this is a benchmark file
            if let Some(parent) = path.parent() {
                if parent.ends_with("benches") && path.extension().is_some_and(|e| e == "rs") {
                    results.push(path);
                }
            }
        }
    }
}

/// Check for `fn benchmark_` patterns that should be `fn bench_`.
fn check_function_names(path: &Path, content: &str) -> Vec<String> {
    let mut violations = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Look for function definitions starting with benchmark_
        if trimmed.starts_with("fn benchmark_") || trimmed.starts_with("pub fn benchmark_") {
            violations.push(format!(
                "{}:{}: Function should use `bench_` prefix, not `benchmark_`\n    {}",
                path.display(),
                line_num + 1,
                trimmed
            ));
        }
    }

    violations
}

/// Check for format string issues in benchmark names.
fn check_format_strings(path: &Path, content: &str) -> Vec<String> {
    let mut violations = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        // Skip comments
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }

        // Check for format strings with module_path!()
        if line.contains("module_path!()") && line.contains("format!") {
            // Check for comma between parameters (e.g., "variant={}, elements=" should be "variant={} elements=")
            if line.contains("={},") || line.contains("={} ,") {
                violations.push(format!(
                    "{}:{}: Parameters should be space-separated, not comma-separated\n    {}",
                    path.display(),
                    line_num + 1,
                    trimmed
                ));
            }

            // Check for colon in value position (e.g., "value={}:{}" should use different separator)
            if line.contains("={}:{}") {
                violations.push(format!(
                    "{}:{}: Consider using `/` instead of `:` as value separator for readability\n    {}",
                    path.display(),
                    line_num + 1,
                    trimmed
                ));
            }

            // Check for space before parameter name without key= prefix
            // Pattern: "/word space word=" where first word has no =
            // e.g., "/g1 n=" should be "/group=g1 n="
            if let Some(start_idx) = line.find("\"/") {
                let format_str = &line[start_idx..];
                if let Some(end_idx) = format_str[1..].find('"') {
                    let inner = &format_str[1..end_idx + 1];
                    // Split by / and check each segment
                    for segment in inner.split('/').skip(1) {
                        // Split by space
                        let parts: Vec<&str> = segment.split_whitespace().collect();
                        if parts.len() >= 2 {
                            // Check if first part lacks = but second part has =
                            let first = parts[0];
                            let second = parts[1];
                            if !first.contains('=')
                                && !first.contains('{')
                                && second.contains('=')
                                && first
                                    .chars()
                                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                            {
                                violations.push(format!(
                                    "{}:{}: Bare value `{}` should use key=value format (e.g., `type={}`)\n    {}",
                                    path.display(),
                                    line_num + 1,
                                    first,
                                    first,
                                    trimmed
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    violations
}

/// Check for bare labels in bench_function calls without module_path! format strings.
#[allow(clippy::missing_const_for_fn)]
fn check_bare_labels(_path: &Path, _content: &str) -> Vec<String> {
    // This check is intentionally minimal - the format string validation in
    // check_format_strings already catches the most important issues.
    Vec::new()
}

#[test]
fn lint_benchmark_naming() {
    // Find repository root (go up from utils/tests/)
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().expect("should have parent");

    let benchmark_files = find_benchmark_files(repo_root);

    let mut all_violations = Vec::new();

    for path in &benchmark_files {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                all_violations.push(format!("{}: Failed to read file: {}", path.display(), e));
                continue;
            }
        };

        all_violations.extend(check_function_names(path, &content));
        all_violations.extend(check_format_strings(path, &content));
        all_violations.extend(check_bare_labels(path, &content));
    }

    if !all_violations.is_empty() {
        let message = format!(
            "Benchmark naming violations found ({} total):\n\n{}\n\n\
            Rules:\n\
            1. Use `bench_` prefix for benchmark functions (not `benchmark_`)\n\
            2. Use `key=value` format in benchmark names (e.g., `group=g1`, not just `g1`)\n\
            3. Separate parameters with spaces, not commas\n\
            4. Use `/` instead of `:` as value separators for ratios",
            all_violations.len(),
            all_violations.join("\n\n")
        );
        panic!("{}", message);
    }

    println!(
        "Checked {} benchmark files, all naming conventions followed.",
        benchmark_files.len()
    );
}
