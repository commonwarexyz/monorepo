//! Trace mutation helpers.
//!
//! The canonical (Trace-native) mutator lives in [`canonical`]. This module
//! only exposes a small filesystem utility shared with the canonical driver
//! and its supporting binaries.

pub mod canonical;

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Recursively walks `dir` and returns every `*.json` path under it,
/// sorted lexicographically for deterministic ordering across platforms.
pub fn find_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("warning: cannot read {}: {e}", dir.display());
            return out;
        }
    };
    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    children.sort();
    for path in children {
        if path.is_dir() {
            // Skip hidden directories (e.g. .seen marker dir)
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                continue;
            }
            out.extend(find_json_files(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out
}
