use std::collections::HashSet;
use syn::{Item, UseTree};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependency {
    pub crate_name: String,
    pub path_segments: Vec<String>,
}

pub fn parse_dependencies(content: &str) -> Vec<Dependency> {
    let Ok(file) = syn::parse_file(content) else {
        return Vec::new();
    };

    let mut deps = Vec::new();
    let mut seen = HashSet::new();

    for item in &file.items {
        if let Item::Use(item_use) = item {
            collect_commonware_deps(&item_use.tree, &mut Vec::new(), &mut deps, &mut seen);
        }
    }

    deps
}

fn collect_commonware_deps(
    tree: &UseTree,
    current_path: &mut Vec<String>,
    deps: &mut Vec<Dependency>,
    seen: &mut HashSet<Dependency>,
) {
    match tree {
        UseTree::Path(path) => {
            current_path.push(path.ident.to_string());
            collect_commonware_deps(&path.tree, current_path, deps, seen);
            current_path.pop();
        }
        UseTree::Name(name) => {
            current_path.push(name.ident.to_string());
            try_add_dep(current_path, deps, seen);
            current_path.pop();
        }
        UseTree::Rename(rename) => {
            current_path.push(rename.ident.to_string());
            try_add_dep(current_path, deps, seen);
            current_path.pop();
        }
        UseTree::Glob(_) => {
            try_add_dep(current_path, deps, seen);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_commonware_deps(item, current_path, deps, seen);
            }
        }
    }
}

fn try_add_dep(path: &[String], deps: &mut Vec<Dependency>, seen: &mut HashSet<Dependency>) {
    if path.is_empty() {
        return;
    }

    let first = &path[0];

    if let Some(crate_name) = first.strip_prefix("commonware_") {
        let dep = Dependency {
            crate_name: crate_name.to_string(),
            path_segments: path[1..].to_vec(),
        };

        if !seen.contains(&dep) {
            seen.insert(dep.clone());
            deps.push(dep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_import() {
        let code = r#"use commonware_codec::Encode;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "codec");
        assert_eq!(deps[0].path_segments, vec!["Encode"]);
    }

    #[test]
    fn test_curly_brace_import() {
        let code = r#"use commonware_codec::{Encode, Write, Read};"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.path_segments == vec!["Encode"]));
        assert!(deps.iter().any(|d| d.path_segments == vec!["Write"]));
        assert!(deps.iter().any(|d| d.path_segments == vec!["Read"]));
    }

    #[test]
    fn test_nested_import() {
        let code = r#"use commonware_runtime::buffer::PoolRef;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "runtime");
        assert_eq!(deps[0].path_segments, vec!["buffer", "PoolRef"]);
    }

    #[test]
    fn test_glob_import() {
        let code = r#"use commonware_codec::*;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "codec");
        assert!(deps[0].path_segments.is_empty());
    }

    #[test]
    fn test_rename_import() {
        let code = r#"use commonware_codec::Read as CodecRead;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "codec");
        assert_eq!(deps[0].path_segments, vec!["Read"]);
    }

    #[test]
    fn test_ignores_doc_comments() {
        let code = r#"
//! use commonware_codec::Encode;
/// ```rust
/// use commonware_codec::Write;
/// ```
use commonware_codec::Read;
"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].path_segments, vec!["Read"]);
    }

    #[test]
    fn test_ignores_non_commonware() {
        let code = r#"
use std::collections::HashMap;
use tokio::sync::Mutex;
use commonware_codec::Encode;
"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "codec");
    }

    #[test]
    fn test_nested_curly_braces() {
        let code = r#"use commonware_codec::{types::{Vec, Map}, Encode};"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.path_segments == vec!["types", "Vec"]));
        assert!(deps.iter().any(|d| d.path_segments == vec!["types", "Map"]));
        assert!(deps.iter().any(|d| d.path_segments == vec!["Encode"]));
    }
}
