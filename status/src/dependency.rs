use std::collections::HashSet;
use syn::{Item, UseTree};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependency {
    pub crate_name: String,
    pub module_path: Vec<String>,
}

impl Dependency {
    pub fn module_string(&self) -> String {
        if self.module_path.is_empty() {
            self.crate_name.clone()
        } else {
            format!("{}::{}", self.crate_name, self.module_path.join("::"))
        }
    }
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
        let module_path = extract_module_path(&path[1..]);

        let dep = Dependency {
            crate_name: crate_name.to_string(),
            module_path,
        };

        if !seen.contains(&dep) {
            seen.insert(dep.clone());
            deps.push(dep);
        }
    }
}

fn extract_module_path(segments: &[String]) -> Vec<String> {
    let mut module_path = Vec::new();

    for segment in segments {
        if is_likely_module_name(segment) {
            module_path.push(segment.clone());
        } else {
            break;
        }
    }

    module_path
}

fn is_likely_module_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first_char = name.chars().next().unwrap();
    first_char.is_lowercase() || first_char == '_'
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
        assert!(deps[0].module_path.is_empty());
    }

    #[test]
    fn test_curly_brace_import() {
        let code = r#"use commonware_codec::{Encode, Write, Read};"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "codec");
        assert!(deps[0].module_path.is_empty());
    }

    #[test]
    fn test_nested_import() {
        let code = r#"use commonware_runtime::buffer::PoolRef;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "runtime");
        assert_eq!(deps[0].module_path, vec!["buffer"]);
    }

    #[test]
    fn test_glob_import() {
        let code = r#"use commonware_codec::*;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "codec");
        assert!(deps[0].module_path.is_empty());
    }

    #[test]
    fn test_rename_import() {
        let code = r#"use commonware_codec::Read as CodecRead;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "codec");
        assert!(deps[0].module_path.is_empty());
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
        assert!(deps[0].module_path.is_empty());
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
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.module_path == vec!["types"]));
        assert!(deps.iter().any(|d| d.module_path.is_empty()));
    }

    #[test]
    fn test_module_string() {
        let dep = Dependency {
            crate_name: "runtime".to_string(),
            module_path: vec!["buffer".to_string()],
        };
        assert_eq!(dep.module_string(), "runtime::buffer");

        let dep_root = Dependency {
            crate_name: "codec".to_string(),
            module_path: vec![],
        };
        assert_eq!(dep_root.module_string(), "codec");
    }

    #[test]
    fn test_deeply_nested_module() {
        let code = r#"use commonware_runtime::utils::buffer::pool::PoolRef;"#;
        let deps = parse_dependencies(code);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].crate_name, "runtime");
        assert_eq!(deps[0].module_path, vec!["utils", "buffer", "pool"]);
    }
}
