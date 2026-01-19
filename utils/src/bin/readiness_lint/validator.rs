//! Validate readiness constraints.

use crate::parser::{Module, Workspace};
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    path::Path,
};
use syn::visit::Visit;

/// Check for missing #[ready(N)] annotations on public items.
/// Returns a list of fully qualified item paths that are missing annotations.
pub fn check_missing_annotations(workspace: &Workspace) -> Vec<String> {
    let mut missing = Vec::new();

    for (crate_name, krate) in &workspace.crates {
        // Check root items (lib.rs)
        for item in &krate.root_missing_items {
            missing.push(format!("{crate_name}::{item}"));
        }

        // Check all modules recursively
        collect_missing_items(&krate.modules, crate_name, &mut missing);
    }

    missing.sort();
    missing
}

/// Recursively collect missing items from modules.
fn collect_missing_items(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    missing: &mut Vec<String>,
) {
    for module in modules.values() {
        for item in &module.missing_items {
            missing.push(format!("{crate_name}::{}::{item}", module.path));
        }
        collect_missing_items(&module.submodules, crate_name, missing);
    }
}

/// A readiness constraint violation.
#[derive(Debug, Clone)]
pub struct Violation {
    /// The item that has the violation
    pub item: String,
    /// The readiness level of the item
    pub item_readiness: u8,
    /// The dependency that caused the violation
    pub dependency: String,
    /// The readiness level of the dependency
    pub dependency_readiness: u8,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (readiness {}) depends on {} (readiness {})",
            self.item, self.item_readiness, self.dependency, self.dependency_readiness
        )
    }
}

/// Validate all readiness constraints in the workspace.
/// Checks that items with readiness N only depend on items with readiness >= N.
pub fn validate(workspace: &Workspace) -> Vec<Violation> {
    let mut violations = Vec::new();

    // Build a map of item path -> readiness for all items in all crates
    let item_readiness = build_item_readiness_map(workspace);

    // Check each crate
    for (crate_name, krate) in &workspace.crates {
        // Check root items
        for (item_name, &readiness) in &krate.root_items {
            if readiness > 0 {
                let lib_rs = krate.path.join("src/lib.rs");
                check_item_dependencies(
                    &format!("{crate_name}::{item_name}"),
                    readiness,
                    &lib_rs,
                    &item_readiness,
                    &mut violations,
                );
            }
        }

        // Check module items
        check_module_items(&krate.modules, crate_name, &item_readiness, &mut violations);
    }

    // Deduplicate violations
    violations.sort_by(|a, b| (&a.item, &a.dependency).cmp(&(&b.item, &b.dependency)));
    violations.dedup_by(|a, b| a.item == b.item && a.dependency == b.dependency);

    violations
}

/// Build a map from item path to readiness level.
fn build_item_readiness_map(workspace: &Workspace) -> HashMap<String, u8> {
    let mut map = HashMap::new();

    for (crate_name, krate) in &workspace.crates {
        // Add root items
        for (item_name, &readiness) in &krate.root_items {
            map.insert(format!("{crate_name}::{item_name}"), readiness);
        }

        // Add items from all modules
        collect_item_readiness(&krate.modules, crate_name, &mut map);

        // Handle re-exports from lib.rs
        add_reexport_readiness(krate, &mut map);
    }

    map
}

/// Recursively collect item readiness from modules.
fn collect_item_readiness(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    map: &mut HashMap<String, u8>,
) {
    for module in modules.values() {
        for (item_name, &readiness) in &module.items {
            let item_path = format!("{crate_name}::{}::{item_name}", module.path);
            map.insert(item_path, readiness);
        }
        collect_item_readiness(&module.submodules, crate_name, map);
    }
}

/// Add readiness entries for items re-exported from modules.
fn add_reexport_readiness(krate: &crate::parser::Crate, map: &mut HashMap<String, u8>) {
    let lib_rs = krate.path.join("src/lib.rs");
    let content = match fs::read_to_string(&lib_rs) {
        Ok(c) => c,
        Err(_) => return,
    };

    let syntax = match syn::parse_file(&content) {
        Ok(s) => s,
        Err(_) => return,
    };

    for item in &syntax.items {
        if let syn::Item::Use(item_use) = item {
            if !matches!(item_use.vis, syn::Visibility::Public(_)) {
                continue;
            }
            collect_reexport_items(&krate.name, &item_use.tree, &[], map);
        }
    }
}

/// Recursively collect re-exported items and map them to their source readiness.
fn collect_reexport_items(
    crate_name: &str,
    tree: &syn::UseTree,
    prefix: &[String],
    map: &mut HashMap<String, u8>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut new_prefix = prefix.to_vec();
            new_prefix.push(path.ident.to_string());
            collect_reexport_items(crate_name, &path.tree, &new_prefix, map);
        }
        syn::UseTree::Name(name) => {
            if !prefix.is_empty() {
                let item_name = name.ident.to_string();
                if item_name.chars().next().map_or(false, |c| c.is_uppercase()) {
                    let source_path = format!("{crate_name}::{}::{item_name}", prefix.join("::"));
                    let alias_path = format!("{crate_name}::{item_name}");
                    if let Some(&readiness) = map.get(&source_path) {
                        map.insert(alias_path, readiness);
                    }
                }
            }
        }
        syn::UseTree::Rename(rename) => {
            if !prefix.is_empty() {
                let original_name = rename.ident.to_string();
                let alias_name = rename.rename.to_string();
                if alias_name
                    .chars()
                    .next()
                    .map_or(false, |c| c.is_uppercase())
                {
                    let source_path =
                        format!("{crate_name}::{}::{original_name}", prefix.join("::"));
                    let alias_path = format!("{crate_name}::{alias_name}");
                    if let Some(&readiness) = map.get(&source_path) {
                        map.insert(alias_path, readiness);
                    }
                }
            }
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_reexport_items(crate_name, item, prefix, map);
            }
        }
    }
}

/// Check all module items recursively.
fn check_module_items(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    item_readiness: &HashMap<String, u8>,
    violations: &mut Vec<Violation>,
) {
    for module in modules.values() {
        // Skip test modules
        if is_test_module(&module.path) {
            continue;
        }

        for (item_name, &readiness) in &module.items {
            if readiness > 0 {
                check_item_dependencies(
                    &format!("{crate_name}::{}::{item_name}", module.path),
                    readiness,
                    &module.file_path,
                    item_readiness,
                    violations,
                );
            }
        }

        check_module_items(&module.submodules, crate_name, item_readiness, violations);
    }
}

/// Check if an item's dependencies satisfy readiness constraints.
fn check_item_dependencies(
    item_path: &str,
    item_readiness: u8,
    file_path: &Path,
    all_item_readiness: &HashMap<String, u8>,
    violations: &mut Vec<Violation>,
) {
    let imports = extract_imports(file_path);

    for import in imports {
        if let Some(&dep_readiness) = all_item_readiness.get(&import) {
            if dep_readiness < item_readiness {
                violations.push(Violation {
                    item: item_path.to_string(),
                    item_readiness,
                    dependency: import,
                    dependency_readiness: dep_readiness,
                });
            }
        }
    }
}

/// Check if a module path indicates test code.
fn is_test_module(path: &str) -> bool {
    let parts: Vec<_> = path.split("::").collect();
    parts.iter().any(|p| {
        *p == "tests" || *p == "test" || *p == "conformance" || *p == "benches" || *p == "mocks"
    })
}

/// Visitor that collects all commonware paths from the AST.
struct CommonwarePathVisitor {
    paths: HashSet<String>,
    in_test_cfg: bool,
}

impl CommonwarePathVisitor {
    fn new() -> Self {
        Self {
            paths: HashSet::new(),
            in_test_cfg: false,
        }
    }

    fn has_test_cfg(attrs: &[syn::Attribute]) -> bool {
        for attr in attrs {
            if attr.path().is_ident("cfg") {
                if let Ok(meta) = attr.meta.require_list() {
                    let tokens = meta.tokens.to_string();
                    if tokens.contains("test") {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl<'ast> Visit<'ast> for CommonwarePathVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if Self::has_test_cfg(&node.attrs) {
            return;
        }
        if !self.in_test_cfg {
            collect_use_paths(&node.tree, &[], &mut self.paths);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if Self::has_test_cfg(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if Self::has_test_cfg(&node.attrs) {
            return;
        }
        for attr in &node.attrs {
            if attr.path().is_ident("test") {
                return;
            }
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if Self::has_test_cfg(&node.attrs) {
            return;
        }
        syn::visit::visit_item_impl(self, node);
    }
}

/// Recursively collect paths from a use tree.
fn collect_use_paths(tree: &syn::UseTree, prefix: &[String], paths: &mut HashSet<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut new_prefix = prefix.to_vec();
            new_prefix.push(path.ident.to_string());
            collect_use_paths(&path.tree, &new_prefix, paths);
        }
        syn::UseTree::Name(name) => {
            let mut full_path = prefix.to_vec();
            full_path.push(name.ident.to_string());
            add_commonware_path(&full_path, paths);
        }
        syn::UseTree::Rename(rename) => {
            let mut full_path = prefix.to_vec();
            full_path.push(rename.ident.to_string());
            add_commonware_path(&full_path, paths);
        }
        syn::UseTree::Glob(_) => {
            add_commonware_path(prefix, paths);
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_paths(item, prefix, paths);
            }
        }
    }
}

/// Add a path if it's a commonware path.
fn add_commonware_path(path: &[String], paths: &mut HashSet<String>) {
    if path.is_empty() {
        return;
    }

    let first = &path[0];
    if !first.starts_with("commonware_") {
        return;
    }

    let crate_name = first.replace('_', "-");
    if crate_name == "commonware-macros" {
        return;
    }

    if path.len() == 1 {
        paths.insert(crate_name);
        return;
    }

    let rest: Vec<_> = path[1..].iter().map(|s| s.as_str()).collect();
    let full_path = format!("{crate_name}::{}", rest.join("::"));
    paths.insert(full_path);
}

/// Extract commonware imports from a Rust source file.
fn extract_imports(file_path: &Path) -> Vec<String> {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let syntax = match syn::parse_file(&content) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut visitor = CommonwarePathVisitor::new();
    visitor.visit_file(&syntax);

    let mut imports: Vec<_> = visitor.paths.into_iter().collect();
    imports.sort();
    imports
}
