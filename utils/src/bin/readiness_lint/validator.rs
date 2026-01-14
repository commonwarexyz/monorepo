//! Validate readiness constraints.

use crate::parser::{Module, Workspace};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;
use syn::visit::Visit;

/// A readiness constraint violation.
#[derive(Debug, Clone)]
pub struct Violation {
    /// The module that has the violation
    pub module: String,
    /// The readiness level of the module
    pub module_readiness: u8,
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
            self.module, self.module_readiness, self.dependency, self.dependency_readiness
        )
    }
}

/// Validate all readiness constraints in the workspace.
pub fn validate(workspace: &Workspace) -> Vec<Violation> {
    let mut violations = Vec::new();

    // Build a map of module path -> readiness for all modules in all crates
    let module_readiness = build_module_readiness_map(workspace);

    // Check each crate
    for (crate_name, krate) in &workspace.crates {
        check_modules(
            &krate.modules,
            crate_name,
            &module_readiness,
            0,
            &mut violations,
        );
    }

    violations
}

/// Build a map from "crate_name::module::path" to readiness level.
/// Includes ALL modules - unmarked modules have readiness 0 (inherited or default).
fn build_module_readiness_map(workspace: &Workspace) -> HashMap<String, u8> {
    let mut map = HashMap::new();

    for (crate_name, krate) in &workspace.crates {
        // Collect all modules with their effective readiness
        collect_all_module_readiness(&krate.modules, crate_name, 0, &mut map);

        // Handle re-exports: check for "pub use X::*" patterns in lib.rs
        add_reexport_aliases(krate, &mut map);
    }

    map
}

/// Recursively collect ALL modules into the map with their effective readiness.
fn collect_all_module_readiness(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    inherited_readiness: u8,
    map: &mut HashMap<String, u8>,
) {
    for (mod_name, module) in modules {
        let effective = if module.is_explicit {
            module.readiness
        } else {
            inherited_readiness
        };

        // Store with full path: crate_name::module::path
        let full_path = format!("{crate_name}::{}", module.path);
        map.insert(full_path, effective);

        // Also store just the module name for simpler lookups
        let simple_path = format!("{crate_name}::{mod_name}");
        map.insert(simple_path, effective);

        collect_all_module_readiness(&module.submodules, crate_name, effective, map);
    }
}

/// Add aliases for re-exported modules.
/// Handles patterns like "pub use utils::*" which re-export submodules at crate root.
fn add_reexport_aliases(krate: &crate::parser::Crate, map: &mut HashMap<String, u8>) {
    let lib_rs = krate.path.join("src/lib.rs");
    let content = match fs::read_to_string(&lib_rs) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Find "pub use <module>::*" patterns
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("pub use ") && trimmed.ends_with("::*;") {
            // Extract the module name being re-exported
            let module_name = trimmed
                .strip_prefix("pub use ")
                .and_then(|s| s.strip_suffix("::*;"))
                .map(|s| s.trim());

            if let Some(reexported_module) = module_name {
                // Find this module and add aliases for all its submodules
                if let Some(module) = krate.modules.get(reexported_module) {
                    add_submodule_aliases(&krate.name, reexported_module, module, map);
                }
            }
        }
    }
}

/// Add aliases for submodules that are re-exported.
/// e.g., "runtime::utils::buffer" also becomes "runtime::buffer"
fn add_submodule_aliases(
    crate_name: &str,
    parent_module: &str,
    module: &Module,
    map: &mut HashMap<String, u8>,
) {
    for (submod_name, submod) in &module.submodules {
        // The original path is "crate::parent::submod"
        let original_path = format!("{crate_name}::{parent_module}::{submod_name}");

        // The alias path is "crate::submod" (without the parent)
        let alias_path = format!("{crate_name}::{submod_name}");

        // Copy the readiness from the original path
        if let Some(&readiness) = map.get(&original_path) {
            map.insert(alias_path, readiness);
        }

        // Recursively handle nested submodules
        // e.g., "runtime::utils::buffer::pool" -> "runtime::buffer::pool"
        add_nested_aliases(crate_name, parent_module, submod, map);
    }
}

/// Add aliases for nested submodules.
fn add_nested_aliases(
    crate_name: &str,
    parent_module: &str,
    module: &Module,
    map: &mut HashMap<String, u8>,
) {
    for (_submod_name, submod) in &module.submodules {
        // The module path already includes parent, e.g., "buffer::pool"
        // We need to create alias "crate::buffer::pool" from "crate::utils::buffer::pool"
        let original_path = format!("{crate_name}::{}", submod.path);
        let alias_path = original_path.replace(&format!("::{parent_module}::"), "::");

        if let Some(&readiness) = map.get(&original_path) {
            map.insert(alias_path, readiness);
        }

        add_nested_aliases(crate_name, parent_module, submod, map);
    }
}

/// Check all modules recursively for constraint violations.
fn check_modules(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    module_readiness: &HashMap<String, u8>,
    inherited_readiness: u8,
    violations: &mut Vec<Violation>,
) {
    for (mod_name, module) in modules {
        // Skip test modules - they're exempt from readiness constraints
        if is_test_module(mod_name) {
            continue;
        }

        let effective_readiness = if module.is_explicit {
            module.readiness
        } else {
            inherited_readiness
        };

        // Check modules with effective readiness > 0 (explicit or inherited)
        if effective_readiness > 0 {
            // Parse the module file to find imports
            let imports = extract_imports(&module.file_path);

            for import in imports {
                // Check if this import has lower readiness
                if let Some(&dep_readiness) = module_readiness.get(&import) {
                    if dep_readiness < effective_readiness {
                        violations.push(Violation {
                            module: format!("{crate_name}::{}", module.path),
                            module_readiness: effective_readiness,
                            dependency: import,
                            dependency_readiness: dep_readiness,
                        });
                    }
                }
            }
        }

        // Check submodules
        check_modules(
            &module.submodules,
            crate_name,
            module_readiness,
            effective_readiness,
            violations,
        );
    }
}

/// Check if a module name indicates test code.
fn is_test_module(name: &str) -> bool {
    name == "tests" || name == "test" || name == "conformance" || name == "benches" || name == "mocks"
}

/// Visitor that collects all commonware module paths from the AST.
struct CommonwarePathVisitor {
    modules: HashSet<String>,
    /// Track if we're inside a #[cfg(test)] block
    in_test_cfg: bool,
}

impl CommonwarePathVisitor {
    fn new() -> Self {
        Self {
            modules: HashSet::new(),
            in_test_cfg: false,
        }
    }

    /// Extract module path from a syn::Path if it's a commonware import.
    fn extract_from_path(&mut self, path: &syn::Path) {
        if self.in_test_cfg {
            return;
        }

        let segments: Vec<_> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segments.is_empty() {
            return;
        }

        // Check if first segment is a commonware crate
        let first = &segments[0];
        if !first.starts_with("commonware_") {
            return;
        }

        // Convert underscore to dash for crate name
        let crate_name = first.replace('_', "-");

        // Skip macros crate
        if crate_name == "commonware-macros" {
            return;
        }

        // Look for module segments (lowercase identifiers after crate name)
        if segments.len() > 1 {
            let second = &segments[1];
            // If second segment starts with lowercase, it's likely a module
            if second.chars().next().map_or(false, |c| c.is_lowercase()) {
                self.modules.insert(format!("{crate_name}::{second}"));
            }
        }
    }

    /// Check if attributes contain #[cfg(test)]
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
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.extract_from_path(path);
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        // Skip use statements with #[cfg(test)]
        if Self::has_test_cfg(&node.attrs) {
            return;
        }
        if !self.in_test_cfg {
            collect_use_paths(&node.tree, &[], &mut self.modules);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        // Skip modules with #[cfg(test)]
        if Self::has_test_cfg(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        // Skip functions with #[cfg(test)] or #[test]
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
fn collect_use_paths(tree: &syn::UseTree, prefix: &[String], modules: &mut HashSet<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut new_prefix = prefix.to_vec();
            new_prefix.push(path.ident.to_string());
            collect_use_paths(&path.tree, &new_prefix, modules);
        }
        syn::UseTree::Name(name) => {
            let mut full_path = prefix.to_vec();
            full_path.push(name.ident.to_string());
            add_commonware_module(&full_path, modules);
        }
        syn::UseTree::Rename(rename) => {
            let mut full_path = prefix.to_vec();
            full_path.push(rename.ident.to_string());
            add_commonware_module(&full_path, modules);
        }
        syn::UseTree::Glob(_) => {
            // For glob imports, add the prefix as the module
            add_commonware_module(prefix, modules);
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_paths(item, prefix, modules);
            }
        }
    }
}

/// Add a module path if it's a commonware module.
fn add_commonware_module(path: &[String], modules: &mut HashSet<String>) {
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

    // Look for module segment (second element, lowercase)
    if path.len() > 1 {
        let second = &path[1];
        if second.chars().next().map_or(false, |c| c.is_lowercase()) {
            modules.insert(format!("{crate_name}::{second}"));
        }
    }
}

/// Extract commonware module imports from a Rust source file using full AST parsing.
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

    let mut imports: Vec<_> = visitor.modules.into_iter().collect();
    imports.sort();
    imports
}
