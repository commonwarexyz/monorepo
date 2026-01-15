//! Validate readiness constraints.

use crate::parser::{Module, Workspace};
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    path::{Path, PathBuf},
};
use syn::visit::Visit;

/// Check for crate-level readiness!() annotations (prohibited).
/// Returns a list of (crate_name, lib.rs path) pairs that have crate-level readiness.
pub fn check_crate_level_readiness(workspace: &Workspace) -> Vec<(String, PathBuf)> {
    let mut violations = Vec::new();

    for (crate_name, krate) in &workspace.crates {
        if krate.root_is_explicit {
            let lib_rs = krate.path.join("src/lib.rs");
            violations.push((crate_name.clone(), lib_rs));
        }
    }

    violations.sort_by(|a, b| a.0.cmp(&b.0));
    violations
}

/// A conflict where a readiness annotation has descendants with their own annotations.
#[derive(Debug, Clone)]
pub struct ReadinessConflict {
    pub crate_name: String,
    pub module_path: String,
    pub readiness: u8,
    /// Descendant items with #[ready()]
    pub items: Vec<String>,
    /// Descendant submodules with readiness!()
    pub submodules: Vec<String>,
}

impl fmt::Display for ReadinessConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}::{} (readiness {}) has descendants with annotations",
            self.crate_name, self.module_path, self.readiness
        )?;
        if !self.items.is_empty() {
            write!(f, " - items: {}", self.items.join(", "))?;
        }
        if !self.submodules.is_empty() {
            write!(f, " - submodules: {}", self.submodules.join(", "))?;
        }
        Ok(())
    }
}

/// Check for nested readiness annotations.
/// If any ancestor has a readiness annotation, descendants cannot have their own.
pub fn check_readiness_conflicts(workspace: &Workspace) -> Vec<ReadinessConflict> {
    let mut conflicts = Vec::new();

    for (crate_name, krate) in &workspace.crates {
        collect_readiness_conflicts(&krate.modules, crate_name, &mut conflicts);
    }

    conflicts.sort_by(|a, b| (&a.crate_name, &a.module_path).cmp(&(&b.crate_name, &b.module_path)));
    conflicts
}

fn collect_readiness_conflicts(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    conflicts: &mut Vec<ReadinessConflict>,
) {
    for module in modules.values() {
        if module.is_explicit {
            // Check for items with #[ready()] in this module
            let mut items: Vec<_> = module.items.keys().cloned().collect();
            items.sort();

            // Check for any descendant submodules with readiness!()
            let mut submodules = Vec::new();
            collect_explicit_descendants(&module.submodules, &mut submodules);
            submodules.sort();

            if !items.is_empty() || !submodules.is_empty() {
                conflicts.push(ReadinessConflict {
                    crate_name: crate_name.to_string(),
                    module_path: module.path.clone(),
                    readiness: module.readiness,
                    items,
                    submodules,
                });
            }
        }
        collect_readiness_conflicts(&module.submodules, crate_name, conflicts);
    }
}

/// Recursively collect all descendant modules with explicit readiness!().
fn collect_explicit_descendants(modules: &HashMap<String, Module>, result: &mut Vec<String>) {
    for module in modules.values() {
        if module.is_explicit {
            result.push(module.path.clone());
        }
        collect_explicit_descendants(&module.submodules, result);
    }
}

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
            krate.root_readiness,
            &mut violations,
        );
    }

    // Deduplicate violations (same module + dependency pair)
    violations.sort_by(|a, b| (&a.module, &a.dependency).cmp(&(&b.module, &b.dependency)));
    violations.dedup_by(|a, b| a.module == b.module && a.dependency == b.dependency);

    violations
}

/// Build a map from "crate_name::module::path" or "crate_name::Item" to readiness level.
/// Includes modules, crate roots, and items with explicit #[ready(N)] annotations.
fn build_module_readiness_map(workspace: &Workspace) -> HashMap<String, u8> {
    let mut map = HashMap::new();

    for (crate_name, krate) in &workspace.crates {
        // Add crate root readiness (for crate-level imports like `use commonware_stream::Config`)
        map.insert(crate_name.clone(), krate.root_readiness);

        // Add items defined at crate root (lib.rs) with their explicit #[ready(N)]
        for (item_name, readiness) in &krate.root_items {
            let item_path = format!("{crate_name}::{item_name}");
            map.insert(item_path, *readiness);
        }

        // Collect all modules with their effective readiness
        // Modules inherit from crate root if not explicitly set
        collect_all_module_readiness(&krate.modules, crate_name, krate.root_readiness, &mut map);

        // Handle re-exports: check for "pub use X::*" patterns in lib.rs
        add_reexport_aliases(krate, &mut map);

        // Handle item re-exports: map "crate::Item" to source module's readiness
        add_item_reexport_readiness(krate, &mut map);

        // Handle module-level re-exports (from mod.rs files)
        add_module_reexports(krate, &mut map);
    }

    map
}

/// Recursively collect ALL modules and their items into the map with their effective readiness.
fn collect_all_module_readiness(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    inherited_readiness: u8,
    map: &mut HashMap<String, u8>,
) {
    for (_mod_name, module) in modules {
        let effective = if module.is_explicit {
            module.readiness
        } else {
            inherited_readiness
        };

        // Store with full path: crate_name::module::path
        let full_path = format!("{crate_name}::{}", module.path);
        map.insert(full_path.clone(), effective);

        // Add items with explicit #[ready(N)] annotations
        // Items without explicit annotation inherit the module's readiness
        for (item_name, item_readiness) in &module.items {
            let item_path = format!("{full_path}::{item_name}");
            map.insert(item_path, *item_readiness);
            // Also add at crate level for re-exports (crate::Item)
            // This is handled separately via add_item_reexport_readiness
        }

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

/// Add readiness entries for items re-exported from modules.
/// Parses lib.rs for patterns like `pub use module::Item` and maps `crate::Item` to module's readiness.
fn add_item_reexport_readiness(krate: &crate::parser::Crate, map: &mut HashMap<String, u8>) {
    let lib_rs = krate.path.join("src/lib.rs");
    let content = match fs::read_to_string(&lib_rs) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Parse the file to extract use statements
    let syntax = match syn::parse_file(&content) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Collect all pub use statements
    for item in &syntax.items {
        if let syn::Item::Use(item_use) = item {
            // Only process public re-exports
            if !matches!(item_use.vis, syn::Visibility::Public(_)) {
                continue;
            }
            collect_reexport_items(&krate.name, &item_use.tree, &[], map);
        }
    }
}

/// Recursively collect re-exported items and map them to their source module's readiness.
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
            // pub use module::Item - map crate::Item to source item's or module's readiness
            if !prefix.is_empty() {
                let item_name = name.ident.to_string();
                // Only process items (capitalized names)
                if item_name.chars().next().map_or(false, |c| c.is_uppercase()) {
                    let module_path = format!("{crate_name}::{}", prefix.join("::"));
                    let item_at_module_path = format!("{module_path}::{item_name}");
                    let item_path = format!("{crate_name}::{item_name}");

                    // First, check if the item has an explicit #[ready(N)] annotation
                    if let Some(&readiness) = map.get(&item_at_module_path) {
                        map.insert(item_path, readiness);
                    } else if let Some(&readiness) = map.get(&module_path) {
                        // Fall back to module's readiness
                        map.insert(item_path, readiness);
                    } else {
                        // Try just the first module segment
                        let first_module = format!("{crate_name}::{}", prefix[0]);
                        let item_at_first_module = format!("{first_module}::{item_name}");
                        if let Some(&readiness) = map.get(&item_at_first_module) {
                            map.insert(item_path, readiness);
                        } else if let Some(&readiness) = map.get(&first_module) {
                            map.insert(item_path, readiness);
                        }
                    }
                }
            }
        }
        syn::UseTree::Rename(rename) => {
            // pub use module::Item as Alias - map crate::Alias to source item's or module's readiness
            if !prefix.is_empty() {
                let alias_name = rename.rename.to_string();
                let original_name = rename.ident.to_string();
                if alias_name
                    .chars()
                    .next()
                    .map_or(false, |c| c.is_uppercase())
                {
                    let module_path = format!("{crate_name}::{}", prefix.join("::"));
                    let item_at_module_path = format!("{module_path}::{original_name}");
                    let item_path = format!("{crate_name}::{alias_name}");

                    // First, check if the item has an explicit #[ready(N)] annotation
                    if let Some(&readiness) = map.get(&item_at_module_path) {
                        map.insert(item_path, readiness);
                    } else if let Some(&readiness) = map.get(&module_path) {
                        map.insert(item_path, readiness);
                    } else {
                        let first_module = format!("{crate_name}::{}", prefix[0]);
                        let item_at_first_module = format!("{first_module}::{original_name}");
                        if let Some(&readiness) = map.get(&item_at_first_module) {
                            map.insert(item_path, readiness);
                        } else if let Some(&readiness) = map.get(&first_module) {
                            map.insert(item_path, readiness);
                        }
                    }
                }
            }
        }
        syn::UseTree::Glob(_) => {
            // pub use module::* - handled by add_reexport_aliases
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_reexport_items(crate_name, item, prefix, map);
            }
        }
    }
}

/// Add readiness entries for items re-exported from submodules in mod.rs files.
/// Handles patterns like `pub use scheme::{Item1, Item2}` in mod.rs.
fn add_module_reexports(krate: &crate::parser::Crate, map: &mut HashMap<String, u8>) {
    for (mod_name, module) in &krate.modules {
        add_module_reexports_recursive(&krate.name, mod_name, module, map);
    }
}

fn add_module_reexports_recursive(
    crate_name: &str,
    mod_path: &str,
    module: &Module,
    map: &mut HashMap<String, u8>,
) {
    // Check if this is a directory module (has mod.rs)
    let mod_rs = module.file_path.clone();
    if mod_rs.file_name().map_or(false, |n| n == "mod.rs") {
        // Parse the mod.rs file for re-exports
        if let Ok(content) = fs::read_to_string(&mod_rs) {
            if let Ok(syntax) = syn::parse_file(&content) {
                for item in &syntax.items {
                    if let syn::Item::Use(item_use) = item {
                        if matches!(item_use.vis, syn::Visibility::Public(_)) {
                            collect_module_reexport_items(
                                crate_name,
                                mod_path,
                                &item_use.tree,
                                &[],
                                map,
                            );
                        }
                    }
                }
            }
        }
    }

    // Recurse into submodules
    for (submod_name, submod) in &module.submodules {
        let submod_path = format!("{mod_path}::{submod_name}");
        add_module_reexports_recursive(crate_name, &submod_path, submod, map);
    }
}

/// Collect re-exported items from a use tree in a mod.rs file.
fn collect_module_reexport_items(
    crate_name: &str,
    mod_path: &str,
    tree: &syn::UseTree,
    prefix: &[String],
    map: &mut HashMap<String, u8>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut new_prefix = prefix.to_vec();
            new_prefix.push(path.ident.to_string());
            collect_module_reexport_items(crate_name, mod_path, &path.tree, &new_prefix, map);
        }
        syn::UseTree::Name(name) => {
            if !prefix.is_empty() {
                let item_name = name.ident.to_string();
                // Only process items (capitalized names)
                if item_name.chars().next().map_or(false, |c| c.is_uppercase()) {
                    // Source path: crate::mod_path::submod::Item
                    let source_submod = prefix.join("::");
                    let source_item_path =
                        format!("{crate_name}::{mod_path}::{source_submod}::{item_name}");
                    // Target path: crate::mod_path::Item (re-exported without submod)
                    let target_item_path = format!("{crate_name}::{mod_path}::{item_name}");

                    // Look up the source item's readiness
                    if let Some(&readiness) = map.get(&source_item_path) {
                        map.insert(target_item_path, readiness);
                    } else {
                        // Fall back to source module's readiness
                        let source_mod_path = format!("{crate_name}::{mod_path}::{source_submod}");
                        if let Some(&readiness) = map.get(&source_mod_path) {
                            map.insert(target_item_path, readiness);
                        }
                    }
                }
            }
        }
        syn::UseTree::Rename(rename) => {
            if !prefix.is_empty() {
                let alias_name = rename.rename.to_string();
                let original_name = rename.ident.to_string();
                if alias_name
                    .chars()
                    .next()
                    .map_or(false, |c| c.is_uppercase())
                {
                    let source_submod = prefix.join("::");
                    let source_item_path =
                        format!("{crate_name}::{mod_path}::{source_submod}::{original_name}");
                    let target_item_path = format!("{crate_name}::{mod_path}::{alias_name}");

                    if let Some(&readiness) = map.get(&source_item_path) {
                        map.insert(target_item_path, readiness);
                    } else {
                        let source_mod_path = format!("{crate_name}::{mod_path}::{source_submod}");
                        if let Some(&readiness) = map.get(&source_mod_path) {
                            map.insert(target_item_path, readiness);
                        }
                    }
                }
            }
        }
        syn::UseTree::Glob(_) => {
            // Skip glob imports
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_module_reexport_items(crate_name, mod_path, item, prefix, map);
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
            // Parse all files in the module to find imports
            let imports = extract_imports_from_module(&module.file_path);

            for import in imports {
                // Check if this import has lower readiness
                // Only check imports that have explicit readiness entries
                // (either item-level #[ready(N)] or module-level readiness!())
                let (dep_path, dep_readiness) = if let Some(&r) = module_readiness.get(&import) {
                    (import.clone(), r)
                } else {
                    // Import not found - this means it doesn't have an explicit readiness annotation
                    // Skip checking since crate-level readiness!() is prohibited
                    continue;
                };

                if dep_readiness < effective_readiness {
                    violations.push(Violation {
                        module: format!("{crate_name}::{}", module.path),
                        module_readiness: effective_readiness,
                        dependency: dep_path,
                        dependency_readiness: dep_readiness,
                    });
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
    name == "tests"
        || name == "test"
        || name == "conformance"
        || name == "benches"
        || name == "mocks"
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
    /// Tracks the full path including items for item-level readiness resolution.
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

        if segments.len() == 1 {
            // Just the crate itself (e.g., `use commonware_stream;`)
            self.modules.insert(crate_name);
            return;
        }

        // Build the full path: crate::module::submodule::Item
        // We track the full path so item-level readiness can be resolved
        let rest: Vec<_> = segments[1..].iter().map(|s| s.as_str()).collect();
        let full_path = format!("{crate_name}::{}", rest.join("::"));
        self.modules.insert(full_path);
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
/// Tracks the full path including items for item-level readiness resolution.
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

    if path.len() == 1 {
        // Just the crate itself (e.g., `use commonware_stream;`)
        modules.insert(crate_name);
        return;
    }

    // Build the full path: crate::module::submodule::Item
    // We track the full path so item-level readiness can be resolved
    let rest: Vec<_> = path[1..].iter().map(|s| s.as_str()).collect();
    let full_path = format!("{crate_name}::{}", rest.join("::"));
    modules.insert(full_path);
}

/// Extract commonware module imports from all files in a module.
/// If the module is a directory (mod.rs), recursively checks all .rs files.
fn extract_imports_from_module(file_path: &Path) -> Vec<String> {
    let mut all_imports = HashSet::new();

    // If this is a mod.rs file, check all files in the directory
    if file_path.file_name().map_or(false, |n| n == "mod.rs") {
        if let Some(dir) = file_path.parent() {
            collect_imports_recursive(dir, &mut all_imports);
        }
    } else {
        // Single file module
        for import in extract_imports(file_path) {
            all_imports.insert(import);
        }
    }

    let mut imports: Vec<_> = all_imports.into_iter().collect();
    imports.sort();
    imports
}

/// Recursively collect imports from all .rs files in a directory.
fn collect_imports_recursive(dir: &Path, imports: &mut HashSet<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip test-related directories
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if is_test_module(name) {
                    continue;
                }
            }
            collect_imports_recursive(&path, imports);
        } else if path.extension().map_or(false, |e| e == "rs") {
            // Skip test-related files (e.g., conformance.rs, tests.rs)
            if let Some(stem) = path.file_stem().and_then(|n| n.to_str()) {
                if is_test_module(stem) {
                    continue;
                }
            }
            for import in extract_imports(&path) {
                imports.insert(import);
            }
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
