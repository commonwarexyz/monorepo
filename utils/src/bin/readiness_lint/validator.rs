//! Validate readiness constraints.

use crate::parser::{Module, Workspace};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

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
/// Also includes crate-level entries for checking crate root imports.
fn build_module_readiness_map(workspace: &Workspace) -> HashMap<String, u8> {
    let mut map = HashMap::new();

    for (crate_name, krate) in &workspace.crates {
        // Collect all module readiness levels
        let mut levels = Vec::new();
        collect_module_readiness(&krate.modules, crate_name, 0, &mut map, &mut levels);

        // Crate-level readiness is the minimum of all explicit module readiness
        // If no explicit modules, default to 0
        let crate_readiness = levels.into_iter().min().unwrap_or(0);
        map.insert(crate_name.clone(), crate_readiness);
    }

    map
}

/// Recursively collect module readiness into the map and levels vector.
fn collect_module_readiness(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    inherited_readiness: u8,
    map: &mut HashMap<String, u8>,
    explicit_levels: &mut Vec<u8>,
) {
    for (mod_name, module) in modules {
        let effective_readiness = if module.is_explicit {
            module.readiness
        } else {
            inherited_readiness
        };

        // Track explicit readiness for crate-level computation
        if module.is_explicit {
            explicit_levels.push(module.readiness);
        }

        // Store with full path: crate_name::module::path
        let full_path = format!("{crate_name}::{}", module.path);
        map.insert(full_path, effective_readiness);

        // Also store just the module name for simpler lookups
        let simple_path = format!("{crate_name}::{mod_name}");
        map.insert(simple_path, effective_readiness);

        collect_module_readiness(
            &module.submodules,
            crate_name,
            effective_readiness,
            map,
            explicit_levels,
        );
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
    for module in modules.values() {
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

/// Extract commonware imports from a Rust source file.
fn extract_imports(file_path: &Path) -> Vec<String> {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut imports = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Look for use statements
        if trimmed.starts_with("use ") || trimmed.starts_with("pub use ") {
            let use_part = if trimmed.starts_with("pub use ") {
                &trimmed[8..]
            } else {
                &trimmed[4..]
            };

            imports.extend(extract_commonware_imports(use_part));
        }
    }

    // Deduplicate
    imports.sort();
    imports.dedup();
    imports
}

/// Extract commonware import paths from a use statement.
/// Returns both the specific module path and the crate name for fallback checking.
fn extract_commonware_imports(use_stmt: &str) -> Vec<String> {
    let use_stmt = use_stmt.trim();
    let mut imports = Vec::new();

    // Handle commonware_* imports (underscore form used in code)
    if use_stmt.starts_with("commonware_") {
        let end = use_stmt.find(';').unwrap_or(use_stmt.len());
        let path = &use_stmt[..end];

        // Convert underscore to dash for crate name
        let parts: Vec<&str> = path.splitn(2, "::").collect();
        let crate_name = parts[0].replace('_', "-");

        // Skip macros crate (it's just proc macros, no modules to check)
        if crate_name == "commonware-macros" {
            return imports;
        }

        if parts.len() > 1 {
            let rest = parts[1];

            // Check if this looks like a module path (lowercase first char) vs a type (uppercase)
            let first_segment_end = rest.find(|c| c == ':' || c == '{' || c == ';').unwrap_or(rest.len());
            let first_segment = rest[..first_segment_end].trim();

            if !first_segment.is_empty() && !first_segment.starts_with('{') {
                // If it starts with lowercase, it's likely a module
                if first_segment.chars().next().map_or(false, |c| c.is_lowercase()) {
                    imports.push(format!("{crate_name}::{first_segment}"));
                }
            }
        }

        // Always include the crate itself as a fallback
        // This ensures we check crate-level exports
        imports.push(crate_name);
    }

    imports
}
