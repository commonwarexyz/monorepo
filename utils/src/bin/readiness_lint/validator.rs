//! Validate readiness constraints.

use crate::analyzer::Dependencies;
use crate::parser::{Module, Workspace};
use std::collections::HashMap;
use std::fmt;

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
pub fn validate(workspace: &Workspace, dependencies: &Dependencies) -> Vec<Violation> {
    let mut violations = Vec::new();

    // Build a map of crate name to minimum readiness level
    let crate_readiness = compute_crate_readiness(workspace);

    // Check cross-crate dependencies
    for (crate_name, deps) in &dependencies.crate_deps {
        let Some(krate) = workspace.crates.get(crate_name) else {
            continue;
        };

        for dep in deps {
            // Skip non-commonware dependencies
            if !dep.starts_with("commonware-") {
                continue;
            }

            // Skip conformance crate (test infrastructure)
            if dep == "commonware-conformance" || dep == "commonware-conformance-macros" {
                continue;
            }

            let dep_readiness = crate_readiness.get(dep).copied().unwrap_or(0);

            // Check each module with explicit readiness
            check_modules_against_dep(
                &krate.modules,
                crate_name,
                dep,
                dep_readiness,
                &mut violations,
            );
        }
    }

    violations
}

/// Compute the minimum readiness level for each crate.
fn compute_crate_readiness(workspace: &Workspace) -> HashMap<String, u8> {
    let mut readiness = HashMap::new();

    for (name, krate) in &workspace.crates {
        let min = compute_min_module_readiness(&krate.modules);
        readiness.insert(name.clone(), min);
    }

    readiness
}

/// Collect all explicit readiness levels from modules recursively.
fn collect_explicit_readiness(modules: &HashMap<String, Module>, levels: &mut Vec<u8>) {
    for module in modules.values() {
        if module.is_explicit {
            levels.push(module.readiness);
        }
        collect_explicit_readiness(&module.submodules, levels);
    }
}

/// Compute the minimum readiness level across all modules.
/// Returns 0 if no modules have explicit readiness annotations.
fn compute_min_module_readiness(modules: &HashMap<String, Module>) -> u8 {
    let mut levels = Vec::new();
    collect_explicit_readiness(modules, &mut levels);
    levels.into_iter().min().unwrap_or(0)
}

/// Check modules against a dependency's readiness level.
fn check_modules_against_dep(
    modules: &HashMap<String, Module>,
    crate_name: &str,
    dep_name: &str,
    dep_readiness: u8,
    violations: &mut Vec<Violation>,
) {
    for (_mod_name, module) in modules {
        if module.is_explicit && module.readiness > dep_readiness {
            violations.push(Violation {
                module: format!("{crate_name}::{}", module.path),
                module_readiness: module.readiness,
                dependency: dep_name.to_string(),
                dependency_readiness: dep_readiness,
            });
        }

        // Check submodules
        check_modules_against_dep(
            &module.submodules,
            crate_name,
            dep_name,
            dep_readiness,
            violations,
        );
    }
}
