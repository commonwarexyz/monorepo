//! Validate readiness constraints.

use crate::parser::{get_missing_annotations, Workspace};
use std::fmt;

/// Check for missing #[ready(N)] annotations on public items.
pub fn check_missing_annotations(workspace: &Workspace) -> Vec<String> {
    get_missing_annotations(workspace)
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
///
/// Note: This is a simplified version that checks crate-level dependencies.
/// For full import-level checking, we would need to analyze the source files.
pub fn validate(workspace: &Workspace) -> Vec<Violation> {
    let mut violations = Vec::new();

    // Check crate-level dependencies
    // For each crate, check if any of its items depend on items from other crates
    // with lower readiness levels
    for krate in workspace.crates.values() {
        for item in &krate.items {
            let Some(item_readiness) = item.readiness else {
                continue;
            };

            if item_readiness == 0 {
                continue;
            }

            // Check dependencies at crate level
            for dep_crate_name in &krate.dependencies {
                if let Some(dep_crate) = workspace.crates.get(dep_crate_name) {
                    for dep_item in &dep_crate.items {
                        if let Some(dep_readiness) = dep_item.readiness {
                            if dep_readiness < item_readiness {
                                violations.push(Violation {
                                    item: item.path.clone(),
                                    item_readiness,
                                    dependency: dep_item.path.clone(),
                                    dependency_readiness: dep_readiness,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Deduplicate violations
    violations.sort_by(|a, b| (&a.item, &a.dependency).cmp(&(&b.item, &b.dependency)));
    violations.dedup_by(|a, b| a.item == b.item && a.dependency == b.dependency);

    violations
}
