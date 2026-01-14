//! Generate readiness.json output.

use crate::parser::{Module, Workspace};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OutputError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Output format for readiness.json - explorer style.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReadinessOutput {
    pub version: String,
    #[serde(default)]
    pub generated: String,
    pub crates: Vec<CrateOutput>,
    pub summary: Summary,
}

/// Output for a single crate - grouped by readiness level.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CrateOutput {
    pub name: String,
    /// Entries grouped by readiness level.
    /// Each entry is either a module name or "{Item1, Item2, ...}" for grouped items.
    pub readiness: BTreeMap<u8, Vec<String>>,
}

/// Summary statistics.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    pub total_modules: usize,
    pub total_items: usize,
    pub modules_by_level: BTreeMap<u8, usize>,
    pub items_by_level: BTreeMap<u8, usize>,
}

/// Generate readiness.json output.
pub fn generate(workspace: &Workspace, output_path: &Path) -> Result<(), OutputError> {
    let output = build_output(workspace);
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(output_path, json)?;
    Ok(())
}

/// Check if the existing readiness.json is up-to-date.
pub fn check(workspace: &Workspace, check_path: &Path) -> Result<bool, OutputError> {
    let expected = build_output(workspace);

    let existing_content = fs::read_to_string(check_path)?;
    let mut existing: ReadinessOutput = serde_json::from_str(&existing_content)?;

    // Ignore the generated timestamp when comparing
    existing.generated = String::new();

    let mut expected_for_cmp = expected;
    expected_for_cmp.generated = String::new();

    Ok(existing == expected_for_cmp)
}

/// Build the readiness output structure.
fn build_output(workspace: &Workspace) -> ReadinessOutput {
    let mut crates = Vec::new();
    let mut total_modules = 0;
    let mut total_items = 0;
    let mut modules_by_level: BTreeMap<u8, usize> = BTreeMap::new();
    let mut items_by_level: BTreeMap<u8, usize> = BTreeMap::new();

    let mut crate_names: Vec<_> = workspace.crates.keys().collect();
    crate_names.sort();

    for crate_name in crate_names {
        let krate = &workspace.crates[crate_name];

        // Collect entries by readiness level
        let mut by_level: BTreeMap<u8, Vec<String>> = BTreeMap::new();

        // Add root items (from lib.rs) with explicit #[ready(N)]
        let mut items_at_level: BTreeMap<u8, Vec<String>> = BTreeMap::new();
        for (item_name, &readiness) in &krate.root_items {
            items_at_level
                .entry(readiness)
                .or_default()
                .push(item_name.clone());
        }

        // Format items as "{Item1, Item2, ...}" and add to by_level
        for (level, mut items) in items_at_level {
            items.sort();
            total_items += items.len();
            *items_by_level.entry(level).or_insert(0) += items.len();
            let formatted = format_items(&items);
            by_level.entry(level).or_default().push(formatted);
        }

        // Collect modules with explicit readiness!(N)
        collect_explicit_modules(
            &krate.modules,
            &mut by_level,
            &mut total_modules,
            &mut modules_by_level,
            &mut total_items,
            &mut items_by_level,
        );

        // Skip crates with nothing to show
        if by_level.is_empty() {
            continue;
        }

        // Sort entries within each level
        for entries in by_level.values_mut() {
            entries.sort();
        }

        crates.push(CrateOutput {
            name: crate_name.clone(),
            readiness: by_level,
        });
    }

    ReadinessOutput {
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated: chrono::Utc::now().to_rfc3339(),
        crates,
        summary: Summary {
            total_modules,
            total_items,
            modules_by_level,
            items_by_level,
        },
    }
}

/// Recursively collect modules that have explicit readiness!(N) annotations.
fn collect_explicit_modules(
    modules: &HashMap<String, Module>,
    by_level: &mut BTreeMap<u8, Vec<String>>,
    total_modules: &mut usize,
    modules_by_level: &mut BTreeMap<u8, usize>,
    total_items: &mut usize,
    items_by_level: &mut BTreeMap<u8, usize>,
) {
    for module in modules.values() {
        // Only include modules with explicit readiness!(N)
        if module.is_explicit {
            *total_modules += 1;
            *modules_by_level.entry(module.readiness).or_insert(0) += 1;
            by_level
                .entry(module.readiness)
                .or_default()
                .push(module.path.clone());
        } else {
            // Module doesn't have explicit readiness, but check for items with #[ready(N)]
            if !module.items.is_empty() {
                let mut items_at_level: BTreeMap<u8, Vec<String>> = BTreeMap::new();
                for (item_name, &readiness) in &module.items {
                    items_at_level
                        .entry(readiness)
                        .or_default()
                        .push(item_name.clone());
                }

                for (level, mut items) in items_at_level {
                    items.sort();
                    *total_items += items.len();
                    *items_by_level.entry(level).or_insert(0) += items.len();
                    let formatted = format_items_with_module(&module.path, &items);
                    by_level.entry(level).or_default().push(formatted);
                }
            }
        }

        // Recurse into submodules
        collect_explicit_modules(
            &module.submodules,
            by_level,
            total_modules,
            modules_by_level,
            total_items,
            items_by_level,
        );
    }
}

/// Format a list of items as "{Item1, Item2, ...}".
fn format_items(items: &[String]) -> String {
    if items.len() == 1 {
        format!("{{{}}}", items[0])
    } else {
        format!("{{{}}}", items.join(", "))
    }
}

/// Format a list of items with module prefix as "module::{Item1, Item2, ...}".
fn format_items_with_module(module_path: &str, items: &[String]) -> String {
    if items.len() == 1 {
        format!("{module_path}::{{{}}}", items[0])
    } else {
        format!("{module_path}::{{{}}}", items.join(", "))
    }
}
