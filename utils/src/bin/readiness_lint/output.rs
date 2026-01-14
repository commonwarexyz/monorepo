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

/// Output format for readiness.json - hierarchical explorer style.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReadinessOutput {
    pub version: String,
    #[serde(default)]
    pub generated: String,
    pub crates: Vec<CrateOutput>,
    pub summary: Summary,
}

/// Output for a single crate with hierarchical entries.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CrateOutput {
    pub name: String,
    pub entries: Vec<Entry>,
}

/// An entry in the hierarchy - either a module, items, or a grouping node.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Entry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub children: Vec<Entry>,
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

        // Collect flat entries first
        let mut flat_entries: Vec<(String, u8)> = Vec::new();

        // Add root items (from lib.rs) with explicit #[ready(N)]
        let mut items_at_level: BTreeMap<u8, Vec<String>> = BTreeMap::new();
        for (item_name, &readiness) in &krate.root_items {
            items_at_level
                .entry(readiness)
                .or_default()
                .push(item_name.clone());
        }

        // Format items as "{Item1, Item2, ...}"
        for (level, mut items) in items_at_level {
            items.sort();
            total_items += items.len();
            *items_by_level.entry(level).or_insert(0) += items.len();
            let formatted = format_items(&items);
            flat_entries.push((formatted, level));
        }

        // Collect all modules
        collect_modules(
            &krate.modules,
            &mut flat_entries,
            &mut total_modules,
            &mut modules_by_level,
            &mut total_items,
            &mut items_by_level,
            false,
        );

        // Skip crates with nothing to show
        if flat_entries.is_empty() {
            continue;
        }

        // Build hierarchical tree from flat entries
        let entries = build_tree(&mut flat_entries);

        crates.push(CrateOutput {
            name: crate_name.clone(),
            entries,
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

/// Build a hierarchical tree from flat path entries.
fn build_tree(entries: &mut [(String, u8)]) -> Vec<Entry> {
    // Sort entries by path for consistent output
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Group by first path segment
    let mut groups: BTreeMap<String, Vec<(String, u8)>> = BTreeMap::new();
    let mut direct: BTreeMap<String, u8> = BTreeMap::new();
    let mut items: Vec<(String, u8)> = Vec::new();

    for (path, readiness) in entries.iter() {
        // Items like "{Foo, Bar}" go directly at root
        if path.starts_with('{') {
            items.push((path.clone(), *readiness));
            continue;
        }

        // Split on :: to get first segment
        if let Some(pos) = path.find("::") {
            let first = &path[..pos];
            let rest = &path[pos + 2..];
            groups
                .entry(first.to_string())
                .or_default()
                .push((rest.to_string(), *readiness));
        } else {
            // No :: means it's a direct entry
            direct.insert(path.clone(), *readiness);
        }
    }

    let mut result = Vec::new();

    // Merge direct entries with their children from groups
    let all_names: std::collections::BTreeSet<_> =
        direct.keys().chain(groups.keys()).cloned().collect();

    for name in all_names {
        let has_direct = direct.contains_key(&name);
        let has_children = groups.contains_key(&name);

        match (has_direct, has_children) {
            (true, true) => {
                // Both direct entry and children - merge them
                let readiness = direct[&name];
                let mut children = groups.remove(&name).unwrap();
                let child_entries = build_tree(&mut children);
                result.push(Entry {
                    name,
                    readiness: Some(readiness),
                    children: child_entries,
                });
            }
            (true, false) => {
                // Only direct entry, no children
                let readiness = direct[&name];
                result.push(Entry {
                    name,
                    readiness: Some(readiness),
                    children: Vec::new(),
                });
            }
            (false, true) => {
                // Only children, no direct entry
                let mut children = groups.remove(&name).unwrap();
                if children.len() == 1
                    && !children[0].0.contains("::")
                    && !children[0].0.starts_with('{')
                {
                    // Single child without further nesting - flatten to "parent::child"
                    let (child_name, readiness) = &children[0];
                    result.push(Entry {
                        name: format!("{name}::{child_name}"),
                        readiness: Some(*readiness),
                        children: Vec::new(),
                    });
                } else {
                    // Multiple children or nested - create group
                    let child_entries = build_tree(&mut children);
                    result.push(Entry {
                        name,
                        readiness: None,
                        children: child_entries,
                    });
                }
            }
            (false, false) => unreachable!(),
        }
    }

    // Add item entries (like "{Foo, Bar}")
    for (name, readiness) in items {
        result.push(Entry {
            name,
            readiness: Some(readiness),
            children: Vec::new(),
        });
    }

    // Sort: groups first (no readiness), then by name
    result.sort_by(|a, b| match (a.readiness, b.readiness) {
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });

    result
}

/// Recursively collect modules and their readiness levels.
fn collect_modules(
    modules: &HashMap<String, Module>,
    entries: &mut Vec<(String, u8)>,
    total_modules: &mut usize,
    modules_by_level: &mut BTreeMap<u8, usize>,
    total_items: &mut usize,
    items_by_level: &mut BTreeMap<u8, usize>,
    parent_explicit: bool,
) {
    for module in modules.values() {
        if module.is_explicit {
            *total_modules += 1;
            *modules_by_level.entry(module.readiness).or_insert(0) += 1;
            entries.push((module.path.clone(), module.readiness));

            collect_modules(
                &module.submodules,
                entries,
                total_modules,
                modules_by_level,
                total_items,
                items_by_level,
                true,
            );
        } else if parent_explicit {
            collect_modules(
                &module.submodules,
                entries,
                total_modules,
                modules_by_level,
                total_items,
                items_by_level,
                true,
            );
        } else {
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
                    entries.push((formatted, level));
                }
            } else if module.submodules.is_empty() {
                *total_modules += 1;
                *modules_by_level.entry(0).or_insert(0) += 1;
                entries.push((module.path.clone(), 0));
            }

            collect_modules(
                &module.submodules,
                entries,
                total_modules,
                modules_by_level,
                total_items,
                items_by_level,
                false,
            );
        }
    }
}

/// Format a list of items as "crate::{Item1, Item2, ...}".
fn format_items(items: &[String]) -> String {
    if items.len() == 1 {
        format!("crate::{{{}}}", items[0])
    } else {
        format!("crate::{{{}}}", items.join(", "))
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
