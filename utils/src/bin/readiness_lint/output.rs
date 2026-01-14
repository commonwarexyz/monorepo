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

/// Output format for readiness.json.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReadinessOutput {
    pub version: String,
    #[serde(default)]
    pub generated: String,
    pub crates: Vec<CrateOutput>,
    pub summary: Summary,
}

/// Output for a single crate.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CrateOutput {
    pub name: String,
    /// Module counts by readiness level (e.g., {0: 45, 2: 3} means 45 at level 0, 3 at level 2)
    pub module_counts: BTreeMap<u8, usize>,
    pub modules: Vec<ModuleOutput>,
}

/// Output for a single module.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ModuleOutput {
    pub path: String,
    pub readiness: u8,
    pub is_explicit: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub submodules: Vec<ModuleOutput>,
}

/// Summary statistics.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    pub total_modules: usize,
    pub by_level: BTreeMap<u8, usize>,
}

/// Generate readiness.json output.
pub fn generate(workspace: &Workspace, output_path: &Path) -> Result<(), OutputError> {
    let output = build_output(workspace);
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(output_path, json)?;
    Ok(())
}

/// Collect modules into output format.
fn collect_modules(
    modules: &HashMap<String, Module>,
    inherited_readiness: u8,
) -> (Vec<ModuleOutput>, usize, BTreeMap<u8, usize>) {
    let mut output = Vec::new();
    let mut count = 0;
    let mut by_level = BTreeMap::new();

    // Sort modules by name for consistent output
    let mut mod_names: Vec<_> = modules.keys().collect();
    mod_names.sort();

    for mod_name in mod_names {
        let module = &modules[mod_name];

        let effective_readiness = if module.is_explicit {
            module.readiness
        } else {
            inherited_readiness
        };

        let (submodules, subcount, sublevel) =
            collect_modules(&module.submodules, effective_readiness);

        count += 1 + subcount;
        *by_level.entry(effective_readiness).or_insert(0) += 1;
        for (level, c) in sublevel {
            *by_level.entry(level).or_insert(0) += c;
        }

        output.push(ModuleOutput {
            path: module.path.clone(),
            readiness: effective_readiness,
            is_explicit: module.is_explicit,
            submodules,
        });
    }

    (output, count, by_level)
}

/// Check if the existing readiness.json is up-to-date.
/// Returns Ok(true) if up-to-date, Ok(false) if out-of-date, Err on error.
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
    let mut by_level: BTreeMap<u8, usize> = BTreeMap::new();

    let mut crate_names: Vec<_> = workspace.crates.keys().collect();
    crate_names.sort();

    for crate_name in crate_names {
        let krate = &workspace.crates[crate_name];

        let (modules, module_count, level_counts) = collect_modules(&krate.modules, 0);

        // Skip crates with no public modules
        if modules.is_empty() {
            continue;
        }

        total_modules += module_count;
        for (level, count) in &level_counts {
            *by_level.entry(*level).or_insert(0) += count;
        }

        crates.push(CrateOutput {
            name: crate_name.clone(),
            module_counts: level_counts,
            modules,
        });
    }

    ReadinessOutput {
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated: chrono::Utc::now().to_rfc3339(),
        crates,
        summary: Summary {
            total_modules,
            by_level,
        },
    }
}
