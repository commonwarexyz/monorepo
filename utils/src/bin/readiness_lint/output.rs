//! Generate readiness.json output.

use crate::parser::{Module, Workspace};
use serde::Serialize;
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
#[derive(Debug, Serialize)]
pub struct ReadinessOutput {
    pub version: String,
    pub generated: String,
    pub crates: Vec<CrateOutput>,
    pub summary: Summary,
}

/// Output for a single crate.
#[derive(Debug, Serialize)]
pub struct CrateOutput {
    pub name: String,
    pub readiness: u8,
    pub modules: Vec<ModuleOutput>,
}

/// Output for a single module.
#[derive(Debug, Serialize)]
pub struct ModuleOutput {
    pub path: String,
    pub readiness: u8,
    pub is_explicit: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub submodules: Vec<ModuleOutput>,
}

/// Summary statistics.
#[derive(Debug, Serialize)]
pub struct Summary {
    pub total_modules: usize,
    pub by_level: BTreeMap<u8, usize>,
}

/// Generate readiness.json output.
pub fn generate(workspace: &Workspace, output_path: &Path) -> Result<(), OutputError> {
    let mut crates = Vec::new();
    let mut total_modules = 0;
    let mut by_level: BTreeMap<u8, usize> = BTreeMap::new();

    // Sort crates by name for consistent output
    let mut crate_names: Vec<_> = workspace.crates.keys().collect();
    crate_names.sort();

    for crate_name in crate_names {
        let krate = &workspace.crates[crate_name];

        let (modules, module_count, level_counts) = collect_modules(&krate.modules, 0);

        total_modules += module_count;
        for (level, count) in level_counts {
            *by_level.entry(level).or_insert(0) += count;
        }

        let crate_readiness = compute_crate_readiness(&krate.modules);

        crates.push(CrateOutput {
            name: crate_name.clone(),
            readiness: crate_readiness,
            modules,
        });
    }

    let output = ReadinessOutput {
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated: chrono::Utc::now().to_rfc3339(),
        crates,
        summary: Summary {
            total_modules,
            by_level,
        },
    };

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

/// Compute the overall readiness level for a crate.
/// Returns the minimum readiness among all explicitly annotated modules.
/// Returns 0 if no modules have explicit readiness annotations.
fn compute_crate_readiness(modules: &HashMap<String, Module>) -> u8 {
    let mut min: Option<u8> = None;

    for module in modules.values() {
        if module.is_explicit {
            min = Some(min.map_or(module.readiness, |m| m.min(module.readiness)));
        }

        // Check submodules for explicit readiness
        let submodule_readiness = compute_crate_readiness(&module.submodules);
        if submodule_readiness > 0 {
            min = Some(min.map_or(submodule_readiness, |m| m.min(submodule_readiness)));
        }
    }

    min.unwrap_or(0)
}
