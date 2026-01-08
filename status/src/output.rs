use crate::{
    marker::Stage,
    scanner::{CrateScan, ModuleStatus},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

fn file_path_to_module_path(file_path: &str) -> String {
    let path = file_path
        .strip_prefix("src/")
        .unwrap_or(file_path)
        .strip_suffix(".rs")
        .unwrap_or(file_path);

    if path == "lib" {
        return "(root)".to_string();
    }

    let path = path.strip_suffix("/mod").unwrap_or(path);

    path.replace('/', "::")
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub generated: String,
    pub crates: BTreeMap<String, CrateStatus>,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
pub struct CrateStatus {
    pub modules: BTreeMap<String, ModuleStatusOutput>,
}

#[derive(Debug, Serialize)]
pub struct ModuleStatusOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gamma: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited_from: Option<String>,
}

impl From<&ModuleStatus> for ModuleStatusOutput {
    fn from(status: &ModuleStatus) -> Self {
        Self {
            beta: status.markers.beta.clone(),
            gamma: status.markers.gamma.clone(),
            lts: status.markers.lts.clone(),
            inherited_from: status.inherited_from.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub total_modules: usize,
    pub by_stage: BTreeMap<String, usize>,
    pub lts_count: usize,
}

pub fn generate_report(all_scans: &BTreeMap<String, CrateScan>) -> StatusReport {
    let mut crates = BTreeMap::new();
    let mut total_modules = 0;
    let mut by_stage = BTreeMap::new();
    by_stage.insert("alpha".to_string(), 0);
    by_stage.insert("beta".to_string(), 0);
    by_stage.insert("gamma".to_string(), 0);
    let mut lts_count = 0;

    for (crate_name, scan) in all_scans {
        let mut modules = BTreeMap::new();

        for (path, status) in &scan.modules {
            let module_path = file_path_to_module_path(path);
            modules.insert(module_path, ModuleStatusOutput::from(status));

            total_modules += 1;

            match status.markers.current_stage() {
                Stage::Alpha => *by_stage.get_mut("alpha").unwrap() += 1,
                Stage::Beta => *by_stage.get_mut("beta").unwrap() += 1,
                Stage::Gamma => *by_stage.get_mut("gamma").unwrap() += 1,
            }

            if status.markers.is_lts() {
                lts_count += 1;
            }
        }

        crates.insert(crate_name.clone(), CrateStatus { modules });
    }

    let now: DateTime<Utc> = Utc::now();

    StatusReport {
        generated: now.to_rfc3339(),
        crates,
        summary: Summary {
            total_modules,
            by_stage,
            lts_count,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_path_to_module_path_lib() {
        assert_eq!(file_path_to_module_path("src/lib.rs"), "(root)");
    }

    #[test]
    fn test_file_path_to_module_path_simple() {
        assert_eq!(file_path_to_module_path("src/types.rs"), "types");
    }

    #[test]
    fn test_file_path_to_module_path_mod_rs() {
        assert_eq!(file_path_to_module_path("src/journal/mod.rs"), "journal");
    }

    #[test]
    fn test_file_path_to_module_path_nested() {
        assert_eq!(
            file_path_to_module_path("src/journal/fixed.rs"),
            "journal::fixed"
        );
    }

    #[test]
    fn test_file_path_to_module_path_deeply_nested() {
        assert_eq!(
            file_path_to_module_path("src/utils/buffer/pool.rs"),
            "utils::buffer::pool"
        );
    }

    #[test]
    fn test_file_path_to_module_path_nested_mod_rs() {
        assert_eq!(
            file_path_to_module_path("src/journal/types/mod.rs"),
            "journal::types"
        );
    }
}
