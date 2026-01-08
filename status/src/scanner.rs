use crate::dependency::{parse_dependencies, Dependency};
use crate::error::Error;
use crate::marker::{parse_markers, Markers};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct ModuleStatus {
    #[serde(flatten)]
    pub markers: Markers,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited_from: Option<String>,
    #[serde(skip)]
    pub dependencies: Vec<Dependency>,
}

impl ModuleStatus {
    pub const fn new(markers: Markers, dependencies: Vec<Dependency>) -> Self {
        Self {
            markers,
            inherited_from: None,
            dependencies,
        }
    }
}

#[derive(Debug)]
pub struct CrateScan {
    pub name: String,
    pub modules: BTreeMap<String, ModuleStatus>,
}

pub fn scan_crate(crate_path: &Path, crate_name: &str) -> Result<CrateScan, Error> {
    let src_path = crate_path.join("src");
    let mut modules = BTreeMap::new();

    if !src_path.exists() {
        return Ok(CrateScan {
            name: crate_name.to_string(),
            modules,
        });
    }

    scan_directory(&src_path, &src_path, &mut modules)?;

    Ok(CrateScan {
        name: crate_name.to_string(),
        modules,
    })
}

fn scan_directory(
    base_path: &Path,
    current_path: &Path,
    modules: &mut BTreeMap<String, ModuleStatus>,
) -> Result<(), Error> {
    let entries = std::fs::read_dir(current_path)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            scan_directory(base_path, &path, modules)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let rel_path = path
                .strip_prefix(base_path.parent().unwrap())
                .unwrap()
                .to_string_lossy()
                .to_string();

            let content = std::fs::read_to_string(&path)?;
            let markers = parse_markers(&content);
            let dependencies = parse_dependencies(&content);

            modules.insert(rel_path, ModuleStatus::new(markers, dependencies));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_status_serialization() {
        let status = ModuleStatus {
            markers: Markers {
                beta: Some("0.1.0".to_string()),
                gamma: None,
                lts: Some("0.2.0".to_string()),
            },
            inherited_from: None,
            dependencies: vec![],
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains(r#""beta":"0.1.0""#));
        assert!(json.contains(r#""lts":"0.2.0""#));
        assert!(!json.contains("gamma"));
        assert!(!json.contains("inherited_from"));
    }
}
