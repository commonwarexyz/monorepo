use crate::{
    dependency::Dependency,
    marker::Markers,
    scanner::{CrateScan, ModuleStatus},
};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    pub path: String,
    pub message: String,
    pub severity: Severity,
}

pub fn check_redundant_markers(
    crate_name: &str,
    modules: &BTreeMap<String, ModuleStatus>,
) -> Vec<Conflict> {
    let mut conflicts = Vec::new();

    let explicit_mod_markers: BTreeMap<&str, &Markers> = modules
        .iter()
        .filter(|(path, status)| {
            path.ends_with("/mod.rs")
                && !status.markers.is_empty()
                && status.inherited_from.is_none()
        })
        .map(|(path, status)| (path.as_str(), &status.markers))
        .collect();

    for (path, status) in modules {
        if status.inherited_from.is_some() {
            continue;
        }

        if status.markers.is_empty() {
            continue;
        }

        let path_obj = Path::new(path);
        let mut current = path_obj.parent();

        while let Some(dir) = current {
            let mod_path = format!("{}/mod.rs", dir.display());

            if let Some(parent_markers) = explicit_mod_markers.get(mod_path.as_str()) {
                if mod_path != *path {
                    if status.markers.beta.is_some() && parent_markers.beta.is_some() {
                        conflicts.push(Conflict {
                            path: format!("{}/{}", crate_name, path),
                            message: format!(
                                "Redundant @beta marker (already inherited from {})",
                                mod_path
                            ),
                            severity: Severity::Error,
                        });
                    }
                    if status.markers.gamma.is_some() && parent_markers.gamma.is_some() {
                        conflicts.push(Conflict {
                            path: format!("{}/{}", crate_name, path),
                            message: format!(
                                "Redundant @gamma marker (already inherited from {})",
                                mod_path
                            ),
                            severity: Severity::Error,
                        });
                    }
                    if status.markers.lts.is_some() && parent_markers.lts.is_some() {
                        conflicts.push(Conflict {
                            path: format!("{}/{}", crate_name, path),
                            message: format!(
                                "Redundant @lts marker (already inherited from {})",
                                mod_path
                            ),
                            severity: Severity::Error,
                        });
                    }
                    break;
                }
            }

            current = dir.parent();
        }
    }

    conflicts
}

pub fn check_lts_violations(
    all_scans: &BTreeMap<String, CrateScan>,
    excluded_crates: &[&str],
) -> Vec<Conflict> {
    let mut violations = Vec::new();

    for (crate_name, scan) in all_scans {
        for (path, status) in &scan.modules {
            if !status.markers.is_lts() {
                continue;
            }

            for dep in &status.dependencies {
                if excluded_crates.contains(&dep.crate_name.as_str()) {
                    continue;
                }

                let Some(dep_scan) = all_scans.get(&dep.crate_name) else {
                    continue;
                };

                if !is_module_lts(dep, dep_scan) {
                    violations.push(Conflict {
                        path: format!("{}/{}", crate_name, path),
                        message: format!(
                            "LTS module imports from non-LTS module: {}",
                            dep.module_string()
                        ),
                        severity: Severity::Error,
                    });
                }
            }
        }
    }

    violations
}

fn is_module_lts(dep: &Dependency, scan: &CrateScan) -> bool {
    let module_files = get_module_files(&dep.module_path);

    for module_file in module_files {
        if let Some(status) = scan.modules.get(&module_file) {
            if status.markers.is_lts() {
                return true;
            }
        }
    }

    false
}

fn get_module_files(module_path: &[String]) -> Vec<String> {
    let mut files = Vec::new();

    if module_path.is_empty() {
        files.push("src/lib.rs".to_string());
    } else {
        let path = module_path.join("/");
        files.push(format!("src/{}.rs", path));
        files.push(format!("src/{}/mod.rs", path));
        files.push("src/lib.rs".to_string());
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_module_files_root() {
        let files = get_module_files(&[]);
        assert_eq!(files, vec!["src/lib.rs"]);
    }

    #[test]
    fn test_get_module_files_nested() {
        let files = get_module_files(&["buffer".to_string()]);
        assert!(files.contains(&"src/buffer.rs".to_string()));
        assert!(files.contains(&"src/buffer/mod.rs".to_string()));
        assert!(files.contains(&"src/lib.rs".to_string()));
    }

    #[test]
    fn test_get_module_files_deeply_nested() {
        let files = get_module_files(&["utils".to_string(), "buffer".to_string()]);
        assert!(files.contains(&"src/utils/buffer.rs".to_string()));
        assert!(files.contains(&"src/utils/buffer/mod.rs".to_string()));
        assert!(files.contains(&"src/lib.rs".to_string()));
    }
}
