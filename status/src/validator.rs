use crate::dependency::Dependency;
use crate::marker::Markers;
use crate::scanner::{CrateScan, ModuleStatus};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

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

                if !is_dependency_lts(dep, dep_scan) {
                    let dep_str = format_dependency(dep);
                    violations.push(Conflict {
                        path: format!("{}/{}", crate_name, path),
                        message: format!("LTS module imports from non-LTS: {}", dep_str),
                        severity: Severity::Error,
                    });
                }
            }
        }
    }

    violations
}

fn is_dependency_lts(dep: &Dependency, scan: &CrateScan) -> bool {
    let possible_paths = generate_possible_paths(&dep.path_segments);

    for possible_path in possible_paths {
        if let Some(status) = scan.modules.get(&possible_path) {
            if status.markers.is_lts() {
                return true;
            }
        }
    }

    false
}

fn generate_possible_paths(segments: &[String]) -> Vec<String> {
    let mut paths = vec!["src/lib.rs".to_string()];

    if segments.is_empty() {
        return paths;
    }

    for i in 1..=segments.len() {
        let prefix: Vec<String> = segments[..i].iter().map(|s| s.to_lowercase()).collect();
        let joined = prefix.join("/");

        paths.push(format!("src/{}.rs", joined));
        paths.push(format!("src/{}/mod.rs", joined));
    }

    paths
}

fn format_dependency(dep: &Dependency) -> String {
    if dep.path_segments.is_empty() {
        format!("commonware_{}", dep.crate_name)
    } else {
        format!(
            "commonware_{}::{}",
            dep.crate_name,
            dep.path_segments.join("::")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_possible_paths() {
        let paths = generate_possible_paths(&["buffer".to_string(), "PoolRef".to_string()]);
        assert!(paths.contains(&"src/lib.rs".to_string()));
        assert!(paths.contains(&"src/buffer.rs".to_string()));
        assert!(paths.contains(&"src/buffer/mod.rs".to_string()));
        assert!(paths.contains(&"src/buffer/poolref.rs".to_string()));
        assert!(paths.contains(&"src/buffer/poolref/mod.rs".to_string()));
    }

    #[test]
    fn test_format_dependency() {
        let dep = Dependency {
            crate_name: "codec".to_string(),
            path_segments: vec!["Encode".to_string()],
        };
        assert_eq!(format_dependency(&dep), "commonware_codec::Encode");

        let dep_empty = Dependency {
            crate_name: "codec".to_string(),
            path_segments: vec![],
        };
        assert_eq!(format_dependency(&dep_empty), "commonware_codec");
    }
}
