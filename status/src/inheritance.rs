use crate::{marker::Markers, scanner::ModuleStatus};
use std::{collections::BTreeMap, path::Path};

pub fn apply_inheritance(modules: &mut BTreeMap<String, ModuleStatus>) {
    let explicit_mod_markers: BTreeMap<String, Markers> = modules
        .iter()
        .filter(|(path, status)| path.ends_with("/mod.rs") && !status.markers.is_empty())
        .map(|(path, status)| (path.clone(), status.markers.clone()))
        .collect();

    let paths: Vec<String> = modules.keys().cloned().collect();

    for path in paths {
        let status = modules.get(&path).unwrap();

        if !status.markers.is_empty() {
            continue;
        }

        if let Some((parent_path, parent_markers)) = find_parent_mod(&path, &explicit_mod_markers) {
            let status = modules.get_mut(&path).unwrap();
            status.markers = parent_markers;
            status.inherited_from = Some(parent_path);
        }
    }
}

fn find_parent_mod(
    path: &str,
    explicit_markers: &BTreeMap<String, Markers>,
) -> Option<(String, Markers)> {
    let path_obj = Path::new(path);
    let mut current = path_obj.parent();

    while let Some(dir) = current {
        let mod_path = format!("{}/mod.rs", dir.display());

        if let Some(markers) = explicit_markers.get(&mod_path) {
            return Some((mod_path, markers.clone()));
        }

        current = dir.parent();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{marker::Markers, scanner::ModuleStatus};

    fn make_status(markers: Markers) -> ModuleStatus {
        ModuleStatus {
            markers,
            inherited_from: None,
            dependencies: vec![],
        }
    }

    #[test]
    fn test_inheritance_from_mod_rs() {
        let mut modules = BTreeMap::new();

        modules.insert(
            "src/journal/mod.rs".to_string(),
            make_status(Markers {
                beta: Some("0.1.0".to_string()),
                lts: Some("0.1.0".to_string()),
                ..Default::default()
            }),
        );
        modules.insert(
            "src/journal/fixed.rs".to_string(),
            make_status(Markers::default()),
        );
        modules.insert(
            "src/journal/contiguous/mod.rs".to_string(),
            make_status(Markers::default()),
        );

        apply_inheritance(&mut modules);

        let fixed = modules.get("src/journal/fixed.rs").unwrap();
        assert_eq!(fixed.markers.beta, Some("0.1.0".to_string()));
        assert_eq!(fixed.markers.lts, Some("0.1.0".to_string()));
        assert_eq!(fixed.inherited_from, Some("src/journal/mod.rs".to_string()));

        let contiguous = modules.get("src/journal/contiguous/mod.rs").unwrap();
        assert_eq!(contiguous.markers.beta, Some("0.1.0".to_string()));
    }

    #[test]
    fn test_lib_rs_does_not_cascade() {
        let mut modules = BTreeMap::new();

        modules.insert(
            "src/lib.rs".to_string(),
            make_status(Markers {
                beta: Some("0.1.0".to_string()),
                ..Default::default()
            }),
        );
        modules.insert("src/types.rs".to_string(), make_status(Markers::default()));

        apply_inheritance(&mut modules);

        let types = modules.get("src/types.rs").unwrap();
        assert!(types.markers.is_empty());
        assert!(types.inherited_from.is_none());
    }

    #[test]
    fn test_explicit_markers_not_overwritten() {
        let mut modules = BTreeMap::new();

        modules.insert(
            "src/journal/mod.rs".to_string(),
            make_status(Markers {
                beta: Some("0.1.0".to_string()),
                ..Default::default()
            }),
        );
        modules.insert(
            "src/journal/fixed.rs".to_string(),
            make_status(Markers {
                gamma: Some("0.2.0".to_string()),
                ..Default::default()
            }),
        );

        apply_inheritance(&mut modules);

        let fixed = modules.get("src/journal/fixed.rs").unwrap();
        assert_eq!(fixed.markers.gamma, Some("0.2.0".to_string()));
        assert!(fixed.markers.beta.is_none());
        assert!(fixed.inherited_from.is_none());
    }
}
