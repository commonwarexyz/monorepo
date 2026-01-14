//! Parse the workspace to extract modules and readiness annotations.

mod cfg_if;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use toml::Value;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Invalid workspace: {0}")]
    InvalidWorkspace(String),
}

/// A parsed workspace containing all crates and their modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub crates: HashMap<String, Crate>,
}

/// A parsed crate with its modules and dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crate {
    pub name: String,
    pub path: PathBuf,
    pub modules: HashMap<String, Module>,
    pub dependencies: Vec<String>,
    pub dev_dependencies: Vec<String>,
}

/// A module with its readiness level and submodules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub path: String,
    pub readiness: u8,
    pub file_path: PathBuf,
    pub submodules: HashMap<String, Module>,
    pub is_explicit: bool,
}

impl Default for Module {
    fn default() -> Self {
        Self {
            path: String::new(),
            readiness: 0,
            file_path: PathBuf::new(),
            submodules: HashMap::new(),
            is_explicit: false,
        }
    }
}

/// Parse the workspace at the given root path.
pub fn parse_workspace(root: &Path) -> Result<Workspace, ParseError> {
    let cargo_toml_path = root.join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
    let cargo_toml: Value = toml::from_str(&cargo_toml_content)?;

    let members = cargo_toml
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .ok_or_else(|| ParseError::InvalidWorkspace("No workspace.members found".to_string()))?;

    let mut crates = HashMap::new();

    for member in members {
        let member_path = member
            .as_str()
            .ok_or_else(|| ParseError::InvalidWorkspace("Invalid member path".to_string()))?;

        // Skip fuzz crates and examples
        if member_path.contains("/fuzz") || member_path.starts_with("examples/") {
            continue;
        }

        let crate_path = root.join(member_path);
        if let Ok(krate) = parse_crate(&crate_path) {
            crates.insert(krate.name.clone(), krate);
        }
    }

    Ok(Workspace { crates })
}

/// Parse a single crate.
fn parse_crate(path: &Path) -> Result<Crate, ParseError> {
    let cargo_toml_path = path.join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(&cargo_toml_path)?;
    let cargo_toml: Value = toml::from_str(&cargo_toml_content)?;

    let name = cargo_toml
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| ParseError::InvalidWorkspace("No package.name found".to_string()))?
        .to_string();

    // Extract dependencies
    let dependencies = extract_deps(&cargo_toml, "dependencies");
    let dev_dependencies = extract_deps(&cargo_toml, "dev-dependencies");

    // Parse modules from lib.rs
    let lib_rs_path = path.join("src/lib.rs");
    let modules = if lib_rs_path.exists() {
        parse_modules(&lib_rs_path, &path.join("src"), "")?
    } else {
        HashMap::new()
    };

    Ok(Crate {
        name,
        path: path.to_path_buf(),
        modules,
        dependencies,
        dev_dependencies,
    })
}

/// Extract dependency names from Cargo.toml.
fn extract_deps(cargo_toml: &Value, section: &str) -> Vec<String> {
    cargo_toml
        .get(section)
        .and_then(|d| d.as_table())
        .map(|t| {
            t.keys()
                .filter(|k| k.starts_with("commonware-"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Parse modules from a Rust source file.
fn parse_modules(
    file_path: &Path,
    src_dir: &Path,
    parent_path: &str,
) -> Result<HashMap<String, Module>, ParseError> {
    let content = fs::read_to_string(file_path)?;
    let mut modules = HashMap::new();

    // Parse the file to find module declarations
    let parsed = match syn::parse_file(&content) {
        Ok(f) => f,
        Err(_) => return Ok(modules),
    };

    // Also check for cfg_if! blocks
    let cfg_if_modules = cfg_if::extract_modules_from_cfg_if(&content);

    for item in &parsed.items {
        if let syn::Item::Mod(item_mod) = item {
            let mod_name = item_mod.ident.to_string();
            let mod_path = if parent_path.is_empty() {
                mod_name.clone()
            } else {
                format!("{parent_path}::{mod_name}")
            };

            // Determine the module file path
            let (mod_file_path, has_submodules) = if item_mod.content.is_some() {
                // Inline module
                (file_path.to_path_buf(), false)
            } else {
                // External module
                let mod_rs = src_dir.join(&mod_name).join("mod.rs");
                let mod_file = src_dir.join(format!("{mod_name}.rs"));
                if mod_rs.exists() {
                    (mod_rs, true)
                } else if mod_file.exists() {
                    (mod_file, false)
                } else {
                    continue;
                }
            };

            // Check for #[readiness(N)] inside the module file
            let readiness = extract_readiness_from_file(&mod_file_path);

            // Recursively parse submodules
            let submodules = if has_submodules {
                let mod_dir = src_dir.join(&mod_name);
                parse_modules(&mod_file_path, &mod_dir, &mod_path)?
            } else {
                HashMap::new()
            };

            modules.insert(
                mod_name.clone(),
                Module {
                    path: mod_path,
                    readiness,
                    file_path: mod_file_path,
                    submodules,
                    is_explicit: readiness > 0,
                },
            );
        }
    }

    // Merge cfg_if modules
    for (mod_name, _cfg_if_readiness) in cfg_if_modules {
        let mod_path = if parent_path.is_empty() {
            mod_name.clone()
        } else {
            format!("{parent_path}::{mod_name}")
        };

        let mod_rs = src_dir.join(&mod_name).join("mod.rs");
        let mod_file = src_dir.join(format!("{mod_name}.rs"));
        let (mod_file_path, has_submodules) = if mod_rs.exists() {
            (mod_rs, true)
        } else if mod_file.exists() {
            (mod_file, false)
        } else {
            continue;
        };

        // Check for #[readiness(N)] inside the module file
        let readiness = extract_readiness_from_file(&mod_file_path);

        let submodules = if has_submodules {
            let mod_dir = src_dir.join(&mod_name);
            parse_modules(&mod_file_path, &mod_dir, &mod_path)?
        } else {
            HashMap::new()
        };

        modules
            .entry(mod_name.clone())
            .and_modify(|m| {
                if readiness > m.readiness {
                    m.readiness = readiness;
                    m.is_explicit = true;
                }
            })
            .or_insert(Module {
                path: mod_path,
                readiness,
                file_path: mod_file_path,
                submodules,
                is_explicit: readiness > 0,
            });
    }

    Ok(modules)
}

/// Extract readiness level from a module file.
/// Looks for `readiness!(N)` patterns (with or without path prefix).
fn extract_readiness_from_file(file_path: &Path) -> u8 {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    for line in content.lines() {
        let trimmed = line.trim();

        // Look for pattern: readiness!(N) or commonware_macros::readiness!(N)
        if let Some(pos) = trimmed.find("readiness!(") {
            let rest = &trimmed[pos + 11..];
            if let Some(end) = rest.find(')') {
                if let Ok(level) = rest[..end].trim().parse::<u8>() {
                    return level.min(4);
                }
            }
        }
    }

    0
}
